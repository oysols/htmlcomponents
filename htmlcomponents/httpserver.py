from __future__ import annotations

import binascii
from itertools import zip_longest
import concurrent.futures
import contextlib
import dataclasses
import enum
import functools
import gzip
import hashlib
import hmac
import http.server
import json
import mimetypes
import secrets
import socket
import ssl
import textwrap
import time
import traceback
import typing
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from types import UnionType
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Protocol,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
    runtime_checkable,
)

SECURE_COOKIES = True
COOKIE_HMAC_SECRET = secrets.token_bytes(32)


@runtime_checkable
class HTMLRenderable(Protocol):
    def render_html(self) -> str:
        pass


class ContentType:
    text_html = "text/html"
    text_plain = "text/plain"
    octet_stream = "application/octet-stream"
    application_json = "application/json"


class Method(str, enum.Enum):
    get = "GET"
    head = "HEAD"
    post = "POST"
    put = "PUT"
    delete = "DELETE"
    connect = "CONNECT"
    options = "OPTIONS"
    trace = "TRACE"
    patch = "PATCH"
    # connect = "CONNECT"


def serialize_with_hmac(key: bytes, data: Any) -> str:
    # Used for cookies
    data_bytes = json.dumps(data).encode()
    hmac_hex = hmac.new(key, msg=data_bytes, digestmod=hashlib.sha256).hexdigest()
    data_hex = binascii.hexlify(data_bytes).decode()
    return data_hex + hmac_hex


def deserialize_and_verify_hmac(key: bytes, serialized_data: str) -> Any:
    # Used for cookies
    if not len(serialized_data) > 64:
        raise Exception("Data does not include hmac")
    data_hex = serialized_data[:-64]
    client_specifiec_hmac_hex = serialized_data[-64:]
    data_bytes = binascii.unhexlify(data_hex)
    data_hmac_hex = hmac.new(key, msg=data_bytes, digestmod=hashlib.sha256).hexdigest()
    if not hmac.compare_digest(data_hmac_hex, client_specifiec_hmac_hex):
        raise Exception("HMAC verification failed")
    return json.loads(data_bytes.decode())


def file_content_iterator(
    file: Path, chunk_size: int, from_offset: int = 0, to_offset: int | None = None
) -> Iterator[bytes]:
    with file.open("rb") as f:
        f.seek(from_offset)
        while True:
            pos = f.tell()
            if to_offset and (pos + chunk_size) >= to_offset:
                yield f.read(to_offset - pos)
                break
            data = f.read(chunk_size)
            if data == b"":
                break
            yield data


def match_path(pattern: str, path: str) -> Dict[str, str] | None:
    # Returns None if it does not match
    # Returns matching variables if included in pattern
    parsed = {}
    assert pattern.startswith("/")
    assert path.startswith("/")
    regex_parts = pattern.split("/")[1:]
    path_parts = path.split("/")[1:]
    # Short ciruit so we know that path_parts is always equal or longer in zip_longest
    if len(regex_parts) > len(path_parts):
        return None
    glob = None
    for pattern_part, path_part in zip_longest(regex_parts, path_parts):
        if glob is not None:
            parsed[glob] += f"/{path_part}"
            continue
        elif pattern_part == path_part:
            continue
        elif pattern_part.startswith("<*") and pattern_part.endswith(">"):
            glob = pattern_part[2:-1]
            parsed[glob] = path_part
        elif pattern_part.startswith("<") and pattern_part.endswith(">"):
            if not path_part:
                return None
            parsed[pattern_part[1:-1]] = path_part
        elif "<" in pattern_part or ">" in pattern_part:
            raise Exception(f"Unexpected brackets in route '{pattern}'")
        else:
            return None
    return parsed


T = TypeVar("T")


@dataclass
class Headers:
    # Cannot use a simple dictionary for headers since we might receive duplicates
    # Mostly a problem with multiple Set-Cookie in proxy mode
    # https://www.rfc-editor.org/rfc/rfc7230
    # > recipients ought to handle "Set-Cookie" as a special case while processing header fields.
    raw_headers: list[tuple[str, str]]

    @staticmethod
    def from_raw(http_headers: list[str]) -> Headers:
        return Headers([(k.strip(), v.strip()) for k, v in [header.split(":", 1) for header in http_headers if header]])

    @overload
    def get(self, key: str) -> str | None: ...

    @overload
    def get(self, key: str, default: T) -> str | T: ...

    # Replace overloads with TypeVar Defaults in Python 3.13 https://peps.python.org/pep-0696
    def get(self, key: str, default: T = None) -> str | T:  # type: ignore
        for k, v in self.raw_headers:
            if k.lower() == key.lower():
                return v
        return default

    def set(self, key: str, value: str) -> None:
        has_set = False
        new_raw_headers = []
        for k, v in self.raw_headers:
            if k.lower() == key.lower():
                if has_set:
                    continue
                new_raw_headers.append((key, value))
                has_set = True
            else:
                new_raw_headers.append((k, v))
        else:
            if not has_set:
                new_raw_headers.append((key, value))
        self.raw_headers = new_raw_headers

    def copy(self) -> Headers:
        return Headers(self.raw_headers.copy())

    def to_dict(self) -> dict[str, str]:
        return {k: v for k, v in self.raw_headers}


@dataclass
class Request:
    remote_addr: str
    method: Method
    path: str
    query_params: Dict[str, str]
    headers: Headers
    content_length: int
    body: bytes
    request_start: float
    matched_route: str | None
    matched_route_mapping: Dict[str, str] | None

    def __repr__(self) -> str:
        return f"Request<{self.method.value} {self.matched_route}>"

    @staticmethod
    def from_wsgi(environ: Dict[str, Any]) -> "Request":
        method = Method(environ["REQUEST_METHOD"])
        path = environ["PATH_INFO"]
        query_params = dict(urllib.parse.parse_qsl(environ["QUERY_STRING"]))
        # WSGI request headers are prefixed with HTTP_
        raw_headers = [(k[5:].replace("_", "-"), v) for k, v in environ.items() if k.startswith("HTTP_")]
        headers = Headers(raw_headers)
        remote_addr = environ["REMOTE_ADDR"]
        # Read body if content_length
        content_length = int(environ["CONTENT_LENGTH"]) if environ["CONTENT_LENGTH"] else 0
        body = environ["wsgi.input"].read(content_length) if content_length else b""
        return Request(
            remote_addr,
            method,
            path,
            query_params,
            headers,
            content_length,
            body,
            time.time(),
            None,
            None,
        )

    @staticmethod
    def from_raw(
        remote_addr: str, header: bytes, buf_sock_reader: BufferedSocketReader, conn: socket.socket | None
    ) -> Request:
        http_code_header, *http_headers = header.decode().split("\r\n")
        raw_method, url, _protocol = http_code_header.split()
        method = Method(raw_method)
        path, *query_string = url.split("?", 1)
        query_params = dict(urllib.parse.parse_qsl(query_string[0], keep_blank_values=True)) if query_string else {}
        headers = Headers.from_raw(http_headers)
        # Read body if content_length
        content_length = int(headers.get("Content-Length", 0))
        body = buf_sock_reader.read(content_length) if content_length else b""
        return Request(
            headers.get("X-Forwarded-For") or remote_addr,  # TODO: Security
            method,
            path,
            query_params,
            headers,
            content_length,
            body,
            time.time(),
            None,
            None,
        )

    def get_session(self) -> Dict[Any, Any]:
        # Parse session cookie
        # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cookie
        # Cookie: name=value; name2=value2; name3=value3
        session = {}
        for cookie in self.headers.get("Cookie", "").split(";"):
            try:
                name, data = cookie.strip().split("=")
                if name == "session":
                    session = deserialize_and_verify_hmac(COOKIE_HMAC_SECRET, data)
                    break
            except Exception:
                pass
        return session

    def form_data(self) -> Dict[str, str]:
        return dict(urllib.parse.parse_qsl(self.body.decode(), keep_blank_values=True))

    def json(self) -> Dict[str, Any]:
        return json.loads(self.body.decode())  # type: ignore

    def print(self) -> None:
        print(self)
        for k, v in dataclasses.asdict(self).items():
            print(" ", k, v)


@dataclass
class Response:
    body: bytes | Iterator[bytes]
    code: int
    headers: Headers

    def __repr__(self) -> str:
        return f"Response<{self.code}>"

    def __init__(
        self,
        body: BodyResponse,
        code: int = 200,
        headers: Dict[str, str] | None = None,
        set_session: Dict[str, str] | None = None,
        raw_headers: Headers | None = None,
    ) -> None:
        if raw_headers:
            assert isinstance(body, (bytes, Iterator))
            self.body = body
            self.code = code
            assert headers is None
            assert set_session is None
            self.headers = raw_headers
            return
        self.body, content_type = self.cast_body_response(body)
        self.code = code
        self.headers = Headers([])
        self.headers.set("Content-Type", content_type)
        if isinstance(self.body, bytes):
            self.headers.set("Content-Length", str(len(self.body)))
        if set_session is not None:
            serialized_data = serialize_with_hmac(COOKIE_HMAC_SECRET, set_session)
            if set_session == {}:
                cookie = "session=; Max-Age=0; Path=/"
            elif SECURE_COOKIES:
                cookie = f"session={serialized_data}; Secure; HttpOnly; SameSite=Lax; Path=/"
            else:
                cookie = f"session={serialized_data}; HttpOnly; SameSite=Lax; Path=/"
            self.headers.set("Set-Cookie", cookie)
        if headers:
            for k, v in headers.items():
                self.headers.set(k, v)

    @staticmethod
    def cast_body_response(body: BodyResponse) -> Tuple[bytes | Iterator[bytes], str]:
        # Returns bytes and guesses content type
        if isinstance(body, Iterator):
            return body, ContentType.text_plain
        elif isinstance(body, bytes):
            return body, ContentType.octet_stream
        elif isinstance(body, str):
            return body.encode(), ContentType.text_plain
        elif isinstance(body, dict):
            return json.dumps(body).encode(), ContentType.application_json
        elif isinstance(body, HTMLRenderable):
            return body.render_html().encode(), ContentType.text_html
        elif isinstance(body, list):
            components = []
            for item in body:
                if not isinstance(item, HTMLRenderable):
                    raise TypeError(f"Unsupported cast from list of {type(item).__name__} to bytes.")
                components.append(item.render_html().encode())
            return b"\n".join(components), ContentType.text_html
        raise TypeError(f"Unsupported cast from {type(body).__name__} to bytes.")


BodyResponse = bytes | str | Dict[str, Any] | HTMLRenderable | Sequence[HTMLRenderable] | Iterator[bytes]
RouteFunctionResponse = Response | BodyResponse
RouteFunction = Callable[[Request], RouteFunctionResponse] | Callable[[], RouteFunctionResponse]


class App:
    routes: List[Tuple[str, str, RouteFunction]]

    def __init__(self) -> None:
        self.routes = []

    def add_route(self, pattern: str, method: str) -> Callable[[RouteFunction], RouteFunction]:
        def outer(func: RouteFunction) -> RouteFunction:
            self.routes.append((method, pattern, func))
            return func

        return outer

    get = functools.partialmethod(add_route, method=Method.get)
    post = functools.partialmethod(add_route, method=Method.post)

    @staticmethod
    def default_route() -> Response:
        return Response(b"Page not found", 404, {"Content-Type": "text/plain"})

    def get_route(self, method: str, path: str) -> Tuple[str | None, Dict[str, str] | None, RouteFunction]:
        for route_method, pattern, route_function in self.routes:
            if route_method != method:
                continue
            if (matched_variables := match_path(pattern, path)) is not None:
                return pattern, matched_variables, route_function
        return None, None, self.default_route

    @staticmethod
    def gzip_middleware(request: Request, response: Response) -> None:
        if isinstance(response.body, bytes) and "gzip" in [
            encoding.strip() for encoding in request.headers.get("Accept-Encoding", "").split(",")
        ]:
            if response.headers.get("Content-Encoding"):
                return
            response.body = gzip.compress(response.body)
            response.headers.set("Content-Encoding", "gzip")
            response.headers.set("Content-Length", str(len(response.body)))

    def handle(self, request: Request) -> Response:
        # Get route
        route, mapping, route_function = self.get_route(request.method, request.path)
        # Add routing to Request object
        request.matched_route = route
        request.matched_route_mapping = mapping
        # Call route function
        if route_function.__code__.co_argcount == 0:  # 0 argument types + 1 return type = 1
            # Function does not take the Request object as argument
            route_response: RouteFunctionResponse = route_function()  # type: ignore
        else:
            # Function takes the Request object as argument
            route_response = route_function(request)  # type: ignore
        # Convert RouteFunctionResponse to Response
        response = route_response if isinstance(route_response, Response) else Response(route_response)
        # Post processing
        self.gzip_middleware(request, response)
        return response

    def run(self, host: str = "0.0.0.0", port: int = 8000) -> None:
        http_server(self.handle, host, port)

    def to_wsgi(self) -> WSGIWrapper:
        return WSGIWrapper(self.handle)

    def run_wsgiref(self, host: str = "0.0.0.0", port: int = 8000) -> None:
        import wsgiref.simple_server

        with wsgiref.simple_server.make_server(host, port, self.to_wsgi()) as httpd:
            print(f"wsgiref serving on {host}:{port}")
            httpd.serve_forever()

    def serve_static_path(
        self, base_route: str, local_path: Path, guess_content_type: bool = True, cache_control: int | None = None
    ) -> None:
        CHUNK_SIZE = 1024 * 1024
        resolved_local_path = local_path.resolve()
        route = str(Path("/") / base_route.strip("/") / "<*path>")

        @self.get(route)
        @cast_request
        def static_path(path_path: str, header_range: str | None) -> Response:
            local_path = (resolved_local_path / Path(path_path)).resolve()
            assert local_path.relative_to(resolved_local_path)
            if not local_path.is_file():
                return self.default_route()
            file_size = local_path.stat().st_size
            content_type = "application/octet-stream"
            if guess_content_type:
                content_type = mimetypes.guess_type(local_path)[0] or content_type
            headers = {
                "Accept-Ranges": "bytes",
                "Content-Type": content_type,
            }
            if cache_control is not None:
                headers |= {"Cache-Control": f"private,max-age={cache_control}"}
            # Support Content-Range to allow remote seeking in files
            if header_range:
                try:
                    bytestring, rangestring = header_range.split("=")
                    if bytestring != "bytes":
                        raise TypeError("Unsupported range type")
                    startstring, endstring = rangestring.split("-")
                    start = int(startstring)
                    inclusive_end = int(endstring) if endstring else file_size - 1
                    if start < 0 or start >= file_size or inclusive_end < start or inclusive_end >= file_size:
                        raise ValueError("Invalid byte range")
                except Exception as e:
                    return Response(f"Invalid Range request: {e}", 400)
                return Response(
                    file_content_iterator(local_path, CHUNK_SIZE, start, inclusive_end + 1),
                    206,
                    headers
                    | {
                        "Content-Range": f"bytes {start}-{inclusive_end}/{file_size}",
                        "Content-Length": str(file_size - start),
                    },
                )
            return Response(
                file_content_iterator(local_path, CHUNK_SIZE),
                200,
                headers | {"Content-Length": str(file_size)},
            )


class BufferedSocketReader:
    def __init__(self, conn: socket.socket, timeout: int = 5) -> None:
        self.conn = conn
        self.buffer: bytes = b""
        self.max_buf_size = 10e6  # bytes
        self.timeout = timeout  # seconds

        self.conn.settimeout(self.timeout)

    def _recv_to_buf(self, size: int) -> None:
        try:
            recv = self.conn.recv(size)
        except TimeoutError:
            raise TimeoutError(f"Read timed out after {self.timeout}s")
        if recv == b"":
            raise ConnectionResetError("Client closed connection")
        self.buffer += recv
        if len(self.buffer) > self.max_buf_size:
            raise Exception(f"Read buffer exceeds max size: {len(self.buffer)} > {self.max_buf_size}")

    def read_to_delimiter(self, delimiter: bytes) -> bytes:
        while delimiter not in self.buffer:
            self._recv_to_buf(1024)
        data, self.buffer = self.buffer.split(delimiter, maxsplit=1)
        return data + delimiter

    def read(self, size: int) -> bytes:
        while len(self.buffer) < size:
            self._recv_to_buf(size - len(self.buffer))
        data, self.buffer = self.buffer[:size], self.buffer[size:]
        return data

    def is_alive(self) -> bool:
        try:
            self.conn.settimeout(0)
            self._recv_to_buf(1)
        except (BlockingIOError, ssl.SSLWantReadError):
            return True
        except Exception:
            return False
        finally:
            self.conn.settimeout(self.timeout)
        raise Exception("Unexpected data from socket")


RequestHandler = Callable[[Request], Response]


class WrappedSSLSocket(ssl.SSLSocket):
    intercepted_sni_hostname: str | None = None


def connection_handler(
    conn: socket.socket | WrappedSSLSocket,
    client_address: str,
    handler: RequestHandler,
    keep_alive: bool,
    use_tls: bool,
    debug: bool = False,
) -> None:
    connection_start = time.time()
    pretty_client_address = f"{client_address[0]}:{client_address[1]}"
    reason_for_close = None
    if debug:
        print(f"{pretty_client_address} Connection opened")
    try:
        # Perform SSL handshake inside thread to avoid blocking main loop
        if use_tls:
            assert isinstance(conn, WrappedSSLSocket)
            conn.settimeout(5)
            conn.do_handshake()
            if debug:
                print(f"{pretty_client_address} Connection TLS handshake {(time.time() - connection_start)*1000:.2f}ms")

        socket_reader = BufferedSocketReader(conn)
        while True:  # Reuse connection if keep alive is set
            request_start = time.time()
            header = socket_reader.read_to_delimiter(b"\r\n\r\n")
            request = Request.from_raw(client_address[0], header, socket_reader, conn)

            # Validate that Host matches SNI
            if use_tls:
                assert isinstance(conn, WrappedSSLSocket)
                host, *port = request.headers.get("Host", "").split(":")
                if port:
                    assert len(port) == 1
                    assert int(port[0]) > 0
                    assert int(port[0]) <= 65535
                if host != conn.intercepted_sni_hostname:
                    raise ssl.SSLError(
                        f"Host header does not match SNI {request.headers.get('Host')} != {conn.intercepted_sni_hostname}"
                    )

            try:
                response = handler(request)
            except Exception:
                traceback.print_exc()
                response = Response("Internal Server Error", 500)
            request_handler_duration = time.time() - request.request_start
            response.headers.set("Server", "httpserver.py")
            response.headers.set("Connection", "keep-alive" if keep_alive else "close")
            phrase, _ = http.server.BaseHTTPRequestHandler.responses[response.code]
            conn.sendall(f"HTTP/1.1 {response.code} {phrase}\r\n".encode())
            conn.sendall(b"\r\n".join([f"{k}: {v}".encode() for k, v in response.headers.raw_headers]))
            conn.sendall(b"\r\n\r\n")

            # Send body
            transfered_bytes = 0
            body_iterable = iter([response.body]) if isinstance(response.body, bytes) else response.body
            transfer_exception = None
            try:
                for chunk in body_iterable:
                    transfered_bytes += len(chunk)
                    if chunk == b"" and not socket_reader.is_alive():
                        # Endpoint can yield b"" to verify connection status
                        break
                    conn.sendall(chunk)
            except Exception as e:
                transfer_exception = e
                raise
            finally:
                # Request logging
                total_duration = time.time() - request_start
                print(
                    pretty_client_address,
                    request.headers.get("Host"),
                    response.code,
                    request.method.value,
                    request.path,
                    f"{request_handler_duration * 1000:.2f}ms",
                    f"{transfered_bytes / 1000:.3f}kB",
                    f"{total_duration * 1000:.2f}ms",
                    (
                        f"{type(transfer_exception).__name__}: {transfer_exception}"
                        if transfer_exception is not None
                        else ""
                    ),
                )
            if not keep_alive:
                reason_for_close = "No keep alive"
                break
    except (ConnectionResetError, TimeoutError, BrokenPipeError, ssl.SSLError) as e:
        reason_for_close = f"{type(e).__name__}: {e}"
    except Exception as e:
        reason_for_close = f"Unhandled Exception: {e}"
        traceback.print_exc()
    finally:
        if debug:
            print(
                f"{pretty_client_address} Connection closed {(time.time() - connection_start)*1000:.2f}ms: {reason_for_close}"
            )
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()


def sni_callback(ssl_sock: WrappedSSLSocket, hostname: str, context: ssl.SSLContext) -> None:
    # Store SNI to validate against Host header
    ssl_sock.intercepted_sni_hostname = hostname


def http_server(
    handler: RequestHandler,
    host: str = "0.0.0.0",
    port: int = 8000,
    threads: int = 20,
    keep_alive: bool = False,
    use_tls: bool = False,
    tls_crt: Path | None = None,
    tls_key: Path | None = None,
    debug: bool = False,
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Disable Nagle's algorithm https://en.wikipedia.org/wiki/Nagle's_algorithm
    sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    server_address = (host, port)
    sock.bind(server_address)
    sock.listen(socket.SOMAXCONN)
    print(f"socketserver listening on {host}:{port}")
    # Create a tls context if tls is enabled
    maybe_ssl: typing.ContextManager[socket.socket | ssl.SSLSocket] = contextlib.nullcontext(sock)
    if use_tls:
        if tls_crt is None or tls_key is None:
            raise Exception("Missing tsl_crt or tsl_key")
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(tls_crt, tls_key)
        # Wrap to store SNI for validation
        ssl_context.sslsocket_class = WrappedSSLSocket
        ssl_context.sni_callback = sni_callback  # type: ignore
        maybe_ssl = ssl_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
    with maybe_ssl as sock:
        max_queue = 200
        # Connection thread pool
        with concurrent.futures.ThreadPoolExecutor(threads) as e:
            while True:
                if e._work_queue.qsize() > max_queue:
                    print(f"Warn: All threads busy. Queue of {e._work_queue.qsize()}")
                    while e._work_queue.qsize() > max_queue:
                        time.sleep(0.001)
                    print("Threads available")
                conn, client_address = sock.accept()
                e.submit(connection_handler, conn, client_address, handler, keep_alive, use_tls, debug)


@dataclass
class WSGIWrapper:
    """Implements WSGIApplication interface: Callable[[WSGIEnvironment, StartResponse], Iterable[bytes]]"""

    def __init__(self, handler: RequestHandler) -> None:
        self.handler = handler

    def __call__(
        self,
        environ: Dict[str, Any],  # wsgiref.types.WSGIEnvironment
        start_response: Callable[[str, List[Tuple[str, str]]], Callable[..., Any]],  # wsgiref.types.StartResponse,
    ) -> Iterable[bytes]:
        request = Request.from_wsgi(environ)

        response = self.handler(request)

        phrase, _ = http.server.BaseHTTPRequestHandler.responses[response.code]
        start_response(f"{response.code} {phrase}", [(k, v) for k, v in response.headers.raw_headers])
        if isinstance(response.body, bytes):
            yield response.body
        else:
            yield from response.body


# Endpoint argument parsing


def validate_and_cast_to_type(
    data: Any,
    data_type: Type[T],
    cast_int_to_float: bool = True,
    cast_str_to_int_and_float: bool = True,
    cast_dict_to_dataclass: bool = True,
    force_cast_unsupported_datatype: bool = False,
) -> T:
    if isinstance(data, data_type):
        return data
    if data_type == Any:
        return data  # type: ignore
    # Catch options to pass down recursively
    arguments = locals().copy()
    arguments.pop("data_type")
    arguments.pop("data")
    options = arguments
    if not isinstance(data_type, (typing._GenericAlias, typing.GenericAlias, type, UnionType)):  # type: ignore
        raise TypeError(f"{data_type} type:{type(data_type).__name__} is not a type")
    # Basic types
    simple_types = [int, float, str, bool, bytes]
    if data_type in simple_types:
        if cast_int_to_float and isinstance(data, int) and data_type is float:
            return float(data)  # type: ignore
        if cast_str_to_int_and_float and isinstance(data, str) and data_type in [int, float]:
            return data_type(data)  # type: ignore
        raise TypeError(f"Expected {data_type}, got '{type(data).__name__}'")
    # Dataclasses
    if dataclasses.is_dataclass(data_type):
        if dataclasses.is_dataclass(data):
            raise TypeError(f"Expected {data_type}, got '{type(data).__name__}'")
        elif cast_dict_to_dataclass:
            if not isinstance(data, dict):
                raise TypeError(f"Expected dict when casting to {data_type}, got '{type(data).__name__}'")
        else:
            raise TypeError("Casting to dataclass not allowed.")
        fieldtypes = typing.get_type_hints(data_type)
        return data_type(
            **{key: validate_and_cast_to_type(value, fieldtypes[key], **options) for key, value in data.items()}
        )  # type: ignore
    # Generic types
    elif hasattr(data_type, "__origin__"):
        # List[type]
        if data_type.__origin__ is list:  # type: ignore
            (item_type,) = data_type.__args__  # type: ignore
            return [validate_and_cast_to_type(item, item_type, **options) for item in data]  # type: ignore
        # TODO: Tuple
        # Dict[type, type]
        elif data_type.__origin__ is dict:  # type: ignore
            key_type, value_type = data_type.__args__  # type: ignore
            return {
                validate_and_cast_to_type(key, key_type, **options): validate_and_cast_to_type(
                    value, value_type, **options
                )
                for key, value in data.items()
            }  # type: ignore
        else:
            raise TypeError(f"Unsupported generic type {data_type}")
    # UnionTypes: str | None
    if isinstance(data_type, UnionType) or (
        hasattr(data_type, "__origin__") and data_type.__origin__ == Union  # type: ignore
    ):
        for subtype in data_type.__args__:  # type: ignore
            try:
                return validate_and_cast_to_type(data, subtype, *options)  # type: ignore
            except TypeError:
                pass
        raise TypeError(f"Expected union data type {data_type}, but got {type(data).__name__}")
    # Unsupported datatype
    if force_cast_unsupported_datatype:
        return data_type(data)  # type: ignore
    raise TypeError(f"Unsupported datatype: {data_type}")


def request_to_spec(
    path_regex: str | None, request: Request, spec: Dict[str, Type[T]]
) -> Tuple[Dict[str, T] | None, List[str]]:
    validated_data = {}
    validation_errors: List[str] = []
    for name, annotation_type in spec.items():
        value: Any
        match name.split("_", maxsplit=1):
            case ["request"]:
                value = request
            case ["body"]:
                value = request.body
            case ["body", "form_data"]:
                value = request.form_data()
            case ["header", header]:
                headerized = "-".join([word.title() for word in header.split("_")])
                value = request.headers.get(headerized)
            case ["path", path]:
                value = request.matched_route_mapping.get(path) if request.matched_route_mapping else None
            case ["param", param]:
                value = request.query_params.get(param)
            case ["session"]:
                value = request.get_session()
            case arg:
                raise Exception(f"Unexpected argument {'_'.join(arg)}")
        try:
            validated_data[name] = validate_and_cast_to_type(value, annotation_type)
        except Exception:
            pretty_type_name = (
                annotation_type.__name__ if hasattr(annotation_type, "__name__") else str(annotation_type)
            )
            validation_errors.append(f"{name}: expected '{pretty_type_name}'")
    if validation_errors:
        return None, validation_errors
    return validated_data, []


def validate_and_call_route_function(
    request: Request, route_function: Callable[..., RouteFunctionResponse]
) -> RouteFunctionResponse:
    annotations = typing.get_type_hints(route_function)
    annotations.pop("return", None)  # return type is part of the annotations
    if route_function.__code__.co_argcount != len(annotations):
        raise TypeError("Route function does not have type information for all arguments")
    validated_spec, errors = request_to_spec(request.matched_route, request, annotations)
    if validated_spec is None:
        response: RouteFunctionResponse = Response(
            b"Request Type Error: " + ", ".join(errors).encode(), 400, {"content-type": "text/plain"}
        )
    else:
        response = route_function(**validated_spec)
    return response


def cast_request(route_function: Callable[..., RouteFunctionResponse]) -> RouteFunction:
    """Extracts the property and validates/casts to the type specified in the type hints

    request                 Request
    body                    Request.body
    body_form_data          Request.form_data()
    header_<header_name>    Request.headers.get("<Header-Name>")
    path_<path_variable>    Request.matched_route_mapping.get("<path_variable>")
    param_<param_name>      Request.query_params.get("<param_name>")
    session                 Request.get_session()

    Example:
    ```
    @app.route("/")
    @cast_request
    def index(header_user_agent: int):
        ...
    ```
    The index function will be called with `header_user_agent = int(request.headers.get("User-Agent"))`
    This might raise a type error and returns Response<400> to the user.
    > Request Type Error: header_user_agent: Expected 'int', but got 'Mozilla/5.0...
    """

    def decorator(request: Request) -> RouteFunctionResponse:
        return validate_and_call_route_function(request, route_function)

    return decorator


def main() -> None:
    """usage: `httpserver [PORT]`"""
    import sys

    port = int(sys.argv[1]) if len(sys.argv) == 2 else 8000

    app = App()
    app.serve_static_path("", Path("."))
    app.run(port=port)


def iterate_from_chunked_encoding(socket_reader: BufferedSocketReader) -> Iterator[bytes]:
    while True:
        buffer = b""
        chunk = socket_reader.read_to_delimiter(b"\r\n")
        length = int(chunk[:-2], 16)
        buffer += chunk
        if length == 0:
            yield buffer
            break
        buffer += socket_reader.read(length)
        buffer += socket_reader.read(len("\r\n"))
        yield buffer
    yield socket_reader.read(len("\r\n"))


def iterate_from_content_length(socket_reader: BufferedSocketReader, content_length: int) -> Iterator[bytes]:
    chunk = 1024 * 1024
    remaining_bytes = content_length
    while remaining_bytes > 0:
        if remaining_bytes <= chunk:
            yield socket_reader.read(remaining_bytes)
            break
        yield socket_reader.read(chunk)
        remaining_bytes -= chunk


def proxy_request(request: Request, host: str, port: int) -> Response:
    # Connect to proxied host
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    # Add proxy headers
    headers = request.headers.copy()
    headers.set("X-Forwarded-For", request.remote_addr)

    # Reassemble request HTTP headers
    params = "&".join(
        [urllib.parse.quote(k) + ("=" + urllib.parse.quote(v) if v else "") for k, v in request.query_params.items()]
    )
    data = f"{request.method.value} {request.path + ('?' + params if params else '')} HTTP/1.1\r\n"
    for k, v in headers.raw_headers:
        data += f"{k}: {v}\r\n"
    data += "\r\n"

    # Proxy the request
    s.sendall(data.encode() + request.body)

    # Parse proxied response headers
    socket_reader = BufferedSocketReader(s, timeout=5)
    header = socket_reader.read_to_delimiter(b"\r\n\r\n")
    http_top_header, *http_headers = header.decode().split("\r\n")
    _protocol, code, *_description = http_top_header.split()
    headers = Headers.from_raw(http_headers)

    # Proxy body response
    if "chunked" in headers.get("Transfer-Encoding", ""):
        stream = iterate_from_chunked_encoding(socket_reader)
    else:
        stream = iterate_from_content_length(socket_reader, int(headers.get("Content-Length", 0)))

    return Response(stream, int(code), raw_headers=headers)


if __name__ == "__main__":
    app = App()

    @app.get("/hello")
    def hello() -> BodyResponse:
        return "Hello, World!"

    @app.get("/")
    def index(request: Request) -> Response:
        data = dataclasses.asdict(request)
        data["headers"] = request.headers.to_dict()
        data["body"] = data["body"].decode()  # To make it work with json.dumps
        data["clear_text_session"] = request.get_session()
        return Response(data, 200, set_session={"secret": "cookiestuff3"})

    @app.get("/<variable>")
    @cast_request
    def cast(
        request: Request,
        path_variable: int,
        header_user_agent: str,
        param_page: int | None,
        body: bytes,
    ) -> BodyResponse:
        return textwrap.dedent(
            f"""\
                Success!
                {request=:}
                {path_variable=:}
                {header_user_agent=:}
                {param_page=:}
                {body.decode()=:}"""
        )

    app.run()
