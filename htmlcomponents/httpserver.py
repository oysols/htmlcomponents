from __future__ import annotations

import base64
import binascii
import concurrent.futures
import contextlib
import dataclasses
import datetime
import enum
import functools
import gzip
import hashlib
import hmac
import http.server
import json
import mimetypes
import secrets
import select
import signal
import socket
import ssl
import sys
import textwrap
import threading
import time
import traceback
import typing
import urllib.parse
from dataclasses import dataclass, field
from itertools import zip_longest
from pathlib import Path
from types import FrameType, UnionType
from typing import (
    Any,
    Callable,
    Iterable,
    Iterator,
    Protocol,
    Sequence,
    Type,
    TypeVar,
    Union,
    cast,
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
    text_javascript = "application/javascript"
    octet_stream = "application/octet-stream"
    application_json = "application/json"
    image_jpeg = "image/jpeg"
    image_png = "image/png"


class Method(str, enum.Enum):
    get = "GET"
    head = "HEAD"
    post = "POST"
    put = "PUT"
    delete = "DELETE"
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


class ProtocolError(Exception):
    pass


def match_path(pattern: str, path: str) -> dict[str, str] | None:
    # Returns None if it does not match
    # Returns matching variables if included in pattern
    parsed = {}
    assert pattern.startswith("/"), "Route pattern should start with /"
    assert path.startswith("/")
    regex_parts = pattern.split("/")[1:]
    path_parts = path.split("/")[1:]
    # Short ciruit so we know that path_parts is always equal or longer in zip_longest
    if len(regex_parts) > len(path_parts):
        return None
    glob = None
    for pattern_part, path_part in zip_longest(regex_parts, path_parts):
        if glob is not None:
            # TODO: Does not handle "<*glob>/something"
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
        # TODO: Exception if header is duplicated, might not be a good idea
        result = None
        for k, v in self.raw_headers:
            if k.lower() == key.lower():
                if result is not None:
                    raise Exception(f"Duplicate header key: {key}")
                result = v
        if result is not None:
            return result
        return default

    def set(self, key: str, value: str) -> None:
        has_set = False
        new_raw_headers = []
        for k, v in self.raw_headers:
            if k.lower() == key.lower():
                if has_set:
                    # Do not allow duplicate keys. Not copying existing duplicate.
                    continue
                new_raw_headers.append((key, value))
                has_set = True
            else:
                new_raw_headers.append((k, v))
        if not has_set:
            new_raw_headers.append((key, value))
        self.raw_headers = new_raw_headers

    def remove(self, key: str) -> None:
        new_raw_headers = []
        for k, v in self.raw_headers:
            if k.lower() != key.lower():
                new_raw_headers.append((k, v))
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
    query_params: dict[str, str]
    headers: Headers
    stream: BufferedSocketReader
    request_start: float
    matched_route: str | None
    matched_route_mapping: dict[str, str] | None
    log: Callable[..., None] = print
    _cached_body: bytes | None = None

    def __repr__(self) -> str:
        return f"Request<{self.method.value} {self.path}>"

    @staticmethod
    def from_raw(
        remote_addr: str,
        header: bytes,
        buf_sock_reader: BufferedSocketReader,
        read_x_forwarded_for: bool = False,
        log: Callable[..., None] = print,
    ) -> Request:
        http_code_header, *http_headers = header.decode().split("\r\n")
        raw_method, url, protocol = http_code_header.split()
        if protocol not in ["HTTP/1.0", "HTTP/1.1"]:
            raise ProtocolError(f"Unsupported protocol {protocol}")
        method = Method(raw_method)
        path, *query_string = url.split("?", 1)
        query_params = dict(urllib.parse.parse_qsl(query_string[0], keep_blank_values=True)) if query_string else {}
        headers = Headers.from_raw(http_headers)
        return Request(
            remote_addr,
            method,
            path,
            query_params,
            headers,
            buf_sock_reader,
            time.time(),
            None,
            None,
            log,
            None,
        )

    def body(self) -> bytes:
        if self._cached_body is not None:
            return self._cached_body
        if "chunked" in self.headers.get("Transfer-Encoding", ""):
            self._cached_body = b""
            for chunk in self.stream.iterate_from_chunked_encoding():
                self._cached_body += chunk
        else:
            content_length = int(self.headers.get("Content-Length", 0))
            self._cached_body = self.stream.read(content_length) if content_length else b""
        return self._cached_body

    def to_multipart(self) -> "MultiPart":
        return MultiPart.from_request(self)

    def get_session(self) -> dict[Any, Any]:
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

    def form_data(self) -> dict[str, str]:
        return dict(urllib.parse.parse_qsl(self.body().decode(), keep_blank_values=True))

    def json(self) -> dict[str, Any]:
        return json.loads(self.body().decode())  # type: ignore

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
        headers: dict[str, str] | None = None,
        set_session: dict[str, str] | None = None,
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
        # TODO: Alternative interface to session/cookies: Make it composeable. Might simplify response generation.
        # return Response("hello", 200, {"some_header": 1, **set_cookie(data, name="session", max_age=0, secure=False)})
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
    def cast_body_response(body: BodyResponse) -> tuple[bytes | Iterator[bytes], str]:
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


BodyResponse = bytes | str | dict[str, Any] | HTMLRenderable | Sequence[HTMLRenderable] | Iterator[bytes]
RouteFunctionResponse = Response | BodyResponse
RouteFunction = Callable[[Request], RouteFunctionResponse] | Callable[[], RouteFunctionResponse]


@dataclass
class MultiPartSubPart:
    headers: Headers | None
    form_name: str | None
    form_filename: str | None
    data_iterator: Iterator[bytes]

    def data(self) -> bytes:
        return b"".join(self.data_iterator)


@dataclass
class MultiPart:
    """Read multipart form data from incoming request
    for part in request.to_multipart():
        data[part.form_name] = part.data()
    """

    buffered_reader: BufferedSocketReader
    delimiter: bytes
    content_length: int

    @staticmethod
    def from_request(request: Request) -> "MultiPart":
        # Get multipart delimiter
        multipart_content_type, boundary = request.headers.get("Content-Type", "").split(";")
        assert multipart_content_type.strip() == "multipart/form-data"
        _, boundary_token = boundary.strip().split("=")
        delimiter = f"\r\n--{boundary_token}".encode()
        # Get content-length
        content_length_str = request.headers.get("Content-Length")
        assert content_length_str is not None
        content_length = int(content_length_str)
        request.stream.reset_byte_counter()
        # Discard data until first delimiter (this delimiter does not start with \r\n)
        request.stream.read_to_delimiter(delimiter[2:])
        return MultiPart(request.stream, delimiter, content_length)

    def __iter__(self) -> Iterator[MultiPartSubPart]:
        while True:
            raw_headers = self.buffered_reader.read_to_delimiter(b"\r\n\r\n")
            headers = Headers.from_raw(raw_headers.decode().split("\r\n"))
            content_disposition = headers.get("Content-Disposition")
            assert content_disposition is not None
            form_data_string, *form_data_kv = content_disposition.split(";")
            assert form_data_string == "form-data"
            parameters = {k.strip(): v.strip().strip('"') for k, v in [kv.split("=") for kv in form_data_kv]}

            data_iterator = self._read_part_iterator()
            yield MultiPartSubPart(headers, parameters.get("name"), parameters.get("filename"), data_iterator)
            for _ in data_iterator:  # Make sure iterator is exhausted
                pass
            # Read trailing data
            trailing = self.buffered_reader.read(2)
            if trailing == b"--":
                trailing = self.buffered_reader.read(2)
                assert trailing == b"\r\n"
                break
            assert trailing == b"\r\n"
        assert self.buffered_reader.get_byte_count() == self.content_length

    def _read_part_iterator(self, chunk_size: int = 4096) -> Iterator[bytes]:
        for chunk in self.buffered_reader.iterate_until_delimiter(self.delimiter, chunk_size):
            yield chunk


class BufferedSocketReader:
    def __init__(self, conn: socket.socket, timeout: int = 5) -> None:
        self.conn = conn
        self.buffer: bytes = b""
        self.max_buf_size = 10_000_000  # bytes
        self.timeout = timeout  # seconds
        self._stream_byte_count = 0

        self.conn.settimeout(self.timeout)

    def _recv_to_buf(self, size: int) -> None:
        if size <= 0:
            return
        try:
            recv = self.conn.recv(size)
        except TimeoutError:
            raise TimeoutError(f"Read timed out after {self.timeout}s")
        if recv == b"":
            raise ConnectionResetError("Client closed connection")
        self._stream_byte_count += len(recv)
        self.buffer += recv
        if len(self.buffer) > self.max_buf_size:
            raise Exception(f"Read buffer exceeds max size: {len(self.buffer)} > {self.max_buf_size}")

    def read(self, size: int) -> bytes:
        while len(self.buffer) < size:
            self._recv_to_buf(size - len(self.buffer))
        data, self.buffer = self.buffer[:size], self.buffer[size:]
        return data

    def iterate_until_size(self, size: int) -> Iterator[bytes]:
        chunk_size = 4096
        remaining_bytes = size
        while remaining_bytes > 0:
            if remaining_bytes <= chunk_size:
                yield self.read(remaining_bytes)
                break
            yield self.read(chunk_size)
            remaining_bytes -= chunk_size

    def iterate_until_delimiter(self, delimiter: bytes, chunk_size: int) -> Iterator[bytes]:
        while delimiter not in self.buffer:
            if len(self.buffer) >= (chunk_size + len(delimiter) - 1):
                data, self.buffer = self.buffer[:chunk_size], self.buffer[chunk_size:]
                yield data
            else:
                self._recv_to_buf(4096)
        data, self.buffer = self.buffer.split(delimiter, maxsplit=1)
        yield data

    def read_to_delimiter(self, delimiter: bytes) -> bytes:
        data = b""
        for chunk in self.iterate_until_delimiter(delimiter, self.max_buf_size):
            data += chunk
        return data

    def iterate_from_chunked_encoding(self, include_encoding: bool = False) -> Iterator[bytes]:
        rn = b"\r\n"
        while True:
            raw_length = self.read_to_delimiter(rn)
            length = int(raw_length, 16)
            raw_stream = raw_length + rn
            if length == 0:
                assert self.read(len(rn)) == rn
                raw_stream += rn
                if include_encoding:
                    yield raw_stream
                break
            chunk = self.read(length)
            raw_stream += chunk
            assert self.read(len(rn)) == rn
            raw_stream += rn
            yield raw_stream if include_encoding else chunk

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

    def reset_byte_counter(self) -> None:
        self._stream_byte_count = len(self.buffer)

    def get_byte_count(self) -> int:
        return self._stream_byte_count - len(self.buffer)

    def set_timeout(self, timeout: int) -> None:
        self.timeout = timeout
        self.conn.settimeout(timeout)


RequestHandler = Callable[[Request], Response | None]
ResponseHandler = Callable[[Request, Response], Response]


class WrappedSSLSocket(ssl.SSLSocket):
    intercepted_sni_hostname: str | None = None


def connection_handler(
    conn: socket.socket | WrappedSSLSocket,
    client_address: tuple[str, str],
    handler: RequestHandler,
    keep_alive: bool,
    use_tls: bool,
    read_x_forwarded_for: bool,
    debug: bool = False,
) -> None:
    connection_start = time.time()
    debug_address_prefix = f"{client_address[0]}:{client_address[1]}"
    reason_for_close = None
    if debug:
        print(f"{debug_address_prefix} Connection opened")
    try:
        # Perform SSL handshake inside thread to avoid blocking main loop
        if use_tls:
            assert isinstance(conn, WrappedSSLSocket)
            conn.settimeout(5)
            conn.do_handshake()
            if debug:
                print(f"{debug_address_prefix} Connection TLS handshake {(time.time() - connection_start)*1000:.2f}ms")

        socket_reader = BufferedSocketReader(conn)
        while True:  # Reuse connection if keep alive is set
            request_start = time.time()
            header = socket_reader.read_to_delimiter(b"\r\n\r\n")
            request = Request.from_raw(client_address[0], header, socket_reader, read_x_forwarded_for)

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

            # Call request handler
            try:
                response = handler(request)
                if response is None:
                    response = Response("Page not found", 404)
            except Exception:
                traceback.print_exc()
                response = Response("Internal Server Error", 500)
            request_handler_duration = time.time() - request.request_start

            # Send headers
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
                x_forwarded_for = request.headers.get("X-Forwarded-For", "").split(",")[0]
                log_client_address = x_forwarded_for if x_forwarded_for and read_x_forwarded_for else client_address[0]
                print(
                    log_client_address if not debug else f"{debug_address_prefix} {log_client_address}",
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
                f"{debug_address_prefix} Connection closed {(time.time() - connection_start)*1000:.2f}ms: {reason_for_close}"
            )
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()


class SignalHandler:
    def __init__(self) -> None:
        self.sigterm = False
        signal.signal(signal.SIGTERM, self.set_sigterm)

    def set_sigterm(self, signum: int, frame: FrameType | None) -> None:
        self.sigterm = True


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
    read_x_forwarded_for: bool = False,
    share_socket: bool = False,
    debug: bool = False,
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if share_socket:
        # SO_REUSEPORT allows multiple processes to listen on same port
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    # SO_REUSEADDR allows a process use a port that is in TIME_WAIT from previous process
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Disable Nagle's algorithm https://en.wikipedia.org/wiki/Nagle's_algorithm
    sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
    server_address = (host, port)
    sock.bind(server_address)
    sock.listen(socket.SOMAXCONN)
    # Set socket timeout to periodically check signal handler
    sock.settimeout(1)
    signal_handler = SignalHandler()
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
    print(f"socketserver listening on {host}:{port}")
    with maybe_ssl as sock:
        max_queue = 100
        # Connection thread pool
        with concurrent.futures.ThreadPoolExecutor(threads) as e:
            while True:
                if signal_handler.sigterm:
                    print("Received SIGTERM. Gracefully shutting down.")
                    break
                if e._work_queue.qsize() > max_queue:
                    print(f"Warn: All threads busy. Queue of {e._work_queue.qsize()}")
                    while e._work_queue.qsize() > max_queue:
                        time.sleep(0.001)
                    print("Threads available")
                try:
                    conn, client_address = sock.accept()
                except TimeoutError:
                    continue
                except Exception as exception:
                    # Observed an error once
                    # OSError: [Errno 107] Transport endpoint is not connected
                    print(f"Error during accept() in main thread: {exception}")
                    traceback.print_exc()
                    continue
                e.submit(
                    connection_handler, conn, client_address, handler, keep_alive, use_tls, read_x_forwarded_for, debug
                )


class WSGIWrapper:
    """Implements WSGIApplication interface: Callable[[WSGIEnvironment, StartResponse], Iterable[bytes]]"""

    def __init__(self, request_handler: RequestHandler) -> None:
        self.request_handler = request_handler

    def __call__(
        self,
        environ: dict[str, Any],  # wsgiref.types.WSGIEnvironment
        start_response: Callable[[str, list[tuple[str, str]]], Callable[..., Any]],  # wsgiref.types.StartResponse,
    ) -> Iterable[bytes]:
        method = Method(environ["REQUEST_METHOD"])
        path = environ["PATH_INFO"]
        query_params = dict(urllib.parse.parse_qsl(environ["QUERY_STRING"]))
        # WSGI request headers are prefixed with HTTP_
        raw_headers = [(k[5:].replace("_", "-"), v) for k, v in environ.items() if k.startswith("HTTP_")]
        headers = Headers(raw_headers)
        remote_addr = environ["REMOTE_ADDR"]
        request = Request(
            remote_addr,
            method,
            path,
            query_params,
            headers,
            environ["wsgi.input"],  # Not correct type, but does support `.read`
            time.time(),
            None,
            None,
        )

        response = self.request_handler(request)
        if response is None:
            response = Response("Page not found", 404)

        phrase, _ = http.server.BaseHTTPRequestHandler.responses[response.code]
        start_response(f"{response.code} {phrase}", [(k, v) for k, v in response.headers.raw_headers])
        if isinstance(response.body, bytes):
            yield response.body
        else:
            yield from response.body


def run_wsgiref(request_handler: RequestHandler, host: str = "0.0.0.0", port: int = 8000) -> None:
    import wsgiref.simple_server

    with wsgiref.simple_server.make_server(host, port, WSGIWrapper(request_handler)) as httpd:
        print(f"wsgiref serving on {host}:{port}")
        httpd.serve_forever()


# Endpoint argument parsing


def validate_and_cast_to_type(
    data: Any,
    data_type: Type[T],
    cast_int_to_float: bool = True,
    cast_str_to_int_and_float: bool = True,
    cast_dict_to_dataclass: bool = True,
    force_cast_unsupported_datatype: bool = False,
) -> T:
    """
    >>> validate_and_cast_to_type({"a": [1,2,3]}, dict[str, list[int]])
    {'a': [1, 2, 3]}
    >>> validate_and_cast_to_type(33.4, dict | float | None)
    33.4

    """
    if not hasattr(data_type, "__origin__") and isinstance(data, data_type):  # If not generic
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
        )
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
    path_regex: str | None, request: Request, spec: dict[str, Type[T]]
) -> tuple[dict[str, T] | None, list[str]]:
    validated_data = {}
    validation_errors: list[str] = []
    for name, annotation_type in spec.items():
        value: Any
        match name.split("_", maxsplit=1):
            case ["request"]:
                value = request
            case ["body"]:
                value = request.body()
            case ["form"]:
                value = request.form_data()
            case ["form", form_key]:
                value = request.form_data().get(form_key)
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
                raise Exception(f"Unsupported function argument name: {'_'.join(arg)}")
        try:
            validated_data[name] = validate_and_cast_to_type(value, annotation_type)
        except Exception as e:
            pretty_type_name = (
                annotation_type.__name__ if hasattr(annotation_type, "__name__") else str(annotation_type)
            )
            validation_errors.append(f"{name}: expected '{pretty_type_name}': {e.__class__.__name__}: {e}")
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
            b"Request Type Error: " + ", ".join(errors).encode(), 422, {"content-type": "text/plain"}
        )
    else:
        response = route_function(**validated_spec)
    return response


def cast_request(route_function: Callable[..., RouteFunctionResponse]) -> RouteFunction:
    """Extracts the property and validates/casts to the type specified in the type hints

    request                 Request
    body                    Request.body
    form                    Request.form_data()
    form_<name>             Request.form_data().get("<name>")
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
    This might raise a type error and returns Response<422> to the user.
    > Request Type Error: header_user_agent: Expected 'int', but got 'Mozilla/5.0...
    """

    def decorator(request: Request) -> RouteFunctionResponse:
        return validate_and_call_route_function(request, route_function)

    return decorator


def main() -> None:
    """usage: `httpserver [PORT]`"""
    port = int(sys.argv[1]) if len(sys.argv) == 2 else 8000
    http_server(ServeStaticPath("", Path(".")), port=port, read_x_forwarded_for=True)


def proxy_request(request: Request, host: str, port: int) -> Response:
    # Connect to proxied host
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
    except Exception:
        return Response("Bad gateway", 502)

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
    s.sendall(data.encode())
    if "chunked" in headers.get("Transfer-Encoding", ""):
        for chunk in request.stream.iterate_from_chunked_encoding(include_encoding=True):
            s.sendall(chunk)
    else:
        for chunk in request.stream.iterate_until_size(int(request.headers.get("Content-Length", 0))):
            s.sendall(chunk)

    # Parse proxied response headers
    socket_reader = BufferedSocketReader(s, timeout=60)
    header = socket_reader.read_to_delimiter(b"\r\n\r\n")
    http_top_header, *http_headers = header.decode().split("\r\n")
    _protocol, code, *_description = http_top_header.split()
    headers = Headers.from_raw(http_headers)

    # Proxy body response
    if "chunked" in headers.get("Transfer-Encoding", ""):
        stream = socket_reader.iterate_from_chunked_encoding(include_encoding=True)
    else:
        stream = socket_reader.iterate_until_size(int(headers.get("Content-Length", 0)))

    return Response(stream, int(code), raw_headers=headers)


@dataclass
class App:
    request_handlers: list[RequestHandler]
    response_handlers: list[ResponseHandler] = field(default_factory=list)

    def __call__(self, request: Request) -> Response:
        for handler in self.request_handlers:
            app_response = handler(request)
            if app_response is not None:
                break
        else:
            app_response = Response("Page not found", 404)
        for response_handler in self.response_handlers:
            app_response = response_handler(request, app_response)
        return app_response


class Router:
    routes: list[tuple[str, str, RouteFunction]]

    def __init__(self) -> None:
        self.routes = []

    def add_route(self, pattern: str, method: str) -> Callable[[RouteFunction], RouteFunction]:
        def outer(func: RouteFunction) -> RouteFunction:
            self.routes.append((method, pattern, func))
            return func

        return outer

    get = functools.partialmethod(add_route, method=Method.get)
    post = functools.partialmethod(add_route, method=Method.post)

    def _get_route(self, method: str, path: str) -> tuple[str, dict[str, str], RouteFunction] | None:
        for route_method, pattern, route_function in self.routes:
            if route_method != method:
                continue
            if (matched_variables := match_path(pattern, path)) is not None:
                return pattern, matched_variables, route_function
        return None

    def __call__(self, request: Request) -> Response | None:
        route = self._get_route(request.method, request.path)
        if route is None:
            return None
        pattern, mapping, route_function = route
        # Add routing to Request object
        request.matched_route = pattern
        request.matched_route_mapping = mapping
        # Call route function
        if route_function.__code__.co_argcount == 0:  # 0 argument types + 1 return type = 1
            route_function = cast(Callable[[], RouteFunctionResponse], route_function)
            # Function does not take the Request object as argument
            router_response = route_function()
        else:
            route_function = cast(Callable[[Request], RouteFunctionResponse], route_function)
            # Function takes the Request object as argument
            router_response = route_function(request)
        # Convert RouteFunctionResponse to Response
        return router_response if isinstance(router_response, Response) else Response(router_response)

    def run(self, port: int = 5000) -> None:
        http_server(self, port=port)


class ServeStaticPath:
    CHUNK_SIZE = 1024 * 1024

    def __init__(
        self,
        base_route: str,
        local_path: Path,
        guess_content_type: bool = True,
        cache_control: int | None = None,
        directory_listing: bool = False,
    ) -> None:
        self.base_route = base_route.rstrip("/") + "/<*path>"
        self.resolved_local_path = local_path.resolve()
        self.guess_content_type = guess_content_type
        self.cache_control = cache_control
        if not self.resolved_local_path.is_dir():
            raise Exception("Expected directory")
        self.directory_listing = directory_listing

    def __call__(self, request: Request) -> Response | None:
        # Check if we match route
        match = match_path(self.base_route, request.path)
        if not match:
            return None
        path = match["path"]
        # Convert to local path
        local_path = (self.resolved_local_path / Path(path)).resolve()
        # Assert that file is child of local_path
        assert local_path.relative_to(self.resolved_local_path)
        # Directory listing
        if self.directory_listing:
            # Check if it is directory
            if local_path.is_dir():
                index = local_path / "index.html"
                if index.is_file():
                    # Show index instead
                    local_path = index
                else:
                    out = f"<head><title>{Path(request.path).name}</title></head><body>\n"
                    for p in sorted(local_path.iterdir()):
                        name = p.name
                        href = str(Path(request.path) / p.name)
                        if p.is_dir():
                            name += "/"
                            href += "/"
                        out += f'<a href="{href}">{name}</a><br/>\n'
                    out += "</body>"
                    return Response(out, 200, {"content-type": "text/html"})
        # Check that file exists
        if not local_path.is_file():
            return Response("Page not found", 404)
        # Check file size and prepare response
        file_size = local_path.stat().st_size
        content_type = "application/octet-stream"
        if self.guess_content_type:
            content_type = mimetypes.guess_type(local_path)[0] or content_type
        headers = {
            "Accept-Ranges": "bytes",
            "Content-Type": content_type,
        }
        if self.cache_control is not None:
            headers |= {"Cache-Control": f"private,max-age={self.cache_control}"}

        # Support Content-Range to allow remote seeking in files
        header_range = request.headers.get("Range")
        if header_range:
            try:
                bytestring, rangestring = header_range.split("=")
                if bytestring != "bytes":
                    raise TypeError("Unsupported range type")
                startstring, endstring = rangestring.split("-")
                start = int(startstring)
                inclusive_end = int(endstring) if endstring else file_size - 1
                # Accept end larger than file size
                if start < 0 or start >= file_size or inclusive_end < start:
                    raise ValueError("Invalid byte range")
            except Exception as e:
                return Response(f"Invalid Range request: {e}", 400)
            return Response(
                file_content_iterator(local_path, self.CHUNK_SIZE, start, inclusive_end + 1),
                206,
                headers
                | {
                    "Content-Range": f"bytes {start}-{inclusive_end}/{file_size}",
                    "Content-Length": str(file_size - start),
                },
            )
        return Response(
            file_content_iterator(local_path, self.CHUNK_SIZE),
            200,
            headers | {"Content-Length": str(file_size)},
        )


def proxy_fix(request: Request) -> None:
    request.remote_addr = request.headers.get("X-Forwarded-For") or request.remote_addr


def gzip_response(request: Request, response: Response) -> Response:
    if (
        isinstance(response.body, bytes)
        and response.headers.get("Content-Encoding") is None
        and "gzip" in [encoding.strip() for encoding in request.headers.get("Accept-Encoding", "").split(",")]
    ):
        response.body = gzip.compress(response.body)
        response.headers.set("Content-Encoding", "gzip")
        response.headers.set("Content-Length", str(len(response.body)))
    return response


if __name__ == "__main__":
    router = Router()

    @router.get("/")
    def index(request: Request) -> Response:
        data = {
            "remote_addr": request.remote_addr,
            "method": request.method,
            "path": request.path,
            "query_params": request.query_params,
            "headers": request.headers.to_dict(),
            "stream": "BufferedSocketReader",
            "request_start": request.request_start,
            "matched_route": request.matched_route,
            "matched_route_mapping": request.matched_route_mapping,
            "clear_text_cookie": request.get_session(),
        }
        return Response(data, 200, set_session={"secret": "cookiestuff3"})

    @router.get("/<variable>")
    @cast_request
    def castit(
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

    app = App([proxy_fix, router], response_handlers=[gzip_response])
    http_server(app, port=5000)
