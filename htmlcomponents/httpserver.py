from __future__ import annotations

import binascii
import concurrent.futures
import dataclasses
import enum
import functools
import gzip
import hashlib
import hmac
import http.server
import json
import secrets
import select
import socket
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
    BinaryIO,
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


def normalize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    # Always normalizing headers to avoid duplicates and key lookup issues
    return {k.strip().title(): v.strip() for k, v in headers.items()}


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


def is_connection_alive(conn: socket.socket) -> bool:
    try:
        if conn.recv(1, socket.MSG_DONTWAIT | socket.MSG_PEEK) == b"":
            return False
    except BlockingIOError:
        return True
    except ConnectionResetError:
        return False
    return True


def match_path(pattern: str, path: str) -> Dict[str, str] | None:
    # Returns None if it does not match
    # Returns matching variables if included in pattern
    parsed = {}
    assert pattern.startswith("/")
    assert path.startswith("/")
    regex_parts = pattern.split("/")[1:]
    path_parts = path.split("/")[1:]
    if len(regex_parts) != len(path_parts):
        return None
    for pattern_part, path_part in zip(regex_parts, path_parts):
        if pattern_part == path_part:
            continue
        elif pattern_part.startswith("<") and pattern_part.endswith(">"):
            if not path_part:
                return None
            parsed[pattern_part[1:-1]] = path_part
        elif "<" in pattern_part or ">" in pattern_part:
            raise Exception(f"Unexpected brackets in route '{pattern}'")
        else:
            return None
    return parsed


@dataclass
class Request:
    remote_addr: str
    method: Method
    path: str
    query_params: Dict[str, str]
    headers: Dict[str, str]
    content_length: int
    body: bytes
    request_start: float
    matched_route: str | None
    matched_route_mapping: Dict[str, str] | None
    _conn: socket.socket | None  # Not available in wsgi mode

    def __repr__(self) -> str:
        return f"Request<{self.method.value} {self.matched_route}>"

    @staticmethod
    def from_wsgi(environ: Dict[str, Any]) -> "Request":
        method = Method(environ["REQUEST_METHOD"])
        path = environ["PATH_INFO"]
        query_params = dict(urllib.parse.parse_qsl(environ["QUERY_STRING"]))
        # WSGI request headers are prefixed with HTTP_
        headers = normalize_headers({k[5:].replace("_", "-"): v for k, v in environ.items() if k.startswith("HTTP_")})
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
            None,
        )

    @staticmethod
    def from_raw(remote_addr: str, header: bytes, body_byte_stream: BinaryIO, conn: socket.socket | None) -> Request:
        http_code_header, *http_headers = header.decode().split("\r\n")
        raw_method, url, _protocol = http_code_header.split()
        method = Method(raw_method)
        path, *query_string = url.split("?", 1)
        query_params = dict(urllib.parse.parse_qsl(query_string[0])) if query_string else {}
        headers = normalize_headers({k: v for k, v in [header.split(":", 1) for header in http_headers if header]})
        # Read body if content_length
        content_length = int(headers.get("Content-Length", 0))
        body = body_byte_stream.read(content_length) if content_length else b""
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
            conn,
        )

    def get_session(self) -> Dict[Any, Any] | None:
        # Parse session cookie
        # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cookie
        # Cookie: name=value; name2=value2; name3=value3
        session = None
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
        return json.loads(self.body.decode())

    def print(self) -> None:
        print(self)
        for k, v in dataclasses.asdict(self).items():
            print(" ", k, v)

    def assert_connection_ok(self) -> None:
        """Detects if the connection is broken/client is disconnected. Not supported in WSGI mode"""
        if self._conn is None:
            raise NotImplementedError("Server does not expose socket.")
        if not is_connection_alive(self._conn):
            raise ConnectionError("Connection closed by remote")


@dataclass
class Response:
    body: bytes | Iterator[bytes]
    code: int
    headers: Dict[str, str]

    def __repr__(self) -> str:
        return f"Response<{self.code}>"

    def __init__(
        self,
        body: BodyResponse,
        code: int = 200,
        headers: Dict[str, str] | None = None,
        set_session: Dict[str, str] | None = None,
    ) -> None:
        self.body, content_type = self.cast_body_response(body)
        self.headers = normalize_headers({"Content-Type": content_type})
        if isinstance(self.body, bytes):
            self.headers |= normalize_headers({"Content-Length": str(len(self.body))})
        self.headers |= normalize_headers(headers) if headers else {}
        self.code = code
        if set_session is not None:
            serialized_data = serialize_with_hmac(COOKIE_HMAC_SECRET, set_session)
            if set_session == {}:
                cookie = {"Set-Cookie": "session=; Max-Age=0"}
            elif SECURE_COOKIES:
                cookie = {"Set-Cookie": f"session={serialized_data}; Secure; HttpOnly; SameSite=Lax"}
            else:
                cookie = {"Set-Cookie": f"session={serialized_data}; HttpOnly; SameSite=Lax"}
            self.headers.update(cookie)

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
                    raise TypeError(f"Unsupported cast from list of {type(item)} to bytes.")
                components.append(item.render_html().encode())
            return b"\n".join(components), ContentType.text_html
        raise TypeError(f"Unsupported cast from {type(body)} to bytes.")


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
            response.body = gzip.compress(response.body)
            response.headers.update(
                normalize_headers({"Content-Encoding": "gzip", "Content-Length": str(len(response.body))})
            )

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
        # Logging
        duration = time.time() - request.request_start
        print(request.remote_addr, response.code, request.method.value, request.path, f"{duration * 1000:.2f}ms")
        return response

    def run(self, host: str = "0.0.0.0", port: int = 8000) -> None:
        http_server(self.handle, host, port)

    def to_wsgi(self):
        return WSGIWrapper(self.handle)

    def run_wsgiref(self, host: str = "0.0.0.0", port: int = 8000) -> None:
        import wsgiref.simple_server

        with wsgiref.simple_server.make_server(host, port, self.to_wsgi()) as httpd:
            print(f"wsgiref serving on {host}:{port}")
            httpd.serve_forever()

    def serve_static(self, route: str, local_path: Path) -> None:
        resolved_local_path = local_path.resolve()

        @self.get(f"{route.rstrip('/')}/<path>")
        @cast_request
        def static(request: Request, path_path: str) -> bytes:
            local_path = (resolved_local_path / Path(path_path)).resolve()
            assert local_path.relative_to(resolved_local_path)
            return local_path.read_bytes()


class BufferedSocketReader:
    def __init__(self, conn: socket.socket) -> None:
        self.conn = conn
        self.buffer: bytes = b""
        self.max_buf_size = 10e6  # bytes
        self.timeout = 30  # seconds

    def _recv_to_buf(self, size: int) -> None:
        r, _, _ = select.select([self.conn], [], [], self.timeout)
        if r:
            self.buffer += self.conn.recv(size)
        else:
            raise Exception(f"Read timeout {self.timeout}s")
        if len(self.buffer) > self.max_buf_size:
            raise Exception(f"Read buffer exceeds max size: {len(self.buffer)} > {self.max_buf_size}")

    def read_to_delimiter(self, delimiter: bytes) -> bytes | None:
        while delimiter not in self.buffer:
            self._recv_to_buf(1024)
        data, self.buffer = self.buffer.split(delimiter, maxsplit=1)
        return data

    def read(self, size: int) -> bytes:
        while len(self.buffer) < size:
            self._recv_to_buf(size - len(self.buffer))
        data, self.buffer = self.buffer[:size], self.buffer[size:]
        return data


RequestHandler = Callable[[Request], Response]


def http_server(handler: RequestHandler, host: str = "0.0.0.0", port: int = 8000, threads: int = 20) -> None:
    def connection_handler(conn: socket.socket, client_address: str, handler: RequestHandler) -> None:
        try:
            socket_reader = BufferedSocketReader(conn)
            header = socket_reader.read_to_delimiter(b"\r\n\r\n")
            request = Request.from_raw(client_address[0], header, socket_reader, conn)  # type: ignore
            try:
                response = handler(request)
            except Exception:
                traceback.print_exc()
                response = Response("Internal Server Error", 500)
            response.headers["Server"] = "httpserver.py"
            phrase, _ = http.server.BaseHTTPRequestHandler.responses[response.code]
            conn.sendall(f"HTTP/1.1 {response.code} {phrase}\r\n".encode())
            conn.sendall(b"\r\n".join([f"{k}: {v}".encode() for k, v in response.headers.items()]))
            conn.sendall(b"\r\n\r\n")
            body_iterable = iter([response.body]) if isinstance(response.body, bytes) else response.body
            for chunk in body_iterable:
                if chunk == b"" and not is_connection_alive(conn):
                    print("Connection closed by remote.")
                    break
                conn.sendall(chunk)
        except Exception:
            traceback.print_exc()
        finally:
            conn.close()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = (host, port)
    sock.bind(server_address)
    sock.listen(10)
    print(f"socketserver listening on {host}:{port}")

    with concurrent.futures.ThreadPoolExecutor(threads) as e:
        while True:
            if e._work_queue.qsize() > threads:
                print("Warn: All threads busy")
                while e._work_queue.qsize() > threads:
                    time.sleep(0.1)
                print("Threads available")
            conn, client_address = sock.accept()
            e.submit(connection_handler, conn, client_address, handler)


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
        start_response(f"{response.code} {phrase}", [(k, v) for k, v in response.headers.items()])
        if isinstance(response.body, bytes):
            yield response.body
        else:
            yield from response.body


# Endpoint argument parsing


T = TypeVar("T")


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
        return data
    # Catch options to pass down recursively
    arguments = locals().copy()
    arguments.pop("data_type")
    arguments.pop("data")
    options = arguments
    if not isinstance(data_type, (typing._GenericAlias, typing.GenericAlias, type, UnionType)):  # type: ignore
        raise TypeError(f"{data_type} type:{type(data_type)} is not a type")
    # Basic types
    simple_types = [int, float, str, bool, bytes]
    if data_type in simple_types:
        if cast_int_to_float and isinstance(data, int) and data_type == float:
            return float(data)  # type: ignore
        if cast_str_to_int_and_float and isinstance(data, str) and data_type in [int, float]:
            return data_type(data)  # type: ignore
        raise TypeError(f"Expected {data_type}, got '{type(data)}'")
    # Dataclasses
    if dataclasses.is_dataclass(data_type):
        if dataclasses.is_dataclass(data):
            raise TypeError(f"Expected {data_type}, got '{type(data)}'")
        elif cast_dict_to_dataclass:
            if not isinstance(data, dict):
                raise TypeError(f"Expected dict when casting to {data_type}, got '{type(data)}'")
        else:
            raise TypeError("Casting to dataclass not allowed.")
        fieldtypes = typing.get_type_hints(data_type)
        return data_type(
            **{key: validate_and_cast_to_type(value, fieldtypes[key], **options) for key, value in data.items()}
        )  # type: ignore
    # Generic types
    elif hasattr(data_type, "__origin__"):
        # List[type]
        if data_type.__origin__ == list:  # type: ignore
            (item_type,) = data_type.__args__  # type: ignore
            return [validate_and_cast_to_type(item, item_type, **options) for item in data]  # type: ignore
        # TODO: Tuple
        # Dict[type, type]
        elif data_type.__origin__ == dict:  # type: ignore
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
        raise TypeError(f"Expected union data type {data_type}, but got {type(data)}")
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
            case arg:
                raise Exception(f"Unexpected argument {'_'.join(arg)}")
        try:
            validated_data[name] = validate_and_cast_to_type(value, annotation_type)
        except Exception:
            pretty_type_name = (
                annotation_type.__name__ if hasattr(annotation_type, "__name__") else str(annotation_type)
            )
            validation_errors.append(f"{name}: Expected '{pretty_type_name}', but got '{value}'.")
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


if __name__ == "__main__":
    app = App()

    @app.get("/hello")
    def hello() -> BodyResponse:
        return "Hello, World!"

    @app.get("/")
    def index(request: Request) -> Response:
        request._conn = None  # To make it work with .asdict
        data = dataclasses.asdict(request)
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
