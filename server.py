#!/usr/bin/env python3
"""Multi-threaded HTTP API web server for Assignment 2.

This module implements a basic HTTP/1.1 web server that can serve static
files and exposes a JSON API used by the single page application found in
``static/index.html``.  The server communicates with the remote assignment
message database using the binary length-prefixed JSON protocol described in
``a2.html``.

The implementation deliberately avoids higher-level HTTP helper frameworks and
only relies on ``socket`` plus a handful of standard-library modules that are
explicitly permitted by the assignment handout.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

# HTTP response templates ----------------------------------------------------

_STATUS_MESSAGES: Dict[int, str] = {status.value: status.phrase for status in HTTPStatus}


# Utility functions ----------------------------------------------------------

def _http_date(timestamp: Optional[float] = None) -> str:
    """Return an RFC1123 formatted timestamp for HTTP headers."""

    if timestamp is None:
        timestamp = time.time()
    return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(timestamp))


def _safe_join(root: str, path: str) -> Optional[str]:
    """Safely join *path* to *root* preventing directory traversal."""

    path = path.lstrip("/")
    root_abs = os.path.abspath(root)
    normalized = os.path.abspath(os.path.normpath(os.path.join(root_abs, path)))
    if not normalized.startswith(root_abs):
        return None
    return normalized


# Database client ------------------------------------------------------------

class DatabaseError(Exception):
    """Base class for database related errors."""


class RateLimitedError(DatabaseError):
    """Raised when the database signals rate limiting."""


@dataclass
class DatabaseResponse:
    """Container for parsed database responses."""

    method: str
    status: int
    payload: Dict[str, object]

    @property
    def is_ok(self) -> bool:
        return self.status == 0


class DatabaseClient:
    """Blocking TCP client for the assignment database API."""

    def __init__(self, host: str, port: int, timeout: float = 5.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout

    def request(self, payload: Dict[str, object]) -> DatabaseResponse:
        message = json.dumps(payload).encode("utf-8")
        header = len(message).to_bytes(4, "big", signed=False)

        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            sock.sendall(header + message)
            length_prefix = self._recv_exact(sock, 4)
            if len(length_prefix) < 4:
                raise DatabaseError("incomplete response header from database")
            length = int.from_bytes(length_prefix, "big", signed=False)
            body = self._recv_exact(sock, length)

        if len(body) != length:
            raise DatabaseError("incomplete response body from database")

        try:
            decoded = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise DatabaseError("invalid JSON response from database") from exc

        status = int(decoded.get("status", -1))
        if status == 271:
            raise RateLimitedError("database rate limited the request")

        method = str(decoded.get("method", payload.get("method", "")))
        payload_data = {k: v for k, v in decoded.items() if k not in {"status", "method"}}
        return DatabaseResponse(method=method, status=status, payload=payload_data)

    def _recv_exact(self, sock: socket.socket, size: int) -> bytes:
        chunks: List[bytes] = []
        bytes_remaining = size
        while bytes_remaining > 0:
            chunk = sock.recv(bytes_remaining)
            if not chunk:
                break
            chunks.append(chunk)
            bytes_remaining -= len(chunk)
        return b"".join(chunks)


# Session management ---------------------------------------------------------

class SessionStore:
    """In-memory thread-safe session store."""

    def __init__(self) -> None:
        self._sessions: Dict[str, str] = {}
        self._lock = threading.Lock()

    def create(self, username: str) -> str:
        session_id = os.urandom(16).hex()
        with self._lock:
            self._sessions[session_id] = username
        return session_id

    def destroy(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def lookup(self, session_id: Optional[str]) -> Optional[str]:
        if not session_id:
            return None
        with self._lock:
            return self._sessions.get(session_id)


# HTTP request/response handling --------------------------------------------

@dataclass
class HTTPRequest:
    method: str
    target: str
    version: str
    headers: Dict[str, str]
    body: bytes

    @property
    def json(self) -> Dict[str, object]:
        if not self.body:
            return {}
        try:
            return json.loads(self.body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("invalid JSON body") from exc

    def cookie(self, key: str) -> Optional[str]:
        cookie_header = self.headers.get("cookie")
        if not cookie_header:
            return None
        cookies = {}
        for chunk in cookie_header.split(";"):
            if "=" in chunk:
                k, v = chunk.strip().split("=", 1)
                cookies[k] = v
        return cookies.get(key)


class HTTPError(Exception):
    """Represents HTTP errors that should be returned to the client."""

    def __init__(self, status: int, message: str = "", headers: Optional[Dict[str, str]] = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.headers = headers or {}


class RequestHandler:
    """Handles HTTP requests for a single TCP connection."""

    def __init__(self, conn: socket.socket, addr: Tuple[str, int], server: "ThreadedHTTPServer") -> None:
        self.conn = conn
        self.addr = addr
        self.server = server

    def handle(self) -> None:
        try:
            request = self._read_request()
            response = self.server.dispatch(request)
        except HTTPError as exc:
            response = self.server.make_response(exc.status, {"error": exc.message})
            headers = exc.headers
        except Exception as exc:  # pylint: disable=broad-except
            response = self.server.make_response(500, {"error": "internal server error"})
            headers = {}
            print(f"Unhandled error while processing request from {self.addr}: {exc}")
        else:
            headers = {}

        try:
            self.server.send_response(self.conn, response, extra_headers=headers)
        finally:
            self.conn.close()

    def _read_request(self) -> HTTPRequest:
        buffer = b""
        self.conn.settimeout(5.0)
        while b"\r\n\r\n" not in buffer:
            chunk = self.conn.recv(4096)
            if not chunk:
                break
            buffer += chunk
            if len(buffer) > 65536:
                raise HTTPError(413, "request headers too large")

        if b"\r\n\r\n" not in buffer:
            raise HTTPError(400, "malformed request")

        header_part, body_part = buffer.split(b"\r\n\r\n", 1)
        header_lines = header_part.decode("iso-8859-1").split("\r\n")
        if not header_lines:
            raise HTTPError(400, "missing request line")

        request_line = header_lines[0]
        try:
            method, target, version = request_line.split()
        except ValueError as exc:
            raise HTTPError(400, "invalid request line") from exc

        headers: Dict[str, str] = {}
        for line in header_lines[1:]:
            if not line:
                continue
            if ":" not in line:
                raise HTTPError(400, "malformed header line")
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

        content_length = int(headers.get("content-length", "0") or 0)
        body = body_part
        while len(body) < content_length:
            chunk = self.conn.recv(content_length - len(body))
            if not chunk:
                break
            body += chunk
        body = body[:content_length]

        return HTTPRequest(method=method.upper(), target=target, version=version, headers=headers, body=body)


# Web server -----------------------------------------------------------------

class ThreadedHTTPServer:
    """Minimal multi-threaded HTTP server with API routing."""

    def __init__(self, host: str, port: int, static_dir: str, db_client: DatabaseClient) -> None:
        self.host = host
        self.port = port
        self.static_dir = os.path.abspath(static_dir)
        self.db_client = db_client
        self.sessions = SessionStore()
        self.shutdown_event = threading.Event()

    # ------------------------------------------------------------------
    # Networking
    # ------------------------------------------------------------------

    def serve_forever(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(100)
            sock.settimeout(1.0)
            print(f"Server listening on {self.host}:{self.port}")

            while not self.shutdown_event.is_set():
                try:
                    conn, addr = sock.accept()
                except socket.timeout:
                    continue
                thread = threading.Thread(target=self._handle_connection, args=(conn, addr), daemon=True)
                thread.start()

    def _handle_connection(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        handler = RequestHandler(conn, addr, self)
        handler.handle()

    # ------------------------------------------------------------------
    # Request dispatching
    # ------------------------------------------------------------------

    def dispatch(self, request: HTTPRequest) -> Tuple[int, Dict[str, str], bytes]:
        parsed = urlparse(request.target)
        path = parsed.path or "/"

        if path.startswith("/api/"):
            return self._dispatch_api(request, path, parse_qs(parsed.query))
        return self._dispatch_static(path)

    def _dispatch_static(self, path: str) -> Tuple[int, Dict[str, str], bytes]:
        if path == "/":
            path = "/index.html"

        full_path = _safe_join(self.static_dir, unquote(path))
        if not full_path or not os.path.isfile(full_path):
            raise HTTPError(404, "file not found")

        with open(full_path, "rb") as fh:
            body = fh.read()

        content_type = self._guess_mime_type(full_path)
        headers = {
            "Content-Type": content_type,
            "Content-Length": str(len(body)),
            "Date": _http_date(),
            "Connection": "close",
        }
        return 200, headers, body

    def _dispatch_api(self, request: HTTPRequest, path: str, query: Dict[str, List[str]]) -> Tuple[int, Dict[str, str], bytes]:
        if path == "/api/login":
            if request.method == "POST":
                return self._api_login(request)
            if request.method == "GET":
                return self._api_session_status(request)
            if request.method == "DELETE":
                return self._api_logout(request)
            raise HTTPError(405, "method not allowed", headers={"Allow": "GET, POST, DELETE"})

        if path == "/api/user":
            if request.method == "POST":
                return self._api_register(request)
            raise HTTPError(405, "method not allowed", headers={"Allow": "POST"})

        if path == "/api/messages":
            if request.method == "GET":
                return self._api_get_messages(request, query)
            if request.method == "POST":
                return self._api_new_message(request)
            raise HTTPError(405, "method not allowed", headers={"Allow": "GET, POST"})

        delete_match = re.fullmatch(r"/api/messages/([0-9]+)", path)
        if delete_match and request.method == "DELETE":
            message_id = int(delete_match.group(1))
            return self._api_delete_message(request, message_id)

        raise HTTPError(404, "unknown API path")

    # ------------------------------------------------------------------
    # API endpoints
    # ------------------------------------------------------------------

    def _require_session(self, request: HTTPRequest) -> str:
        session_id = request.cookie("session")
        username = self.sessions.lookup(session_id)
        if not username:
            raise HTTPError(401, "not authenticated")
        return username

    def _api_register(self, request: HTTPRequest) -> Tuple[int, Dict[str, str], bytes]:
        try:
            payload = request.json
        except ValueError as exc:
            raise HTTPError(400, str(exc)) from exc

        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        if not username or not password:
            raise HTTPError(400, "username and password required")

        db_payload = {"method": "AddUser", "user": username, "pass": password}
        response = self._db_request_with_backoff(db_payload)
        if not response.is_ok:
            error = response.payload.get("error", "unable to register user")
            raise HTTPError(400, str(error))

        return self.make_response(200, {"status": "registered"})

    def _api_login(self, request: HTTPRequest) -> Tuple[int, Dict[str, str], bytes]:
        try:
            payload = request.json
        except ValueError as exc:
            raise HTTPError(400, str(exc)) from exc

        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        if not username or not password:
            raise HTTPError(400, "username and password required")

        db_payload = {"method": "GetUser", "user": username}
        response = self._db_request_with_backoff(db_payload)
        if not response.is_ok:
            raise HTTPError(401, "invalid username or password")

        user_info = response.payload.get("user", {})
        if not isinstance(user_info, dict) or user_info.get("pass") != password:
            raise HTTPError(401, "invalid username or password")

        session_id = self.sessions.create(username)
        headers = {
            "Set-Cookie": f"session={session_id}; HttpOnly; Path=/",
        }
        body = {"status": "ok", "user": {"username": username}}
        return self.make_response(200, body, extra_headers=headers)

    def _api_session_status(self, request: HTTPRequest) -> Tuple[int, Dict[str, str], bytes]:
        username = self.sessions.lookup(request.cookie("session"))
        if not username:
            return self.make_response(200, {"authenticated": False})
        return self.make_response(200, {"authenticated": True, "user": {"username": username}})

    def _api_logout(self, request: HTTPRequest) -> Tuple[int, Dict[str, str], bytes]:
        session_id = request.cookie("session")
        if session_id:
            self.sessions.destroy(session_id)
        headers = {"Set-Cookie": "session=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/"}
        return self.make_response(200, {"status": "logged out"}, extra_headers=headers)

    def _api_get_messages(self, request: HTTPRequest, query: Dict[str, List[str]]) -> Tuple[int, Dict[str, str], bytes]:
        username = self._require_session(request)
        last_values = query.get("last", [])
        last_value = None
        if last_values:
            try:
                last_value = int(last_values[0])
            except ValueError:
                raise HTTPError(400, "invalid last parameter")

        response = self._db_request_with_backoff({"method": "GetMessages"})
        if not response.is_ok:
            raise HTTPError(500, str(response.payload.get("error", "failed to fetch messages")))

        messages = response.payload.get("msgs", [])
        if not isinstance(messages, list):
            messages = []

        filtered: List[Dict[str, object]] = []
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            if last_value is not None and int(msg.get("time", 0)) <= last_value:
                continue
            msg_copy = {
                "id": int(msg.get("id", 0)),
                "time": int(msg.get("time", 0)),
                "author": str(msg.get("author", "")),
                "msg": str(msg.get("msg", "")),
                "owned": str(msg.get("author", "")) == username,
            }
            filtered.append(msg_copy)

        return self.make_response(200, {"messages": filtered, "user": {"username": username}})

    def _api_new_message(self, request: HTTPRequest) -> Tuple[int, Dict[str, str], bytes]:
        username = self._require_session(request)
        try:
            payload = request.json
        except ValueError as exc:
            raise HTTPError(400, str(exc)) from exc

        message_text = str(payload.get("message", "")).strip()
        if not message_text:
            raise HTTPError(400, "message text required")

        db_payload = {
            "method": "NewMessage",
            "author": username,
            "msg": message_text,
            "time": int(time.time_ns()),
        }
        response = self._db_request_with_backoff(db_payload)
        if not response.is_ok:
            raise HTTPError(500, str(response.payload.get("error", "failed to create message")))

        return self.make_response(201, {"status": "created", "id": response.payload.get("id")})

    def _api_delete_message(self, request: HTTPRequest, message_id: int) -> Tuple[int, Dict[str, str], bytes]:
        username = self._require_session(request)
        # Verify ownership by looking up messages
        response = self._db_request_with_backoff({"method": "GetMessages"})
        if not response.is_ok:
            raise HTTPError(500, "unable to validate message ownership")

        owned = False
        for msg in response.payload.get("msgs", []) or []:
            if isinstance(msg, dict) and int(msg.get("id", -1)) == message_id:
                owned = str(msg.get("author", "")) == username
                break

        if not owned:
            raise HTTPError(403, "cannot delete message you do not own")

        response = self._db_request_with_backoff({"method": "DeleteMessage", "id": message_id})
        if not response.is_ok:
            raise HTTPError(500, str(response.payload.get("error", "failed to delete message")))

        return self.make_response(200, {"status": "deleted"})

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _db_request_with_backoff(self, payload: Dict[str, object], retries: int = 3) -> DatabaseResponse:
        delay = 1.0
        for attempt in range(retries):
            try:
                return self.db_client.request(payload)
            except RateLimitedError:
                if attempt == retries - 1:
                    raise HTTPError(503, "database rate limit exceeded")
                time.sleep(delay)
                delay *= 2
            except OSError as exc:
                if attempt == retries - 1:
                    raise HTTPError(503, f"database connection failed: {exc}")
                time.sleep(delay)
                delay *= 2
        raise HTTPError(503, "database unavailable")

    def make_response(
        self,
        status: int,
        payload: Dict[str, object],
        *,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Dict[str, str], bytes]:
        body_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Content-Length": str(len(body_bytes)),
            "Date": _http_date(),
            "Connection": "close",
        }
        if extra_headers:
            headers.update(extra_headers)
        return status, headers, body_bytes

    def send_response(
        self,
        conn: socket.socket,
        response: Tuple[int, Dict[str, str], bytes],
        *,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        status, headers, body = response
        headers = dict(headers)
        if extra_headers:
            headers.update(extra_headers)

        reason = _STATUS_MESSAGES.get(status, "OK")
        status_line = f"HTTP/1.1 {status} {reason}\r\n"
        header_lines = "".join(f"{key}: {value}\r\n" for key, value in headers.items())
        http_message = (status_line + header_lines + "\r\n").encode("iso-8859-1") + body
        conn.sendall(http_message)

    def _guess_mime_type(self, path: str) -> str:
        if path.endswith(".html"):
            return "text/html; charset=utf-8"
        if path.endswith(".css"):
            return "text/css; charset=utf-8"
        if path.endswith(".js"):
            return "application/javascript; charset=utf-8"
        if path.endswith(".json"):
            return "application/json; charset=utf-8"
        if path.endswith(".png"):
            return "image/png"
        if path.endswith(".jpg") or path.endswith(".jpeg"):
            return "image/jpeg"
        if path.endswith(".gif"):
            return "image/gif"
        return "application/octet-stream"


# Entry point ----------------------------------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Multi-threaded API web server")
    parser.add_argument("--host", default="0.0.0.0", help="Host/IP to bind")
    parser.add_argument("--port", type=int, default=8080, help="TCP port to bind")
    parser.add_argument("--db-host", required=True, help="Database host name")
    parser.add_argument("--db-port", type=int, default=50042, help="Database TCP port")
    parser.add_argument("--static", default="static", help="Directory containing static assets")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    db_client = DatabaseClient(args.db_host, args.db_port)
    server = ThreadedHTTPServer(args.host, args.port, args.static, db_client)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down...")
        server.shutdown_event.set()


if __name__ == "__main__":
    main()
