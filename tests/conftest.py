from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import pytest

from isipsafe import Client


class Recorded:
    def __init__(self, method: str, path: str, query: Dict[str, List[str]], headers: Dict[str, str], body: bytes):
        self.method = method
        self.path = path
        self.query = query
        self.headers = headers
        self.body = body

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


class StubAPI:
    def __init__(self) -> None:
        self.routes: Dict[Tuple[str, str], List[Tuple[int, Any, Dict[str, str]]]] = {}
        self.requests: List[Recorded] = []

    def add(
        self, method: str, path: str, status: int = 200, body: Any = None, headers: Optional[Dict[str, str]] = None
    ) -> None:
        self.routes.setdefault((method, path), []).append((status, body, headers or {}))

    def respond(self, method: str, path: str) -> Tuple[int, Any, Dict[str, str]]:
        queue = self.routes.get((method, path))
        if not queue:
            return 404, {"errors": [{"detail": "not found", "status": 404}]}, {}
        return queue.pop(0) if len(queue) > 1 else queue[0]


def _handler(stub: StubAPI) -> type:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def _handle(self) -> None:
            parsed = urlparse(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            stub.requests.append(
                Recorded(
                    self.command, parsed.path, parse_qs(parsed.query, keep_blank_values=True), dict(self.headers), body
                )
            )
            status, payload, extra = stub.respond(self.command, parsed.path)
            data = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            for name, value in extra.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(data)

        do_GET = _handle
        do_POST = _handle
        do_DELETE = _handle

    return Handler


@pytest.fixture
def stub() -> Iterator[StubAPI]:
    api = StubAPI()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(api))
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    api.base_url = f"http://127.0.0.1:{server.server_address[1]}/api/v1"  # type: ignore[attr-defined]
    try:
        yield api
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def client(stub: StubAPI, monkeypatch: pytest.MonkeyPatch) -> Client:
    monkeypatch.delenv("ISIPSAFE_API_KEY", raising=False)
    monkeypatch.delenv("ISIPSAFE_KEY", raising=False)
    c = Client("sl_test_key", base_url=stub.base_url, timeout=5)  # type: ignore[attr-defined]
    c._sleep = lambda _seconds: None
    return c
