"""REST API integration tests for the SecureLink web UI.

Spin up a real :class:`ui.web_ui._SecureLinkServer` on a free localhost port and
exercise the JSON API endpoints end-to-end, monkeypatching the core transport
calls so no real network is touched.
"""

from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.request
from http.client import HTTPConnection
from pathlib import Path

import pytest

import ui.web_ui as web_ui
from ui.web_ui import _SecureLinkHandler, _SecureLinkServer


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _start_server(monkeypatch: pytest.MonkeyPatch) -> tuple[int, _SecureLinkServer]:
    port = _free_port()
    server = _SecureLinkServer(("127.0.0.1", port), _SecureLinkHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return port, server


def _request(method: str, port: int, path: str, body: dict | None = None) -> dict:
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path, body=json.dumps(body).encode() if body else None,
                     headers={"Content-Type": "application/json"} if body else {})
        resp = conn.getresponse()
        raw = resp.read()
    finally:
        conn.close()
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def test_rest_status_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    port, server = _start_server(monkeypatch)
    try:
        data = _request("GET", port, "/api/status")
        assert isinstance(data, dict)
        for key in ("bytes_sent", "bytes_received", "chunks", "alerts"):
            assert key in data
    finally:
        server.shutdown()
        server.server_close()


def test_rest_history_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    port, server = _start_server(monkeypatch)
    try:
        data = _request("GET", port, "/api/history?limit=5")
        assert isinstance(data, dict)
        assert "records" in data
        assert isinstance(data["records"], list)
    finally:
        server.shutdown()
        server.server_close()


def test_rest_peers_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    port, server = _start_server(monkeypatch)
    try:
        data = _request("GET", port, "/api/peers")
        assert isinstance(data, dict)
        assert "peers" in data
        assert isinstance(data["peers"], list)
    finally:
        server.shutdown()
        server.server_close()


def test_rest_send_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_send_paths(paths, peer_host, *, config, **kwargs):
        captured["paths"] = paths
        captured["peer_host"] = peer_host
        captured["port"] = config.port
        from core.transport import TransferStats
        return TransferStats(bytes_transferred=1234, chunks=5, alerts=0, files=1)

    monkeypatch.setattr(web_ui, "send_paths", fake_send_paths)

    port, server = _start_server(monkeypatch)
    try:
        data = _request("POST", port, "/api/send", {
            "paths": ["report.pdf"],
            "peer_host": "10.0.0.5",
            "peer_port": 55001,
            "mode": "lan",
        })
        assert data.get("sent") is True
        assert data.get("bytes_transferred") == 1234
        assert captured["peer_host"] == "10.0.0.5"
        assert captured["port"] == 55001
    finally:
        server.shutdown()
        server.server_close()


def test_rest_send_missing_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    port, server = _start_server(monkeypatch)
    try:
        data = _request("POST", port, "/api/send", {"paths": []})
        assert data.get("error") == "no paths provided"
    finally:
        server.shutdown()
        server.server_close()


def test_rest_receive_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    port, server = _start_server(monkeypatch)
    try:
        data = _request("POST", port, "/api/receive", {
            "peer_port": 55002,
            "output_dir": str(Path.cwd()),
            "mode": "lan",
        })
        assert data.get("listening") is True
        assert data.get("port") == 55002
        assert server.receive_thread is not None and server.receive_thread.is_alive()
    finally:
        server.shutdown()
        server.server_close()


def test_rest_receive_stop_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    port, server = _start_server(monkeypatch)
    try:
        _request("POST", port, "/api/receive", {
            "peer_port": 55003,
            "output_dir": str(Path.cwd()),
            "mode": "lan",
        })
        data = _request("POST", port, "/api/receive_stop")
        assert data.get("stopped") is True
    finally:
        server.shutdown()
        server.server_close()


def test_rest_unknown_endpoint_404(monkeypatch: pytest.MonkeyPatch) -> None:
    port, server = _start_server(monkeypatch)
    try:
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request("GET", "/api/does-not-exist")
            resp = conn.getresponse()
            assert resp.status == 404
        finally:
            conn.close()
    finally:
        server.shutdown()
        server.server_close()
