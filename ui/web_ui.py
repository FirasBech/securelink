"""Web UI for SecureLink — browser-based file transfer interface.

Serves a lightweight HTML/JS frontend plus JSON API endpoints backed by the
same core transport layer the CLI and desktop dashboard use. Launched via
``python -m ui.cli web`` on ``127.0.0.1`` (localhost only, by design).

No external web framework is required: stdlib ``http.server`` does the serving,
and the frontend is a single static HTML file (``ui/static/index.html``).
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

from core.discovery import discover_peers
from core.history import list_transfers
from core.transport import (
    TransportConfig,
    collect_transfer_items,
    receive_paths,
    send_paths,
)
from core.udp_transport import wan_send_paths, wan_receive_paths

STATIC_DIR = Path(__file__).resolve().parent / "static"
INDEX_HTML = STATIC_DIR / "index.html"
HOST = "127.0.0.1"
PORT = 8080


class _SecureLinkHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the SecureLink web UI.

    Routes:
      GET  /                -> index.html
      GET  /api/status      -> session counters
      GET  /api/history     -> recent transfer history
      GET  /api/peers       -> discovered peers (mDNS)
      POST /api/send        -> send file(s) to a peer
      POST /api/receive     -> start listening for a transfer
      POST /api/receive_stop-> stop listening
    """

    server_version = "SecureLink-WebUI/1.0"

    # ---- request plumbing -------------------------------------------------

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Silence default stderr logging; the desktop app owns the console."""
        return

    def _send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _path(self) -> str:
        return self.path.split("?", 1)[0]

    # ---- routes -----------------------------------------------------------

    def do_GET(self) -> None:
        route = self._path()
        if route == "/":
            self._serve_index()
        elif route == "/api/status":
            self._api_status()
        elif route == "/api/history":
            self._api_history()
        elif route == "/api/peers":
            self._api_peers()
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        route = self._path()
        if route == "/api/send":
            self._api_send()
        elif route == "/api/receive":
            self._api_receive()
        elif route == "/api/receive_stop":
            self._api_receive_stop()
        else:
            self._send_json(404, {"error": "not found"})

    # ---- handlers ---------------------------------------------------------

    def _serve_index(self) -> None:
        try:
            body = INDEX_HTML.read_text(encoding="utf-8").encode("utf-8")
        except OSError:
            body = b"<html><body>Web UI not found</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _api_status(self) -> None:
        from ui.mcp_server import _load_session_state

        try:
            data = _load_session_state()
        except Exception as exc:  # noqa: BLE001
            data = {"error": str(exc)}
        self._send_json(200, data)

    def _api_history(self) -> None:
        limit = 100
        try:
            from urllib.parse import parse_qs, urlparse

            qs = parse_qs(urlparse(self.path).query)
            if "limit" in qs:
                limit = int(qs["limit"][0])
        except Exception:
            pass
        try:
            records = list_transfers(limit=limit)
        except Exception as exc:  # noqa: BLE001
            records = []
            self._send_json(200, {"error": str(exc), "records": records})
            return
        self._send_json(200, {"records": records})

    def _api_peers(self) -> None:
        try:
            peers = discover_peers(timeout=2.0)
        except Exception as exc:  # noqa: BLE001
            peers = []
            self._send_json(200, {"error": str(exc), "peers": peers})
            return
        self._send_json(
            200,
            {
                "peers": [
                    {
                        "name": p.name,
                        "address": p.address,
                        "port": p.port,
                        "vlan_id": p.vlan_id,
                        "trusted": p.trusted,
                        "source": p.source,
                    }
                    for p in peers
                ]
            },
        )

    def _api_send(self) -> None:
        body = self._read_body()
        paths = body.get("paths") or []
        peer_host = body.get("peer_host") or "127.0.0.1"
        peer_port = int(body.get("peer_port") or 55000)
        mode = body.get("mode") or "auto"
        token = body.get("token")

        if isinstance(paths, str):
            paths = [paths]
        if not paths:
            self._send_json(400, {"error": "no paths provided"})
            return

        try:
            if token:
                from core.settings import Settings
                from core.udp_transport import wan_send_paths

                settings = Settings()
                rendezvous = settings.rendezvous_addr()
                if rendezvous is None:
                    self._send_json(400, {"error": "no rendezvous configured; set one in Settings"})
                    return
                parsed = rendezvous
                stats = wan_send_paths(
                    paths,
                    parsed,
                    rendezvous_addr=parsed,
                    token=token,
                )
                result = {"sent": True, "bytes_transferred": stats.bytes_transferred, "chunks": stats.chunks}
            else:
                resolved = (mode or "auto").strip().lower()
                transport_mode = resolved if resolved in {"lan", "vpn", "wan"} else "lan"
                config = TransportConfig(mode=transport_mode, port=peer_port)
                stats = send_paths(paths, peer_host, config=config)
                result = {
                    "sent": True,
                    "bytes_transferred": stats.bytes_transferred,
                    "chunks": stats.chunks,
                    "files": stats.files,
                }
            self._send_json(200, result)
        except Exception as exc:  # noqa: BLE001
            self._send_json(500, {"error": str(exc)})

    def _api_receive(self) -> None:
        body = self._read_body()
        peer_port = int(body.get("peer_port") or 55000)
        output_dir = body.get("output_dir") or str(Path.cwd())
        mode = body.get("mode") or "lan"
        allow_unknown = bool(body.get("allow_unknown", False))
        allowlist = body.get("allowlist") or ()
        if isinstance(allowlist, str):
            allowlist = tuple(x.strip() for x in allowlist.split(",") if x.strip())
        else:
            allowlist = tuple(allowlist)

        config = TransportConfig(
            mode=mode,
            port=peer_port,
            allow_unknown=allow_unknown,
            allowlist=allowlist,
            output_dir=Path(output_dir),
        )

        server = self.server
        assert isinstance(server, _SecureLinkServer)
        if server.receive_thread is not None and server.receive_thread.is_alive():
            self._send_json(409, {"error": "already listening"})
            return

        cancel = threading.Event()
        server.receive_cancel = cancel
        server.receive_thread_active = True

        def _worker() -> None:
            try:
                paths, stats = receive_paths(config=config, cancel_event=cancel)
                server.ui_callbacks.get("on_receive_finished", lambda *a, **k: None)(
                    [str(p) for p in paths], stats.bytes_transferred, stats.chunks
                )
            except Exception as exc:  # noqa: BLE001
                server.ui_callbacks.get("on_receive_failed", lambda *a, **k: None)(str(exc))
            finally:
                server.receive_thread_active = False

        server.receive_thread = threading.Thread(target=_worker, daemon=True)
        server.receive_thread.start()
        self._send_json(
            200,
            {
                "listening": True,
                "port": peer_port,
                "mode": mode,
            },
        )

    def _api_receive_stop(self) -> None:
        server = self.server
        assert isinstance(server, _SecureLinkServer)
        if server.receive_cancel is not None:
            server.receive_cancel.set()
        self._send_json(200, {"stopped": True})


class _SecureLinkServer(ThreadingHTTPServer):
    """HTTP server carrying receive-thread state shared across handler instances."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.receive_thread: Optional[threading.Thread] = None
        self.receive_cancel: Optional[threading.Event] = None
        self.receive_thread_active = False
        self.ui_callbacks: dict[str, Any] = {}


def run_web_ui(host: str = HOST, port: int = PORT) -> None:
    """Start the SecureLink web UI server (blocking)."""

    server = _SecureLinkServer((host, port), _SecureLinkHandler)
    print(f"SecureLink web UI listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main() -> int:
    """CLI entry point: ``securelink web``."""
    run_web_ui()
    return 0
