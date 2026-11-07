from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest

import ui.web_ui as web_ui
from ui.web_ui import INDEX_HTML, STATIC_DIR, _SecureLinkHandler, _SecureLinkServer, run_web_ui


def test_index_html_exists() -> None:
    assert INDEX_HTML.exists()
    content = INDEX_HTML.read_text(encoding="utf-8")
    assert "<title>SecureLink" in content
    assert 'json("/send"' in content
    assert 'json("/receive"' in content


def test_static_dir_exists() -> None:
    assert STATIC_DIR.is_dir()


def test_handler_has_expected_routes() -> None:
    # The handler must implement do_GET/do_POST and route the expected paths.
    handler = _SecureLinkHandler.__new__(_SecureLinkHandler)
    assert callable(getattr(handler, "do_GET", None))
    assert callable(getattr(handler, "do_POST", None))
    # The HTML references the API endpoints the server routes.
    content = INDEX_HTML.read_text(encoding="utf-8")
    for endpoint in ("/send", "/receive", "/receive_stop", "/peers", "/history"):
        assert endpoint in content


def test_server_has_receive_state() -> None:
    server = _SecureLinkServer(("127.0.0.1", 0), _SecureLinkHandler)
    assert server.receive_thread is None
    assert server.receive_cancel is None
    assert server.receive_thread_active is False
    server.server_close()


def test_cli_web_registered() -> None:
    from ui.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(["web", "--port", "9999"])
    assert args.command == "web"
    assert args.port == 9999
    assert args.host == "127.0.0.1"


def test_web_help_includes_web_command() -> None:
    from ui.cli import build_parser

    parser = build_parser()
    help_text = parser.format_help()
    assert "web" in help_text


def test_send_paths_importable() -> None:
    # web_ui imports these; ensure they resolve without error
    from core.transport import send_paths, receive_paths, TransportConfig
    assert callable(send_paths)
    assert callable(receive_paths)
    assert TransportConfig is not None
