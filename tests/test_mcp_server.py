from __future__ import annotations

import asyncio
import json

from ui.mcp_server import mcp, natcheck, scan_peers, send_file, status, transfer_history


def _list_tool_names() -> list[str]:
    tools = asyncio.run(mcp.list_tools())
    return [tool.name for tool in tools]


def test_mcp_server_registers_securelink_tools() -> None:
    names = _list_tool_names()
    assert {"scan_peers", "natcheck", "send_file", "status", "transfer_history"} <= set(names)


def test_mcp_status_returns_json() -> None:
    data = json.loads(status())
    assert isinstance(data, dict)
    for key in ("bytes_sent", "bytes_received", "chunks", "alerts"):
        assert key in data


def test_mcp_transfer_history_returns_json() -> None:
    data = json.loads(transfer_history())
    assert isinstance(data, list)


def test_mcp_scan_peers_returns_json() -> None:
    data = json.loads(scan_peers())
    assert isinstance(data, list)
