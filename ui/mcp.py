"""MCP server entry point: run SecureLink as an MCP server over stdio.

Usage (stdio transport, the default for local agent integrations):

    python -m ui.mcp

The server exposes SecureLink operations as MCP tools (see ``ui.mcp_server``):
scan peers, check NAT, send files, receive files, session status.
"""

from __future__ import annotations

import asyncio

from ui.mcp_server import mcp


async def _run() -> None:
    await mcp.run_stdio_async()


def main() -> int:
    asyncio.run(_run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
