"""End-to-end check: connect an MCP client to the SecureLink MCP server over stdio
and list/call its tools.

Usage: python scripts/verify_mcp_client.py
"""

from __future__ import annotations

import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> int:
    params = StdioServerParameters(command=sys.executable, args=["-m", "ui.mcp"])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init_result = await session.initialize()
            print("SERVER INFO:", init_result.server_info.name, init_result.server_info.version)

            tools_result = await session.list_tools()
            names = [tool.name for tool in tools_result.tools]
            print("TOOLS:", sorted(names))
            assert {"scan_peers", "natcheck", "send_file", "status", "transfer_history"} <= set(names)

            status_result = await session.call_tool("status", {})
            print("STATUS RESULT:", status_result)

            history_result = await session.call_tool("transfer_history", {"limit": 5})
            print("HISTORY RESULT:", history_result)

    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
