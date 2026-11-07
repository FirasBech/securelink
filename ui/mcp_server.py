"""MCP server exposing SecureLink operations as tools for AI agents.

Runs over the MCP stdio transport (``python -m ui.mcp``) and exposes the
core SecureLink operations — scanning, NAT checks, sending, receiving, status —
as agent-callable tools backed by the same transport layer the CLI uses.

No server of SecureLink's own is involved: these tools call the local core
functions directly, exactly like the CLI subcommands do.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.discovery import PeerAdvertisement, discover_peers
from core.nat import NatError, detect_nat_mapping
from core.settings import Settings, SettingsError, parse_host_port
from core.transport import TransportConfig, send_file
from core.udp_transport import wan_receive_file, wan_send_file
from mcp.server.mcpserver import MCPServer

mcp = MCPServer(name="securelink", version="1.0.0")


def _peer_json(peer: PeerAdvertisement) -> dict[str, Any]:
    return {
        "name": peer.name,
        "address": peer.address,
        "port": peer.port,
        "vlan_id": peer.vlan_id,
        "fingerprint": peer.fingerprint,
        "trusted": peer.trusted,
        "source": peer.source,
        "metadata": peer.metadata or {},
    }


def _load_session_state() -> dict[str, Any]:
    path = Path.home() / ".securelink" / "session.json"
    default: dict[str, Any] = {"bytes_sent": 0, "bytes_received": 0, "chunks": 0, "alerts": 0}
    if not path.exists():
        return default
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default
    return data if isinstance(data, dict) else default


@mcp.tool(description="Scan the local network for SecureLink peers via mDNS.")
def scan_peers(timeout: float = 2.5) -> str:
    """Return the list of SecureLink peers currently visible on the LAN."""

    try:
        peers = discover_peers(timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": str(exc)})
    return json.dumps([_peer_json(peer) for peer in peers])


@mcp.tool(description="Classify this host's NAT and whether WAN hole punching should work.")
def natcheck(timeout: float = 3.0) -> str:
    """Probe STUN servers and report the NAT mapping (open / cone / symmetric / udp_blocked)."""

    try:
        result = detect_nat_mapping(timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": str(exc)})
    return json.dumps(
        {
            "mapping": result.mapping,
            "hole_punch_likely": bool(result.hole_punch_likely),
            "reflexive": (
                f"{result.reflexive.ip}:{result.reflexive.port}"
                if result.reflexive is not None
                else None
            ),
            "advice": result.advice,
        }
    )


@mcp.tool(description="Send a file to a peer over LAN, VPN, or WAN (reliable UDP / coordination).")
def send_file(
    file_path: str,
    peer_host: str,
    peer_port: int = 55000,
    token: str | None = None,
    mode: str | None = None,
) -> str:
    """Send ``file_path`` to ``peer_host:peer_port``.

    Use ``token`` for an internet (coordination-server) transfer; leave it unset
    for a local/LAN/VPN send. ``mode`` overrides the transport choice (lan / vpn /
    wan); omit it to auto-select.
    """

    if token:
        settings = Settings()
        rendezvous = settings.rendezvous_addr()
        if rendezvous is None:
            return json.dumps({"error": "no rendezvous configured; set one in Settings or omit the token"})
        rendezvous_addr, relay_addr = rendezvous
        parsed = parse_host_port(rendezvous)
        stats = wan_send_file(
            file_path,
            parsed,
            rendezvous_addr=parsed,
            token=token,
            relay_addr=relay_addr,
        )
        return json.dumps({"sent": True, "bytes_transferred": stats.bytes_transferred, "chunks": stats.chunks})

    resolved = (mode or "auto").strip().lower()
    if resolved in {"", "auto"}:
        transport_mode = _auto_mode(peer_host)
    elif resolved in {"lan", "vpn", "wan"}:
        transport_mode = resolved
    else:
        return json.dumps({"error": f"unknown mode {mode!r}; expected lan | vpn | wan | auto"})

    config = TransportConfig(mode=transport_mode, port=peer_port)
    stats = send_file(file_path, peer_host, config=config)
    return json.dumps({"sent": True, "bytes_transferred": stats.bytes_transferred, "chunks": stats.chunks})


@mcp.tool(description="Show SecureLink session counters (bytes sent/received, chunks, alerts).")
def status() -> str:
    """Return the current session counters from ~/.securelink/session.json."""

    return json.dumps(_load_session_state())


def _auto_mode(peer_host: str) -> str:
    from core.discovery import auto_select_transport_mode

    return auto_select_transport_mode(vlan_id=None, peer_address=peer_host)


def create_server() -> MCPServer:
    """Return the configured SecureLink MCP server instance."""

    return mcp
