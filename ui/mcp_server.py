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


@mcp.tool(description="Send several files/folders to peers concurrently (one transport session per send).")
def send_concurrent(
    items: list[dict[str, Any]],
    max_workers: int = 4,
) -> str:
    """Send multiple files/folders to peers concurrently.

    ``items`` is a list of ``{"path": ..., "peer_host": ..., "peer_port": ...}``
    dicts — one entry per transfer, each with its own destination. Transfers run
    in parallel (capped by ``max_workers``) over independent transport sessions.
    Returns one stats summary per item, in input order.
    """

    from core.concurrent import send_concurrent as send_many
    from core.transport import TransportConfig

    transfers: list[tuple[str, str, int]] = []
    for item in items or []:
        transfers.append(
            (
                item.get("path") or "",
                item.get("peer_host") or "127.0.0.1",
                int(item.get("peer_port") or 55000),
            )
        )

    results = send_many(transfers, config=TransportConfig(), max_workers=max_workers)
    summaries = [
        {
            "bytes_transferred": result.bytes_transferred,
            "chunks": result.chunks,
            "alerts": result.alerts,
            "files": result.files,
        }
        for result in results
    ]
    return json.dumps({"sent": True, "results": summaries})


@mcp.tool(description="Show SecureLink session counters (bytes sent/received, chunks, alerts).")
def status() -> str:
    """Return the current session counters from ~/.securelink/session.json."""

    return json.dumps(_load_session_state())


@mcp.tool(description="List recent transfer history / receipts.")
def transfer_history(limit: int = 20) -> str:
    """Return the most recent transfer records from the durable history."""

    from core.history import list_transfers

    return json.dumps(list_transfers(limit=limit))


@mcp.tool(description="Inspect this computer's GPUs and detected agent and 3D commands. This is local only.")
def local_workstation_status() -> str:
    """Return local capabilities without launching tools or checking credentials."""
    from core.workstation import local_inventory

    return json.dumps(local_inventory())


def _local_job_queue():
    from core.job_queue import JobQueue
    return JobQueue(Path.home() / ".securelink" / "workstation-jobs.sqlite3")


@mcp.tool(description="List jobs recorded on this computer. No remote worker is connected.")
def local_jobs(limit: int = 100) -> str:
    from core.job_queue import JobError
    try:
        return json.dumps(_local_job_queue().list(limit))
    except JobError as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool(description="Store a local job request; this does not launch a worker or execute the job.")
def submit_local_job(kind: str, payload: dict[str, Any], gpu_count: int = 0,
                     min_free_mib: int = 0, job_id: str | None = None) -> str:
    from core.job_queue import JobError
    try:
        return json.dumps(_local_job_queue().submit(kind, payload, gpu_count=gpu_count,
                                                   min_free_mib=min_free_mib, job_id=job_id))
    except JobError as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool(description="Read progress, questions, and answers for a local workstation job.")
def local_job_events(job_id: str, after: int = 0) -> str:
    from core.job_queue import JobError
    try:
        return json.dumps(_local_job_queue().events(job_id, after=after))
    except JobError as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool(description="Answer the current question for a local workstation job.")
def answer_local_job(job_id: str, question_id: str, answer: str) -> str:
    from core.job_queue import JobError
    try:
        return json.dumps(_local_job_queue().answer_question(job_id, question_id, answer))
    except JobError as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool(description="Cancel a queued local job or request cancellation of a running one.")
def cancel_local_job(job_id: str) -> str:
    from core.job_queue import JobError
    try:
        return json.dumps(_local_job_queue().cancel(job_id))
    except JobError as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool(description="Control a configured SecureLink workstation through verified OpenSSH. "
          "Methods: status, jobs.list, jobs.get, jobs.submit, jobs.events, jobs.answer, jobs.cancel. "
          "The remote PC must already have SSH access, SecureLink and a configured worker.")
def remote_workstation(target: str, project_path: str, method: str,
                       params: dict[str, Any] | None = None, port: int = 22) -> str:
    from core.remote_workstation import RemoteError, request
    allowed = {"status", "jobs.list", "jobs.get", "jobs.submit", "jobs.events", "jobs.answer", "jobs.cancel"}
    if method not in allowed:
        return json.dumps({"error": "unsupported workstation method"})
    try:
        return json.dumps(request(target, project_path, method, params, port=port))
    except (RemoteError, ValueError, TypeError) as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool(description="Send a local file up to 8 MiB to the configured remote workstation workspace over SSH. "
          "Existing remote files are not overwritten.")
def remote_upload_file(target: str, project_path: str, local_path: str, remote_path: str,
                       port: int = 22) -> str:
    import base64
    from core.remote_workstation import RemoteError, request
    try:
        source = Path(local_path)
        if not source.is_file() or source.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("file is missing or exceeds the 8 MiB transfer limit")
        data = source.read_bytes()
        if len(data) > 8 * 1024 * 1024:
            raise ValueError("file exceeds the 8 MiB transfer limit")
        return json.dumps(request(target, project_path, "files.put",
                                  {"path": remote_path, "data_base64": base64.b64encode(data).decode("ascii")},
                                  port=port))
    except (RemoteError, ValueError, OSError) as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool(description="Retrieve a remote workspace file up to 8 MiB over SSH without overwriting a local file.")
def remote_download_file(target: str, project_path: str, remote_path: str, local_path: str,
                         port: int = 22) -> str:
    import base64
    import binascii
    from core.remote_workstation import RemoteError, request
    try:
        payload = request(target, project_path, "files.get", {"path": remote_path}, port=port)
        data = base64.b64decode(payload["data_base64"], validate=True)
        if len(data) > 8 * 1024 * 1024:
            raise ValueError("file exceeds the 8 MiB transfer limit")
        with Path(local_path).open("xb") as handle:
            handle.write(data)
        return json.dumps({"path": local_path, "size": len(data)})
    except (RemoteError, ValueError, OSError, KeyError, binascii.Error) as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool(description="Retry a failed transfer recorded in the durable history (send or receive).")
def retry_transfer(
    direction: str,
    file_path: str,
    peer_host: str | None = None,
    peer_port: int = 55000,
    token: str | None = None,
    mode: str | None = None,
) -> str:
    """Retry a previously failed transfer.

    ``direction`` is ``"send"`` (re-send ``file_path`` to ``peer_host:peer_port``)
    or ``"recv"`` (re-listen for a peer to deliver ``file_path``).
    """

    from core.history import list_transfers

    if direction == "send":
        if token:
            from core.settings import Settings
            from core.udp_transport import wan_send_file

            settings = Settings()
            rendezvous = settings.rendezvous_addr()
            if rendezvous is None:
                return json.dumps({"error": "no rendezvous configured; cannot retry WAN send"})
            parsed = rendezvous
            stats = wan_send_file(
                file_path,
                parsed,
                rendezvous_addr=parsed,
                token=token,
            )
            return json.dumps({"retried": True, "direction": "send", "bytes_transferred": stats.bytes_transferred})
        from core.transport import send_file

        config = TransportConfig(mode=(mode or "auto"), port=peer_port)
        stats = send_file(file_path, peer_host or "127.0.0.1", config=config)
        return json.dumps({"retried": True, "direction": "send", "bytes_transferred": stats.bytes_transferred})

    if direction == "recv":
        from core.transport import receive_file

        config = TransportConfig(mode=(mode or "lan"), port=peer_port, output_dir=Path.cwd())
        path, stats = receive_file(config=config)
        return json.dumps({"retried": True, "direction": "recv", "bytes_transferred": stats.bytes_transferred})

    return json.dumps({"error": f"unknown direction {direction!r}; expected 'send' or 'recv'"})


def _auto_mode(peer_host: str) -> str:
    from core.discovery import auto_select_transport_mode

    return auto_select_transport_mode(vlan_id=None, peer_address=peer_host)


def create_server() -> MCPServer:
    """Return the configured SecureLink MCP server instance."""

    return mcp
