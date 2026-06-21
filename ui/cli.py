from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path
from typing import Any

from core.discovery import auto_select_transport_mode, discover_peers
from core.stun import StunError, discover_public_endpoint
from core.transport import TransferStats, TransportConfig, receive_file, send_file
from core.udp_transport import udp_receive_file, udp_send_file
from security.capture import JsonEventLogger

SESSION_STATE_PATH = Path.home() / ".securelink" / "session.json"
LOG_DIR = Path.home() / ".securelink" / "logs"


def _load_session_state() -> dict[str, Any]:
    if not SESSION_STATE_PATH.exists():
        return {"bytes_sent": 0, "bytes_received": 0, "chunks": 0, "alerts": 0}
    try:
        data = json.loads(SESSION_STATE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"bytes_sent": 0, "bytes_received": 0, "chunks": 0, "alerts": 0}
    return data if isinstance(data, dict) else {"bytes_sent": 0, "bytes_received": 0, "chunks": 0, "alerts": 0}


def _save_session_state(state: dict[str, Any]) -> None:
    SESSION_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    SESSION_STATE_PATH.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def _update_state(stats: TransferStats, direction: str) -> None:
    state = _load_session_state()
    if direction == "send":
        state["bytes_sent"] = int(state.get("bytes_sent", 0)) + stats.bytes_transferred
    elif direction == "recv":
        state["bytes_received"] = int(state.get("bytes_received", 0)) + stats.bytes_transferred
    state["chunks"] = int(state.get("chunks", 0)) + stats.chunks
    state["alerts"] = int(state.get("alerts", 0)) + stats.alerts
    _save_session_state(state)


def _prompt_trust(fingerprint: str) -> bool:
    answer = input(f"Trust remote device {fingerprint}? [y/N] ").strip().lower()
    return answer in {"y", "yes"}


def _cmd_send(args: argparse.Namespace) -> int:
    if args.wan:
        config = TransportConfig(
            mode="wan",
            port=args.port,
            mtu=args.mtu,
            allow_unknown=args.allow_unknown,
            vlan_id=args.vlan,
        )
        stats = udp_send_file(
            args.file, args.peer, args.port, config=config, trust_prompt=_prompt_trust
        )
    else:
        mode = auto_select_transport_mode(vlan_id=args.vlan, peer_address=args.peer)
        config = TransportConfig(
            mode=mode,
            port=args.port,
            mtu=args.mtu,
            allow_unknown=args.allow_unknown,
            vlan_id=args.vlan,
        )
        stats = send_file(args.file, args.peer, config=config, trust_prompt=_prompt_trust)
    _update_state(stats, "send")
    print(json.dumps({"status": "sent", "bytes": stats.bytes_transferred, "chunks": stats.chunks}, indent=2))
    return 0


def _cmd_recv(args: argparse.Namespace) -> int:
    mode = "wan" if args.wan else ("vlan" if args.vlan is not None else "lan")
    config = TransportConfig(
        mode=mode,
        port=args.port,
        mtu=args.mtu,
        allow_unknown=args.allow_unknown,
        allowlist=tuple(args.allowlist or ()),
        output_dir=Path(args.output_dir),
        vlan_id=args.vlan,
    )
    if args.wan:
        output_path, stats = udp_receive_file(config=config, trust_prompt=_prompt_trust)
    else:
        output_path, stats = receive_file(config=config, trust_prompt=_prompt_trust)
    _update_state(stats, "recv")
    print(json.dumps({"status": "received", "path": str(output_path), "bytes": stats.bytes_transferred, "chunks": stats.chunks}, indent=2))
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    peers = discover_peers(timeout=args.timeout)
    print(json.dumps([peer.__dict__ for peer in peers], indent=2, sort_keys=True))
    return 0


def _read_log_lines(path: Path, alerts_only: bool) -> list[str]:
    if not path.exists():
        return []
    results: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        if alerts_only:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not payload.get("alert"):
                continue
        results.append(line)
    return results


def _cmd_logs(args: argparse.Namespace) -> int:
    log_path = LOG_DIR / f"{date.today().isoformat()}.json"
    lines = _read_log_lines(log_path, alerts_only=args.alerts_only)
    if args.tail and len(lines) > args.tail:
        lines = lines[-args.tail :]
    for line in lines:
        print(line)
    return 0


def _cmd_status(_args: argparse.Namespace) -> int:
    state = _load_session_state()
    print(json.dumps(state, indent=2, sort_keys=True))
    return 0


def _cmd_stun(args: argparse.Namespace) -> int:
    try:
        endpoint = discover_public_endpoint(args.stun_host, args.stun_port)
    except StunError as exc:
        print(json.dumps({"status": "error", "message": str(exc)}, indent=2))
        return 1
    print(json.dumps({"public_ip": endpoint.ip, "public_port": endpoint.port}, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="securelink")
    subparsers = parser.add_subparsers(dest="command", required=True)

    send_parser = subparsers.add_parser("send", help="send a file to a peer")
    send_parser.add_argument("file", help="file to transfer")
    send_parser.add_argument("peer", help="peer host or IP")
    send_parser.add_argument("--vlan", type=int, default=None)
    send_parser.add_argument("--wan", action="store_true", help="use reliable UDP (WAN) transport")
    send_parser.add_argument("--port", type=int, default=55000)
    send_parser.add_argument("--mtu", type=int, default=1500)
    send_parser.add_argument("--allow-unknown", action="store_true")
    send_parser.set_defaults(func=_cmd_send)

    recv_parser = subparsers.add_parser("recv", help="receive a file")
    recv_parser.add_argument("--port", type=int, default=55000)
    recv_parser.add_argument("--allowlist", nargs="*", default=[])
    recv_parser.add_argument("--output-dir", default=str(Path.cwd()))
    recv_parser.add_argument("--allow-unknown", action="store_true")
    recv_parser.add_argument("--mtu", type=int, default=1500)
    recv_parser.add_argument("--vlan", type=int, default=None)
    recv_parser.add_argument("--wan", action="store_true", help="use reliable UDP (WAN) transport")
    recv_parser.set_defaults(func=_cmd_recv)

    scan_parser = subparsers.add_parser("scan", help="discover peers on LAN")
    scan_parser.add_argument("--timeout", type=float, default=2.5)
    scan_parser.set_defaults(func=_cmd_scan)

    logs_parser = subparsers.add_parser("logs", help="view structured logs")
    logs_parser.add_argument("--tail", type=int, default=20)
    logs_parser.add_argument("--alerts-only", action="store_true")
    logs_parser.set_defaults(func=_cmd_logs)

    status_parser = subparsers.add_parser("status", help="show session stats")
    status_parser.set_defaults(func=_cmd_status)

    stun_parser = subparsers.add_parser("stun", help="discover this host's public endpoint via STUN")
    stun_parser.add_argument("--stun-host", default="stun.l.google.com")
    stun_parser.add_argument("--stun-port", type=int, default=19302)
    stun_parser.set_defaults(func=_cmd_stun)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
