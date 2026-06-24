from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path
from typing import Any

from core.discovery import auto_select_transport_mode, discover_peers, tailscale_peers
from core.stun import StunError, discover_public_endpoint
from core.transport import TransferStats, TransportConfig, receive_file, send_file
from core.udp_transport import udp_receive_file, udp_send_file
from security.capture import JsonEventLogger

def _securelink_root(base_dir: Path | None) -> Path:
    return (base_dir or Path.home()) / ".securelink"


def _base_dir(args: argparse.Namespace) -> Path | None:
    state_dir = getattr(args, "state_dir", None)
    return Path(state_dir) if state_dir else None


def _default_state() -> dict[str, Any]:
    return {"bytes_sent": 0, "bytes_received": 0, "chunks": 0, "alerts": 0}


def _load_session_state(base_dir: Path | None) -> dict[str, Any]:
    path = _securelink_root(base_dir) / "session.json"
    if not path.exists():
        return _default_state()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return _default_state()
    return data if isinstance(data, dict) else _default_state()


def _save_session_state(state: dict[str, Any], base_dir: Path | None) -> None:
    path = _securelink_root(base_dir) / "session.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def _update_state(stats: TransferStats, direction: str, base_dir: Path | None) -> None:
    state = _load_session_state(base_dir)
    if direction == "send":
        state["bytes_sent"] = int(state.get("bytes_sent", 0)) + stats.bytes_transferred
    elif direction == "recv":
        state["bytes_received"] = int(state.get("bytes_received", 0)) + stats.bytes_transferred
    state["chunks"] = int(state.get("chunks", 0)) + stats.chunks
    state["alerts"] = int(state.get("alerts", 0)) + stats.alerts
    _save_session_state(state, base_dir)


def _prompt_trust(fingerprint: str) -> bool:
    answer = input(f"Trust remote device {fingerprint}? [y/N] ").strip().lower()
    return answer in {"y", "yes"}


def _cmd_send(args: argparse.Namespace) -> int:
    base_dir = _base_dir(args)
    mode = "wan" if args.wan else auto_select_transport_mode(vlan_id=args.vlan, peer_address=args.peer)
    config = TransportConfig(
        mode=mode,
        port=args.port,
        mtu=args.mtu,
        allow_unknown=args.allow_unknown,
        vlan_id=args.vlan,
    )
    if mode == "wan":
        stats = udp_send_file(
            args.file, args.peer, args.port, config=config, trust_prompt=_prompt_trust, base_dir=base_dir
        )
    else:
        stats = send_file(args.file, args.peer, config=config, trust_prompt=_prompt_trust, base_dir=base_dir)
    _update_state(stats, "send", base_dir)
    print(json.dumps({"status": "sent", "bytes": stats.bytes_transferred, "chunks": stats.chunks}, indent=2))
    return 0


def _cmd_recv(args: argparse.Namespace) -> int:
    base_dir = _base_dir(args)
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
        output_path, stats = udp_receive_file(config=config, trust_prompt=_prompt_trust, base_dir=base_dir)
    else:
        output_path, stats = receive_file(config=config, trust_prompt=_prompt_trust, base_dir=base_dir)
    _update_state(stats, "recv", base_dir)
    print(json.dumps({"status": "received", "path": str(output_path), "bytes": stats.bytes_transferred, "chunks": stats.chunks}, indent=2))
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    peers = discover_peers(timeout=args.timeout)
    seen = {peer.address for peer in peers}
    # Best-effort: empty unless the Tailscale CLI is installed and up.
    for peer in tailscale_peers():
        if peer.address not in seen:
            peers.append(peer)
            seen.add(peer.address)
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
    log_path = _securelink_root(_base_dir(args)) / "logs" / f"{date.today().isoformat()}.json"
    lines = _read_log_lines(log_path, alerts_only=args.alerts_only)
    if args.tail and len(lines) > args.tail:
        lines = lines[-args.tail :]
    for line in lines:
        print(line)
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    state = _load_session_state(_base_dir(args))
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


def _cmd_natcheck(args: argparse.Namespace) -> int:
    from core.nat import detect_nat_mapping

    assessment = detect_nat_mapping(timeout=args.timeout)
    print(
        json.dumps(
            {
                "mapping": assessment.mapping,
                "reflexive_ip": assessment.reflexive.ip if assessment.reflexive else None,
                "reflexive_port": assessment.reflexive.port if assessment.reflexive else None,
                "hole_punch_likely": assessment.hole_punch_likely,
                "advice": assessment.advice,
            },
            indent=2,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="securelink")
    subparsers = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--state-dir",
        default=None,
        help="base directory for identity, known_hosts, session state, and logs (default: ~)",
    )

    send_parser = subparsers.add_parser("send", help="send a file to a peer", parents=[common])
    send_parser.add_argument("file", help="file to transfer")
    send_parser.add_argument("peer", help="peer host or IP")
    send_parser.add_argument("--vlan", type=int, default=None)
    send_parser.add_argument("--wan", action="store_true", help="use reliable UDP (WAN) transport")
    send_parser.add_argument("--port", type=int, default=55000)
    send_parser.add_argument("--mtu", type=int, default=1500)
    send_parser.add_argument("--allow-unknown", action="store_true")
    send_parser.set_defaults(func=_cmd_send)

    recv_parser = subparsers.add_parser("recv", help="receive a file", parents=[common])
    recv_parser.add_argument("--port", type=int, default=55000)
    recv_parser.add_argument("--allowlist", nargs="*", default=[])
    recv_parser.add_argument("--output-dir", default=str(Path.cwd()))
    recv_parser.add_argument("--allow-unknown", action="store_true")
    recv_parser.add_argument("--mtu", type=int, default=1500)
    recv_parser.add_argument("--vlan", type=int, default=None)
    recv_parser.add_argument("--wan", action="store_true", help="use reliable UDP (WAN) transport")
    recv_parser.set_defaults(func=_cmd_recv)

    scan_parser = subparsers.add_parser("scan", help="discover peers on LAN", parents=[common])
    scan_parser.add_argument("--timeout", type=float, default=2.5)
    scan_parser.set_defaults(func=_cmd_scan)

    logs_parser = subparsers.add_parser("logs", help="view structured logs", parents=[common])
    logs_parser.add_argument("--tail", type=int, default=20)
    logs_parser.add_argument("--alerts-only", action="store_true")
    logs_parser.set_defaults(func=_cmd_logs)

    status_parser = subparsers.add_parser("status", help="show session stats", parents=[common])
    status_parser.set_defaults(func=_cmd_status)

    stun_parser = subparsers.add_parser("stun", help="discover this host's public endpoint via STUN", parents=[common])
    stun_parser.add_argument("--stun-host", default="stun.l.google.com")
    stun_parser.add_argument("--stun-port", type=int, default=19302)
    stun_parser.set_defaults(func=_cmd_stun)

    natcheck_parser = subparsers.add_parser(
        "natcheck", help="classify this host's NAT and whether WAN hole punching will work", parents=[common]
    )
    natcheck_parser.add_argument("--timeout", type=float, default=3.0)
    natcheck_parser.set_defaults(func=_cmd_natcheck)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
