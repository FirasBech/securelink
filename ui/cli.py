from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path
from typing import Any

from core.discovery import auto_select_transport_mode, discover_peers, tailscale_peers
from core.settings import Settings, SettingsError, parse_host_port
from core.stun import StunError, discover_public_endpoint
from core.transport import TransferStats, TransportConfig, receive_file, send_file
from core.udp_transport import (
    udp_receive_file,
    udp_send_file,
    wan_receive_file,
    wan_send_file,
)
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


def _coordination_endpoints(
    args: argparse.Namespace, base_dir: Path | None
) -> tuple[tuple[str, int], tuple[str, int] | None]:
    """Resolve rendezvous (required) and relay (optional) from flags or settings."""
    settings = Settings.load(base_dir)
    rendezvous_text = getattr(args, "rendezvous", None) or settings.rendezvous
    relay_text = getattr(args, "relay", None) or settings.relay
    if not rendezvous_text:
        raise SettingsError(
            "no rendezvous server set. Pass --rendezvous host:port or configure one "
            "(SecureLink bundles none; you host your own)."
        )
    rendezvous_addr = parse_host_port(rendezvous_text)
    relay_addr = parse_host_port(relay_text) if relay_text else None
    return rendezvous_addr, relay_addr


def _cmd_wansend(args: argparse.Namespace) -> int:
    base_dir = _base_dir(args)
    try:
        rendezvous_addr, relay_addr = _coordination_endpoints(args, base_dir)
    except SettingsError as exc:
        print(json.dumps({"status": "error", "message": str(exc)}, indent=2))
        return 1
    config = TransportConfig(mode="wan", allow_unknown=args.allow_unknown)
    stats = wan_send_file(
        args.file,
        rendezvous_addr=rendezvous_addr,
        token=args.token,
        relay_addr=relay_addr,
        config=config,
        trust_prompt=_prompt_trust,
        base_dir=base_dir,
    )
    _update_state(stats, "send", base_dir)
    print(json.dumps({"status": "sent", "bytes": stats.bytes_transferred, "chunks": stats.chunks}, indent=2))
    return 0


def _cmd_wanrecv(args: argparse.Namespace) -> int:
    base_dir = _base_dir(args)
    try:
        rendezvous_addr, relay_addr = _coordination_endpoints(args, base_dir)
    except SettingsError as exc:
        print(json.dumps({"status": "error", "message": str(exc)}, indent=2))
        return 1
    config = TransportConfig(
        mode="wan",
        allow_unknown=args.allow_unknown,
        allowlist=tuple(args.allowlist or ()),
        output_dir=Path(args.output_dir),
    )
    output_path, stats = wan_receive_file(
        rendezvous_addr=rendezvous_addr,
        token=args.token,
        relay_addr=relay_addr,
        config=config,
        trust_prompt=_prompt_trust,
        base_dir=base_dir,
    )
    _update_state(stats, "recv", base_dir)
    print(json.dumps({"status": "received", "path": str(output_path), "bytes": stats.bytes_transferred, "chunks": stats.chunks}, indent=2))
    return 0


def _cmd_settings(args: argparse.Namespace) -> int:
    base_dir = _base_dir(args)
    settings = Settings.load(base_dir)
    changed = False
    for field in ("rendezvous", "relay", "stun_host"):
        value = getattr(args, field, None)
        if value is not None:
            setattr(settings, field, value or None)  # empty string clears it
            changed = True
    if args.stun_port is not None:
        settings.stun_port = args.stun_port or None
        changed = True
    if changed:
        settings.save(base_dir)
    print(json.dumps(settings.as_dict(), indent=2))
    return 0


def _serve_forever(server: Any, kind: str) -> int:
    import threading

    server.start()
    host, port = server.address
    print(json.dumps({"status": f"{kind} listening", "host": host, "port": port}), flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


def _cmd_rendezvous(args: argparse.Namespace) -> int:
    from core.nat import RendezvousServer

    return _serve_forever(RendezvousServer(host=args.host, port=args.port), "rendezvous")


def _cmd_relay(args: argparse.Namespace) -> int:
    from core.nat import RelayServer

    return _serve_forever(RelayServer(host=args.host, port=args.port), "relay")


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

    wansend_parser = subparsers.add_parser(
        "wansend", help="send a file over the internet via a coordination server (you host it)", parents=[common]
    )
    wansend_parser.add_argument("file", help="file to transfer")
    wansend_parser.add_argument("--token", required=True, help="shared token both peers agree on")
    wansend_parser.add_argument("--rendezvous", default=None, help="host:port (overrides settings)")
    wansend_parser.add_argument("--relay", default=None, help="host:port relay fallback (overrides settings)")
    wansend_parser.add_argument("--allow-unknown", action="store_true")
    wansend_parser.set_defaults(func=_cmd_wansend)

    wanrecv_parser = subparsers.add_parser(
        "wanrecv", help="receive a file over the internet via a coordination server", parents=[common]
    )
    wanrecv_parser.add_argument("--token", required=True, help="shared token both peers agree on")
    wanrecv_parser.add_argument("--rendezvous", default=None, help="host:port (overrides settings)")
    wanrecv_parser.add_argument("--relay", default=None, help="host:port relay fallback (overrides settings)")
    wanrecv_parser.add_argument("--output-dir", default=str(Path.cwd()))
    wanrecv_parser.add_argument("--allowlist", nargs="*", default=[])
    wanrecv_parser.add_argument("--allow-unknown", action="store_true")
    wanrecv_parser.set_defaults(func=_cmd_wanrecv)

    settings_parser = subparsers.add_parser(
        "settings", help="show or set your coordination-server settings (BYO; none bundled)", parents=[common]
    )
    settings_parser.add_argument("--rendezvous", default=None, help="set rendezvous host:port ('' clears)")
    settings_parser.add_argument("--relay", default=None, help="set relay host:port ('' clears)")
    settings_parser.add_argument("--stun-host", dest="stun_host", default=None)
    settings_parser.add_argument("--stun-port", dest="stun_port", type=int, default=None)
    settings_parser.set_defaults(func=_cmd_settings)

    rendezvous_parser = subparsers.add_parser(
        "rendezvous", help="run a rendezvous server (endpoint matchmaker for hole punching)", parents=[common]
    )
    rendezvous_parser.add_argument("--host", default="0.0.0.0")
    rendezvous_parser.add_argument("--port", type=int, default=0)
    rendezvous_parser.set_defaults(func=_cmd_rendezvous)

    relay_parser = subparsers.add_parser(
        "relay", help="run a UDP relay server (fallback for symmetric NATs)", parents=[common]
    )
    relay_parser.add_argument("--host", default="0.0.0.0")
    relay_parser.add_argument("--port", type=int, default=0)
    relay_parser.set_defaults(func=_cmd_relay)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
