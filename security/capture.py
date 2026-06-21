from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Callable

from .arp_guard import ArpGuard
from .ttl_guard import TtlGuard
from .vlan_guard import VlanPolicyEngine

try:
    from scapy.all import TCP, IP, Dot1Q, sniff
except ImportError:  # pragma: no cover - optional dependency
    TCP = IP = Dot1Q = sniff = None


DEFAULT_PORT = 55000


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: str
    event: str
    src_ip: str | None
    dst_ip: str | None
    vlan_id: int | None
    bytes: int
    chunk_id: int | None
    encrypted: bool
    hmac_valid: bool
    ttl: int | None
    alert: bool
    message: str
    metadata: dict[str, Any] = field(default_factory=dict)


class JsonEventLogger:
    def __init__(self, log_dir: Path | None = None) -> None:
        self.log_dir = log_dir or (Path.home() / ".securelink" / "logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def log(self, event: SecurityEvent) -> Path:
        log_path = self.log_dir / f"{date.today().isoformat()}.json"
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(event), sort_keys=True) + "\n")
        return log_path


class PacketCapture:
    def __init__(
        self,
        *,
        port: int = DEFAULT_PORT,
        logger: JsonEventLogger | None = None,
        allowlist: tuple[str, ...] = (),
        vlan_engine: VlanPolicyEngine | None = None,
    ) -> None:
        self.port = port
        self.logger = logger or JsonEventLogger()
        self.allowlist = allowlist
        self.vlan_engine = vlan_engine or VlanPolicyEngine()
        self.arp_guard = ArpGuard()
        self.ttl_guard = TtlGuard()
        self._thread: threading.Thread | None = None
        self._stop_requested = threading.Event()

    def _packet_to_event(
        self,
        packet: Any,
        *,
        event: str = "transfer",
        chunk_id: int | None = None,
        encrypted: bool = True,
        hmac_valid: bool = True,
        message: str = "packet captured",
    ) -> SecurityEvent:
        src_ip = None
        dst_ip = None
        ttl = None
        vlan_id = None
        bytes_count = len(bytes(packet)) if packet is not None else 0

        if IP is not None and packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            ttl = int(ip_layer.ttl)

        if Dot1Q is not None and packet.haslayer(Dot1Q):
            vlan_id = int(packet[Dot1Q].vlan)

        alert = not hmac_valid
        if self.allowlist and src_ip is not None:
            alert = alert or not self._source_allowed(src_ip)

        return SecurityEvent(
            timestamp=datetime.now(UTC).isoformat(),
            event=event,
            src_ip=src_ip,
            dst_ip=dst_ip,
            vlan_id=vlan_id,
            bytes=bytes_count,
            chunk_id=chunk_id,
            encrypted=encrypted,
            hmac_valid=hmac_valid,
            ttl=ttl,
            alert=alert,
            message=message,
            metadata={},
        )

    def _source_allowed(self, src_ip: str) -> bool:
        if not self.allowlist:
            return True
        try:
            import ipaddress

            source = ipaddress.ip_address(src_ip)
            for entry in self.allowlist:
                if source in ipaddress.ip_network(entry, strict=False):
                    return True
        except Exception:
            return False
        return False

    def handle_packet(self, packet: Any) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []

        arp_observation = self.arp_guard.inspect_packet(packet)
        if arp_observation is not None:
            events.append(
                SecurityEvent(
                    timestamp=arp_observation.timestamp,
                    event="arp_spoof" if arp_observation.alert else "transfer",
                    src_ip=arp_observation.ip_address,
                    dst_ip=None,
                    vlan_id=None,
                    bytes=len(bytes(packet)),
                    chunk_id=None,
                    encrypted=False,
                    hmac_valid=True,
                    ttl=None,
                    alert=arp_observation.alert,
                    message=arp_observation.message,
                    metadata=arp_observation.metadata,
                )
            )

        ttl_observation = self.ttl_guard.inspect_packet(packet)
        if ttl_observation is not None:
            events.append(
                SecurityEvent(
                    timestamp=ttl_observation.timestamp,
                    event="ttl_anomaly" if ttl_observation.alert else "transfer",
                    src_ip=ttl_observation.peer_ip,
                    dst_ip=None,
                    vlan_id=None,
                    bytes=len(bytes(packet)),
                    chunk_id=None,
                    encrypted=False,
                    hmac_valid=True,
                    ttl=ttl_observation.ttl,
                    alert=ttl_observation.alert,
                    message=ttl_observation.message,
                    metadata=ttl_observation.metadata,
                )
            )

        vlan_observation = self.vlan_engine.inspect_packet(packet)
        if vlan_observation is not None:
            events.append(
                SecurityEvent(
                    timestamp=vlan_observation.timestamp,
                    event="vlan_violation" if vlan_observation.alert else "transfer",
                    src_ip=None,
                    dst_ip=None,
                    vlan_id=vlan_observation.src_vlan,
                    bytes=len(bytes(packet)),
                    chunk_id=None,
                    encrypted=False,
                    hmac_valid=True,
                    ttl=None,
                    alert=vlan_observation.alert,
                    message=vlan_observation.message,
                    metadata=vlan_observation.metadata,
                )
            )

        events.append(self._packet_to_event(packet))
        for event in events:
            self.logger.log(event)
        return events

    def start(self) -> None:
        if sniff is None:
            raise RuntimeError("scapy is required for packet capture")
        if self._thread and self._thread.is_alive():
            return

        def _runner() -> None:
            sniff(
                filter=f"tcp port {self.port}",
                prn=self.handle_packet,
                store=False,
                stop_filter=lambda _: self._stop_requested.is_set(),
            )

        self._stop_requested.clear()
        self._thread = threading.Thread(target=_runner, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_requested.set()
