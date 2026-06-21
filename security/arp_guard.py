from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

try:
    from scapy.layers.l2 import ARP
except ImportError:  # pragma: no cover - optional dependency
    ARP = None


@dataclass(frozen=True)
class ArpObservation:
    timestamp: str
    ip_address: str
    mac_address: str
    previous_mac: str | None
    alert: bool
    message: str
    metadata: dict[str, Any]


class ArpGuard:
    def __init__(self) -> None:
        self._baseline: dict[str, str] = {}

    def set_baseline(self, mappings: dict[str, str]) -> None:
        self._baseline.update(mappings)

    def snapshot(self, ip_address: str, mac_address: str) -> None:
        self._baseline[ip_address] = mac_address

    def inspect_packet(self, packet: Any) -> ArpObservation | None:
        if ARP is None or not packet.haslayer(ARP):
            return None

        arp_layer = packet[ARP]
        if int(arp_layer.op) != 2:
            return None

        timestamp = datetime.now(UTC).isoformat()
        ip_address = str(arp_layer.psrc)
        mac_address = str(arp_layer.hwsrc)
        previous_mac = self._baseline.get(ip_address)
        alert = previous_mac is not None and previous_mac.lower() != mac_address.lower()
        message = "arp mapping changed" if alert else "arp reply recorded"

        if previous_mac is None:
            self._baseline[ip_address] = mac_address

        return ArpObservation(
            timestamp=timestamp,
            ip_address=ip_address,
            mac_address=mac_address,
            previous_mac=previous_mac,
            alert=alert,
            message=message,
            metadata={"operation": int(arp_layer.op)},
        )
