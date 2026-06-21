from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

try:
    from scapy.layers.inet import IP
except ImportError:  # pragma: no cover - optional dependency
    IP = None


@dataclass(frozen=True)
class TtlObservation:
    timestamp: str
    peer_ip: str
    ttl: int
    alert: bool
    message: str
    metadata: dict[str, Any]


class TtlGuard:
    def __init__(self, tolerance: int = 2) -> None:
        self.tolerance = tolerance
        self._baseline_ttls: dict[str, int] = {}

    def inspect_packet(self, packet: Any) -> TtlObservation | None:
        if IP is None or not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        peer_ip = str(ip_layer.src)
        ttl = int(ip_layer.ttl)
        timestamp = datetime.now(UTC).isoformat()

        if peer_ip not in self._baseline_ttls:
            self._baseline_ttls[peer_ip] = ttl
            return TtlObservation(
                timestamp=timestamp,
                peer_ip=peer_ip,
                ttl=ttl,
                alert=False,
                message="baseline TTL recorded",
                metadata={"baseline": ttl},
            )

        baseline_ttl = self._baseline_ttls[peer_ip]
        ttl_drop = baseline_ttl - ttl
        alert = ttl_drop > self.tolerance
        message = "TTL dropped by more than the configured tolerance" if alert else "ttl within tolerance"
        return TtlObservation(
            timestamp=timestamp,
            peer_ip=peer_ip,
            ttl=ttl,
            alert=alert,
            message=message,
            metadata={"baseline": baseline_ttl, "drop": ttl_drop},
        )
