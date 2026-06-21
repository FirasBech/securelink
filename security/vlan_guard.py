from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    from scapy.layers.l2 import Dot1Q
except ImportError:  # pragma: no cover - optional dependency
    Dot1Q = None


DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "vlan_policy.json"


@dataclass(frozen=True)
class VlanObservation:
    timestamp: str
    src_vlan: int | None
    dst_vlan: int | None
    tags: list[int]
    trunk_port: bool
    allowed: bool
    alert: bool
    message: str
    metadata: dict[str, Any] = field(default_factory=dict)


class VlanPolicyEngine:
    def __init__(self, policy: dict[int, list[int]] | None = None, policy_path: Path | None = None) -> None:
        self.policy_path = policy_path or DEFAULT_POLICY_PATH
        self.policy = policy or self._load_policy()

    def _load_policy(self) -> dict[int, list[int]]:
        if not self.policy_path.exists():
            return {}
        try:
            raw = json.loads(self.policy_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        policy: dict[int, list[int]] = {}
        for key, value in raw.items():
            try:
                src_vlan = int(key)
                policy[src_vlan] = [int(item) for item in value]
            except Exception:
                continue
        return policy

    def is_allowed(self, src_vlan: int | None, dst_vlan: int | None) -> bool:
        if src_vlan is None or dst_vlan is None:
            return False
        if src_vlan not in self.policy:
            return False
        return dst_vlan in self.policy[src_vlan]

    def extract_vlan_tags(self, packet: Any) -> list[int]:
        if Dot1Q is None or not packet.haslayer(Dot1Q):
            return []

        tags: list[int] = []
        layer = packet.getlayer(Dot1Q)
        while layer is not None:
            try:
                tags.append(int(layer.vlan))
            except Exception:
                break
            next_layer = getattr(layer, "payload", None)
            if next_layer is None:
                break
            if hasattr(next_layer, "vlan"):
                layer = next_layer
                continue
            layer = next_layer.getlayer(Dot1Q) if hasattr(next_layer, "getlayer") else None
        return tags

    def inspect_packet(self, packet: Any, dst_vlan: int | None = None) -> VlanObservation:
        tags = self.extract_vlan_tags(packet)
        src_vlan = tags[0] if tags else None
        trunk_port = len(tags) > 1
        allowed = self.is_allowed(src_vlan, dst_vlan) if dst_vlan is not None else True
        alert = not allowed and src_vlan is not None and dst_vlan is not None
        message = "vlan policy violation" if alert else ("trunk port detected" if trunk_port else "vlan observed")
        return VlanObservation(
            timestamp=datetime.now(UTC).isoformat(),
            src_vlan=src_vlan,
            dst_vlan=dst_vlan,
            tags=tags,
            trunk_port=trunk_port,
            allowed=allowed,
            alert=alert,
            message=message,
            metadata={"policy_path": str(self.policy_path)},
        )

    def validate_transfer(self, src_vlan: int | None, dst_vlan: int | None) -> VlanObservation:
        allowed = self.is_allowed(src_vlan, dst_vlan)
        alert = not allowed
        return VlanObservation(
            timestamp=datetime.now(UTC).isoformat(),
            src_vlan=src_vlan,
            dst_vlan=dst_vlan,
            tags=[value for value in (src_vlan, dst_vlan) if value is not None],
            trunk_port=False,
            allowed=allowed,
            alert=alert,
            message="vlan policy violation" if alert else "transfer allowed",
            metadata={"policy_path": str(self.policy_path)},
        )
