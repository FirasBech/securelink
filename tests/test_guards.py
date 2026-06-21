from __future__ import annotations

from types import SimpleNamespace

import security.arp_guard as arp_guard_module
import security.ttl_guard as ttl_guard_module
import security.vlan_guard as vlan_guard_module
from security.arp_guard import ArpGuard
from security.ttl_guard import TtlGuard
from security.vlan_guard import VlanPolicyEngine


class FakePacket:
    def __init__(self, layers):
        self.layers = layers

    def haslayer(self, layer):
        return layer in self.layers

    def __getitem__(self, layer):
        return self.layers[layer]

    def getlayer(self, layer):
        return self.layers.get(layer)

    def __bytes__(self):
        return b"packet"


class FakeVlanLayer:
    def __init__(self, vlan, payload=None):
        self.vlan = vlan
        self.payload = payload

    def getlayer(self, layer):
        if layer is vlan_guard_module.Dot1Q:
            return self.payload
        return None


class FakeIpLayer:
    def __init__(self, src, dst, ttl):
        self.src = src
        self.dst = dst
        self.ttl = ttl


class FakeArpLayer:
    def __init__(self, op, psrc, hwsrc):
        self.op = op
        self.psrc = psrc
        self.hwsrc = hwsrc


def test_ttl_guard_detects_drop(monkeypatch) -> None:
    sentinel = object()
    monkeypatch.setattr(ttl_guard_module, "IP", sentinel)
    guard = TtlGuard(tolerance=2)

    baseline_packet = FakePacket({sentinel: FakeIpLayer("10.0.0.2", "10.0.0.1", 64)})
    assert guard.inspect_packet(baseline_packet).alert is False

    suspicious_packet = FakePacket({sentinel: FakeIpLayer("10.0.0.2", "10.0.0.1", 60)})
    observation = guard.inspect_packet(suspicious_packet)
    assert observation is not None
    assert observation.alert is True


def test_arp_guard_flags_changed_mapping(monkeypatch) -> None:
    sentinel = object()
    monkeypatch.setattr(arp_guard_module, "ARP", sentinel)
    guard = ArpGuard()
    guard.set_baseline({"10.0.0.1": "aa:bb:cc:dd:ee:ff"})

    packet = FakePacket({sentinel: FakeArpLayer(2, "10.0.0.1", "11:22:33:44:55:66")})
    observation = guard.inspect_packet(packet)
    assert observation is not None
    assert observation.alert is True
    assert observation.previous_mac == "aa:bb:cc:dd:ee:ff"


def test_vlan_policy_engine_enforces_allowlist(tmp_path, monkeypatch) -> None:
    policy_path = tmp_path / "vlan_policy.json"
    policy_path.write_text('{"10": [20]}', encoding="utf-8")
    monkeypatch.setattr(vlan_guard_module, "DEFAULT_POLICY_PATH", policy_path)
    monkeypatch.setattr(vlan_guard_module, "Dot1Q", object())
    engine = VlanPolicyEngine()

    allowed = engine.validate_transfer(10, 20)
    denied = engine.validate_transfer(10, 30)
    assert allowed.allowed is True
    assert denied.alert is True

    inner = FakeVlanLayer(20)
    outer = FakeVlanLayer(10, payload=inner)
    packet = FakePacket({vlan_guard_module.Dot1Q: outer})
    tags = engine.extract_vlan_tags(packet)
    assert tags == [10, 20]
