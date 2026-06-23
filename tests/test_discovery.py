from __future__ import annotations

from core import discovery
from core.discovery import (
    LocalAddress,
    auto_select_transport_mode,
    classify_address,
    is_vpn_address,
    local_reachable_addresses,
    tailscale_peers,
)


def test_vlan_id_takes_precedence_over_address() -> None:
    assert auto_select_transport_mode(vlan_id=30, peer_address="8.8.8.8") == "vlan"


def test_private_and_loopback_addresses_select_lan() -> None:
    assert auto_select_transport_mode(peer_address="192.168.1.10") == "lan"
    assert auto_select_transport_mode(peer_address="10.0.0.5") == "lan"
    assert auto_select_transport_mode(peer_address="127.0.0.1") == "lan"


def test_public_addresses_select_wan() -> None:
    assert auto_select_transport_mode(peer_address="8.8.8.8") == "wan"
    assert auto_select_transport_mode(peer_address="1.1.1.1") == "wan"


def test_hostnames_and_missing_address_default_to_lan() -> None:
    assert auto_select_transport_mode(peer_address="fileserver.local") == "lan"
    assert auto_select_transport_mode() == "lan"


def test_cgnat_addresses_select_vpn() -> None:
    # Tailscale's 100.64.0.0/10 range routes over the VPN (direct TCP), not WAN.
    assert auto_select_transport_mode(peer_address="100.64.0.1") == "vpn"
    assert auto_select_transport_mode(peer_address="100.101.22.7") == "vpn"
    # ...but a VLAN id still wins.
    assert auto_select_transport_mode(vlan_id=5, peer_address="100.64.0.1") == "vlan"


def test_classify_address_buckets() -> None:
    assert classify_address("100.64.0.1") == "vpn"
    assert classify_address("192.168.1.5") == "lan"
    assert classify_address("10.0.0.1") == "lan"
    assert classify_address("8.8.8.8") == "public"
    assert classify_address("127.0.0.1") == "loopback"
    assert classify_address("169.254.1.1") == "link-local"
    assert classify_address("fe80::1") == "link-local"


def test_is_vpn_address() -> None:
    assert is_vpn_address("100.100.1.1") is True
    assert is_vpn_address("192.168.0.1") is False
    assert is_vpn_address("not-an-ip") is False


def test_local_reachable_addresses_excludes_loopback_and_classifies() -> None:
    addresses = local_reachable_addresses(probe_tailscale=False)
    assert isinstance(addresses, list)
    assert all(isinstance(a, LocalAddress) for a in addresses)
    # Only shareable kinds; loopback and link-local are filtered out.
    assert all(a.kind in {"lan", "vpn", "public"} for a in addresses)
    assert all(not a.address.startswith("127.") for a in addresses)
    assert all(not a.address.lower().startswith("fe80") for a in addresses)


def test_local_reachable_addresses_can_include_loopback() -> None:
    addresses = local_reachable_addresses(include_loopback=True, probe_tailscale=False)
    # getaddrinfo on the hostname may or may not surface loopback, but if any
    # loopback address shows up it must be classified as such.
    assert all(
        a.kind == "loopback"
        for a in addresses
        if a.address.startswith("127.") or a.address == "::1"
    )


_FAKE_STATUS = {
    "Self": {"TailscaleIPs": ["100.64.0.10", "fd7a:115c:a1e0::a"]},
    "Peer": {
        "nodekey:aaa": {
            "HostName": "laptop",
            "TailscaleIPs": ["100.101.0.5", "fd7a::5"],
            "OS": "windows",
            "Online": True,
        },
        "nodekey:bbb": {
            "HostName": "phone.",
            "TailscaleIPs": ["100.102.0.6"],
            "OS": "android",
            "Online": False,
        },
        "nodekey:ccc": {"HostName": "noip"},  # no TailscaleIPs -> skipped
    },
}


def test_tailscale_peers_parsing_and_ordering() -> None:
    peers = tailscale_peers(port=55001, status=_FAKE_STATUS)
    assert [p.name for p in peers] == ["laptop", "phone"]  # online first; "." stripped
    laptop = peers[0]
    assert laptop.address == "100.101.0.5"  # IPv4 preferred over IPv6
    assert laptop.port == 55001
    assert laptop.source == "tailscale"
    assert laptop.metadata["online"] == "true"
    assert laptop.metadata["os"] == "windows"
    assert peers[1].metadata["online"] == "false"


def test_tailscale_peers_empty_without_cli(monkeypatch) -> None:
    monkeypatch.setattr(discovery.shutil, "which", lambda _name: None)
    assert tailscale_peers() == []
    assert discovery.tailscale_status() is None
    assert discovery._tailscale_self_addresses() == []


def test_tailscale_self_addresses_from_status() -> None:
    assert discovery._tailscale_self_addresses(status=_FAKE_STATUS) == [
        "100.64.0.10",
        "fd7a:115c:a1e0::a",
    ]
