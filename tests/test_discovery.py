from __future__ import annotations

from core.discovery import auto_select_transport_mode


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
