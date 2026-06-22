from __future__ import annotations

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PeerAdvertisement:
    name: str
    address: str
    port: int
    vlan_id: int | None = None
    fingerprint: str | None = None
    trusted: bool = False
    source: str = "mdns"
    metadata: dict[str, Any] = field(default_factory=dict)


def announce_peer(
    *,
    name: str,
    port: int,
    vlan_id: int | None = None,
    service_type: str = "_securelink._tcp.local.",
    properties: dict[str, str] | None = None,
) -> tuple[Any, Any]:
    try:
        from zeroconf import ServiceInfo, Zeroconf
    except ImportError as exc:
        raise RuntimeError("zeroconf is required for LAN discovery") from exc

    zc = Zeroconf()
    info = ServiceInfo(
        service_type,
        f"{name}.{service_type}",
        addresses=[socket.inet_aton(socket.gethostbyname(socket.gethostname()))],
        port=port,
        properties={
            **(properties or {}),
            **({"vlan_id": str(vlan_id)} if vlan_id is not None else {}),
        },
    )
    zc.register_service(info)
    return zc, info


def discover_peers(timeout: float = 2.5, service_type: str = "_securelink._tcp.local.") -> list[PeerAdvertisement]:
    try:
        from zeroconf import ServiceBrowser, Zeroconf
    except ImportError as exc:
        raise RuntimeError("zeroconf is required for LAN discovery") from exc

    peers: list[PeerAdvertisement] = []
    peers_lock = threading.Lock()

    class Listener:
        def add_service(self, zeroconf: Any, service_type: str, name: str) -> None:
            info = zeroconf.get_service_info(service_type, name)
            if info is None:
                return
            address = ""
            if info.addresses:
                address = str(ipaddress.ip_address(info.addresses[0]))
            vlan_id = None
            if info.properties.get(b"vlan_id"):
                try:
                    vlan_id = int(info.properties[b"vlan_id"].decode("utf-8"))
                except Exception:
                    vlan_id = None
            with peers_lock:
                peers.append(
                    PeerAdvertisement(
                        name=name,
                        address=address,
                        port=info.port,
                        vlan_id=vlan_id,
                        metadata={
                            key.decode("utf-8"): value.decode("utf-8")
                            for key, value in info.properties.items()
                        },
                    )
                )

        def remove_service(self, zeroconf: Any, service_type: str, name: str) -> None:
            pass

        def update_service(self, zeroconf: Any, service_type: str, name: str) -> None:
            pass

    zc = Zeroconf()
    browser = ServiceBrowser(zc, service_type, Listener())
    try:
        time.sleep(timeout)
    finally:
        browser.cancel()
        zc.close()
    return peers


def auto_select_transport_mode(
    *,
    vlan_id: int | None = None,
    peer_address: str | None = None,
) -> str:
    if vlan_id is not None:
        return "vlan"
    if peer_address:
        try:
            ip = ipaddress.ip_address(peer_address)
        except ValueError:
            return "lan"  # a hostname is assumed to be local/LAN
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            return "wan"  # a public address routes over the WAN transport
    return "lan"
