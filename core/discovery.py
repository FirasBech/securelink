from __future__ import annotations

import ipaddress
import json
import os
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any

# RFC 6598 shared address space. Tailscale hands out addresses from this range,
# so a peer here is reached over a VPN-style virtual link, not the open WAN.
CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")
DEFAULT_PEER_PORT = 55000


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


@dataclass(frozen=True)
class LocalAddress:
    address: str
    kind: str  # "lan" | "vpn" | "public" | "loopback" | "link-local"


@dataclass(frozen=True)
class TailscaleState:
    installed: bool          # the `tailscale` CLI is on PATH
    running: bool            # BackendState == "Running"
    logged_in: bool          # signed in to a tailnet (creds present)
    backend_state: str       # raw BackendState, e.g. "Running" / "NeedsLogin" / "Stopped"
    self_ip: str | None      # this host's tailnet IPv4, if any

    def summary(self) -> str:
        """A short, user-facing description of what (if anything) to do."""
        if not self.installed:
            return ""  # Tailscale isn't used here; say nothing
        if not self.running and not self.logged_in and not self.backend_state:
            return "Tailscale is installed but its service isn't running — start Tailscale to use VPN peers."
        if not self.logged_in:
            return "Tailscale is installed but not signed in — run 'tailscale up' to use VPN peers."
        if not self.running:
            return f"Tailscale is signed in but not connected (state: {self.backend_state})."
        return ""  # running and logged in — nothing to nag about


SECURELINK_SERVICE_TYPE = "_securelink._tcp.local."
APP_NAME = "SecureLink"


def _service_instance_label(value: str) -> str:
    """Make a hostname safe as an mDNS instance label (dots split labels)."""

    cleaned = " ".join(str(value).replace(".", "-").split())
    return cleaned or APP_NAME


def _advertised_addresses() -> list[bytes]:
    """Packed IPv4 addresses to publish, best (route-selected) first.

    mDNS must tell peers which address to dial. ``local_reachable_addresses``
    gives the address the OS would actually use for outbound traffic, so it goes
    first; ``ifaddr`` (already a zeroconf dependency) adds any other NICs so
    multi-homed machines are reachable on each network.
    """

    addresses: list[bytes] = []
    seen: set[bytes] = set()

    def push(raw: str) -> None:
        try:
            packed = socket.inet_aton(raw)
        except OSError:
            return
        if packed not in seen:
            seen.add(packed)
            addresses.append(packed)

    for item in local_reachable_addresses(include_loopback=False, probe_tailscale=False):
        push(item.address)

    try:
        import ifaddr  # transitively required by zeroconf

        for adapter in ifaddr.get_adapters():
            for ip in adapter.ips:
                if isinstance(ip.ip, str) and ":" not in ip.ip:
                    push(ip.ip)
    except Exception:
        pass

    if not addresses:
        try:
            push(socket.gethostbyname(socket.gethostname()))
        except OSError:
            pass
    return addresses


def _preferred_address(addresses: list[str]) -> str:
    """Pick the address most likely to be reachable by a LAN peer."""

    def rank(address: str) -> int:
        try:
            kind = classify_address(address)
        except ValueError:
            return 9
        return {"lan": 0, "vpn": 1, "public": 2}.get(kind, 8)

    ipv4 = [address for address in addresses if ":" not in address]
    return min(ipv4 or addresses, key=rank) if addresses else ""


class PeerAdvertiser:
    """Advertise this host as a SecureLink peer over mDNS while the app runs.

    Being registered is what makes one SecureLink installation appear in another
    installation's peer list: discovery is service-based, so the other machine
    must also be running SecureLink. Start/stop are safe to call from a worker
    thread and repeated calls are idempotent.
    """

    def __init__(
        self,
        *,
        port: int,
        name: str | None = None,
        service_type: str = SECURELINK_SERVICE_TYPE,
        properties: dict[str, str] | None = None,
    ) -> None:
        self.port = int(port)
        self.name = name or socket.gethostname() or APP_NAME
        self.service_type = service_type
        self.properties = dict(properties or {})
        self._zeroconf: Any = None
        self._info: Any = None
        self._instance_name: str | None = None
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._zeroconf is not None

    @property
    def instance_name(self) -> str | None:
        return self._instance_name

    @property
    def zeroconf(self) -> Any:
        return self._zeroconf

    @property
    def info(self) -> Any:
        return self._info

    def _build_info(self, service_info_type: Any, instance: str) -> Any:
        properties = {
            "app": APP_NAME,
            "name": self.name,
            "host": socket.gethostname(),
            "version": "2",
            **self.properties,
        }
        return service_info_type(
            self.service_type,
            f"{instance}.{self.service_type}",
            addresses=_advertised_addresses(),
            port=self.port,
            properties={key: str(value) for key, value in properties.items()},
        )

    def start(self) -> None:
        from zeroconf import ServiceInfo, Zeroconf

        with self._lock:
            if self._zeroconf is not None:
                return
            zc = Zeroconf()
            instance = _service_instance_label(self.name)
            info = self._build_info(ServiceInfo, instance)
            try:
                zc.register_service(info)
            except Exception:
                # Usually a duplicate instance name (another SecureLink on this
                # host). Retry once with a suffix; a real failure re-raises.
                instance = f"{instance}-{os.urandom(2).hex()}"
                info = self._build_info(ServiceInfo, instance)
                try:
                    zc.register_service(info)
                except Exception:
                    zc.close()
                    raise
            self._zeroconf = zc
            self._info = info
            self._instance_name = instance

    def update_port(self, port: int) -> None:
        """Re-register with a new receive port (no-op when unchanged)."""

        new_port = int(port)
        if new_port == self.port:
            return
        was_running = self.running
        self.stop()
        self.port = new_port
        if was_running:
            self.start()

    def update_interfaces(self) -> None:
        """Ask zeroconf to rescan NICs (call after a network change)."""

        zc = self._zeroconf
        if zc is None:
            return
        try:
            zc.update_interfaces()
        except Exception:
            pass

    def stop(self) -> None:
        with self._lock:
            zc, info = self._zeroconf, self._info
            self._zeroconf = None
            self._info = None
            self._instance_name = None
            if zc is None:
                return
            if info is not None:
                try:
                    zc.unregister_service(info)
                except Exception:
                    pass
            try:
                zc.close()
            except Exception:
                pass


def announce_peer(
    *,
    name: str,
    port: int,
    vlan_id: int | None = None,
    service_type: str = SECURELINK_SERVICE_TYPE,
    properties: dict[str, str] | None = None,
) -> tuple[Any, Any]:
    """Register a SecureLink service and return ``(zeroconf, service_info)``.

    Kept for callers that want to manage the registration themselves; the
    dashboard uses :class:`PeerAdvertiser` for its start/stop lifecycle.
    """

    advertiser = PeerAdvertiser(
        port=port,
        name=name,
        service_type=service_type,
        properties={
            **(properties or {}),
            **({"vlan_id": str(vlan_id)} if vlan_id is not None else {}),
        },
    )
    advertiser.start()
    return advertiser.zeroconf, advertiser.info


def _decode_properties(info: Any) -> dict[str, str]:
    properties: dict[str, str] = {}
    for key, value in (info.properties or {}).items():
        try:
            decoded_key = key.decode("utf-8") if isinstance(key, bytes) else str(key)
            decoded_value = (
                value.decode("utf-8")
                if isinstance(value, bytes)
                else ("" if value is None else str(value))
            )
        except UnicodeDecodeError:
            continue
        properties[decoded_key] = decoded_value
    return properties


def discover_peers(timeout: float = 2.5, service_type: str = SECURELINK_SERVICE_TYPE) -> list[PeerAdvertisement]:
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
            addresses = [str(ipaddress.ip_address(raw)) for raw in info.addresses]
            address = _preferred_address(addresses)
            properties = _decode_properties(info)
            display_name = (
                properties.get("name")
                or properties.get("host")
                or info.server.rstrip(".").split(".")[0]
                or name.split(".")[0]
            )
            vlan_id = None
            if properties.get("vlan_id"):
                try:
                    vlan_id = int(properties["vlan_id"])
                except ValueError:
                    vlan_id = None
            with peers_lock:
                peers.append(
                    PeerAdvertisement(
                        name=display_name,
                        address=address,
                        port=info.port,
                        vlan_id=vlan_id,
                        source="mdns",
                        metadata={
                            **properties,
                            "addresses": " ".join(addresses),
                            "instance": name,
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

    deduped: dict[tuple[str, int], PeerAdvertisement] = {}
    for peer in peers:
        deduped.setdefault((peer.address, peer.port), peer)
    return sorted(deduped.values(), key=lambda peer: (peer.name.lower(), peer.address))



def classify_address(address: str) -> str:
    """Bucket an IP into lan / vpn / public / loopback / link-local.

    Raises ValueError on a non-IP string. Link-local (``fe80::``, ``169.254.x``)
    is split out because it can't be handed to a remote peer as-is.
    """
    ip = ipaddress.ip_address(address)
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.version == 4 and ip in CGNAT_NETWORK:
        return "vpn"
    if ip.is_private:
        return "lan"
    return "public"


def is_vpn_address(address: str) -> bool:
    """True for a Tailscale/CGNAT peer address (best-effort; False for hostnames)."""
    try:
        return classify_address(address) == "vpn"
    except ValueError:
        return False


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
        if ip.version == 4 and ip in CGNAT_NETWORK:
            return "vpn"  # a Tailscale/CGNAT peer: a stable virtual link, use direct TCP
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            return "wan"  # a public address routes over the WAN transport
    return "lan"


def local_reachable_addresses(
    *,
    include_loopback: bool = False,
    probe_tailscale: bool = True,
) -> list[LocalAddress]:
    """Best-effort list of this host's reachable IPs, classified and ordered.

    Dependency-free: it combines the source address the OS picks for an outbound
    route with the hostname's resolved addresses, plus any Tailscale self IPs
    when the CLI is present. Useful for telling a sender which address to use.
    Ordered VPN first, then LAN, then public.
    """
    found: dict[str, None] = {}

    for family, probe in (
        (socket.AF_INET, ("8.8.8.8", 80)),
        (socket.AF_INET6, ("2001:4860:4860::8888", 80)),
    ):
        sock = None
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.connect(probe)  # no packets sent for UDP; just selects a route
            found.setdefault(sock.getsockname()[0], None)
        except OSError:
            pass
        finally:
            if sock is not None:
                sock.close()

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.setdefault(info[4][0], None)
    except socket.gaierror:
        pass

    if probe_tailscale:
        for addr in _tailscale_self_addresses():
            found.setdefault(addr, None)

    results: list[LocalAddress] = []
    for raw in found:
        address = raw.split("%", 1)[0]  # strip IPv6 scope id (e.g. fe80::1%eth0)
        try:
            kind = classify_address(address)
        except ValueError:
            continue
        if kind == "link-local":
            continue  # not usable by a remote peer without a zone id
        if kind == "loopback" and not include_loopback:
            continue
        results.append(LocalAddress(address=address, kind=kind))

    order = {"vpn": 0, "lan": 1, "public": 2, "loopback": 3}
    results.sort(key=lambda item: (order.get(item.kind, 9), item.address))
    return results


def tailscale_status(timeout: float = 2.0) -> dict[str, Any] | None:
    """Parsed ``tailscale status --json``, or None if the CLI is absent/failing.

    The JSON is parsed even when the CLI exits non-zero (it does that when logged
    out, while still printing a status document with ``BackendState`` set), so
    callers can tell "not signed in" apart from "not installed".
    """
    executable = shutil.which("tailscale")
    if executable is None:
        return None
    try:
        completed = subprocess.run(
            [executable, "status", "--json"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = completed.stdout.strip()
    if not output:
        return None
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def tailscale_state(status: dict[str, Any] | None = None) -> TailscaleState:
    """Report whether Tailscale is installed, running, and signed in.

    Each user signs in to their own tailnet (``tailscale up``); SecureLink can't
    do that for them, so this lets the UI nudge them when credentials are missing.
    """
    installed = shutil.which("tailscale") is not None
    if not installed:
        return TailscaleState(False, False, False, "", None)
    data = status if status is not None else tailscale_status()
    if not data:
        # CLI present but no parseable status (daemon stopped, perms, etc.).
        return TailscaleState(True, False, False, "", None)
    backend = str(data.get("BackendState") or "")
    self_ip = _first_ipv4(_tailscale_self_addresses(data))
    running = backend == "Running"
    logged_in = backend not in {"", "NeedsLogin", "NoState", "NoTailnet"}
    return TailscaleState(True, running, logged_in, backend, self_ip)


def _first_ipv4(addresses: list[str]) -> str | None:
    for addr in addresses:
        if ":" not in addr:
            return addr
    return addresses[0] if addresses else None


def _tailscale_self_addresses(status: dict[str, Any] | None = None) -> list[str]:
    data = status if status is not None else tailscale_status()
    if not data:
        return []
    self_node = data.get("Self")
    if not isinstance(self_node, dict):
        return []
    return [str(ip) for ip in (self_node.get("TailscaleIPs") or [])]


def tailscale_peers(
    *,
    port: int = DEFAULT_PEER_PORT,
    status: dict[str, Any] | None = None,
) -> list[PeerAdvertisement]:
    """Tailnet peers as advertisements (``source="tailscale"``).

    Tailscale can't know whether a peer runs SecureLink or on which port, so the
    SecureLink ``port`` is assumed (default 55000) and can be overridden by the
    caller. Online peers are listed first. Empty when Tailscale is unavailable.
    """
    data = status if status is not None else tailscale_status()
    if not data:
        return []
    raw_peers = data.get("Peer")
    if not isinstance(raw_peers, dict):
        return []

    peers: list[PeerAdvertisement] = []
    for node in raw_peers.values():
        if not isinstance(node, dict):
            continue
        address = _first_ipv4([str(ip) for ip in (node.get("TailscaleIPs") or [])])
        if not address:
            continue
        name = str(node.get("HostName") or node.get("DNSName") or address).rstrip(".")
        peers.append(
            PeerAdvertisement(
                name=name,
                address=address,
                port=port,
                source="tailscale",
                metadata={
                    "online": "true" if node.get("Online") else "false",
                    "os": str(node.get("OS") or ""),
                },
            )
        )

    peers.sort(key=lambda peer: (peer.metadata.get("online") != "true", peer.name.lower()))
    return peers
