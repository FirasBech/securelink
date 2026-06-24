from __future__ import annotations

import socket
import threading

from core import nat
from core.nat import (
    PeerEndpoint,
    RelayServer,
    RendezvousServer,
    detect_nat_mapping,
    relay_connect,
    rendezvous_exchange,
    udp_hole_punch,
    wan_connect,
)
from core.stun import MappedAddress, StunError
from core.udp_transport import ReliableUdpChannel


def test_rendezvous_exchange_swaps_endpoints() -> None:
    server = RendezvousServer(host="127.0.0.1")
    server.start()
    try:
        results: dict[str, PeerEndpoint] = {}
        errors: list[BaseException] = []

        def peer(name: str, advertise: PeerEndpoint) -> None:
            try:
                results[name] = rendezvous_exchange(server.address, "room", advertise, timeout=5)
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        ep_a = PeerEndpoint("203.0.113.1", 40001)
        ep_b = PeerEndpoint("198.51.100.2", 40002)
        ta = threading.Thread(target=peer, args=("A", ep_a))
        tb = threading.Thread(target=peer, args=("B", ep_b))
        ta.start()
        tb.start()
        ta.join(5)
        tb.join(5)

        assert not errors, f"rendezvous failed: {errors!r}"
        # Each peer receives the *other's* advertised endpoint.
        assert results["A"] == ep_b
        assert results["B"] == ep_a
    finally:
        server.stop()


def test_udp_hole_punch_loopback() -> None:
    sock_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock_a.bind(("127.0.0.1", 0))
        sock_b.bind(("127.0.0.1", 0))
        addr_a = sock_a.getsockname()
        addr_b = sock_b.getsockname()

        errors: list[BaseException] = []

        def punch(sock: socket.socket, peer: tuple[str, int]) -> None:
            try:
                udp_hole_punch(sock, peer, timeout=5, interval=0.1)
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        ta = threading.Thread(target=punch, args=(sock_a, addr_b))
        tb = threading.Thread(target=punch, args=(sock_b, addr_a))
        ta.start()
        tb.start()
        ta.join(8)
        tb.join(8)

        assert not ta.is_alive() and not tb.is_alive(), "hole punch did not finish"
        assert not errors, f"hole punch failed: {errors!r}"
    finally:
        sock_a.close()
        sock_b.close()


def _fake_stun(mapping: dict[tuple[str, int], MappedAddress | None]):
    """Return a discover_public_endpoint stand-in keyed by (host, port)."""

    def fake(host, port, *, local_socket=None, timeout=3.0, retries=3):
        result = mapping.get((host, port))
        if result is None:
            raise StunError("no response")
        return result

    return fake


def test_detect_nat_endpoint_independent(monkeypatch) -> None:
    # Both servers report the same public ip:port -> cone NAT, punchable.
    servers = (("a", 1), ("b", 2))
    monkeypatch.setattr(nat, "_primary_local_ipv4", lambda: "192.168.1.50")
    monkeypatch.setattr(
        nat,
        "discover_public_endpoint",
        _fake_stun(
            {
                ("a", 1): MappedAddress("203.0.113.9", 50000),
                ("b", 2): MappedAddress("203.0.113.9", 50000),
            }
        ),
    )
    result = detect_nat_mapping(servers)
    assert result.mapping == "endpoint_independent"
    assert result.hole_punch_likely is True
    assert result.reflexive == PeerEndpoint("203.0.113.9", 50000)


def test_detect_nat_symmetric(monkeypatch) -> None:
    # Different external port per destination -> symmetric NAT, not punchable.
    servers = (("a", 1), ("b", 2))
    monkeypatch.setattr(nat, "_primary_local_ipv4", lambda: "192.168.1.50")
    monkeypatch.setattr(
        nat,
        "discover_public_endpoint",
        _fake_stun(
            {
                ("a", 1): MappedAddress("203.0.113.9", 50000),
                ("b", 2): MappedAddress("203.0.113.9", 61000),
            }
        ),
    )
    result = detect_nat_mapping(servers)
    assert result.mapping == "endpoint_dependent"
    assert result.hole_punch_likely is False
    assert "VPN" in result.advice


def test_detect_nat_open_internet(monkeypatch) -> None:
    # Reflexive address equals the local address -> no NAT.
    servers = (("a", 1), ("b", 2))
    monkeypatch.setattr(nat, "_primary_local_ipv4", lambda: "203.0.113.9")
    monkeypatch.setattr(
        nat,
        "discover_public_endpoint",
        _fake_stun({("a", 1): MappedAddress("203.0.113.9", 50000)}),
    )
    result = detect_nat_mapping(servers)
    assert result.mapping == "open"
    assert result.hole_punch_likely is True


def test_detect_nat_udp_blocked(monkeypatch) -> None:
    servers = (("a", 1), ("b", 2))
    monkeypatch.setattr(nat, "_primary_local_ipv4", lambda: "192.168.1.50")
    monkeypatch.setattr(nat, "discover_public_endpoint", _fake_stun({}))
    result = detect_nat_mapping(servers)
    assert result.mapping == "udp_blocked"
    assert result.hole_punch_likely is False


def test_relay_pairs_and_forwards_reliable_transfer() -> None:
    relay = RelayServer(host="127.0.0.1")
    relay.start()
    connections: dict[str, tuple[socket.socket, tuple[str, int]]] = {}
    errors: list[BaseException] = []
    try:

        def connect(name: str) -> None:
            try:
                connections[name] = relay_connect(
                    relay.address, "room", bind_host="127.0.0.1", timeout=6
                )
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        ta = threading.Thread(target=connect, args=("A",))
        tb = threading.Thread(target=connect, args=("B",))
        ta.start()
        tb.start()
        ta.join(8)
        tb.join(8)

        assert not errors, f"relay pairing failed: {errors!r}"
        sock_a, peer_a = connections["A"]
        sock_b, peer_b = connections["B"]
        # Both peers talk to the relay's address; it forwards between them.
        assert peer_a == relay.address and peer_b == relay.address

        channel_a = ReliableUdpChannel(sock_a, peer_a)
        channel_b = ReliableUdpChannel(sock_b, peer_b)
        received: dict[str, bytes] = {}

        def receive() -> None:
            received["msg"] = channel_b.recv_frame()

        receiver = threading.Thread(target=receive)
        receiver.start()
        channel_a.send_frame(b"relayed-hello")
        channel_a.flush()
        receiver.join(5)

        assert received.get("msg") == b"relayed-hello"
    finally:
        relay.stop()
        for sock, _ in connections.values():
            sock.close()


def test_wan_connect_falls_back_to_relay_when_punch_fails(monkeypatch) -> None:
    # Force hole punching to fail so wan_connect must use the relay.
    from core import nat

    monkeypatch.setattr(
        nat, "udp_hole_punch", lambda *a, **k: (_ for _ in ()).throw(nat.NatError("blocked"))
    )

    rendezvous = RendezvousServer(host="127.0.0.1")
    rendezvous.start()
    relay = RelayServer(host="127.0.0.1")
    relay.start()
    connections: dict[str, tuple[socket.socket, tuple[str, int]]] = {}
    errors: list[BaseException] = []
    try:

        def connect(name: str) -> None:
            try:
                connections[name] = wan_connect(
                    rendezvous_addr=rendezvous.address,
                    token="room",
                    bind_host="127.0.0.1",
                    stun_host=None,
                    relay_addr=relay.address,
                    timeout=6,
                )
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        ta = threading.Thread(target=connect, args=("A",))
        tb = threading.Thread(target=connect, args=("B",))
        ta.start()
        tb.start()
        ta.join(10)
        tb.join(10)

        assert not errors, f"wan_connect relay fallback failed: {errors!r}"
        sock_a, peer_a = connections["A"]
        sock_b, peer_b = connections["B"]
        assert peer_a == relay.address and peer_b == relay.address
    finally:
        rendezvous.stop()
        relay.stop()
        for sock, _ in connections.values():
            sock.close()


def test_wan_connect_then_reliable_transfer_loopback() -> None:
    server = RendezvousServer(host="127.0.0.1")
    server.start()
    connections: dict[str, tuple[socket.socket, tuple[str, int]]] = {}
    errors: list[BaseException] = []
    try:

        def connect(name: str) -> None:
            try:
                connections[name] = wan_connect(
                    rendezvous_addr=server.address,
                    token="room",
                    bind_host="127.0.0.1",
                    stun_host=None,  # advertise the loopback address directly
                    timeout=6,
                )
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        ta = threading.Thread(target=connect, args=("A",))
        tb = threading.Thread(target=connect, args=("B",))
        ta.start()
        tb.start()
        ta.join(10)
        tb.join(10)

        assert not errors, f"wan_connect failed: {errors!r}"
        sock_a, peer_a = connections["A"]
        sock_b, peer_b = connections["B"]

        # The punched sockets carry a real reliable-UDP frame end to end.
        channel_a = ReliableUdpChannel(sock_a, peer_a)
        channel_b = ReliableUdpChannel(sock_b, peer_b)
        received: dict[str, bytes] = {}

        def receive() -> None:
            received["msg"] = channel_b.recv_frame()

        receiver = threading.Thread(target=receive)
        receiver.start()
        channel_a.send_frame(b"punched-hello")
        channel_a.flush()
        receiver.join(5)

        assert received.get("msg") == b"punched-hello"
    finally:
        server.stop()
        for sock, _ in connections.values():
            sock.close()
