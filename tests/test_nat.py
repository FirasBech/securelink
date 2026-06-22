from __future__ import annotations

import socket
import threading

from core.nat import (
    PeerEndpoint,
    RendezvousServer,
    rendezvous_exchange,
    udp_hole_punch,
    wan_connect,
)
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
