from __future__ import annotations

import shutil
import socket
import tempfile
import threading
import time
from pathlib import Path

import pytest

from core.transport import TransportConfig
from core.udp_transport import (
    _HEADER,
    _TYPE_ACK,
    _TYPE_DATA,
    ReliableUdpChannel,
    udp_receive_file,
    udp_send_file,
    wan_chunk_size,
)


def _local_channel() -> tuple[socket.socket, ReliableUdpChannel]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    # Point the peer at our own socket so internally-sent ACKs go nowhere harmful.
    return sock, ReliableUdpChannel(sock, sock.getsockname())


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_receiver_delivers_in_order_and_drops_out_of_order() -> None:
    sock, channel = _local_channel()
    try:
        channel._handle_datagram(_HEADER.pack(_TYPE_DATA, 0) + b"a")
        channel._handle_datagram(_HEADER.pack(_TYPE_DATA, 2) + b"c")  # gap -> dropped
        channel._handle_datagram(_HEADER.pack(_TYPE_DATA, 1) + b"b")
        channel._handle_datagram(_HEADER.pack(_TYPE_DATA, 0) + b"dup")  # duplicate -> dropped
        assert list(channel._delivered) == [b"a", b"b"]
        assert channel._recv_seq == 2
    finally:
        sock.close()


def test_sender_cumulative_ack_advances_window() -> None:
    sock, channel = _local_channel()
    try:
        for seq in range(3):
            channel._send_buffer[seq] = _HEADER.pack(_TYPE_DATA, seq) + b"x"
        channel._next_seq = 3

        channel._handle_datagram(_HEADER.pack(_TYPE_ACK, 1))  # cumulative ack of 0 and 1
        assert channel._send_base == 2
        assert set(channel._send_buffer) == {2}

        channel._handle_datagram(_HEADER.pack(_TYPE_ACK, 0))  # stale ack -> ignored
        assert channel._send_base == 2

        channel._handle_datagram(_HEADER.pack(_TYPE_ACK, 2))
        assert channel._send_base == 3
        assert channel._send_buffer == {}
    finally:
        sock.close()


def test_wan_chunk_size_fits_under_mtu() -> None:
    # capsule prefix (52) + tag (16) + reliable header (5) + IP/UDP (28)
    assert wan_chunk_size(1200) == 1200 - 28 - 5 - 52 - 16
    with pytest.raises(Exception):
        wan_chunk_size(10)


def test_udp_round_trip_loopback() -> None:
    root = Path(tempfile.mkdtemp(prefix="securelink-udp-"))
    try:
        sender_base = root / "sender"
        receiver_base = root / "receiver"
        receiver_out = root / "receiver-out"
        for path in (sender_base, receiver_base, receiver_out):
            path.mkdir(parents=True, exist_ok=True)

        payload = (b"wan-payload-" * 2500)[:18000]
        source = root / "wan.bin"
        source.write_bytes(payload)
        port = _free_udp_port()
        results: dict[str, object] = {}
        errors: list[BaseException] = []

        def receiver() -> None:
            try:
                cfg = TransportConfig(
                    mode="wan",
                    port=port,
                    bind_host="127.0.0.1",
                    output_dir=receiver_out,
                    allow_unknown=True,
                )
                results["recv"] = udp_receive_file(config=cfg, base_dir=receiver_base)
            except BaseException as exc:  # noqa: BLE001 - surfaced to the test
                errors.append(exc)

        thread = threading.Thread(target=receiver, daemon=True)
        thread.start()
        time.sleep(0.25)

        send_cfg = TransportConfig(mode="wan", port=port, allow_unknown=True)
        send_stats = udp_send_file(
            source, "127.0.0.1", port, config=send_cfg, base_dir=sender_base
        )

        thread.join(timeout=15)
        assert not thread.is_alive(), "udp receiver did not finish"
        assert not errors, f"udp receiver failed: {errors!r}"

        recv_path, recv_stats = results["recv"]  # type: ignore[misc]
        assert Path(recv_path).read_bytes() == payload
        assert send_stats.bytes_transferred == len(payload)
        assert recv_stats.bytes_transferred == len(payload)
        assert send_stats.chunks == recv_stats.chunks > 1
    finally:
        shutil.rmtree(root, ignore_errors=True)
