from __future__ import annotations

import shutil
import socket
import tempfile
import threading
import time
from pathlib import Path

import pytest

from core.nat import RendezvousServer
from core.transport import TransportConfig
from core.udp_transport import (
    _HEADER,
    _TYPE_ACK,
    _TYPE_DATA,
    ReliableUdpChannel,
    udp_receive_file,
    udp_send_file,
    wan_chunk_size,
    wan_receive_file,
    wan_send_file,
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


def test_receiver_buffers_out_of_order_then_delivers_in_order() -> None:
    sock, channel = _local_channel()
    try:
        channel._handle_datagram(_HEADER.pack(_TYPE_DATA, 0) + b"a")
        channel._handle_datagram(_HEADER.pack(_TYPE_DATA, 2) + b"c")  # gap -> buffered
        assert list(channel._delivered) == [b"a"]
        assert channel._recv_seq == 1

        channel._handle_datagram(_HEADER.pack(_TYPE_DATA, 1) + b"b")  # fills gap -> 1 and 2 deliver
        channel._handle_datagram(_HEADER.pack(_TYPE_DATA, 0) + b"dup")  # duplicate -> dropped
        assert list(channel._delivered) == [b"a", b"b", b"c"]
        assert channel._recv_seq == 3
    finally:
        sock.close()


def test_sender_selective_ack_advances_window_in_order() -> None:
    sock, channel = _local_channel()
    try:
        for seq in range(3):
            channel._unacked[seq] = [_HEADER.pack(_TYPE_DATA, seq) + b"x", time.monotonic(), False]
        channel._next_seq = 3

        channel._handle_datagram(_HEADER.pack(_TYPE_ACK, 1))  # acks only frame 1
        assert channel._send_base == 0  # base waits for the still-missing frame 0
        assert set(channel._unacked) == {0, 2}

        channel._handle_datagram(_HEADER.pack(_TYPE_ACK, 2))  # acks frame 2
        assert channel._send_base == 0
        assert set(channel._unacked) == {0}

        channel._handle_datagram(_HEADER.pack(_TYPE_ACK, 0))  # base now slides past 0,1,2
        assert channel._send_base == 3
        assert channel._unacked == {}
    finally:
        sock.close()


def test_rto_estimator_updates_from_rtt_samples() -> None:
    sock, channel = _local_channel()
    try:
        assert channel._srtt is None
        channel._update_rto(0.1)
        assert channel._srtt == 0.1
        # RTO = SRTT + 4*RTTVAR = 0.1 + 4*0.05 = 0.30, within [min, max].
        assert abs(channel._rto - 0.30) < 1e-9
        channel._update_rto(0.1)  # agreeing samples shrink the variance term
        assert channel._rto < 0.30
        assert channel._min_rto <= channel._rto <= channel._max_rto
    finally:
        sock.close()


def test_karn_excludes_retransmitted_frames_from_rtt() -> None:
    sock, channel = _local_channel()
    try:
        # A retransmitted frame's ACK must not produce an RTT sample.
        channel._unacked[0] = [_HEADER.pack(_TYPE_DATA, 0) + b"x", time.monotonic() - 0.05, True]
        channel._next_seq = 1
        channel._handle_datagram(_HEADER.pack(_TYPE_ACK, 0))
        assert channel._srtt is None

        # A frame that was never retransmitted does yield a sample.
        channel._unacked[1] = [_HEADER.pack(_TYPE_DATA, 1) + b"y", time.monotonic() - 0.05, False]
        channel._next_seq = 2
        channel._handle_datagram(_HEADER.pack(_TYPE_ACK, 1))
        assert channel._srtt is not None and channel._srtt > 0
    finally:
        sock.close()


def test_slow_start_grows_window_per_ack() -> None:
    sock, channel = _local_channel()
    try:
        channel._ssthresh = 100.0  # stay in slow start
        assert channel._cwnd == 1.0
        for seq in range(3):
            channel._unacked[seq] = [_HEADER.pack(_TYPE_DATA, seq) + b"x", time.monotonic(), False]
            channel._next_seq = seq + 1
            channel._handle_datagram(_HEADER.pack(_TYPE_ACK, seq))
        assert channel._cwnd == 4.0  # 1 + one per ack
    finally:
        sock.close()


def test_congestion_avoidance_grows_window_sublinearly() -> None:
    sock, channel = _local_channel()
    try:
        channel._cwnd = 4.0
        channel._ssthresh = 4.0  # cwnd >= ssthresh -> congestion avoidance
        channel._unacked[0] = [_HEADER.pack(_TYPE_DATA, 0) + b"x", time.monotonic(), False]
        channel._next_seq = 1
        channel._handle_datagram(_HEADER.pack(_TYPE_ACK, 0))
        assert abs(channel._cwnd - 4.25) < 1e-9  # +1/cwnd, not +1
    finally:
        sock.close()


def test_fast_retransmit_on_three_sack_gaps() -> None:
    sock, channel = _local_channel()
    try:
        channel._cwnd = 8.0
        channel._ssthresh = 8.0
        # Frames 0..3 in flight, none retransmitted; frame 0 is the missing base.
        for seq in range(4):
            channel._unacked[seq] = [_HEADER.pack(_TYPE_DATA, seq) + b"x", time.monotonic(), False]
        channel._next_seq = 4

        # Selective ACKs for 1 and 2 are two SACK gaps past base 0 — not enough yet.
        channel._handle_datagram(_HEADER.pack(_TYPE_ACK, 1))
        channel._handle_datagram(_HEADER.pack(_TYPE_ACK, 2))
        assert channel._dup_acks == 2
        assert channel._unacked[0][2] is False  # base not resent yet

        # The third gap ACK triggers an immediate fast retransmit of base 0,
        # without waiting for the RTO.
        channel._handle_datagram(_HEADER.pack(_TYPE_ACK, 3))
        assert channel._dup_acks == 0           # counter reset after the retransmit
        assert channel._unacked[0][2] is True   # base 0 was resent (Karn flag set)
        assert channel._send_base == 0          # still waiting for 0 to be acked
        assert channel._cwnd < 8.0              # multiplicative decrease on the loss
        assert channel._ssthresh == channel._cwnd

        # Once 0 is acked the window clears in order.
        channel._handle_datagram(_HEADER.pack(_TYPE_ACK, 0))
        assert channel._send_base == 4
        assert channel._unacked == {}
    finally:
        sock.close()


def test_loss_event_halves_window() -> None:
    sock, channel = _local_channel()
    try:
        channel._cwnd = 8.0
        channel._ssthresh = 100.0
        # An overdue, unacked frame forces a retransmit (loss event).
        channel._unacked[0] = [_HEADER.pack(_TYPE_DATA, 0) + b"x", time.monotonic() - 10.0, False]
        channel._next_seq = 1
        channel._retransmit_overdue()
        assert channel._cwnd == 4.0  # halved, not collapsed to 1
        assert channel._ssthresh == 4.0
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


def test_coordinated_wan_transfer_via_rendezvous_loopback() -> None:
    root = Path(tempfile.mkdtemp(prefix="securelink-wan-"))
    rendezvous = RendezvousServer(host="127.0.0.1")
    rendezvous.start()
    try:
        sender_base = root / "sender"
        receiver_base = root / "receiver"
        receiver_out = root / "out"
        for path in (sender_base, receiver_base, receiver_out):
            path.mkdir(parents=True, exist_ok=True)

        payload = (b"coordinated-" * 1500)[:12000]
        source = root / "wan.bin"
        source.write_bytes(payload)

        results: dict[str, object] = {}
        errors: list[BaseException] = []

        def receiver() -> None:
            try:
                cfg = TransportConfig(mode="wan", output_dir=receiver_out, allow_unknown=True)
                results["recv"] = wan_receive_file(
                    rendezvous_addr=rendezvous.address,
                    token="room",
                    stun_host=None,  # advertise loopback directly
                    config=cfg,
                    base_dir=receiver_base,
                    timeout=8,
                )
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        thread = threading.Thread(target=receiver, daemon=True)
        thread.start()
        time.sleep(0.25)

        send_cfg = TransportConfig(mode="wan", allow_unknown=True)
        send_stats = wan_send_file(
            source,
            rendezvous_addr=rendezvous.address,
            token="room",
            stun_host=None,
            config=send_cfg,
            base_dir=sender_base,
            timeout=8,
        )

        thread.join(timeout=20)
        assert not thread.is_alive(), "coordinated receiver did not finish"
        assert not errors, f"coordinated transfer failed: {errors!r}"

        recv_path, recv_stats = results["recv"]  # type: ignore[misc]
        assert Path(recv_path).read_bytes() == payload
        assert send_stats.bytes_transferred == recv_stats.bytes_transferred == len(payload)
    finally:
        rendezvous.stop()
        shutil.rmtree(root, ignore_errors=True)
