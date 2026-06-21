"""Exercises the reliable-UDP ARQ under packet loss.

A lossy relay sits between sender and receiver and drops a fraction of
datagrams in both directions, forcing retransmissions, duplicate detection, and
re-ACKs that a lossless loopback never triggers.
"""

from __future__ import annotations

import random
import shutil
import socket
import tempfile
import threading
import time
from pathlib import Path

from core.transport import TransportConfig
from core.udp_transport import udp_receive_file, udp_send_file


class _LossyRelay:
    """Forwards datagrams between sender and receiver, dropping some."""

    def __init__(
        self,
        bind_host: str,
        receiver_addr: tuple[str, int],
        *,
        loss: float = 0.2,
        seed: int = 1234,
    ) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((bind_host, 0))
        self.addr = self._sock.getsockname()
        self._receiver_addr = receiver_addr
        self._sender_addr: tuple[str, int] | None = None
        self._rng = random.Random(seed)
        self._loss = loss
        self._dropped = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    @property
    def dropped(self) -> int:
        return self._dropped

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._sock.close()

    def _run(self) -> None:
        self._sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                data, src = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                # Windows surfaces ICMP port-unreachable as a socket error once a
                # peer closes. Benign for a connectionless relay; keep forwarding.
                continue
            if src == self._receiver_addr:
                dst = self._sender_addr
            else:
                self._sender_addr = src
                dst = self._receiver_addr
            if dst is None:
                continue
            if self._rng.random() < self._loss:
                self._dropped += 1
                continue
            self._sock.sendto(data, dst)


def test_udp_round_trip_through_lossy_relay() -> None:
    root = Path(tempfile.mkdtemp(prefix="securelink-loss-"))
    try:
        sender_base = root / "sender"
        receiver_base = root / "receiver"
        receiver_out = root / "receiver-out"
        for path in (sender_base, receiver_base, receiver_out):
            path.mkdir(parents=True, exist_ok=True)

        payload = bytes((i * 31 + 7) % 256 for i in range(12000))
        source = root / "loss.bin"
        source.write_bytes(payload)

        # Reserve a fixed receiver port so the relay knows where to forward.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("127.0.0.1", 0))
            recv_port = probe.getsockname()[1]
        receiver_addr = ("127.0.0.1", recv_port)

        relay = _LossyRelay("127.0.0.1", receiver_addr, loss=0.25)
        relay.start()

        results: dict[str, object] = {}
        errors: list[BaseException] = []

        def receiver() -> None:
            try:
                cfg = TransportConfig(
                    mode="wan",
                    port=recv_port,
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

        send_cfg = TransportConfig(mode="wan", port=relay.addr[1], allow_unknown=True)
        send_stats = udp_send_file(
            source, "127.0.0.1", relay.addr[1], config=send_cfg, base_dir=sender_base
        )

        thread.join(timeout=40)
        relay.stop()

        assert not thread.is_alive(), "receiver did not finish under loss"
        assert not errors, f"receiver failed under loss: {errors!r}"

        recv_path, recv_stats = results["recv"]  # type: ignore[misc]
        assert Path(recv_path).read_bytes() == payload
        assert send_stats.bytes_transferred == len(payload)
        assert recv_stats.bytes_transferred == len(payload)
        # The point of the test: datagrams really were dropped and recovered.
        assert relay.dropped > 0
    finally:
        shutil.rmtree(root, ignore_errors=True)
