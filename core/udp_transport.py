"""Reliable UDP transport for SecureLink's WAN mode.

UDP is required for STUN-assisted NAT traversal (a hole punched through a NAT is
a UDP binding), but UDP is unreliable and unordered. This module adds a small
selective-repeat ARQ on top of UDP so the existing capsule handshake and
streaming code (``core.transport.stream_send`` / ``stream_receive``) can run over
it unchanged via the shared :class:`~core.transport.FrameChannel` interface.

Each datagram is ``type(1) | seq(4) | payload`` where type is DATA or ACK. The
sender keeps a congestion window of unacked frames in flight (AIMD with slow
start, capped by the receiver window ``window``), ACKs are *per-frame*
(selective), and on timeout only the individual frames that are still unacked and
overdue are retransmitted — not the whole window. The retransmit timeout adapts
to measured RTT (RFC 6298 RTO estimation with Karn's algorithm and exponential
backoff), and a loss event halves the slow-start threshold. The receiver
buffers out-of-order frames within its window and delivers them in order once the
gaps fill. ``flush`` drains the window before close and ``linger`` re-services
retransmissions afterwards, so a dropped final ACK is still recovered. Every pump
processes both ACKs and DATA, so the window stays consistent across the
handshake's request/response turns without a background thread.

Single-threaded and deterministic. All failures raise
``core.transport.TransportError``.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable

from .capsule import AES_TAG_LEN, CAPSULE_PREFIX
from .transport import (
    TransferStats,
    TransportConfig,
    TransportError,
    _resolve_host_address,
    _validate_allowlist,
    stream_receive,
    stream_send,
)

_TYPE_DATA = 0
_TYPE_ACK = 1
_HEADER = struct.Struct("!BI")
_HEADER_LEN = _HEADER.size  # 5
_MAX_DATAGRAM = 65535

DEFAULT_WINDOW = 32

# Adaptive retransmit timeout (RFC 6298-style RTO estimation).
DEFAULT_INITIAL_RTO = 0.5
RTO_MIN = 0.1
RTO_MAX = 1.0

# Conservative defaults to avoid IP fragmentation across the public internet.
WAN_SAFE_MTU = 1200
IP_UDP_OVERHEAD = 28  # 20-byte IPv4 header + 8-byte UDP header


def wan_chunk_size(mtu: int = WAN_SAFE_MTU) -> int:
    """Largest plaintext chunk that keeps a capsule datagram under ``mtu``."""

    size = mtu - IP_UDP_OVERHEAD - _HEADER_LEN - CAPSULE_PREFIX - AES_TAG_LEN
    if size < 1:
        raise TransportError(f"MTU {mtu} too small for a reliable UDP capsule")
    return size


class ReliableUdpChannel:
    """Selective-repeat reliable :class:`~core.transport.FrameChannel` over UDP."""

    def __init__(
        self,
        sock: socket.socket,
        peer_addr: tuple[str, int] | None = None,
        *,
        allowlist: tuple[str, ...] = (),
        window: int = DEFAULT_WINDOW,
        initial_rto: float = DEFAULT_INITIAL_RTO,
        min_rto: float = RTO_MIN,
        max_rto: float = RTO_MAX,
        max_retries: int = 40,
        recv_timeout: float = 20.0,
        cancel_event: threading.Event | None = None,
    ) -> None:
        self._sock = sock
        self._peer_addr = peer_addr
        self._allowlist = allowlist
        self._window = max(1, window)
        self._max_retries = max_retries
        self._recv_timeout = recv_timeout
        self._cancel_event = cancel_event

        # Adaptive RTO (RFC 6298): smoothed RTT + variance, with Karn's algorithm
        # (ignore samples from retransmitted frames) and exponential backoff.
        self._min_rto = min_rto
        self._max_rto = max_rto
        self._rto = initial_rto
        self._srtt: float | None = None
        self._rttvar = 0.0

        # Send side: unacked frames are [send_base, next_seq); each entry is
        # [datagram, last_send_time, retransmitted] so only overdue frames are
        # resent and retransmitted frames are excluded from RTT sampling.
        self._send_base = 0
        self._next_seq = 0
        self._unacked: dict[int, list] = {}
        self._acked: set[int] = set()
        self._retries = 0

        # Congestion control (AIMD with slow start). The send window is the
        # congestion window cwnd (in frames), capped by the receiver window
        # ``self._window``. cwnd grows exponentially until ssthresh, then
        # linearly; a loss (retransmit timeout) halves ssthresh and resets cwnd.
        self._cwnd = 1.0
        self._ssthresh = float(self._window)

        # Receive side: out-of-order frames are buffered until the gap fills.
        self._recv_seq = 0
        self._recv_buffer: dict[int, bytes] = {}
        self._delivered: deque[bytes] = deque()

        if peer_addr is not None and allowlist:
            _validate_allowlist(peer_addr[0], allowlist)

    @property
    def peer_addr(self) -> tuple[str, int] | None:
        return self._peer_addr

    def _learn_peer(self, addr: tuple[str, int]) -> None:
        if self._peer_addr is None:
            if self._allowlist:
                _validate_allowlist(addr[0], self._allowlist)
            self._peer_addr = addr

    def _send_ack(self, seq: int) -> None:
        if self._peer_addr is None:
            return
        try:
            self._sock.sendto(_HEADER.pack(_TYPE_ACK, seq), self._peer_addr)
        except OSError:
            pass

    def _grow_cwnd(self) -> None:
        """Open the congestion window on a successful ACK (slow start / AIMD)."""

        if self._cwnd < self._ssthresh:
            self._cwnd += 1.0  # slow start: exponential growth per RTT
        else:
            self._cwnd += 1.0 / self._cwnd  # congestion avoidance: +1 per RTT
        self._cwnd = min(self._cwnd, float(self._window))

    def _shrink_cwnd(self) -> None:
        """Multiplicative decrease on a loss event: halve the window.

        A full Tahoe reset to 1 collapses throughput under random (non-congestion)
        loss, so this halves cwnd with a small floor instead — closer to Reno's
        multiplicative decrease and far more usable on a lossy link.
        """

        self._cwnd = max(2.0, self._cwnd / 2.0)
        self._ssthresh = self._cwnd

    def _update_rto(self, rtt: float) -> None:
        """Fold a fresh RTT sample into the smoothed RTO (RFC 6298)."""

        if rtt < 0:
            return
        if self._srtt is None:
            self._srtt = rtt
            self._rttvar = rtt / 2
        else:
            self._rttvar = 0.75 * self._rttvar + 0.25 * abs(self._srtt - rtt)
            self._srtt = 0.875 * self._srtt + 0.125 * rtt
        self._rto = min(self._max_rto, max(self._min_rto, self._srtt + 4 * self._rttvar))

    def _handle_datagram(self, data: bytes) -> None:
        if len(data) < _HEADER_LEN:
            return
        mtype, seq = _HEADER.unpack(data[:_HEADER_LEN])
        if mtype == _TYPE_ACK:
            # Selective ACK: this specific frame is delivered.
            entry = self._unacked.pop(seq, None)
            if entry is not None:
                # Karn's algorithm: only sample RTT from frames never retransmitted.
                if not entry[2]:
                    self._update_rto(time.monotonic() - entry[1])
                self._grow_cwnd()
                self._acked.add(seq)
                self._retries = 0
                while self._send_base in self._acked:
                    self._acked.discard(self._send_base)
                    self._send_base += 1
        elif mtype == _TYPE_DATA:
            payload = data[_HEADER_LEN:]
            if seq < self._recv_seq:
                # Already delivered; re-ACK so the sender stops retransmitting.
                self._send_ack(seq)
            elif seq < self._recv_seq + self._window:
                self._recv_buffer.setdefault(seq, payload)
                while self._recv_seq in self._recv_buffer:
                    self._delivered.append(self._recv_buffer.pop(self._recv_seq))
                    self._recv_seq += 1
                self._send_ack(seq)
            # Frames beyond the receive window are ignored (sender will resend).

    def _retransmit_overdue(self) -> None:
        if not self._unacked:
            return
        self._retries += 1
        if self._retries > self._max_retries:
            raise TransportError(
                f"reliable UDP timed out after {self._max_retries} retries"
            )
        now = time.monotonic()
        retransmitted_any = False
        for entry in self._unacked.values():
            if now - entry[1] >= self._rto:
                self._sock.sendto(entry[0], self._peer_addr)
                entry[1] = now
                entry[2] = True  # exclude from RTT sampling (Karn's algorithm)
                retransmitted_any = True
        if retransmitted_any:
            # Loss event: back off the RTO and the congestion window.
            self._rto = min(self._max_rto, self._rto * 2)
            self._shrink_cwnd()

    def _pump(self, *, block: bool) -> None:
        """Process one (blocking) or all immediately-available datagrams.

        A blocking pump that times out retransmits only the overdue frames.
        """

        if block:
            self._sock.settimeout(self._rto)
            try:
                data, addr = self._sock.recvfrom(_MAX_DATAGRAM)
            except socket.timeout:
                self._retransmit_overdue()
                return
            except OSError:
                return
            self._learn_peer(addr)
            self._handle_datagram(data)
            return

        self._sock.settimeout(0.0)
        while True:
            try:
                data, addr = self._sock.recvfrom(_MAX_DATAGRAM)
            except (BlockingIOError, socket.timeout):
                return
            except OSError:
                return
            self._learn_peer(addr)
            self._handle_datagram(data)

    def send_frame(self, payload: bytes) -> None:
        if self._peer_addr is None:
            raise TransportError("reliable UDP send before peer address is known")
        # The number of frames in flight is bounded by the congestion window.
        while (self._next_seq - self._send_base) >= max(1, int(self._cwnd)):
            self._pump(block=True)
        seq = self._next_seq
        datagram = _HEADER.pack(_TYPE_DATA, seq) + payload
        self._unacked[seq] = [datagram, time.monotonic(), False]
        self._sock.sendto(datagram, self._peer_addr)
        self._next_seq += 1
        # Opportunistically absorb any ACKs/DATA so the window keeps sliding.
        self._pump(block=False)

    def recv_frame(self) -> bytes:
        deadline = time.monotonic() + self._recv_timeout
        while not self._delivered:
            if self._cancel_event is not None and self._cancel_event.is_set():
                raise TransportError("receive cancelled")
            if time.monotonic() >= deadline:
                raise TransportError("reliable UDP receive timed out")
            self._pump(block=True)
        return self._delivered.popleft()

    def flush(self) -> None:
        """Block until every sent frame has been cumulatively ACKed."""

        deadline = time.monotonic() + self._max_retries * self._max_rto + 1.0
        while self._send_base < self._next_seq:
            if time.monotonic() >= deadline:
                raise TransportError("reliable UDP flush timed out")
            self._pump(block=True)

    def linger(self, *, poll_timeout: float = 0.3, idle_rounds: int | None = None) -> None:
        """Keep re-ACKing retransmissions briefly after the transfer completes.

        Recovers a dropped final ACK: if the sender's last frame is unacked it
        retransmits, and we answer until the link has been idle for
        ``idle_rounds`` consecutive polls. Any datagram resets the idle counter.
        The idle window must outlast the sender's worst-case (backed-off) RTO, or
        the receiver could close mid-retransmit, so it is derived from
        ``max_rto`` when not given explicitly.
        """

        if self._peer_addr is None:
            return
        if idle_rounds is None:
            idle_rounds = int(self._max_rto / poll_timeout) + 2
        idle = 0
        while idle < idle_rounds:
            self._sock.settimeout(poll_timeout)
            try:
                data, _addr = self._sock.recvfrom(_MAX_DATAGRAM)
            except (socket.timeout, OSError):
                idle += 1
                continue
            idle = 0
            self._handle_datagram(data)


def udp_send_file(
    file_path: str | Path,
    peer_host: str,
    peer_port: int,
    *,
    config: TransportConfig | None = None,
    trust_prompt: Callable[[str], bool] | None = None,
    base_dir: Path | None = None,
    chunk_size: int | None = None,
) -> TransferStats:
    """Send a file to ``peer_host:peer_port`` over reliable UDP (WAN mode)."""

    transfer_path = Path(file_path)
    if not transfer_path.exists():
        raise FileNotFoundError(transfer_path)

    transfer_config = config or TransportConfig(mode="wan", port=peer_port)
    peer_addr = (_resolve_host_address(peer_host), peer_port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        channel = ReliableUdpChannel(sock, peer_addr)
        return stream_send(
            channel,
            transfer_path,
            transfer_config,
            trust_prompt=trust_prompt,
            base_dir=base_dir,
            chunk_size=chunk_size if chunk_size is not None else wan_chunk_size(),
        )
    finally:
        sock.close()


def udp_receive_file(
    *,
    config: TransportConfig | None = None,
    trust_prompt: Callable[[str], bool] | None = None,
    base_dir: Path | None = None,
    cancel_event: threading.Event | None = None,
) -> tuple[Path, TransferStats]:
    """Receive a file over reliable UDP (WAN mode).

    Binds a UDP socket and learns the peer's address from its first datagram;
    the allowlist (if any) is enforced the moment that address is learned.
    """

    transfer_config = config or TransportConfig(mode="wan")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((transfer_config.bind_host, transfer_config.port))
        channel = ReliableUdpChannel(
            sock, None, allowlist=transfer_config.allowlist, cancel_event=cancel_event
        )
        result = stream_receive(
            channel,
            transfer_config,
            trust_prompt=trust_prompt,
            base_dir=base_dir,
        )
        # Stay available briefly so a dropped final ACK can be recovered.
        channel.linger()
        return result
    finally:
        sock.close()
