"""NAT traversal coordination for SecureLink WAN mode.

The pieces needed to get two UDP peers talking through their NATs:

  - ``RendezvousServer`` / ``rendezvous_exchange`` — a tiny TCP matchmaker that
    pairs two peers sharing a token and swaps their (STUN-discovered) UDP
    endpoints. This is the out-of-band signaling channel hole punching needs.
  - ``udp_hole_punch`` — simultaneous-open probing: both peers spray small
    probes at each other's public endpoint until the bidirectional path is open.
  - ``wan_connect`` — the full client flow: bind a UDP socket, discover its
    public endpoint via STUN, exchange endpoints through the rendezvous, punch,
    and return a socket + peer address ready for a ``ReliableUdpChannel``.

The probe datagrams use type bytes distinct from the reliable transport's DATA
(0x00) and ACK (0x01), so any stragglers are harmlessly ignored once the
reliable channel takes over.

For symmetric NATs, where hole punching cannot succeed, ``RelayServer`` /
``relay_connect`` provide a minimal TURN-style UDP relay: both peers register a
shared token with a publicly reachable relay, which then blindly forwards
datagrams between the two registered endpoints. The reliable channel runs over
that relay unchanged (it just sends to the relay's address). ``wan_connect`` can
fall back to it when ``udp_hole_punch`` fails. All failures raise ``NatError``.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass

from .stun import DEFAULT_STUN_HOST, DEFAULT_STUN_PORT, StunError, discover_public_endpoint

# Probe types (0x00/0x01 are the reliable transport's DATA/ACK).
PUNCH = b"\x02"
PUNCH_ACK = b"\x03"

# Relay control types. Clients only ever send REGISTER; the server only ever
# sends PAIRED. Data forwarded through the relay keeps its 0x00/0x01 type byte,
# so the relay can tell a control datagram (0x04) from a data datagram.
RELAY_REGISTER = b"\x04"
RELAY_PAIRED = b"\x06"
_RELAY_MAX_DATAGRAM = 65535

# Two STUN servers with distinct IPs — comparing the reflexive port each one
# reports reveals whether the NAT's mapping is endpoint-independent (punchable)
# or endpoint-dependent / symmetric (not punchable).
DEFAULT_NAT_PROBE_SERVERS = (
    (DEFAULT_STUN_HOST, DEFAULT_STUN_PORT),
    ("stun1.l.google.com", 19302),
)


class NatError(RuntimeError):
    """Raised on any rendezvous or hole-punch failure."""


@dataclass(frozen=True)
class PeerEndpoint:
    ip: str
    port: int

    def as_tuple(self) -> tuple[str, int]:
        return self.ip, self.port


@dataclass(frozen=True)
class NatAssessment:
    """What a STUN probe revealed about this host's NAT, and what to do about it."""

    mapping: str  # open | endpoint_independent | endpoint_dependent | udp_blocked | unknown
    reflexive: PeerEndpoint | None
    hole_punch_likely: bool
    advice: str


def _primary_local_ipv4() -> str | None:
    """The local IPv4 the OS would use to reach the internet (no packets sent)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def detect_nat_mapping(
    servers: tuple[tuple[str, int], ...] = DEFAULT_NAT_PROBE_SERVERS,
    *,
    timeout: float = 3.0,
    bind_host: str = "0.0.0.0",
) -> NatAssessment:
    """Classify this host's NAT by comparing reflexive endpoints from two servers.

    From a single local socket, query each STUN server and compare the public
    ``ip:port`` each reports. Same mapping for both → endpoint-independent (hole
    punching should work). Different → symmetric (it won't; use a VPN or relay).
    Reflexive address equal to the local address → no NAT. No answers → UDP is
    likely blocked. Network-free in tests by monkeypatching ``discover_public_endpoint``.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    results: list[object] = []
    try:
        sock.bind((bind_host, 0))
        sock.settimeout(timeout)
        for host, port in servers:
            try:
                results.append(
                    discover_public_endpoint(host, port, local_socket=sock, timeout=timeout)
                )
            except StunError:
                results.append(None)
    finally:
        sock.close()

    seen = [r for r in results if r is not None]
    if not seen:
        return NatAssessment(
            "udp_blocked",
            None,
            False,
            "No STUN response — outbound UDP may be blocked. Use a VPN (Tailscale) or stay on the LAN.",
        )

    first = seen[0]
    reflexive = PeerEndpoint(first.ip, first.port)  # type: ignore[attr-defined]
    local_ip = _primary_local_ipv4()
    if local_ip and first.ip == local_ip:  # type: ignore[attr-defined]
        return NatAssessment(
            "open", reflexive, True, "No NAT detected — direct WAN transfers should work."
        )

    if len(seen) >= 2:
        a, b = seen[0], seen[1]
        if a.ip == b.ip and a.port == b.port:  # type: ignore[attr-defined]
            return NatAssessment(
                "endpoint_independent",
                reflexive,
                True,
                "Cone NAT (endpoint-independent mapping) — UDP hole punching should work.",
            )
        return NatAssessment(
            "endpoint_dependent",
            reflexive,
            False,
            "Symmetric NAT (mapping changes per destination) — hole punching will likely fail. "
            "Use a VPN (Tailscale) or a relay.",
        )

    return NatAssessment(
        "unknown",
        reflexive,
        False,
        "Only one STUN server answered — NAT type undetermined. A VPN is the safe choice.",
    )


def _send_line(sock: socket.socket, obj: dict) -> None:
    sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))


def _recv_line(sock: socket.socket, *, timeout: float | None = None) -> dict:
    sock.settimeout(timeout)
    buffer = bytearray()
    while b"\n" not in buffer:
        try:
            chunk = sock.recv(1024)
        except socket.timeout as exc:
            raise NatError("rendezvous timed out waiting for a peer") from exc
        if not chunk:
            raise NatError("rendezvous connection closed")
        buffer.extend(chunk)
        if len(buffer) > 64 * 1024:
            raise NatError("rendezvous message too large")
    line = bytes(buffer).split(b"\n", 1)[0]
    decoded = json.loads(line.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise NatError("invalid rendezvous message")
    return decoded


class RendezvousServer:
    """A minimal TCP matchmaker that swaps two peers' endpoints by token."""

    def __init__(self, host: str = "0.0.0.0", port: int = 0) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(8)
        self.address: tuple[str, int] = self._sock.getsockname()
        self._waiters: dict[str, tuple[socket.socket, PeerEndpoint]] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)
        with self._lock:
            for conn, _ in self._waiters.values():
                try:
                    conn.close()
                except OSError:
                    pass
            self._waiters.clear()

    def _serve(self) -> None:
        self._sock.settimeout(0.3)
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            message = _recv_line(conn, timeout=10.0)
            token = str(message["token"])
            endpoint = PeerEndpoint(str(message["ip"]), int(message["port"]))
        except (NatError, KeyError, ValueError, json.JSONDecodeError):
            conn.close()
            return

        partner: tuple[socket.socket, PeerEndpoint] | None = None
        with self._lock:
            waiting = self._waiters.pop(token, None)
            if waiting is None:
                # First peer: park the connection; the partner's handler answers it.
                self._waiters[token] = (conn, endpoint)
            else:
                partner = waiting

        if partner is None:
            return

        partner_conn, partner_endpoint = partner
        try:
            _send_line(conn, {"ip": partner_endpoint.ip, "port": partner_endpoint.port})
            _send_line(partner_conn, {"ip": endpoint.ip, "port": endpoint.port})
        except OSError:
            pass
        finally:
            conn.close()
            partner_conn.close()


def rendezvous_exchange(
    server_addr: tuple[str, int],
    token: str,
    local_endpoint: PeerEndpoint,
    *,
    timeout: float = 10.0,
) -> PeerEndpoint:
    """Advertise our endpoint to the rendezvous and return the peer's."""

    try:
        conn = socket.create_connection(server_addr, timeout=timeout)
    except OSError as exc:
        raise NatError(f"cannot reach rendezvous server {server_addr}") from exc
    with conn:
        _send_line(conn, {"token": token, "ip": local_endpoint.ip, "port": local_endpoint.port})
        reply = _recv_line(conn, timeout=timeout)
    try:
        return PeerEndpoint(str(reply["ip"]), int(reply["port"]))
    except (KeyError, ValueError) as exc:
        raise NatError("malformed rendezvous reply") from exc


def udp_hole_punch(
    sock: socket.socket,
    peer_addr: tuple[str, int],
    *,
    timeout: float = 5.0,
    interval: float = 0.2,
) -> None:
    """Open a bidirectional UDP path to ``peer_addr`` via simultaneous open.

    Sprays PUNCH probes at the peer and answers theirs, returning once we have
    both seen the peer (they can reach us) and had a probe acknowledged (we can
    reach them). Raises ``NatError`` if that does not happen within ``timeout``.
    """

    deadline = time.monotonic() + timeout
    saw_peer = False
    acknowledged = False
    last_send = 0.0

    while time.monotonic() < deadline and not (saw_peer and acknowledged):
        now = time.monotonic()
        if now - last_send >= interval:
            try:
                sock.sendto(PUNCH, peer_addr)
                if saw_peer:
                    sock.sendto(PUNCH_ACK, peer_addr)
            except OSError:
                pass
            last_send = now

        sock.settimeout(max(0.0, min(interval, deadline - time.monotonic())))
        try:
            data, _addr = sock.recvfrom(64)
        except (socket.timeout, OSError):
            continue

        kind = data[:1]
        if kind == PUNCH:
            saw_peer = True
            try:
                sock.sendto(PUNCH_ACK, peer_addr)
            except OSError:
                pass
        elif kind == PUNCH_ACK:
            acknowledged = True

    if not (saw_peer and acknowledged):
        raise NatError(f"UDP hole punch to {peer_addr} timed out")

    # Send a few parting ACKs so a peer still waiting on confirmation can finish.
    for _ in range(3):
        try:
            sock.sendto(PUNCH_ACK, peer_addr)
        except OSError:
            break


class RelayServer:
    """A minimal TURN-style UDP relay: forwards datagrams between two peers.

    Each peer sends ``RELAY_REGISTER | token``; once two distinct endpoints share
    a token the relay pairs them and answers both with ``RELAY_PAIRED``. After
    that, any non-register datagram from one peer is forwarded verbatim to the
    other. The reliable transport's own ARQ rides over this unchanged.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 0) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self.address: tuple[str, int] = self._sock.getsockname()
        # token -> list of registered endpoints; endpoint -> partner endpoint.
        self._members: dict[str, list[tuple[str, int]]] = {}
        self._partner: dict[tuple[str, int], tuple[str, int]] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)

    def _serve(self) -> None:
        self._sock.settimeout(0.3)
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(_RELAY_MAX_DATAGRAM)
            except socket.timeout:
                continue
            except OSError:
                break
            if data[:1] == RELAY_REGISTER:
                self._register(data[1:], addr)
            else:
                partner = self._partner.get(addr)
                if partner is not None:
                    try:
                        self._sock.sendto(data, partner)
                    except OSError:
                        pass

    def _register(self, token_bytes: bytes, addr: tuple[str, int]) -> None:
        try:
            token = token_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return
        with self._lock:
            members = self._members.setdefault(token, [])
            if addr not in members:
                if len(members) >= 2:
                    return  # room full; ignore a third peer
                members.append(addr)
            if len(members) == 2:
                a, b = members
                self._partner[a] = b
                self._partner[b] = a
        # Confirm pairing (idempotent: a re-register after pairing re-confirms).
        if self._partner.get(addr) is not None:
            for endpoint in (addr, self._partner[addr]):
                try:
                    self._sock.sendto(RELAY_PAIRED, endpoint)
                except OSError:
                    pass


def relay_register(
    sock: socket.socket,
    relay_addr: tuple[str, int],
    token: str,
    *,
    timeout: float = 10.0,
    interval: float = 0.2,
) -> None:
    """Register ``token`` with the relay and block until the peer is paired."""

    message = RELAY_REGISTER + token.encode("utf-8")
    deadline = time.monotonic() + timeout
    last_send = 0.0
    while time.monotonic() < deadline:
        now = time.monotonic()
        if now - last_send >= interval:
            try:
                sock.sendto(message, relay_addr)
            except OSError as exc:
                raise NatError(f"cannot reach relay {relay_addr}") from exc
            last_send = now
        sock.settimeout(max(0.0, min(interval, deadline - time.monotonic())))
        try:
            data, addr = sock.recvfrom(64)
        except (socket.timeout, OSError):
            continue
        if addr == relay_addr and data[:1] == RELAY_PAIRED:
            return
    raise NatError("relay pairing timed out")


def relay_connect(
    relay_addr: tuple[str, int],
    token: str,
    *,
    bind_host: str = "0.0.0.0",
    bind_port: int = 0,
    timeout: float = 10.0,
) -> tuple[socket.socket, tuple[str, int]]:
    """Bind a UDP socket and pair with a peer through the relay.

    Returns ``(sock, relay_addr)`` for a ``ReliableUdpChannel``: the channel
    sends to the relay, which forwards to the paired peer (and vice versa).
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((bind_host, bind_port))
        relay_register(sock, relay_addr, token, timeout=timeout)
        return sock, relay_addr
    except Exception:
        sock.close()
        raise


def wan_connect(
    *,
    rendezvous_addr: tuple[str, int],
    token: str,
    bind_host: str = "0.0.0.0",
    bind_port: int = 0,
    stun_host: str | None = DEFAULT_STUN_HOST,
    stun_port: int = DEFAULT_STUN_PORT,
    relay_addr: tuple[str, int] | None = None,
    timeout: float = 10.0,
) -> tuple[socket.socket, tuple[str, int]]:
    """Bind a UDP socket, coordinate via STUN + rendezvous, and hole punch.

    Returns ``(sock, peer_addr)`` ready to hand to a ``ReliableUdpChannel``. Pass
    ``stun_host=None`` to advertise the socket's local address instead of a
    STUN-discovered one (useful for same-host / testing). If hole punching fails
    and ``relay_addr`` is given, falls back to the relay and returns
    ``(sock, relay_addr)`` — the channel then runs over the relay transparently.
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((bind_host, bind_port))
        if stun_host:
            try:
                discovered = discover_public_endpoint(
                    stun_host, stun_port, local_socket=sock, timeout=timeout
                )
            except StunError as exc:
                raise NatError(f"STUN discovery failed: {exc}") from exc
            local_endpoint = PeerEndpoint(discovered.ip, discovered.port)
        else:
            host, port = sock.getsockname()
            if host in ("0.0.0.0", ""):
                host = "127.0.0.1"
            local_endpoint = PeerEndpoint(host, int(port))

        peer_endpoint = rendezvous_exchange(rendezvous_addr, token, local_endpoint, timeout=timeout)
        try:
            udp_hole_punch(sock, peer_endpoint.as_tuple(), timeout=timeout)
        except NatError:
            if relay_addr is None:
                raise
            # Symmetric NAT (or otherwise un-punchable): relay instead.
            relay_register(sock, relay_addr, token, timeout=timeout)
            return sock, relay_addr
        return sock, peer_endpoint.as_tuple()
    except Exception:
        sock.close()
        raise
