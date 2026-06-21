"""Minimal STUN client (RFC 8489 / RFC 5389).

Used by the WAN transport to discover a host's server-reflexive endpoint (its
public IP and port as seen from outside the NAT) before attempting UDP hole
punching.

Scope: Binding Requests over UDP and parsing of (XOR-)MAPPED-ADDRESS from the
Binding Success Response. No authentication, FINGERPRINT, or TURN/relay support.

The message codec is pure and offline-testable; only ``discover_public_endpoint``
touches the network. All failures raise ``StunError``.
"""

from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass

# Header.
MAGIC_COOKIE = 0x2112A442
MAGIC_COOKIE_BYTES = struct.pack("!I", MAGIC_COOKIE)
HEADER_LEN = 20
TRANSACTION_ID_LEN = 12

# Message types.
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
BINDING_ERROR = 0x0111

# Attribute types.
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_ERROR_CODE = 0x0009

# Address families.
FAMILY_IPV4 = 0x01
FAMILY_IPV6 = 0x02

DEFAULT_STUN_HOST = "stun.l.google.com"
DEFAULT_STUN_PORT = 19302


class StunError(RuntimeError):
    """Raised on any STUN encode/decode or transaction failure."""


@dataclass(frozen=True)
class MappedAddress:
    """A reflexive transport address reported by a STUN server."""

    ip: str
    port: int
    family: int = FAMILY_IPV4

    def as_tuple(self) -> tuple[str, int]:
        return self.ip, self.port


def build_binding_request(transaction_id: bytes | None = None) -> tuple[bytes, bytes]:
    """Build a Binding Request with no attributes.

    Returns ``(message_bytes, transaction_id)``. The caller keeps the
    transaction id to validate the matching response.
    """

    if transaction_id is None:
        transaction_id = os.urandom(TRANSACTION_ID_LEN)
    if len(transaction_id) != TRANSACTION_ID_LEN:
        raise StunError(f"transaction id must be {TRANSACTION_ID_LEN} bytes")

    # message type, body length (0), magic cookie, transaction id
    header = struct.pack("!HH", BINDING_REQUEST, 0) + MAGIC_COOKIE_BYTES + transaction_id
    return header, transaction_id


def _iter_attributes(body: bytes):
    """Yield ``(attr_type, value)`` pairs from a STUN message body."""

    offset = 0
    while offset + 4 <= len(body):
        attr_type, length = struct.unpack("!HH", body[offset : offset + 4])
        offset += 4
        if offset + length > len(body):
            raise StunError("truncated STUN attribute")
        value = body[offset : offset + length]
        offset += length
        # Attributes are padded to a 4-byte boundary.
        offset += (-length) % 4
        yield attr_type, value


def _decode_mapped_address(value: bytes, transaction_id: bytes, *, xor: bool) -> MappedAddress:
    if len(value) < 4:
        raise StunError("MAPPED-ADDRESS attribute too short")
    family = value[1]
    raw_port = struct.unpack("!H", value[2:4])[0]
    addr = value[4:]

    if xor:
        port = raw_port ^ (MAGIC_COOKIE >> 16)
    else:
        port = raw_port

    if family == FAMILY_IPV4:
        if len(addr) < 4:
            raise StunError("IPv4 address attribute too short")
        addr_int = struct.unpack("!I", addr[:4])[0]
        if xor:
            addr_int ^= MAGIC_COOKIE
        ip = socket.inet_ntoa(struct.pack("!I", addr_int))
    elif family == FAMILY_IPV6:
        if len(addr) < 16:
            raise StunError("IPv6 address attribute too short")
        raw = bytearray(addr[:16])
        if xor:
            mask = MAGIC_COOKIE_BYTES + transaction_id
            raw = bytearray(b ^ m for b, m in zip(raw, mask))
        ip = socket.inet_ntop(socket.AF_INET6, bytes(raw))
    else:
        raise StunError(f"unknown address family 0x{family:02x}")

    return MappedAddress(ip=ip, port=port, family=family)


def parse_binding_response(data: bytes, transaction_id: bytes) -> MappedAddress:
    """Parse a Binding Success Response and return the reflexive address.

    Prefers XOR-MAPPED-ADDRESS and falls back to the legacy MAPPED-ADDRESS.
    """

    if len(data) < HEADER_LEN:
        raise StunError("STUN response shorter than header")

    msg_type, body_length, cookie = struct.unpack("!HHI", data[:8])
    resp_transaction_id = data[8:HEADER_LEN]

    if cookie != MAGIC_COOKIE:
        raise StunError("bad STUN magic cookie")
    if resp_transaction_id != transaction_id:
        raise StunError("STUN transaction id mismatch")
    if HEADER_LEN + body_length > len(data):
        raise StunError("STUN body length exceeds datagram")
    if msg_type == BINDING_ERROR:
        raise StunError("STUN server returned a Binding Error Response")
    if msg_type != BINDING_SUCCESS:
        raise StunError(f"unexpected STUN message type 0x{msg_type:04x}")

    body = data[HEADER_LEN : HEADER_LEN + body_length]

    mapped: MappedAddress | None = None
    for attr_type, value in _iter_attributes(body):
        if attr_type == ATTR_XOR_MAPPED_ADDRESS:
            return _decode_mapped_address(value, transaction_id, xor=True)
        if attr_type == ATTR_MAPPED_ADDRESS and mapped is None:
            mapped = _decode_mapped_address(value, transaction_id, xor=False)

    if mapped is not None:
        return mapped
    raise StunError("no MAPPED-ADDRESS attribute in STUN response")


def discover_public_endpoint(
    stun_host: str = DEFAULT_STUN_HOST,
    stun_port: int = DEFAULT_STUN_PORT,
    *,
    local_socket: socket.socket | None = None,
    timeout: float = 3.0,
    retries: int = 3,
) -> MappedAddress:
    """Query a STUN server for this host's server-reflexive endpoint.

    If ``local_socket`` is given, the query is sent from it so the discovered
    binding matches the socket the caller will use for hole punching. Otherwise
    a temporary UDP socket is used.
    """

    try:
        server = (socket.gethostbyname(stun_host), stun_port)
    except socket.gaierror as exc:
        raise StunError(f"unable to resolve STUN host {stun_host!r}") from exc

    owns_socket = local_socket is None
    sock = local_socket or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        last_error: Exception | None = None
        for _ in range(max(1, retries)):
            request, transaction_id = build_binding_request()
            try:
                sock.sendto(request, server)
                data, _peer = sock.recvfrom(1024)
            except socket.timeout as exc:
                last_error = exc
                continue
            return parse_binding_response(data, transaction_id)
        raise StunError(f"no STUN response from {stun_host}:{stun_port}") from last_error
    finally:
        if owns_socket:
            sock.close()


if __name__ == "__main__":
    endpoint = discover_public_endpoint()
    print(f"reflexive endpoint: {endpoint.ip}:{endpoint.port}")
