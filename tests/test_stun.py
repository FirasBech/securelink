from __future__ import annotations

import socket
import struct

import pytest

from core.stun import (
    BINDING_ERROR,
    BINDING_REQUEST,
    BINDING_SUCCESS,
    FAMILY_IPV4,
    FAMILY_IPV6,
    HEADER_LEN,
    MAGIC_COOKIE,
    MAGIC_COOKIE_BYTES,
    ATTR_MAPPED_ADDRESS,
    ATTR_XOR_MAPPED_ADDRESS,
    MappedAddress,
    StunError,
    build_binding_request,
    parse_binding_response,
)


def _pad(value: bytes) -> bytes:
    return value + b"\x00" * ((-len(value)) % 4)


def _attribute(attr_type: int, value: bytes) -> bytes:
    return struct.pack("!HH", attr_type, len(value)) + _pad(value)


def _xor_mapped_ipv4(ip: str, port: int) -> bytes:
    x_port = port ^ (MAGIC_COOKIE >> 16)
    addr_int = struct.unpack("!I", socket.inet_aton(ip))[0] ^ MAGIC_COOKIE
    return b"\x00" + bytes([FAMILY_IPV4]) + struct.pack("!H", x_port) + struct.pack("!I", addr_int)


def _mapped_ipv4(ip: str, port: int) -> bytes:
    return b"\x00" + bytes([FAMILY_IPV4]) + struct.pack("!H", port) + socket.inet_aton(ip)


def _xor_mapped_ipv6(ip: str, port: int, transaction_id: bytes) -> bytes:
    x_port = port ^ (MAGIC_COOKIE >> 16)
    mask = MAGIC_COOKIE_BYTES + transaction_id
    raw = socket.inet_pton(socket.AF_INET6, ip)
    xored = bytes(b ^ m for b, m in zip(raw, mask))
    return b"\x00" + bytes([FAMILY_IPV6]) + struct.pack("!H", x_port) + xored


def _response(msg_type: int, transaction_id: bytes, body: bytes) -> bytes:
    return struct.pack("!HH", msg_type, len(body)) + MAGIC_COOKIE_BYTES + transaction_id + body


def test_build_binding_request_structure() -> None:
    message, transaction_id = build_binding_request()
    assert len(message) == HEADER_LEN
    msg_type, body_len, cookie = struct.unpack("!HHI", message[:8])
    assert msg_type == BINDING_REQUEST
    assert body_len == 0
    assert cookie == MAGIC_COOKIE
    assert message[8:HEADER_LEN] == transaction_id
    assert len(transaction_id) == 12


def test_build_binding_request_rejects_bad_transaction_id() -> None:
    with pytest.raises(StunError):
        build_binding_request(b"too-short")


def test_parse_xor_mapped_address_ipv4_round_trip() -> None:
    _, txid = build_binding_request()
    body = _attribute(ATTR_XOR_MAPPED_ADDRESS, _xor_mapped_ipv4("203.0.113.7", 51234))
    data = _response(BINDING_SUCCESS, txid, body)

    result = parse_binding_response(data, txid)
    assert result == MappedAddress(ip="203.0.113.7", port=51234, family=FAMILY_IPV4)


def test_parse_falls_back_to_legacy_mapped_address() -> None:
    _, txid = build_binding_request()
    body = _attribute(ATTR_MAPPED_ADDRESS, _mapped_ipv4("198.51.100.22", 40000))
    data = _response(BINDING_SUCCESS, txid, body)

    result = parse_binding_response(data, txid)
    assert result.ip == "198.51.100.22"
    assert result.port == 40000


def test_xor_mapped_address_is_preferred_over_legacy() -> None:
    _, txid = build_binding_request()
    body = _attribute(ATTR_MAPPED_ADDRESS, _mapped_ipv4("198.51.100.1", 1111)) + _attribute(
        ATTR_XOR_MAPPED_ADDRESS, _xor_mapped_ipv4("203.0.113.9", 2222)
    )
    data = _response(BINDING_SUCCESS, txid, body)

    result = parse_binding_response(data, txid)
    assert result.ip == "203.0.113.9"
    assert result.port == 2222


def test_parse_xor_mapped_address_ipv6_round_trip() -> None:
    _, txid = build_binding_request()
    body = _attribute(ATTR_XOR_MAPPED_ADDRESS, _xor_mapped_ipv6("2001:db8::1", 9000, txid))
    data = _response(BINDING_SUCCESS, txid, body)

    result = parse_binding_response(data, txid)
    assert result.family == FAMILY_IPV6
    assert result.port == 9000
    assert socket.inet_pton(socket.AF_INET6, result.ip) == socket.inet_pton(
        socket.AF_INET6, "2001:db8::1"
    )


def test_transaction_id_mismatch_is_rejected() -> None:
    _, txid = build_binding_request()
    body = _attribute(ATTR_XOR_MAPPED_ADDRESS, _xor_mapped_ipv4("203.0.113.7", 51234))
    data = _response(BINDING_SUCCESS, b"\x01" * 12, body)
    with pytest.raises(StunError, match="transaction id mismatch"):
        parse_binding_response(data, txid)


def test_bad_magic_cookie_is_rejected() -> None:
    _, txid = build_binding_request()
    body = _attribute(ATTR_XOR_MAPPED_ADDRESS, _xor_mapped_ipv4("203.0.113.7", 51234))
    data = struct.pack("!HH", BINDING_SUCCESS, len(body)) + b"\x00\x00\x00\x00" + txid + body
    with pytest.raises(StunError, match="magic cookie"):
        parse_binding_response(data, txid)


def test_binding_error_response_is_rejected() -> None:
    _, txid = build_binding_request()
    data = _response(BINDING_ERROR, txid, b"")
    with pytest.raises(StunError, match="Error Response"):
        parse_binding_response(data, txid)


def test_missing_mapped_address_is_rejected() -> None:
    _, txid = build_binding_request()
    data = _response(BINDING_SUCCESS, txid, b"")
    with pytest.raises(StunError, match="no MAPPED-ADDRESS"):
        parse_binding_response(data, txid)
