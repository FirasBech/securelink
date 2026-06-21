"""SecureLink GRE capsule layer.

Wire format (big-endian):

  GRE Header (8 bytes)
    flags    2 bytes  (0x2000 = checksum-present)
    protocol 2 bytes  (0x0800 = IPv4 payload)
    chunk_id 4 bytes   (monotonic sequence number)
  HMAC-SHA256 32 bytes over (header + nonce + ciphertext)
  AES-GCM nonce 12 bytes
  Ciphertext N bytes (AES-256-GCM tag appended)

All public functions raise CapsuleError on any failure.
"""

from __future__ import annotations

import hashlib
import hmac as stdlib_hmac
import struct
from dataclasses import dataclass

from .crypto import (
    CryptoError,
    HMAC_LEN,
    NONCE_LEN,
    SessionKeys,
    decrypt_chunk,
    encrypt_chunk,
    sign_header,
    verify_header,
)


GRE_FLAGS_CHECKSUM_PRESENT = 0x2000
GRE_PROTOCOL_IPV4 = 0x0800
GRE_FLAG_CHECKSUM = GRE_FLAGS_CHECKSUM_PRESENT
GRE_PROTO_IPV4 = GRE_PROTOCOL_IPV4
GRE_HEADER_SIZE = 8
HMAC_SIZE = HMAC_LEN
SEQUENCE_SIZE = 4
CAPSULE_PREFIX = GRE_HEADER_SIZE + HMAC_SIZE + NONCE_LEN
MIN_CAPSULE_SIZE = CAPSULE_PREFIX
DEFAULT_WINDOW = 128
GRE_OVERHEAD = CAPSULE_PREFIX
AES_TAG_LEN = 16
IP_HEADER = 20
TCP_HEADER = 20


class CapsuleError(RuntimeError):
    """Raised on any capsule-layer failure."""


class SequenceError(CapsuleError):
    pass


class HmacVerificationError(CapsuleError):
    pass


@dataclass(frozen=True)
class CapsuleMetadata:
    chunk_id: int
    sequence: int
    nonce: bytes
    header: bytes


class SequenceTracker:
    """Per-session sequence number enforcer."""

    def __init__(self, window_size: int = DEFAULT_WINDOW, strict: bool = False) -> None:
        self._next_expected = 0
        self._seen: set[int] = set()
        self._window = window_size
        self._strict = strict

    def check(self, chunk_id: int) -> None:
        if chunk_id in self._seen:
            raise SequenceError(f"Replay attack detected - chunk_id {chunk_id} already received")

        if self._strict and chunk_id != self._next_expected:
            raise SequenceError(
                f"Strict sequence violation - expected {self._next_expected}, got {chunk_id}"
            )

        if chunk_id < self._next_expected:
            raise SequenceError(f"Late chunk - expected >= {self._next_expected}, got {chunk_id}")

        if chunk_id > self._next_expected + self._window:
            raise SequenceError(
                f"Sequence gap too large - expected {self._next_expected}, got {chunk_id} (window={self._window})"
            )

        self._seen.add(chunk_id)
        while self._next_expected in self._seen:
            self._next_expected += 1

        cutoff = self._next_expected - self._window
        self._seen = {sequence for sequence in self._seen if sequence >= cutoff}

    def validate(self, chunk_id: int) -> None:
        self.check(chunk_id)

    @property
    def next_expected(self) -> int:
        return self._next_expected

    def reset(self) -> None:
        self._next_expected = 0
        self._seen.clear()


# GRE header helpers.
def _pack_header(chunk_id: int) -> bytes:
    try:
        return struct.pack("!HHI", GRE_FLAGS_CHECKSUM_PRESENT, GRE_PROTOCOL_IPV4, chunk_id)
    except struct.error as exc:
        raise CapsuleError(f"invalid chunk_id {chunk_id}") from exc


def _unpack_header(data: bytes) -> tuple[int, int, int]:
    if len(data) < GRE_HEADER_SIZE:
        raise CapsuleError(f"Header too short: {len(data)} < {GRE_HEADER_SIZE}")
    try:
        flags, protocol, chunk_id = struct.unpack("!HHI", data[:GRE_HEADER_SIZE])
    except struct.error as exc:
        raise CapsuleError(f"invalid GRE header: {exc}") from exc
    return flags, protocol, chunk_id


build_gre_header = _pack_header
parse_gre_header = _unpack_header


def compute_hmac(hmac_key: bytes, payload: bytes) -> bytes:
    try:
        return stdlib_hmac.new(hmac_key, payload, hashlib.sha256).digest()
    except Exception as exc:
        raise CapsuleError(f"HMAC computation failed: {exc}") from exc


def _decode_capsule(
    capsule: bytes,
    *,
    session_keys: SessionKeys,
    tracker: SequenceTracker | None = None,
) -> tuple[int, bytes, bytes, bytes]:
    if len(capsule) < MIN_CAPSULE_SIZE:
        raise CapsuleError("capsule is too short")

    header = capsule[:GRE_HEADER_SIZE]
    capsule_hmac = capsule[GRE_HEADER_SIZE : GRE_HEADER_SIZE + HMAC_SIZE]
    nonce_start = GRE_HEADER_SIZE + HMAC_SIZE
    nonce = capsule[nonce_start : nonce_start + NONCE_LEN]
    ciphertext = capsule[nonce_start + NONCE_LEN :]

    expected_hmac = compute_hmac(session_keys.hmac_key, header + nonce + ciphertext)
    if not stdlib_hmac.compare_digest(expected_hmac, capsule_hmac):
        raise HmacVerificationError("invalid HMAC on received capsule")

    flags, protocol, chunk_id = _unpack_header(header)
    if flags != GRE_FLAGS_CHECKSUM_PRESENT or protocol != GRE_PROTOCOL_IPV4:
        raise CapsuleError("unsupported GRE capsule header")

    if tracker is not None:
        tracker.check(chunk_id)

    try:
        plaintext = decrypt_chunk(nonce, ciphertext, session_keys.aes_key)
    except CryptoError as exc:
        raise CapsuleError(f"Decryption failed: {exc}") from exc

    return chunk_id, plaintext, nonce, header


def build_capsule(
    plaintext: bytes,
    chunk_id: int,
    session_keys: SessionKeys,
) -> bytes:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise CapsuleError("plaintext must be bytes")
    if chunk_id < 0 or chunk_id > 0xFFFFFFFF:
        raise CapsuleError(f"chunk_id out of range: {chunk_id}")

    try:
        nonce, ciphertext = encrypt_chunk(bytes(plaintext), session_keys.aes_key)
    except CryptoError as exc:
        raise CapsuleError(f"Encryption failed: {exc}") from exc

    header = _pack_header(chunk_id)
    mac_input = header + nonce + ciphertext
    try:
        signature = sign_header(mac_input, session_keys.hmac_key)
    except CryptoError as exc:
        raise CapsuleError(f"HMAC signing failed: {exc}") from exc

    return header + signature + nonce + ciphertext


def parse_capsule(
    data: bytes,
    session_keys: SessionKeys,
    *,
    tracker: SequenceTracker | None = None,
) -> tuple[int, bytes]:
    chunk_id, plaintext, _, _ = _decode_capsule(data, session_keys=session_keys, tracker=tracker)
    return chunk_id, plaintext


def unwrap_capsule(
    capsule: bytes,
    session_keys: SessionKeys,
    *,
    tracker: SequenceTracker | None = None,
) -> tuple[bytes, CapsuleMetadata]:
    chunk_id, plaintext, nonce, header = _decode_capsule(
        capsule,
        session_keys=session_keys,
        tracker=tracker,
    )
    return plaintext, CapsuleMetadata(chunk_id=chunk_id, sequence=chunk_id, nonce=nonce, header=header)


# Chunk helpers.
def chunk_file(data: bytes, chunk_size: int) -> list[bytes]:
    if chunk_size < 1:
        raise CapsuleError(f"chunk_size must be >= 1, got {chunk_size}")
    return [data[index : index + chunk_size] for index in range(0, len(data), chunk_size)]


def reassemble(chunks: list[bytes]) -> bytes:
    return b"".join(chunks)


# MTU-aware helpers.
def max_payload_for_mtu(mtu: int) -> int:
    payload = mtu - IP_HEADER - TCP_HEADER - GRE_OVERHEAD - AES_TAG_LEN
    if payload < 1:
        raise CapsuleError(f"MTU {mtu} too small for capsule overhead")
    return payload


MTU_LAN = max_payload_for_mtu(9000)


if __name__ == "__main__":
    from .crypto import KeyExchange

    print("Running capsule self-test...\n")

    kex_a = KeyExchange()
    kex_b = KeyExchange()
    keys = kex_a.derive(kex_b.public_bytes())
    _ = kex_b.derive(kex_a.public_bytes())

    tracker = SequenceTracker(strict=True)

    plaintext = b"SecureLink test payload " * 50
    capsule = build_capsule(plaintext, chunk_id=0, session_keys=keys)
    chunk_id, recovered = parse_capsule(capsule, keys)
    assert recovered == plaintext
    assert chunk_id == 0
    tracker.check(chunk_id)

    file_data = b"X" * 10_000
    chunks = chunk_file(file_data, MTU_LAN)
    tracker2 = SequenceTracker()
    capsules = [build_capsule(chunk, i + 1, keys) for i, chunk in enumerate(chunks)]
    recovered_chunks = []
    for cap in capsules:
        cid, plain = parse_capsule(cap, keys)
        tracker2.check(cid)
        recovered_chunks.append(plain)
    assert reassemble(recovered_chunks) == file_data

    cap = build_capsule(b"secret data", chunk_id=99, session_keys=keys)
    bad = bytearray(cap)
    bad[3] ^= 0x01
    try:
        parse_capsule(bytes(bad), keys)
        raise AssertionError("header tamper not detected")
    except CapsuleError:
        pass

    cap = build_capsule(b"another secret", chunk_id=100, session_keys=keys)
    bad = bytearray(cap)
    bad[-5] ^= 0xFF
    try:
        parse_capsule(bytes(bad), keys)
        raise AssertionError("ciphertext tamper not detected")
    except CapsuleError:
        pass

    strict = SequenceTracker(strict=True)
    strict.check(0)
    try:
        strict.check(2)
        raise AssertionError("sequence skip not detected")
    except CapsuleError:
        pass

    print("All tests passed.")
