from __future__ import annotations

from core.capsule import (
    MTU_LAN,
    SequenceTracker,
    build_capsule,
    chunk_file,
    max_payload_for_mtu,
    parse_capsule,
    reassemble,
)
from core.crypto import KeyExchange, lan_chunk_size, random_session_id


def test_key_exchange_and_capsule_round_trip() -> None:
    kex_a = KeyExchange()
    kex_b = KeyExchange()
    session_keys_a = kex_a.derive(kex_b.public_bytes())
    session_keys_b = kex_b.derive(kex_a.public_bytes())

    assert session_keys_a.aes_key == session_keys_b.aes_key
    assert session_keys_a.hmac_key == session_keys_b.hmac_key

    plaintext = b"securelink payload"
    capsule = build_capsule(plaintext, chunk_id=7, session_keys=session_keys_a)
    recovered_chunk_id, recovered = parse_capsule(capsule, session_keys_a)

    assert recovered == plaintext
    assert recovered_chunk_id == 7


def test_sequence_tracker_and_chunk_helpers() -> None:
    tracker = SequenceTracker(strict=True)
    tracker.check(0)

    try:
        tracker.check(2)
    except Exception:
        pass
    else:
        raise AssertionError("sequence skip should be rejected")

    payload = b"x" * 100
    chunks = chunk_file(payload, 33)
    assert reassemble(chunks) == payload


