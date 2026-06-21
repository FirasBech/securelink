"""SecureLink cryptography module.

Provides:
  - X25519 ephemeral key exchange (one fresh keypair per session)
  - HKDF-SHA256 session key derivation
  - AES-256-GCM authenticated encryption / decryption per chunk
  - HMAC-SHA256 header signing (used by capsule layer)
  - Secure random helpers

All public functions raise CryptoError on any failure.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# Constants.
AES_KEY_LEN = 32
HMAC_KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
HMAC_LEN = 32
X25519_PUB_LEN = 32
SESSION_INFO = b"securelink-v1"
LAN_OVERHEAD_BYTES = 54  # Ethernet (14) + IP (20) + TCP (20)


class CryptoError(Exception):
    """Raised on any cryptographic failure (decrypt, HMAC, bad key, etc.)."""


@dataclass
class SessionKeys:
    """Derived key material for one transfer session."""

    aes_key: bytes
    hmac_key: bytes
    salt: bytes | None = None

    def __post_init__(self) -> None:
        if len(self.aes_key) != AES_KEY_LEN:
            raise CryptoError(f"aes_key must be {AES_KEY_LEN} bytes")
        if len(self.hmac_key) != HMAC_KEY_LEN:
            raise CryptoError(f"hmac_key must be {HMAC_KEY_LEN} bytes")

class KeyExchange:
    """Ephemeral X25519 Diffie-Hellman key exchange."""

    def __init__(self) -> None:
        try:
            self._private_key: X25519PrivateKey = X25519PrivateKey.generate()
        except Exception as exc:
            raise CryptoError(f"failed to generate X25519 key pair: {exc}") from exc
        self._used = False

    def public_bytes(self) -> bytes:
        """Return raw 32-byte public key to send to the peer."""

        try:
            return self._private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        except Exception as exc:
            raise CryptoError(f"failed to serialize X25519 public key: {exc}") from exc

    def derive(self, peer_public_bytes: bytes, *, salt: bytes | None = None, info: bytes = SESSION_INFO) -> SessionKeys:
        """Complete the exchange with the peer's public key."""

        if self._used:
            raise CryptoError("KeyExchange.derive() called more than once on same instance")
        if len(peer_public_bytes) != X25519_PUB_LEN:
            raise CryptoError(
                f"Peer public key must be {X25519_PUB_LEN} bytes, got {len(peer_public_bytes)}"
            )

        self._used = True

        try:
            peer_pub = X25519PublicKey.from_public_bytes(peer_public_bytes)
            shared_secret = self._private_key.exchange(peer_pub)
        except Exception as exc:
            raise CryptoError(f"X25519 exchange failed: {exc}") from exc

        return derive_session_keys(shared_secret, salt=salt, info=info)


def _derive_key_material(shared_secret: bytes, *, salt: bytes | None = None, info: bytes = SESSION_INFO) -> bytes:
    try:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_LEN + HMAC_KEY_LEN,
            salt=salt,
            info=info,
        ).derive(shared_secret)
    except Exception as exc:
        raise CryptoError(f"HKDF derivation failed: {exc}") from exc


def derive_session_keys(shared_secret: bytes, *, salt: bytes | None = None, info: bytes = SESSION_INFO) -> SessionKeys:
    """Derive the AES and HMAC keys from a raw shared secret."""

    key_material = _derive_key_material(shared_secret, salt=salt, info=info)
    return SessionKeys(
        aes_key=key_material[:AES_KEY_LEN],
        hmac_key=key_material[AES_KEY_LEN:],
        salt=salt,
    )



# AES-256-GCM chunk encryption.
def encrypt_chunk(plaintext: bytes, aes_key: bytes) -> tuple[bytes, bytes]:
    if len(aes_key) != AES_KEY_LEN:
        raise CryptoError(f"AES key must be {AES_KEY_LEN} bytes")

    nonce = os.urandom(NONCE_LEN)

    try:
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    except Exception as exc:
        raise CryptoError(f"AES-GCM encrypt failed: {exc}") from exc

    return nonce, ciphertext


def decrypt_chunk(nonce: bytes, ciphertext: bytes, aes_key: bytes) -> bytes:
    if len(aes_key) != AES_KEY_LEN:
        raise CryptoError(f"AES key must be {AES_KEY_LEN} bytes")
    if len(nonce) != NONCE_LEN:
        raise CryptoError(f"Nonce must be {NONCE_LEN} bytes")

    try:
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag:
        raise CryptoError("AES-GCM auth tag invalid - chunk may be tampered")
    except Exception as exc:
        raise CryptoError(f"AES-GCM decrypt failed: {exc}") from exc


# HMAC-SHA256 capsule signing.
def sign_header(header_bytes: bytes, hmac_key: bytes) -> bytes:
    if len(hmac_key) != HMAC_KEY_LEN:
        raise CryptoError(f"HMAC key must be {HMAC_KEY_LEN} bytes")
    try:
        return hmac.new(hmac_key, header_bytes, hashlib.sha256).digest()
    except Exception as exc:
        raise CryptoError(f"HMAC signing failed: {exc}") from exc


def verify_header(header_bytes: bytes, signature: bytes, hmac_key: bytes) -> None:
    if len(hmac_key) != HMAC_KEY_LEN:
        raise CryptoError(f"HMAC key must be {HMAC_KEY_LEN} bytes")
    if len(signature) != HMAC_LEN:
        raise CryptoError(f"Signature must be {HMAC_LEN} bytes")

    expected = sign_header(header_bytes, hmac_key)
    if not hmac.compare_digest(expected, signature):
        raise CryptoError("HMAC verification failed - header may be tampered")


# Secure random helpers.
def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def random_session_id() -> bytes:
    return os.urandom(16)



# MTU compatibility helpers used by the existing tests/transport.
def lan_chunk_size(mtu: int = 1500) -> int:
    return max(1, mtu - LAN_OVERHEAD_BYTES)


if __name__ == "__main__":
    print("Running crypto self-test...\n")

    print("[1] X25519 key exchange")
    kex_a = KeyExchange()
    kex_b = KeyExchange()
    keys_a = kex_a.derive(kex_b.public_bytes())
    keys_b = kex_b.derive(kex_a.public_bytes())
    assert keys_a.aes_key == keys_b.aes_key
    assert keys_a.hmac_key == keys_b.hmac_key
    print("    OK")

    print("[2] AES-256-GCM encrypt / decrypt")
    plaintext = b"Hello, SecureLink! " * 100
    nonce, ciphertext = encrypt_chunk(plaintext, keys_a.aes_key)
    recovered = decrypt_chunk(nonce, ciphertext, keys_b.aes_key)
    assert recovered == plaintext
    print("    OK")

    print("[3] Tamper detection")
    tampered = bytearray(ciphertext)
    tampered[4] ^= 0xFF
    try:
        decrypt_chunk(nonce, bytes(tampered), keys_a.aes_key)
        raise AssertionError("tamper not detected")
    except CryptoError:
        print("    OK")

    print("[4] HMAC header sign / verify")
    header = struct.pack("!HHI", 0x2000, 0x0800, 42)
    sig = sign_header(header, keys_a.hmac_key)
    verify_header(header, sig, keys_b.hmac_key)
    print("    OK")

    print("[5] KeyExchange single-use enforcement")
    try:
        kex_a.derive(kex_b.public_bytes())
        raise AssertionError("second derive not blocked")
    except CryptoError:
        print("    OK")

    print("\nAll tests passed.")
