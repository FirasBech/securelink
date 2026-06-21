from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SECURELINK_DIRNAME = ".securelink"
PRIVATE_KEY_FILENAME = "identity_ed25519.pem"
PUBLIC_KEY_FILENAME = "identity_ed25519.pub"
KNOWN_HOSTS_FILENAME = "known_hosts.json"


@dataclass(frozen=True)
class Identity:
    private_key: Ed25519PrivateKey
    public_key: bytes
    fingerprint: str


class TrustDecisionError(RuntimeError):
    pass


def securelink_dir(base_dir: Path | None = None) -> Path:
    return (base_dir or Path.home()) / SECURELINK_DIRNAME


def identity_paths(base_dir: Path | None = None) -> tuple[Path, Path]:
    root = securelink_dir(base_dir)
    return root / PRIVATE_KEY_FILENAME, root / PUBLIC_KEY_FILENAME


def known_hosts_path(base_dir: Path | None = None) -> Path:
    return securelink_dir(base_dir) / KNOWN_HOSTS_FILENAME


def device_fingerprint(public_key_bytes: bytes) -> str:
    return sha256(public_key_bytes).hexdigest()


def public_key_from_bytes(public_key_bytes: bytes) -> Ed25519PublicKey:
    if len(public_key_bytes) != 32:
        raise ValueError("Ed25519 public keys must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(public_key_bytes)


def serialize_private_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_public_key(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def load_or_create_identity(base_dir: Path | None = None) -> Identity:
    root = securelink_dir(base_dir)
    root.mkdir(parents=True, exist_ok=True)
    private_key_path, public_key_path = identity_paths(base_dir)

    if private_key_path.exists():
        private_key = serialization.load_pem_private_key(
            private_key_path.read_bytes(),
            password=None,
        )
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("stored identity is not an Ed25519 private key")
    else:
        private_key = Ed25519PrivateKey.generate()
        private_key_path.write_bytes(serialize_private_key(private_key))

    public_key = serialize_public_key(private_key.public_key())
    public_key_path.write_bytes(base64.b64encode(public_key))
    return Identity(private_key=private_key, public_key=public_key, fingerprint=device_fingerprint(public_key))


def load_known_hosts(base_dir: Path | None = None) -> dict[str, dict[str, Any]]:
    path = known_hosts_path(base_dir)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def save_known_hosts(hosts: dict[str, dict[str, Any]], base_dir: Path | None = None) -> None:
    path = known_hosts_path(base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(hosts, indent=2, sort_keys=True), encoding="utf-8")


def record_known_host(
    public_key_bytes: bytes,
    *,
    base_dir: Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> str:
    hosts = load_known_hosts(base_dir)
    fingerprint = device_fingerprint(public_key_bytes)
    hosts[fingerprint] = {
        "public_key": base64.b64encode(public_key_bytes).decode("ascii"),
        "metadata": metadata or {},
    }
    save_known_hosts(hosts, base_dir)
    return fingerprint


def verify_signature(public_key_bytes: bytes, signature: bytes, message: bytes) -> bool:
    public_key = public_key_from_bytes(public_key_bytes)
    try:
        public_key.verify(signature, message)
    except Exception:
        return False
    return True


def sign_message(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    return private_key.sign(message)


def confirm_or_record_remote_device(
    public_key_bytes: bytes,
    *,
    allow_unknown: bool = False,
    base_dir: Path | None = None,
    confirmer: Callable[[str], bool] | None = None,
    metadata: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    fingerprint = device_fingerprint(public_key_bytes)
    hosts = load_known_hosts(base_dir)
    if fingerprint in hosts:
        return True, fingerprint

    if allow_unknown:
        record_known_host(public_key_bytes, base_dir=base_dir, metadata={**(metadata or {}), "trusted": False})
        return True, fingerprint

    if confirmer is None:
        raise TrustDecisionError(f"unknown device fingerprint {fingerprint}")

    if confirmer(fingerprint):
        record_known_host(public_key_bytes, base_dir=base_dir, metadata={**(metadata or {}), "trusted": True})
        return True, fingerprint

    return False, fingerprint
