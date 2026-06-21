from __future__ import annotations

from core.auth import confirm_or_record_remote_device, device_fingerprint, load_known_hosts, load_or_create_identity


def test_identity_persists_and_reuses_fingerprint(tmp_path) -> None:
    first = load_or_create_identity(tmp_path)
    second = load_or_create_identity(tmp_path)

    assert first.fingerprint == second.fingerprint
    assert first.public_key == second.public_key
    assert device_fingerprint(first.public_key) == first.fingerprint


def test_known_host_recording(tmp_path) -> None:
    identity = load_or_create_identity(tmp_path)
    accepted, fingerprint = confirm_or_record_remote_device(
        identity.public_key,
        allow_unknown=True,
        base_dir=tmp_path,
    )

    assert accepted is True
    assert fingerprint == identity.fingerprint
    known_hosts = load_known_hosts(tmp_path)
    assert fingerprint in known_hosts
