"""User-controlled settings for SecureLink, stored at ``~/.securelink/settings.json``.

SecureLink bundles **no** servers. Internet (WAN) transfers can optionally use a
coordination server (a rendezvous matchmaker, and a relay for symmetric NATs),
but the user supplies their own — there is no default endpoint baked in. Every
field here is optional; an empty settings file means "LAN/VPN only, no
coordination server", which is the default.

The file is loaded/saved relative to a base directory (``~`` in normal use, a
temp dir in tests), mirroring the rest of the per-user state.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

SETTINGS_FILENAME = "settings.json"


class SettingsError(ValueError):
    """Raised when a user-entered value (e.g. host:port) is malformed."""


def parse_host_port(value: str) -> tuple[str, int]:
    """Parse ``"host:port"`` into ``(host, port)``. Raises ``SettingsError``."""
    text = value.strip()
    if not text or ":" not in text:
        raise SettingsError(f"expected host:port, got {value!r}")
    host, _, port_text = text.rpartition(":")
    host = host.strip()
    if not host:
        raise SettingsError(f"missing host in {value!r}")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise SettingsError(f"invalid port in {value!r}") from exc
    if not (0 < port < 65536):
        raise SettingsError(f"port out of range in {value!r}")
    return host, port


def _clean(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _int_or_none(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


@dataclass
class Settings:
    """Optional, user-supplied configuration. All fields default to unset."""

    rendezvous: str | None = None  # "host:port" of a rendezvous server (BYO)
    relay: str | None = None       # "host:port" of a relay server (BYO)
    stun_host: str | None = None   # override the default public STUN host
    stun_port: int | None = None

    @staticmethod
    def path(base_dir: Path | None = None) -> Path:
        return (base_dir or Path.home()) / ".securelink" / SETTINGS_FILENAME

    @classmethod
    def load(cls, base_dir: Path | None = None) -> "Settings":
        path = cls.path(base_dir)
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls()
        if not isinstance(data, dict):
            return cls()
        return cls(
            rendezvous=_clean(data.get("rendezvous")),
            relay=_clean(data.get("relay")),
            stun_host=_clean(data.get("stun_host")),
            stun_port=_int_or_none(data.get("stun_port")),
        )

    def save(self, base_dir: Path | None = None) -> None:
        path = self.path(base_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.as_dict(), indent=2), encoding="utf-8")

    def as_dict(self) -> dict[str, object]:
        return {
            "rendezvous": self.rendezvous,
            "relay": self.relay,
            "stun_host": self.stun_host,
            "stun_port": self.stun_port,
        }

    # --- convenience accessors that validate on use -----------------------

    def rendezvous_addr(self) -> tuple[str, int] | None:
        return parse_host_port(self.rendezvous) if self.rendezvous else None

    def relay_addr(self) -> tuple[str, int] | None:
        return parse_host_port(self.relay) if self.relay else None
