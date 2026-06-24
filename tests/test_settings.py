from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from core.settings import Settings, SettingsError, parse_host_port


def test_parse_host_port_valid() -> None:
    assert parse_host_port("example.com:6000") == ("example.com", 6000)
    assert parse_host_port(" 1.2.3.4:55000 ") == ("1.2.3.4", 55000)


@pytest.mark.parametrize("bad", ["", "noport", "host:", "host:abc", "host:0", "host:70000", ":6000"])
def test_parse_host_port_invalid(bad: str) -> None:
    with pytest.raises(SettingsError):
        parse_host_port(bad)


def test_settings_default_is_empty(tmp_path: Path) -> None:
    settings = Settings.load(tmp_path)
    assert settings.rendezvous is None
    assert settings.relay is None
    assert settings.rendezvous_addr() is None
    assert settings.relay_addr() is None


def test_settings_round_trip(tmp_path: Path) -> None:
    settings = Settings(rendezvous="rdv.example:6000", relay="relay.example:6001")
    settings.save(tmp_path)
    assert Settings.path(tmp_path).exists()

    loaded = Settings.load(tmp_path)
    assert loaded.rendezvous == "rdv.example:6000"
    assert loaded.relay_addr() == ("relay.example", 6001)


def test_settings_ignore_garbage_file(tmp_path: Path) -> None:
    path = Settings.path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not json", encoding="utf-8")
    # A corrupt file degrades to defaults rather than crashing.
    assert Settings.load(tmp_path).rendezvous is None
