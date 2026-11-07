from __future__ import annotations

import pytest

import core.concurrent as concurrent
from core.concurrent import send_concurrent
from core.transport import TransportConfig, TransferStats


def _stats() -> TransferStats:
    return TransferStats(bytes_transferred=10, chunks=1, alerts=0, files=1)


def test_send_concurrent_empty_returns_empty() -> None:
    assert send_concurrent([]) == []


def test_send_concurrent_returns_stats_in_input_order(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str, int]] = []

    def fake_send_paths(paths, peer_host, *, config, **kwargs):
        calls.append((str(paths), peer_host, config.port))
        return _stats()

    monkeypatch.setattr(concurrent, "send_paths", fake_send_paths)

    items = [
        ("a.txt", "10.0.0.2", 55001),
        ("b.txt", "10.0.0.3", 55002),
        ("c.txt", "10.0.0.4", 55003),
    ]
    results = send_concurrent(items, max_workers=2)

    assert [result.bytes_transferred for result in results] == [10, 10, 10]
    assert len(calls) == 3
    assert calls == [
        ("a.txt", "10.0.0.2", 55001),
        ("b.txt", "10.0.0.3", 55002),
        ("c.txt", "10.0.0.4", 55003),
    ]


def test_send_concurrent_carries_base_config_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, TransportConfig] = {}

    def fake_send_paths(paths, peer_host, *, config, **kwargs):
        captured["config"] = config
        return _stats()

    monkeypatch.setattr(concurrent, "send_paths", fake_send_paths)

    send_concurrent(
        [("a.txt", "10.0.0.2", 55001)],
        config=TransportConfig(mode="wan"),
        max_workers=2,
    )
    assert captured["config"].mode == "wan"
    assert captured["config"].port == 55001


def test_send_concurrent_propagates_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_send_paths(paths, peer_host, *, config, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(concurrent, "send_paths", fake_send_paths)
    with pytest.raises(RuntimeError, match="boom"):
        send_concurrent([("a.txt", "10.0.0.2", 55001)], max_workers=2)
