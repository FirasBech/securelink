"""Concurrent transfer orchestration.

Runs multiple file transfers concurrently, each on its own reliable transport
session, via a small thread pool. Lets an agent / operator pipeline several
sends without waiting for each to finish serially.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Sequence

from core.transport import TransportConfig, TransferStats, send_paths


def send_concurrent(
    items: Sequence[tuple[str | Path, str, int]],
    *,
    config: TransportConfig | None = None,
    max_workers: int = 4,
) -> list[TransferStats]:
    """Send several transfers concurrently.

    ``items`` is a sequence of ``(paths, peer_host, peer_port)`` tuples, where
    ``paths`` is a file or folder to send and the peer address carries the port
    to dial. Each transfer runs on its own thread inside a worker pool, using
    its own transport session (fresh handshake per send).

    Returns the per-transfer stats in input order. If any transfer fails, the
    first exception encountered is propagated.
    """

    if not items:
        return []

    base_config = config or TransportConfig()
    workers = max(1, min(max_workers, len(items)))

    def _send(paths: str | Path, peer_host: str, peer_port: int) -> TransportStats:
        return send_paths(paths, peer_host, config=replace(base_config, port=peer_port))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(_send, paths, peer_host, peer_port)
            for paths, peer_host, peer_port in items
        ]
        return [future.result() for future in futures]
