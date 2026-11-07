"""Durable transfer history / receipts.

Append-only JSONL of completed (or failed) transfers so agents and operators can
query what happened, when, in which direction, over which transport, and with
what outcome — complementing the human-readable security log.

Bounded to the most recent ``MAX_RECORDS`` entries.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HISTORY_FILENAME = "history.jsonl"
MAX_RECORDS = 500


class HistoryError(RuntimeError):
    """Raised on history read/write failure."""


@dataclass(frozen=True)
class TransferRecord:
    timestamp: str
    direction: str  # "send" | "recv"
    file: str
    bytes_transferred: int
    chunks: int
    status: str  # "ok" | "failed"
    mode: str | None = None
    peer: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "direction": self.direction,
            "file": self.file,
            "bytes_transferred": self.bytes_transferred,
            "chunks": self.chunks,
            "status": self.status,
            "mode": self.mode,
            "peer": self.peer,
            "error": self.error,
        }


def _history_path(base_dir: Path | None = None) -> Path:
    return (base_dir or Path.home()) / ".securelink" / HISTORY_FILENAME


def record_transfer(record: TransferRecord, base_dir: Path | None = None) -> None:
    """Append one transfer record to the JSONL history."""

    path = _history_path(base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = record.to_dict()
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
        handle.flush()


def list_transfers(base_dir: Path | None = None, limit: int = 100) -> list[dict[str, Any]]:
    """Return the most recent ``limit`` transfer records (oldest-first slice)."""

    path = _history_path(base_dir)
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise HistoryError(f"failed to read transfer history: {exc}") from exc
    for line in lines:
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            records.append(payload)
    return records[-limit:]
