from __future__ import annotations

import json
from pathlib import Path

from core.history import HistoryError, TransferRecord, list_transfers, record_transfer


def _record(direction: str = "send", status: str = "ok") -> TransferRecord:
    return TransferRecord(
        timestamp="2026-11-07T10:00:00+00:00",
        direction=direction,
        file="report.pdf",
        bytes_transferred=1024,
        chunks=1,
        status=status,
        mode="lan",
        peer="192.168.1.20:55000",
        error=None,
    )


def test_record_and_list_round_trip(tmp_path: Path) -> None:
    base = tmp_path / "sec"
    record_transfer(_record(), base_dir=base)
    record_transfer(_record(direction="recv", status="failed"), base_dir=base)

    records = list_transfers(base_dir=base, limit=10)
    assert len(records) == 2
    assert records[0]["status"] == "ok"
    assert records[1]["status"] == "failed"
    assert records[0]["direction"] == "send"


def test_list_transfers_empty_when_no_history(tmp_path: Path) -> None:
    assert list_transfers(base_dir=tmp_path / "sec", limit=10) == []


def test_list_transfers_invalid_json_is_skipped(tmp_path: Path) -> None:
    path = tmp_path / "sec" / "history.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json}\n", encoding="utf-8")
    assert list_transfers(base_dir=tmp_path / "sec", limit=10) == []


def test_list_transfers_error_on_unreadable(tmp_path: Path) -> None:
    # A directory where the history file should be -> read fails -> HistoryError.
    path = tmp_path / "sec" / ".securelink" / "history.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir()
    try:
        list_transfers(base_dir=tmp_path / "sec", limit=10)
        raise AssertionError("expected HistoryError")
    except HistoryError:
        pass
