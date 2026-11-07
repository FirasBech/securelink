from __future__ import annotations

from pathlib import Path

from core.delta import DeltaBlock, apply_delta, compute_delta, file_delta


def test_compute_delta_empty_when_identical() -> None:
    assert compute_delta(b"hello world", b"hello world") == []


def test_compute_delta_finds_changed_blocks() -> None:
    base = b"A" * 10 + b"B" * 10
    target = b"A" * 10 + b"C" * 10
    blocks = compute_delta(base, target, block_size=8)
    # Block 0 (offset 0) is unchanged; block 1 (offset 8) differs; block 2 (offset 16) differs.
    assert [(b.offset, b.data) for b in blocks] == [(8, b"AACCCCCC"), (16, b"CCCC")]


def test_apply_delta_rebuilds_target() -> None:
    base = b"A" * 10 + b"B" * 10
    target = b"A" * 10 + b"C" * 10
    blocks = compute_delta(base, target, block_size=8)
    assert apply_delta(base, blocks) == target


def test_apply_delta_extends_when_base_shorter(tmp_path: Path) -> None:
    base = b"A" * 4
    target = b"A" * 4 + b"B" * 4
    blocks = compute_delta(base, target, block_size=8)
    assert apply_delta(base, blocks) == target


def test_file_delta_round_trip(tmp_path: Path) -> None:
    base_file = tmp_path / "base.bin"
    target_file = tmp_path / "target.bin"
    base_file.write_bytes(b"hello world")
    target_file.write_bytes(b"hello brave world")

    base_bytes = base_file.read_bytes()
    target_bytes = target_file.read_bytes()
    _target, blocks = file_delta(target_file, base_file)
    assert apply_delta(base_bytes, blocks) == target_bytes
