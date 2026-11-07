"""Incremental (delta) transfers: send only the changed blocks vs. a base file.

A delta transfer compares a target file against a base file (the peer's previously
known content) and sends only the blocks that differ, so unchanged regions are not
re-transmitted. The receiver applies the delta to the base content to rebuild the
target.

Block-based diff with fixed block size; the sender declares nothing extra beyond the
changed blocks, and the receiver overlays them.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path


class DeltaError(RuntimeError):
    """Raised on delta computation / application failure."""


@dataclass(frozen=True)
class DeltaBlock:
    offset: int
    data: bytes


def compute_delta(base: bytes, target: bytes, block_size: int = 65536) -> list[DeltaBlock]:
    """Return the list of changed blocks of ``target`` relative to ``base``.

    Blocks are compared at identical offsets. A block is "changed" when its bytes
    differ from the base (or when the base is shorter than the block). Unchanged
    blocks are omitted, so only real changes are transmitted.
    """

    blocks: list[DeltaBlock] = []
    if not target:
        return blocks
    n_blocks = max(1, math.ceil(len(target) / block_size)) if target else 0
    for index in range(n_blocks):
        offset = index * block_size
        chunk = target[offset : offset + block_size]
        base_chunk = base[offset : offset + block_size] if offset < len(base) else b""
        if chunk != base_chunk:
            blocks.append(DeltaBlock(offset=offset, data=chunk))
    return blocks


def apply_delta(base: bytes, blocks: list[DeltaBlock]) -> bytes:
    """Apply a delta (changed blocks) to ``base`` and return the new content."""

    out = bytearray(base)
    for block in blocks:
        start = block.offset
        end = start + len(block.data)
        if end > len(out):
            out.extend(bytes(end - len(out)))
        out[start:end] = block.data
    return bytes(out)


def file_delta(path: Path, base_path: Path, block_size: int = 65536) -> tuple[bytes, list[DeltaBlock]]:
    """Compute the delta from ``base_path`` to the file at ``path``."""

    target = path.read_bytes()
    base = base_path.read_bytes() if base_path.exists() else b""
    return target, compute_delta(base, target, block_size)
