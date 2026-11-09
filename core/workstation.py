"""Read-only local workstation inventory for users and agent integrations.

This module does not start agents, install software, or expose a network service.
Executable detection only means that a command is on PATH; it does not establish
that a provider is authenticated or ready to run tasks.
"""
from __future__ import annotations

import csv
import os
import platform
import shutil
import socket
import subprocess
from typing import Any


TOOL_COMMANDS = {
    "blender": "blender",
    "claude": "claude",
    "codex": "codex",
    "ollama": "ollama",
    "opencode": "opencode",
}


def _number(value: str) -> int | None:
    try:
        return int(value.strip())
    except ValueError:
        return None


def nvidia_gpus() -> dict[str, Any]:
    """Query NVIDIA's local management utility, without initializing a workload."""
    command = shutil.which("nvidia-smi")
    if not command:
        return {"available": False, "gpus": [], "message": "NVIDIA monitoring tool not found on PATH."}
    try:
        result = subprocess.run(
            [command, "--query-gpu=index,uuid,name,memory.total,memory.free,utilization.gpu",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=5, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "gpus": [], "message": "NVIDIA GPU query unavailable or timed out."}
    if result.returncode:
        return {"available": False, "gpus": [], "message": "NVIDIA GPU query failed; check the driver."}

    gpus = []
    for row in csv.reader(result.stdout.splitlines(), skipinitialspace=True):
        if len(row) != 6 or _number(row[0]) is None:
            continue
        gpus.append({"index": _number(row[0]), "uuid": row[1].strip(), "name": row[2].strip(),
                     "memory_total_mib": _number(row[3]), "memory_free_mib": _number(row[4]),
                     "utilization_percent": _number(row[5])})
    if not gpus:
        return {"available": False, "gpus": [], "message": "No NVIDIA GPU information returned."}
    return {"available": True, "gpus": gpus, "message": None}


def local_inventory() -> dict[str, Any]:
    """Return a snapshot of this machine; detection does not imply readiness."""
    return {
        "name": socket.gethostname(),
        "platform": {"system": platform.system(), "release": platform.release(),
                     "architecture": platform.machine()},
        "logical_cpus": os.cpu_count(),
        "gpu": nvidia_gpus(),
        "tools": {name: {"detected_on_path": shutil.which(command) is not None}
                  for name, command in TOOL_COMMANDS.items()},
    }
