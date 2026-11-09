"""Workstation controller over the operating system's OpenSSH client.

OpenSSH verifies the host key and performs user authentication. No service or
password is managed by SecureLink. The remote endpoint runs only for a single
SSH request, while the separately started worker owns job execution.
"""
from __future__ import annotations

import base64
import json
import re
import shutil
import subprocess
from typing import Any


class RemoteError(RuntimeError):
    pass


def request(target: str, project_path: str, method: str, params: dict[str, Any] | None = None,
            *, port: int = 22, timeout: float = 30) -> dict[str, Any]:
    """Send one JSON request to a remote Windows or Unix SSH account."""
    if not isinstance(target, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+(?:@[A-Za-z0-9_.-]+)?", target):
        raise RemoteError("target must be a hostname or user@hostname")
    if target.startswith("-") or "@-" in target:
        raise RemoteError("invalid SSH target")
    if not isinstance(project_path, str) or not project_path.strip() or len(project_path) > 2048:
        raise RemoteError("remote project path is required")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise RemoteError("SSH port must be between 1 and 65535")
    if not isinstance(method, str) or not method or not isinstance(params or {}, dict):
        raise RemoteError("invalid request")
    ssh = shutil.which("ssh")
    if not ssh:
        raise RemoteError("OpenSSH client was not found")
    encoded = base64.b64encode(project_path.encode("utf-8")).decode("ascii")
    # Path is base64, not interpolated shell code; the Python program is fixed.
    code = ("import base64,os,runpy;"
            f"os.chdir(base64.b64decode('{encoded}').decode('utf-8'));"
            "runpy.run_module('ui.remote_worker',run_name='__main__')")
    remote_command = f'python -c "{code}"'
    body = json.dumps({"method": method, "params": params or {}}, allow_nan=False).encode("utf-8")
    if len(body) > 12 * 1024 * 1024:
        raise RemoteError("request is too large")
    try:
        result = subprocess.run(
            [ssh, "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
             "-o", "ConnectTimeout=10", "-p", str(port), target, remote_command],
            input=body, capture_output=True, timeout=timeout, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RemoteError(f"SSH connection failed: {exc}") from exc
    if result.returncode:
        raise RemoteError("SSH request failed: " + result.stderr.decode("utf-8", "replace")[-2000:])
    if len(result.stdout) > 12 * 1024 * 1024:
        raise RemoteError("remote response is too large")
    try:
        response = json.loads(result.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RemoteError("remote workstation returned invalid JSON") from exc
    if not isinstance(response, dict) or response.get("ok") is not True:
        raise RemoteError(str(response.get("error", "remote request failed")) if isinstance(response, dict)
                          else "remote workstation returned invalid response")
    if not isinstance(response.get("result"), dict):
        raise RemoteError("remote workstation returned invalid result")
    return response["result"]
