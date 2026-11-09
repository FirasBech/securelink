"""Workstation controller over the operating system's OpenSSH client.

OpenSSH verifies the host key and performs user authentication. No service or
password is managed by SecureLink. The remote endpoint runs only for a single
SSH request, while the separately started worker owns job execution.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any


class RemoteError(RuntimeError):
    pass


def request(target: str, project_path: str, method: str, params: dict[str, Any] | None = None,
            *, port: int = 22, timeout: float = 30) -> dict[str, Any]:
    """Send one JSON request to a remote Windows or Unix SSH account."""
    if not isinstance(target, str) or target.count("@") > 1:
        raise RemoteError("target must be a hostname or user@hostname")
    user, separator, host = target.partition("@")
    if not separator:
        host, user = user, ""
    if (separator and not user) or (user and (not re.fullmatch(r"[A-Za-z0-9_.-]+", user) or user.startswith("-"))):
        raise RemoteError("invalid SSH username")
    try:
        valid_host = bool(re.fullmatch(r"[A-Za-z0-9_.-]+", host)) or bool(ipaddress.IPv6Address(host))
    except ValueError:
        valid_host = False
    if not valid_host or host.startswith("-"):
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
    request_params = dict(params or {})
    # An explicit ID lets callers reconcile an uncertain SSH response without
    # submitting a second job. Never mutate the caller's dictionary.
    if method == "jobs.submit" and not request_params.get("job_id"):
        request_params["job_id"] = str(uuid.uuid4())
    submitted_id = request_params.get("job_id") if method == "jobs.submit" else None
    body = json.dumps({"method": method, "params": request_params}, allow_nan=False).encode("utf-8")
    if len(body) > 12 * 1024 * 1024:
        raise RemoteError("request is too large")
    options = [ssh, "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", "ConnectTimeout=10", "-p", str(port)]
    # Use the optional dedicated key in addition to the user's existing SSH
    # identities. Host key verification remains the responsibility of OpenSSH.
    identity = Path.home() / ".ssh" / "securelink_workstation_ed25519"
    if identity.is_file():
        options.extend(["-i", str(identity)])
    try:
        result = subprocess.run(
            [*options, target, remote_command],
            input=body, capture_output=True, timeout=timeout, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        detail = f"SSH connection failed: {exc}"
        if submitted_id:
            detail += f"; submission outcome unknown for job {submitted_id}; check jobs.get before retrying"
        raise RemoteError(detail) from exc
    if result.returncode:
        detail = "SSH request failed: " + result.stderr.decode("utf-8", "replace")[-2000:]
        if submitted_id:
            detail += f"; submission outcome unknown for job {submitted_id}; check jobs.get before retrying"
        raise RemoteError(detail)
    if len(result.stdout) > 12 * 1024 * 1024:
        detail = "remote response is too large"
        if submitted_id:
            detail += f"; submission outcome unknown for job {submitted_id}; check jobs.get before retrying"
        raise RemoteError(detail)
    try:
        response = json.loads(result.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        detail = "remote workstation returned invalid JSON"
        if submitted_id:
            detail += f"; submission outcome unknown for job {submitted_id}; check jobs.get before retrying"
        raise RemoteError(detail) from exc
    if not isinstance(response, dict) or response.get("ok") is not True:
        raise RemoteError(str(response.get("error", "remote request failed")) if isinstance(response, dict)
                          else "remote workstation returned invalid response")
    if not isinstance(response.get("result"), dict):
        detail = "remote workstation returned invalid result"
        if submitted_id:
            detail += f"; submission outcome unknown for job {submitted_id}; check jobs.get before retrying"
        raise RemoteError(detail)
    return response["result"]
