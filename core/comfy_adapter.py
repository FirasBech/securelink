"""Opt-in ComfyUI API adapter bound to one operator-selected NVIDIA GPU.

The operator starts and isolates the ComfyUI server separately. This adapter
does not download models, configure nodes, or start a server.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from core.agent_adapters import WorkloadStillRunning, workspace_path
from core.worker import WorkerCancelled, WorkerContext


class WorkflowRejected(ValueError):
    """A verified ComfyUI validation response says no prompt was queued."""


def _local_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.username or parsed.password or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment):
        raise ValueError("ComfyUI URL must be a local HTTP address without a path")
    return url.rstrip("/")


def _json_request(url: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    body = json.dumps(data, allow_nan=False).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"} if body else {})
    # Avoid configured HTTP proxies for the local-only backend.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=10) as response:
            raw = response.read(8 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as exc:
        if data is not None and 400 <= exc.code < 500:
            try:
                rejection = json.loads(exc.read(1024 * 1024 + 1))
            except (ValueError, UnicodeDecodeError):
                rejection = None
            if (isinstance(rejection, dict) and not rejection.get("prompt_id") and
                    (rejection.get("error") or rejection.get("node_errors"))):
                raise WorkflowRejected("ComfyUI rejected the workflow: " +
                                       str(rejection.get("error") or rejection.get("node_errors"))) from exc
        raise
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("ComfyUI response is too large")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("invalid ComfyUI response")
    return value


def comfy_adapter(workspace: Path, url: str, gpu_uuid: str, *, poll_interval: float = 2,
                  timeout_seconds: int = 7200):
    base = _local_url(url)
    workspace = workspace.resolve(strict=True)
    if not isinstance(gpu_uuid, str) or not gpu_uuid.strip():
        raise ValueError("a dedicated ComfyUI GPU UUID is required")

    def run(job: dict[str, Any], context: WorkerContext) -> dict[str, Any]:
        if job["gpu_uuids"] != [gpu_uuid]:
            raise ValueError("ComfyUI jobs must reserve the GPU assigned to this server")
        path = workspace_path(workspace, job["payload"].get("workflow", ""))
        if not path.is_file() or path.suffix.lower() != ".json" or path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("workflow must be an API-format JSON file in the workspace")
        graph = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(graph, dict) or not graph:
            raise ValueError("workflow must contain a ComfyUI API node graph")
        overrides = job["payload"].get("inputs", {})
        if not isinstance(overrides, dict):
            raise ValueError("inputs must map node IDs to input values")
        for node_id, values in overrides.items():
            if (node_id not in graph or not isinstance(values, dict) or
                    not isinstance(graph[node_id], dict) or not isinstance(graph[node_id].get("inputs"), dict)):
                raise ValueError("input override references an invalid workflow node")
            for key, value in values.items():
                if key not in graph[node_id]["inputs"]:
                    raise ValueError("input override references an unknown input")
                graph[node_id]["inputs"][key] = value
        context.progress("Submitting ComfyUI workflow")
        # A failed POST can still have been accepted; never release a GPU on
        # an ambiguous submission or loss of contact with a running backend.
        context.arm_gpu_workload()
        try:
            response = _json_request(base + "/prompt", {"prompt": graph, "client_id": job["id"]})
        except WorkflowRejected:
            context.confirm_gpu_stopped()
            raise
        except Exception as exc:
            raise WorkloadStillRunning("ComfyUI submission outcome unknown; verify server before recovery") from exc
        prompt_id = response.get("prompt_id")
        if not isinstance(prompt_id, str) or not prompt_id:
            # An explicit error response establishes that no prompt was queued.
            if response.get("error") or response.get("node_errors"):
                context.confirm_gpu_stopped()
                raise ValueError("ComfyUI rejected the workflow: " + str(response.get("error", response.get("node_errors"))))
            raise WorkloadStillRunning("ComfyUI returned no prompt ID; verify server before recovery")
        try:
            context.progress(f"ComfyUI prompt queued: {prompt_id}")
        except Exception as exc:
            raise WorkloadStillRunning("ComfyUI may still be running; verify server before recovery") from exc
        deadline = time.monotonic() + timeout_seconds
        cancellation_reported = False
        while time.monotonic() < deadline:
            try:
                cancelled = context()
                if cancelled and not cancellation_reported:
                    context.progress("Cancellation requested; waiting for ComfyUI to finish safely")
                    cancellation_reported = True
                history = _json_request(base + "/history/" + urllib.parse.quote(prompt_id, safe=""))
            except Exception as exc:
                raise WorkloadStillRunning("Lost contact with ComfyUI; verify server before recovery") from exc
            item = history.get(prompt_id)
            if isinstance(item, dict):
                status = item.get("status", {})
                if isinstance(status, dict) and status.get("status_str") == "error":
                    context.confirm_gpu_stopped()
                    raise RuntimeError("ComfyUI workflow failed; inspect its history on the workstation")
                if isinstance(status, dict) and status.get("completed") is True:
                    context.confirm_gpu_stopped()
                    if cancelled:
                        raise WorkerCancelled()
                    return {"prompt_id": prompt_id, "outputs": item.get("outputs", {})}
            time.sleep(poll_interval)
        raise WorkloadStillRunning("ComfyUI did not finish before timeout; verify server before recovery")

    return run
