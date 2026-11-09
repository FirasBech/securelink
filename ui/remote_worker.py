"""Opt-in workstation worker and SSH-invoked JSON endpoint.

The endpoint reads one request from standard input and does not listen on a
network port. Remote transport and authorization are provided by OpenSSH.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any

from core.agent_adapters import agent_adapter, blender_adapter, workspace_path
from core.comfy_adapter import comfy_adapter
from core.job_queue import JobQueue
from core.worker import LocalWorker
from core.workstation import local_inventory, nvidia_gpus

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_REQUEST_BYTES = 12 * 1024 * 1024


def state_root() -> Path:
    return Path.home() / ".securelink"


def load_config() -> dict[str, Any]:
    path = state_root() / "workstation.json"
    if not path.exists():
        raise ValueError("workstation is not configured; run worker configure first")
    config = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or not isinstance(config.get("workspace"), str):
        raise ValueError("invalid workstation configuration")
    return config


def queue() -> JobQueue:
    return JobQueue(state_root() / "workstation-jobs.sqlite3")


def dispatch(request: dict[str, Any]) -> dict[str, Any]:
    """Handle an authenticated local or SSH session; never execute shell text."""
    if not isinstance(request, dict):
        raise ValueError("request must be an object")
    config = load_config()
    method = request.get("method")
    params = request.get("params", {})
    if not isinstance(params, dict):
        raise ValueError("params must be an object")
    if method == "status":
        return {"workstation": local_inventory(), "workspace_configured": True}
    if method == "jobs.list":
        return {"jobs": queue().list(params.get("limit", 100))}
    if method == "jobs.get":
        return {"job": queue().get(params["job_id"])}
    if method == "jobs.submit":
        job = queue().submit(params["kind"], params.get("payload", {}),
                             gpu_count=params.get("gpu_count", 0),
                             min_free_mib=params.get("min_free_mib", 0),
                             job_id=params.get("job_id"))
        return {"job": job}
    if method == "jobs.events":
        return {"events": queue().events(params["job_id"], after=params.get("after", 0))}
    if method == "jobs.cancel":
        return {"job": queue().cancel(params["job_id"])}
    if method == "jobs.answer":
        return {"job": queue().answer_question(params["job_id"], params["question_id"], params["answer"])}
    if method in {"files.get", "files.put"}:
        path = workspace_path(Path(config["workspace"]), params["path"])
        if method == "files.get":
            if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
                raise ValueError("file is missing or exceeds the 8 MiB transfer limit")
            data = path.read_bytes()
            if len(data) > MAX_FILE_BYTES:
                raise ValueError("file exceeds the 8 MiB transfer limit")
            return {"data_base64": base64.b64encode(data).decode("ascii"), "size": len(data)}
        encoded = params.get("data_base64")
        if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_FILE_BYTES + 2) // 3):
            raise ValueError("invalid or oversized file")
        data = base64.b64decode(encoded, validate=True)
        if len(data) > MAX_FILE_BYTES:
            raise ValueError("file exceeds the 8 MiB transfer limit")
        path.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive create: uploads never replace existing user files.
        with path.open("xb") as handle:
            handle.write(data)
        return {"path": params["path"], "size": len(data)}
    raise ValueError("unknown method")


def rpc() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("request is too large")
        response = {"ok": True, "result": dispatch(json.loads(raw))}
    except Exception as exc:
        response = {"ok": False, "error": str(exc)}
    print(json.dumps(response, ensure_ascii=True), flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="securelink-workstation")
    commands = parser.add_subparsers(dest="command")
    config_parser = commands.add_parser("configure", help="select the workstation workspace")
    config_parser.add_argument("--workspace", required=True)
    serve_parser = commands.add_parser("serve", help="run enabled local agent workers")
    serve_parser.add_argument("--enable", action="append", choices=["codex", "claude", "opencode", "blender", "comfyui"], required=True)
    serve_parser.add_argument("--slots", type=int, default=1)
    serve_parser.add_argument("--codex-path")
    serve_parser.add_argument("--claude-path")
    serve_parser.add_argument("--opencode-path")
    serve_parser.add_argument("--blender-path")
    serve_parser.add_argument("--comfy-url", default="http://127.0.0.1:8188")
    serve_parser.add_argument("--comfy-gpu", help="GPU UUID dedicated to this ComfyUI server")
    args = parser.parse_args(argv)
    if args.command is None:
        return rpc()
    if args.command == "configure":
        workspace = Path(args.workspace).expanduser().resolve(strict=True)
        if not workspace.is_dir():
            parser.error("workspace must be an existing directory")
        root = state_root()
        root.mkdir(parents=True, exist_ok=True)
        (root / "workstation.json").write_text(json.dumps({"workspace": str(workspace)}, indent=2), encoding="utf-8")
        print(f"Workstation workspace configured: {workspace}")
        return 0
    if not 1 <= args.slots <= 32:
        parser.error("slots must be between 1 and 32")
    if "comfyui" in args.enable and (set(args.enable) != {"comfyui"} or args.slots != 1 or not args.comfy_gpu):
        parser.error("ComfyUI requires its own worker with --enable comfyui --slots 1 --comfy-gpu GPU-UUID")
    if args.comfy_gpu and "comfyui" not in args.enable:
        parser.error("--comfy-gpu is only valid for a ComfyUI worker")
    workspace = Path(load_config()["workspace"])
    adapters = {provider: (blender_adapter(workspace, args.blender_path) if provider == "blender" else
                           comfy_adapter(workspace, args.comfy_url, args.comfy_gpu) if provider == "comfyui" else
                           agent_adapter(provider, workspace, getattr(args, provider + "_path")))
                for provider in args.enable}
    job_queue = queue()
    stopping = threading.Event()

    def slot(index: int) -> None:
        def probe():
            data = nvidia_gpus()
            if args.comfy_gpu:
                data["gpus"] = [gpu for gpu in data["gpus"] if gpu["uuid"] == args.comfy_gpu]
            return data

        worker = LocalWorker(job_queue, f"{socket.gethostname()}:{os.getpid()}:{index}", adapters, gpu_probe=probe)
        while not stopping.is_set():
            if worker.run_one() is None:
                stopping.wait(2)

    print(f"Workstation worker started with {args.slots} slot(s); enabled: {', '.join(adapters)}", flush=True)
    with ThreadPoolExecutor(max_workers=args.slots) as executor:
        futures = [executor.submit(slot, index) for index in range(args.slots)]
        try:
            while True:
                done, _ = wait(futures, timeout=1, return_when=FIRST_COMPLETED)
                if done:
                    for future in done:
                        future.result()
                    break
        except KeyboardInterrupt:
            print("Stopping after current jobs finish.", flush=True)
        finally:
            stopping.set()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
