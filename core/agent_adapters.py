"""Opt-in local CLI agent adapters for the workstation worker.

Providers retain their own permission and authentication configuration. These
adapters do not bypass approval prompts or create an operating-system sandbox.
"""
from __future__ import annotations

import os
import hashlib
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from core.worker import WorkerCancelled, WorkerContext


class WorkloadStillRunning(BaseException):
    """Do not release a reservation when a process cannot be stopped."""


def workspace_path(root: Path, relative: str = ".") -> Path:
    """Resolve a path inside the operator-selected workspace."""
    if not isinstance(relative, str) or not relative or "\x00" in relative:
        raise ValueError("workspace path must be a non-empty string")
    base = root.resolve(strict=True)
    candidate = (base / relative).resolve()
    if not candidate.is_relative_to(base):
        raise ValueError("path is outside the configured workspace")
    return candidate


def agent_adapter(provider: str, workspace: Path, executable: str | None = None):
    """Create an agent adapter; provider use must be enabled by the operator."""
    if provider not in {"codex", "claude", "opencode"}:
        raise ValueError("unsupported agent provider")
    workspace = workspace.resolve(strict=True)

    def run(job: dict[str, Any], context: WorkerContext) -> dict[str, Any]:
        payload = job["payload"]
        prompt = payload.get("prompt")
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 100000:
            raise ValueError("prompt must contain 1 to 100000 characters")
        cwd = workspace_path(workspace, payload.get("directory", "."))
        if not cwd.is_dir():
            raise ValueError("working directory does not exist")
        command = executable or shutil.which(provider)
        if not command:
            raise ValueError(f"{provider} executable was not found")
        # Windows batch wrappers interpret arguments through cmd.exe. The only
        # prompt passed as an argument is OpenCode's, so require a native binary.
        if provider == "opencode" and Path(command).suffix.lower() in {".cmd", ".bat"}:
            raise ValueError("configure the native opencode executable, not a batch wrapper")
        if provider == "codex":
            argv = [command, "exec", "--skip-git-repo-check", "-"]
        elif provider == "claude":
            argv = [command, "-p"]
        else:
            argv = [command, "run", "--", prompt]
        env = os.environ.copy()
        env["CUDA_VISIBLE_DEVICES"] = ",".join(job["gpu_uuids"])
        context.progress(f"Starting {provider}")
        # A file avoids deadlocking a child on a full pipe while it works.
        with tempfile.TemporaryFile(mode="w+b") as output:
            kwargs: dict[str, Any] = {"cwd": str(cwd), "env": env, "stdin": subprocess.PIPE,
                                      "stdout": output, "stderr": subprocess.STDOUT}
            if os.name == "nt":
                kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            else:
                kwargs["start_new_session"] = True
            process = subprocess.Popen(argv, **kwargs)
            try:
                def send_input() -> None:
                    try:
                        if process.stdin is not None and provider != "opencode":
                            process.stdin.write(prompt.encode("utf-8"))
                    except (BrokenPipeError, OSError):
                        pass
                    finally:
                        if process.stdin is not None:
                            process.stdin.close()

                threading.Thread(target=send_input, daemon=True).start()
                while process.poll() is None:
                    if context():
                        _stop_process(process)
                        raise WorkerCancelled()
                    time.sleep(0.5)
            except BaseException:
                if process.poll() is None:
                    _stop_process(process)
                raise
            output.seek(0, os.SEEK_END)
            size = output.tell()
            output.seek(max(0, size - 262144))
            text = output.read().decode("utf-8", errors="replace")
            if process.returncode:
                raise RuntimeError(f"{provider} exited with code {process.returncode}: {text[-4000:]}")
            return {"provider": provider, "output": text, "output_truncated": size > 262144}

    return run


def blender_adapter(workspace: Path, executable: str | None = None):
    """Render one frame of a workspace blend file to a unique output directory."""
    workspace = workspace.resolve(strict=True)

    def run(job: dict[str, Any], context: WorkerContext) -> dict[str, Any]:
        scene = workspace_path(workspace, job["payload"].get("scene", ""))
        if not scene.is_file() or scene.suffix.lower() != ".blend":
            raise ValueError("scene must be an existing .blend file in the workspace")
        frame = job["payload"].get("frame", 1)
        if isinstance(frame, bool) or not isinstance(frame, int) or not -1000000 <= frame <= 1000000:
            raise ValueError("frame must be an integer between -1000000 and 1000000")
        command = executable or shutil.which("blender")
        if not command:
            raise ValueError("Blender executable was not found")
        # Render paths are constructed by the worker, not from arbitrary job input.
        folder_name = hashlib.sha256(job["id"].encode("utf-8")).hexdigest()[:24]
        output_dir = workspace_path(workspace, "securelink-output") / folder_name
        output_dir.mkdir(parents=True, exist_ok=False)
        argv = [command, "--background", "--disable-autoexec", str(scene), "--render-output",
                str(output_dir / "render_"), "--render-format", "PNG", "--render-frame", str(frame)]
        env = os.environ.copy()
        env["CUDA_VISIBLE_DEVICES"] = ",".join(job["gpu_uuids"])
        context.progress("Starting Blender render")
        with tempfile.TemporaryFile(mode="w+b") as output:
            kwargs: dict[str, Any] = {"cwd": str(workspace), "env": env, "stdin": subprocess.DEVNULL,
                                      "stdout": output, "stderr": subprocess.STDOUT}
            if os.name == "nt":
                kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            else:
                kwargs["start_new_session"] = True
            process = subprocess.Popen(argv, **kwargs)
            try:
                while process.poll() is None:
                    if context():
                        _stop_process(process)
                        raise WorkerCancelled()
                    time.sleep(0.5)
            except BaseException:
                if process.poll() is None:
                    _stop_process(process)
                raise
            output.seek(0, os.SEEK_END)
            size = output.tell()
            output.seek(max(0, size - 4000))
            text = output.read().decode("utf-8", errors="replace")
            if process.returncode:
                raise RuntimeError(f"Blender exited with code {process.returncode}: {text}")
        images = [str(path.relative_to(workspace)) for path in output_dir.glob("*.png") if path.is_file()]
        if not images:
            raise RuntimeError("Blender exited without a PNG render")
        return {"outputs": images, "frame": frame}

    return run


def _stop_process(process: subprocess.Popen) -> None:
    try:
        if os.name == "nt":
            # taskkill /T terminates descendants before the reservation is released.
            result = subprocess.run([str(Path(os.environ.get("SystemRoot", r"C:\Windows")) /
                                         "System32" / "taskkill.exe"), "/PID", str(process.pid), "/T", "/F"],
                                    capture_output=True, timeout=15, check=False,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if result.returncode and process.poll() is None:
                raise WorkloadStillRunning("could not stop agent process tree; GPU remains reserved")
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=15)
    except ProcessLookupError:
        process.wait(timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WorkloadStillRunning("could not confirm process stopped; GPU remains reserved") from exc
