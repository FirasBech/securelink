"""Explicit, adapter-based local worker primitives.

There is deliberately no background service, remote listener, shell executor,
or built-in agent adapter. Adapters are trusted Python callables supplied by
the host application. They must finish or stop their workload before returning
or raising; only then can this module safely release GPU reservations.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any

from core.job_queue import JobQueue
from core.workstation import nvidia_gpus


class WorkerCancelled(Exception):
    """Raised by an adapter after it has stopped a cancelled workload."""


class WorkerContext:
    """Adapter-facing task updates and cooperative cancellation."""

    def __init__(self, queue: JobQueue, job_id: str, token: str) -> None:
        self._queue, self._job_id, self._token = queue, job_id, token

    def __call__(self) -> bool:
        current = self._queue.get(self._job_id)
        return current is not None and current["status"] == "cancel_requested"

    def progress(self, message: str) -> None:
        self._queue.add_progress(self._job_id, self._token, message)

    def ask_question(self, question: str) -> str:
        return self._queue.ask_question(self._job_id, self._token, question)

    def events(self, after: int = 0) -> list[dict[str, Any]]:
        return self._queue.events(self._job_id, after=after)


class LocalWorker:
    """Claim and run one job at a time using explicitly supplied adapters."""

    def __init__(self, queue: JobQueue, name: str,
                 adapters: Mapping[str, Callable[[dict[str, Any], WorkerContext], dict[str, Any]]],
                 *, gpu_probe: Callable[[], dict[str, Any]] = nvidia_gpus) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("worker name is required")
        if any(not isinstance(kind, str) or not kind or not callable(adapter)
               for kind, adapter in adapters.items()):
            raise ValueError("adapters must map job kinds to callable handlers")
        self.queue = queue
        self.name = name
        self.adapters = dict(adapters)
        self.gpu_probe = gpu_probe

    def run_one(self) -> dict[str, Any] | None:
        """Run one eligible job synchronously, or return None if none is eligible.

        Cancellation is cooperative: the adapter polls the supplied callback,
        stops its process and raises WorkerCancelled only once it has stopped.
        An adapter that ignores cancellation is not forcibly terminated. GPU
        UUIDs in the job are reservations, not automatic CUDA configuration.
        """
        gpu_info = self.gpu_probe()
        gpus = gpu_info.get("gpus", []) if gpu_info.get("available") else []
        claim = self.queue.claim(self.name, self.adapters.keys(), gpus)
        if claim is None:
            return None
        job, token = claim

        try:
            result = self.adapters[job["kind"]](job, WorkerContext(self.queue, job["id"], token))
            if not isinstance(result, dict):
                raise TypeError("adapter result must be an object")
            json.dumps(result, allow_nan=False)
            if self.queue.get(job["id"])["status"] == "waiting_input":
                raise RuntimeError("adapter returned before its question was answered")
        except WorkerCancelled:
            return self.queue.finish(job["id"], token, "cancelled")
        except Exception as exc:
            return self.queue.finish(job["id"], token, "failed", {"error": str(exc)})
        return self.queue.finish(job["id"], token, "completed", result)
