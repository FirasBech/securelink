"""Local durable job queue and exclusive GPU reservations.

This is a storage and scheduling primitive, not an execution or network
service. A future worker must explicitly claim a supported job and account for
its process before completing it. In particular, claims are never silently
replayed after a crash: they remain reserved until explicitly resolved.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


class JobError(ValueError):
    """Invalid job specification or state transition."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _nonnegative_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise JobError(f"{name} must be a non-negative integer")
    return value


def _spec(kind: str, payload: dict[str, Any], gpu_count: int, min_free_mib: int) -> str:
    if not isinstance(kind, str) or not kind.strip() or len(kind) > 100:
        raise JobError("kind must be a non-empty string of at most 100 characters")
    if not isinstance(payload, dict):
        raise JobError("payload must be an object")
    _nonnegative_int(gpu_count, "gpu_count")
    _nonnegative_int(min_free_mib, "min_free_mib")
    if not gpu_count and min_free_mib:
        raise JobError("min_free_mib requires at least one GPU")
    try:
        return json.dumps({"kind": kind, "payload": payload, "gpu_count": gpu_count,
                           "min_free_mib": min_free_mib}, sort_keys=True, allow_nan=False)
    except (ValueError, TypeError) as exc:
        raise JobError("payload must contain JSON-serializable values") from exc


class JobQueue:
    """SQLite-backed queue; each operation opens its own connection."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, spec TEXT NOT NULL, status TEXT NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    claim_token TEXT, worker TEXT, result TEXT,
                    assigned_gpus TEXT NOT NULL DEFAULT '[]'
                );
                CREATE TABLE IF NOT EXISTS gpu_reservations (
                    gpu_uuid TEXT PRIMARY KEY, job_id TEXT NOT NULL,
                    FOREIGN KEY(job_id) REFERENCES jobs(id)
                );
                CREATE TABLE IF NOT EXISTS job_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL, event_type TEXT NOT NULL,
                    payload TEXT NOT NULL, created_at TEXT NOT NULL,
                    FOREIGN KEY(job_id) REFERENCES jobs(id)
                );
                CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status, created_at);
                CREATE INDEX IF NOT EXISTS job_events_job ON job_events(job_id, seq);
            """)
            db.execute("BEGIN IMMEDIATE")
            columns = {row[1] for row in db.execute("PRAGMA table_info(jobs)")}
            if "question_id" not in columns:
                db.execute("ALTER TABLE jobs ADD COLUMN question_id TEXT")

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(str(self.path), timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def _public(db: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        value = {key: row[key] for key in ("id", "status", "created_at", "updated_at", "worker")}
        value.update(json.loads(row["spec"]))
        value["result"] = json.loads(row["result"]) if row["result"] else None
        value["gpu_uuids"] = json.loads(row["assigned_gpus"])
        value["question_id"] = row["question_id"]
        return value

    def submit(self, kind: str, payload: dict[str, Any], *, gpu_count: int = 0,
               min_free_mib: int = 0, job_id: str | None = None) -> dict[str, Any]:
        """Queue an inert job. Reusing an ID with identical input is idempotent."""
        encoded = _spec(kind, payload, gpu_count, min_free_mib)
        if job_id is None:
            job_id = str(uuid.uuid4())
        if not isinstance(job_id, str) or not job_id.strip() or len(job_id) > 200:
            raise JobError("job_id must be a non-empty string of at most 200 characters")
        now = _now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if existing:
                if existing["spec"] != encoded:
                    raise JobError("job_id already exists with a different specification")
                return self._public(db, existing)
            db.execute("INSERT INTO jobs(id, spec, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                       (job_id, encoded, "queued", now, now))
            return self._public(db, db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone())

    def list(self, limit: int = 100) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise JobError("limit must be between 1 and 1000")
        with self._connect() as db:
            rows = db.execute("SELECT * FROM jobs ORDER BY created_at DESC, rowid DESC LIMIT ?", (limit,))
            return [self._public(db, row) for row in rows]

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            return self._public(db, row) if row else None

    def claim(self, worker: str, supported_kinds: Iterable[str],
              gpus: Iterable[dict[str, Any]]) -> tuple[dict[str, Any], str] | None:
        """Atomically reserve an eligible job and its GPUs for one worker.

        GPU entries require a stable uuid and integer memory_free_mib. The
        snapshot must come from the worker's local machine immediately before
        claiming. Memory values are advisory; reservations only coordinate this
        queue, not other applications. The returned secret token is required to
        finish the job and must never be exposed to untrusted clients.
        """
        if not isinstance(worker, str) or not worker.strip():
            raise JobError("worker must be a non-empty string")
        if isinstance(supported_kinds, (str, bytes)):
            raise JobError("supported_kinds must be a collection of job kinds")
        kinds = set(supported_kinds)
        if any(not isinstance(kind, str) or not kind for kind in kinds):
            raise JobError("supported_kinds must contain strings")
        gpu_by_id: dict[str, int] = {}
        seen_gpu_ids: set[str] = set()
        for gpu in gpus:
            if not isinstance(gpu, dict):
                raise JobError("GPU entries must be objects")
            gpu_id, free = gpu.get("uuid"), gpu.get("memory_free_mib")
            if not isinstance(gpu_id, str) or not gpu_id.strip() or gpu_id in seen_gpu_ids:
                raise JobError("GPU UUIDs must be unique non-empty strings")
            seen_gpu_ids.add(gpu_id)
            # Unknown free memory is ineligible, rather than assumed available.
            if free is None:
                continue
            gpu_by_id[gpu_id] = _nonnegative_int(free, "memory_free_mib")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            reserved = {row[0] for row in db.execute("SELECT gpu_uuid FROM gpu_reservations")}
            candidates = db.execute("SELECT * FROM jobs WHERE status = 'queued' ORDER BY created_at, rowid").fetchall()
            for row in candidates:
                spec = json.loads(row["spec"])
                if spec["kind"] not in kinds:
                    continue
                eligible = sorted(gpu_id for gpu_id, free in gpu_by_id.items()
                                  if gpu_id not in reserved and free >= spec["min_free_mib"])
                if len(eligible) < spec["gpu_count"]:
                    continue
                token = uuid.uuid4().hex
                db.execute("UPDATE jobs SET status = 'running', worker = ?, claim_token = ?, updated_at = ?, "
                           "assigned_gpus = ? WHERE id = ?",
                           (worker, token, _now(), json.dumps(eligible[:spec["gpu_count"]]), row["id"]))
                db.executemany("INSERT INTO gpu_reservations(gpu_uuid, job_id) VALUES (?, ?)",
                               [(gpu_id, row["id"]) for gpu_id in eligible[:spec["gpu_count"]]])
                updated = db.execute("SELECT * FROM jobs WHERE id = ?", (row["id"],)).fetchone()
                return self._public(db, updated), token
        return None

    def cancel(self, job_id: str) -> dict[str, Any]:
        """Cancel a queued job or request cancellation from its running worker."""
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if row is None:
                raise JobError("job not found")
            if row["status"] == "queued":
                status = "cancelled"
            elif row["status"] in ("running", "waiting_input", "cancel_requested"):
                status = "cancel_requested"
            else:
                raise JobError("job is already finished")
            db.execute("UPDATE jobs SET status = ?, updated_at = ? WHERE id = ?", (status, _now(), job_id))
            return self._public(db, db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone())

    def finish(self, job_id: str, token: str, status: str, result: dict[str, Any] | None = None) -> dict[str, Any]:
        """Complete a claimed job only after its worker has stopped the process."""
        if status not in ("completed", "failed", "cancelled"):
            raise JobError("invalid final status")
        if result is not None and not isinstance(result, dict):
            raise JobError("result must be an object")
        try:
            encoded = json.dumps(result, allow_nan=False) if result is not None else None
        except (TypeError, ValueError) as exc:
            raise JobError("result must contain JSON-serializable values") from exc
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if row is None or row["status"] not in ("running", "waiting_input", "cancel_requested") or not token or row["claim_token"] != token:
                raise JobError("job is not claimed by this worker")
            db.execute("UPDATE jobs SET status = ?, result = ?, claim_token = NULL, question_id = NULL, updated_at = ? WHERE id = ?",
                       (status, encoded, _now(), job_id))
            db.execute("DELETE FROM gpu_reservations WHERE job_id = ?", (job_id,))
            return self._public(db, db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone())

    def resolve_interrupted(self, job_id: str, reason: str) -> dict[str, Any]:
        """Mark a stranded claim failed, only after confirming its process stopped.

        This is an operator action, never a timer-based retry. Calling it while a
        workload is still running can allocate the same GPU twice.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise JobError("a recovery reason is required")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if row is None or row["status"] not in ("running", "waiting_input", "cancel_requested"):
                raise JobError("job does not have an active claim")
            db.execute("UPDATE jobs SET status = 'failed', result = ?, claim_token = NULL, question_id = NULL, updated_at = ? WHERE id = ?",
                       (json.dumps({"interrupted": True, "reason": reason}), _now(), job_id))
            db.execute("DELETE FROM gpu_reservations WHERE job_id = ?", (job_id,))
            return self._public(db, db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone())

    def add_progress(self, job_id: str, token: str, message: str) -> None:
        """Append a progress update from the owner of a live claim."""
        if not isinstance(message, str) or not message.strip() or len(message) > 10000:
            raise JobError("message must contain 1 to 10000 characters")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if row is None or row["status"] not in ("running", "waiting_input", "cancel_requested") or not token or row["claim_token"] != token:
                raise JobError("job is not claimed by this worker")
            db.execute("INSERT INTO job_events(job_id, event_type, payload, created_at) VALUES (?, ?, ?, ?)",
                       (job_id, "progress", json.dumps({"message": message}), _now()))

    def ask_question(self, job_id: str, token: str, question: str) -> str:
        """Pause a claimed job and publish a question without releasing GPUs."""
        if not isinstance(question, str) or not question.strip() or len(question) > 10000:
            raise JobError("question must contain 1 to 10000 characters")
        question_id = str(uuid.uuid4())
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if row is None or row["status"] != "running" or not token or row["claim_token"] != token:
                raise JobError("job is not running under this worker")
            now = _now()
            db.execute("UPDATE jobs SET status = 'waiting_input', question_id = ?, updated_at = ? WHERE id = ?",
                       (question_id, now, job_id))
            db.execute("INSERT INTO job_events(job_id, event_type, payload, created_at) VALUES (?, ?, ?, ?)",
                       (job_id, "question", json.dumps({"question_id": question_id, "question": question}), now))
        return question_id

    def answer_question(self, job_id: str, question_id: str, answer: str) -> dict[str, Any]:
        """Answer exactly the pending question; stale answers are rejected."""
        if not isinstance(answer, str) or not answer.strip() or len(answer) > 10000:
            raise JobError("answer must contain 1 to 10000 characters")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if row is None or row["status"] != "waiting_input" or not question_id or row["question_id"] != question_id:
                raise JobError("question is not awaiting an answer")
            now = _now()
            db.execute("UPDATE jobs SET status = 'running', question_id = NULL, updated_at = ? WHERE id = ?", (now, job_id))
            db.execute("INSERT INTO job_events(job_id, event_type, payload, created_at) VALUES (?, ?, ?, ?)",
                       (job_id, "answer", json.dumps({"question_id": question_id, "answer": answer}), now))
            return self._public(db, db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone())

    def events(self, job_id: str, *, after: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        """Read task messages after a sequence number, in order."""
        _nonnegative_int(after, "after")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise JobError("limit must be between 1 and 1000")
        with self._connect() as db:
            rows = db.execute("SELECT seq, event_type, payload, created_at FROM job_events "
                              "WHERE job_id = ? AND seq > ? ORDER BY seq LIMIT ?", (job_id, after, limit))
            return [{"seq": row["seq"], "type": row["event_type"], "payload": json.loads(row["payload"]),
                     "created_at": row["created_at"]} for row in rows]

    def recent_events(self, job_id: str, *, limit: int = 25) -> list[dict[str, Any]]:
        """Read the most recent messages in chronological order."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise JobError("limit must be between 1 and 1000")
        with self._connect() as db:
            rows = db.execute("SELECT seq, event_type, payload, created_at FROM job_events "
                              "WHERE job_id = ? ORDER BY seq DESC LIMIT ?", (job_id, limit)).fetchall()
            return [{"seq": row["seq"], "type": row["event_type"], "payload": json.loads(row["payload"]),
                     "created_at": row["created_at"]} for row in reversed(rows)]
