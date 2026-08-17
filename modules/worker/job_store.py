"""Durable SQLite control-plane store for authorized jobs and audit records."""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from modules.domain.models import Campaign, CapabilityTier


class JobStoreError(RuntimeError):
    """Raised when durable job-state operations cannot complete safely."""


DEFAULT_JOB_DIR = Path.home() / ".local" / "state" / "nullsec" / "jobs"
JOB_DIR = Path(os.environ.get("NULLSEC_JOB_DIR", str(DEFAULT_JOB_DIR)))
DB_PATH = Path(os.environ.get("NULLSEC_JOB_DB", str(JOB_DIR / "jobs.db")))
JOB_STATES = {"queued", "leased", "running", "done", "failed", "timed_out", "cancelled"}
TERMINAL_STATES = {"done", "failed", "timed_out", "cancelled"}
TRANSITIONS = {
    "queued": {"leased", "cancelled"},
    "leased": {"queued", "running", "failed", "cancelled"},
    "running": {"done", "failed", "timed_out", "cancelled"},
    "done": set(),
    "failed": {"queued"},
    "timed_out": {"queued"},
    "cancelled": set(),
}


class JobStore:
    """Single-host SQLite repository with migration-safe schema and transaction guards."""

    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = Path(db_path)
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise JobStoreError(f"Cannot create job-store directory: {error}") from error
        self._initialize()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.db_path), timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=10000")
            yield connection
        except sqlite3.Error as error:
            raise JobStoreError(f"Database operation failed: {error}") from error
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY, campaign_id TEXT, actor_id TEXT, policy_decision_id TEXT,
                trace_id TEXT, idempotency_key TEXT, tool TEXT NOT NULL, target TEXT NOT NULL,
                arguments TEXT NOT NULL DEFAULT '{}', options TEXT NOT NULL DEFAULT '',
                execution_mode TEXT NOT NULL DEFAULT 'sandbox_required', status TEXT NOT NULL DEFAULT 'queued',
                priority INTEGER NOT NULL DEFAULT 5, attempt_count INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT 1, lease_owner TEXT, lease_expires_at TEXT,
                last_heartbeat_at TEXT, cancel_requested INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL, started_at TEXT, completed_at TEXT,
                result TEXT, exit_code INTEGER, log_path TEXT)"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS campaigns (
                campaign_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, allowed_targets TEXT NOT NULL,
                allowed_capabilities TEXT NOT NULL, starts_at TEXT NOT NULL, ends_at TEXT NOT NULL,
                active INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS policy_decisions (
                decision_id TEXT PRIMARY KEY, request_id TEXT NOT NULL, campaign_id TEXT NOT NULL,
                actor_id TEXT NOT NULL, allowed INTEGER NOT NULL, reason_code TEXT NOT NULL,
                reason TEXT NOT NULL, decided_at TEXT NOT NULL)"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS audit_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT, campaign_id TEXT, trace_id TEXT,
                event_type TEXT NOT NULL, actor_id TEXT, details TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL)"""
            )
            self._migrate_legacy_columns(connection)
            connection.execute("CREATE INDEX IF NOT EXISTS idx_jobs_queue ON jobs(status, priority, created_at)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_jobs_lease ON jobs(status, lease_expires_at)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_job ON audit_events(job_id, event_id)")
            connection.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_idempotency
                ON jobs(COALESCE(campaign_id, ''), COALESCE(actor_id, ''), idempotency_key)
                WHERE idempotency_key IS NOT NULL"""
            )

    @staticmethod
    def _migrate_legacy_columns(connection: sqlite3.Connection) -> None:
        existing = {row["name"] for row in connection.execute("PRAGMA table_info(jobs)")}
        additions = {
            "campaign_id": "TEXT", "actor_id": "TEXT", "policy_decision_id": "TEXT", "trace_id": "TEXT",
            "idempotency_key": "TEXT", "arguments": "TEXT NOT NULL DEFAULT '{}'",
            "execution_mode": "TEXT NOT NULL DEFAULT 'sandbox_required'", "attempt_count": "INTEGER NOT NULL DEFAULT 0",
            "max_attempts": "INTEGER NOT NULL DEFAULT 1", "lease_owner": "TEXT", "lease_expires_at": "TEXT",
            "last_heartbeat_at": "TEXT", "cancel_requested": "INTEGER NOT NULL DEFAULT 0",
        }
        for column, definition in additions.items():
            if column not in existing:
                connection.execute(f"ALTER TABLE jobs ADD COLUMN {column} {definition}")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _encode(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    def _audit(
        self, connection: sqlite3.Connection, event_type: str, *, job_id: str | None = None,
        campaign_id: str | None = None, trace_id: str | None = None, actor_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        connection.execute(
            """INSERT INTO audit_events (job_id,campaign_id,trace_id,event_type,actor_id,details,created_at)
            VALUES (?,?,?,?,?,?,?)""",
            (job_id, campaign_id, trace_id, event_type, actor_id, self._encode(details or {}), self._now()),
        )

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, Any]:
        job = dict(row)
        try:
            job["arguments"] = json.loads(job["arguments"] or "{}")
        except (KeyError, json.JSONDecodeError):
            job["arguments"] = {}
        job["cancel_requested"] = bool(job.get("cancel_requested"))
        return job

    def create_campaign(self, campaign: Campaign) -> None:
        now = self._now()
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO campaigns (campaign_id,owner_id,allowed_targets,allowed_capabilities,starts_at,ends_at,active,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(campaign_id) DO UPDATE SET
                owner_id=excluded.owner_id,allowed_targets=excluded.allowed_targets,
                allowed_capabilities=excluded.allowed_capabilities,starts_at=excluded.starts_at,
                ends_at=excluded.ends_at,active=excluded.active,updated_at=excluded.updated_at""",
                (campaign.campaign_id, campaign.owner_id, self._encode(sorted(campaign.allowed_targets)),
                 self._encode(sorted(item.value for item in campaign.allowed_capabilities)),
                 campaign.starts_at.isoformat(), campaign.ends_at.isoformat(), int(campaign.active), now, now),
            )
            self._audit(connection, "campaign_recorded", campaign_id=campaign.campaign_id, actor_id=campaign.owner_id)

    def get_campaign(self, campaign_id: str) -> Campaign | None:
        """Return a persisted campaign as an immutable domain object."""
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM campaigns WHERE campaign_id=?", (campaign_id,)).fetchone()
        if row is None:
            return None
        try:
            targets = frozenset(json.loads(row["allowed_targets"]))
            capabilities = frozenset(CapabilityTier(item) for item in json.loads(row["allowed_capabilities"]))
            return Campaign(
                campaign_id=row["campaign_id"],
                owner_id=row["owner_id"],
                allowed_targets=targets,
                allowed_capabilities=capabilities,
                starts_at=datetime.fromisoformat(row["starts_at"]),
                ends_at=datetime.fromisoformat(row["ends_at"]),
                active=bool(row["active"]),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise JobStoreError(f"Persisted campaign is invalid: {error}") from error

    def record_policy_decision(
        self, *, campaign_id: str, request_id: str, actor_id: str, allowed: bool, reason_code: str,
        reason: str, decision_id: str | None = None,
    ) -> str:
        identifier = decision_id or str(uuid.uuid4())
        with self._connection() as connection:
            connection.execute(
                """INSERT INTO policy_decisions (decision_id,request_id,campaign_id,actor_id,allowed,reason_code,reason,decided_at)
                VALUES (?,?,?,?,?,?,?,?)""",
                (identifier, request_id, campaign_id, actor_id, int(allowed), reason_code, reason, self._now()),
            )
            self._audit(connection, "policy_allowed" if allowed else "policy_denied", campaign_id=campaign_id,
                        actor_id=actor_id, details={"decision_id": identifier, "reason_code": reason_code})
        return identifier

    def create_job(
        self, tool: str, target: str, options: str = "", priority: int = 5, *,
        campaign_id: str | None = None, actor_id: str | None = None,
        policy_decision_id: str | None = None, trace_id: str | None = None,
        idempotency_key: str | None = None, arguments: dict[str, Any] | None = None,
        execution_mode: str = "sandbox_required", max_attempts: int = 1,
    ) -> str:
        if not isinstance(tool, str) or not tool.strip() or not isinstance(target, str) or not target.strip():
            raise JobStoreError("Tool name and target must be non-empty strings")
        if execution_mode not in {"development", "sandbox_required"}:
            raise JobStoreError("Unknown execution mode")
        if max_attempts < 1 or priority < 1 or priority > 100:
            raise JobStoreError("Invalid retry or priority value")
        now = self._now()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                if idempotency_key:
                    existing = connection.execute(
                        """SELECT id FROM jobs WHERE COALESCE(campaign_id,'')=COALESCE(?,'')
                        AND COALESCE(actor_id,'')=COALESCE(?,'') AND idempotency_key=?""",
                        (campaign_id, actor_id, idempotency_key),
                    ).fetchone()
                    if existing:
                        connection.execute("COMMIT")
                        return str(existing["id"])
                if policy_decision_id:
                    policy = connection.execute(
                        """SELECT allowed FROM policy_decisions WHERE decision_id=? AND campaign_id=?
                        AND actor_id=?""",
                        (policy_decision_id, campaign_id, actor_id),
                    ).fetchone()
                    if policy is None or not bool(policy["allowed"]):
                        raise JobStoreError("A matching allowed policy decision is required")
                job_id = str(uuid.uuid4())
                connection.execute(
                    """INSERT INTO jobs (id,campaign_id,actor_id,policy_decision_id,trace_id,idempotency_key,tool,target,
                    arguments,options,execution_mode,status,priority,attempt_count,max_attempts,cancel_requested,created_at,updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,'queued',?,0,?,0,?,?)""",
                    (job_id, campaign_id, actor_id, policy_decision_id, trace_id, idempotency_key, tool, target,
                     self._encode(arguments or {}), options, execution_mode, priority, max_attempts, now, now),
                )
                self._audit(connection, "job_created", job_id=job_id, campaign_id=campaign_id, trace_id=trace_id,
                            actor_id=actor_id, details={"tool": tool, "execution_mode": execution_mode})
                connection.execute("COMMIT")
                return job_id
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def _recover_expired_in_transaction(self, connection: sqlite3.Connection, now: str) -> int:
        rows = connection.execute(
            "SELECT * FROM jobs WHERE status IN ('leased','running') AND lease_expires_at IS NOT NULL AND lease_expires_at < ?", (now,)
        ).fetchall()
        for row in rows:
            next_state = "queued" if row["attempt_count"] < row["max_attempts"] and not row["cancel_requested"] else "failed"
            connection.execute(
                """UPDATE jobs SET status=?, lease_owner=NULL, lease_expires_at=NULL, updated_at=?,
                completed_at=CASE WHEN ?='failed' THEN ? ELSE completed_at END,
                result=CASE WHEN ?='failed' THEN 'Lease expired after maximum attempts' ELSE result END WHERE id=?""",
                (next_state, now, next_state, now, next_state, row["id"]),
            )
            self._audit(connection, "job_requeued_after_lease" if next_state == "queued" else "job_failed_after_lease",
                        job_id=row["id"], campaign_id=row["campaign_id"], trace_id=row["trace_id"])
        return len(rows)

    def lease_next_job(self, worker_id: str, lease_seconds: int = 60) -> dict[str, Any] | None:
        if not worker_id or lease_seconds < 1:
            raise JobStoreError("worker_id and positive lease_seconds are required")
        now = datetime.now(timezone.utc)
        expires = (now + timedelta(seconds=lease_seconds)).isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._recover_expired_in_transaction(connection, now.isoformat())
                row = connection.execute(
                    "SELECT * FROM jobs WHERE status='queued' AND cancel_requested=0 ORDER BY priority,created_at LIMIT 1"
                ).fetchone()
                if row is None:
                    connection.execute("COMMIT")
                    return None
                connection.execute(
                    """UPDATE jobs SET status='leased',lease_owner=?,lease_expires_at=?,last_heartbeat_at=?,
                    attempt_count=attempt_count+1,updated_at=? WHERE id=?""",
                    (worker_id, expires, now.isoformat(), now.isoformat(), row["id"]),
                )
                leased = connection.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone()
                self._audit(connection, "job_leased", job_id=row["id"], campaign_id=leased["campaign_id"],
                            trace_id=leased["trace_id"], actor_id=worker_id, details={"lease_expires_at": expires})
                connection.execute("COMMIT")
                return self._decode(leased)
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def pop_queued_job(self) -> str | None:
        """Compatibility helper; workers should use `lease_next_job` and `mark_running`."""
        job = self.lease_next_job("legacy-worker")
        return str(job["id"]) if job else None

    def _transition(self, job_id: str, status: str, *, worker_id: str | None = None,
                    result: str | None = None, exit_code: int | None = None,
                    log_path: str | None = None) -> None:
        if status not in JOB_STATES:
            raise JobStoreError(f"Unknown job status: {status}")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
                if row is None:
                    raise JobStoreError("Job not found")
                current = str(row["status"])
                if status not in TRANSITIONS[current]:
                    raise JobStoreError(f"Invalid job transition: {current} -> {status}")
                if worker_id is not None and row["lease_owner"] != worker_id:
                    raise JobStoreError("Lease is owned by a different worker")
                if row["cancel_requested"] and status != "cancelled":
                    raise JobStoreError("Cancellation was requested")
                now = self._now()
                terminal = status in TERMINAL_STATES
                connection.execute(
                    """UPDATE jobs SET status=?,result=COALESCE(?,result),exit_code=COALESCE(?,exit_code),
                    log_path=COALESCE(?,log_path),started_at=CASE WHEN ?='running' THEN COALESCE(started_at,?) ELSE started_at END,
                    completed_at=CASE WHEN ? THEN ? ELSE completed_at END,
                    lease_owner=CASE WHEN ? THEN NULL ELSE lease_owner END,
                    lease_expires_at=CASE WHEN ? THEN NULL ELSE lease_expires_at END,updated_at=? WHERE id=?""",
                    (status, result, exit_code, log_path, status, now, terminal, now, terminal, terminal, now, job_id),
                )
                self._audit(connection, f"job_{status}", job_id=job_id, campaign_id=row["campaign_id"],
                            trace_id=row["trace_id"], actor_id=worker_id, details={"from": current, "exit_code": exit_code})
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def mark_running(self, job_id: str, worker_id: str) -> None:
        self._transition(job_id, "running", worker_id=worker_id)

    def update_job(self, job_id: str, status: str, result: str | None = None,
                   exit_code: int | None = None, log_path: str | None = None) -> None:
        self._transition(job_id, status, result=result, exit_code=exit_code, log_path=log_path)

    def heartbeat(self, job_id: str, worker_id: str, lease_seconds: int = 60) -> bool:
        now = self._now()
        expiry = (datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)).isoformat()
        with self._connection() as connection:
            changed = connection.execute(
                """UPDATE jobs SET last_heartbeat_at=?,lease_expires_at=?,updated_at=?
                WHERE id=? AND lease_owner=? AND status IN ('leased','running') AND cancel_requested=0""",
                (now, expiry, now, job_id, worker_id),
            )
            return changed.rowcount == 1

    def request_cancel(self, job_id: str, actor_id: str) -> bool:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
                if row is None or row["status"] in TERMINAL_STATES:
                    connection.execute("COMMIT")
                    return False
                now = self._now()
                if row["status"] == "queued":
                    connection.execute("UPDATE jobs SET status='cancelled',cancel_requested=1,completed_at=?,updated_at=? WHERE id=?", (now, now, job_id))
                    event = "job_cancelled"
                else:
                    connection.execute("UPDATE jobs SET cancel_requested=1,updated_at=? WHERE id=?", (now, job_id))
                    event = "job_cancel_requested"
                self._audit(connection, event, job_id=job_id, campaign_id=row["campaign_id"],
                            trace_id=row["trace_id"], actor_id=actor_id)
                connection.execute("COMMIT")
                return True
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def is_cancel_requested(self, job_id: str) -> bool:
        job = self.get_job(job_id)
        return bool(job and job["cancel_requested"])

    def recover_expired_leases(self) -> int:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                count = self._recover_expired_in_transaction(connection, self._now())
                connection.execute("COMMIT")
                return count
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            return self._decode(row) if row else None

    def list_jobs(self, limit: int = 50, status: str | None = None) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        with self._connection() as connection:
            if status:
                rows = connection.execute("SELECT * FROM jobs WHERE status=? ORDER BY created_at DESC LIMIT ?", (status, limit)).fetchall()
            else:
                rows = connection.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
            return [self._decode(row) for row in rows]

    def list_audit_events(self, job_id: str) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM audit_events WHERE job_id=? ORDER BY event_id", (job_id,)).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            event = dict(row)
            event["details"] = json.loads(event["details"] or "{}")
            output.append(event)
        return output

    def get_stats(self) -> dict[str, Any]:
        stats = {state: 0 for state in JOB_STATES}
        with self._connection() as connection:
            rows = connection.execute("SELECT status,COUNT(*) AS count FROM jobs GROUP BY status").fetchall()
        stats.update({str(row["status"]): int(row["count"]) for row in rows})
        stats["total"] = sum(stats.values())
        return stats

    def cleanup_old_jobs(self, days: int = 30) -> int:
        if days < 0:
            raise JobStoreError("Days must be non-negative")
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._connection() as connection:
            return connection.execute("DELETE FROM jobs WHERE created_at < ?", (cutoff,)).rowcount

    def reset_failed_jobs(self) -> int:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM jobs WHERE status IN ('failed','timed_out')").fetchall()
            for row in rows:
                connection.execute(
                    """UPDATE jobs SET status='queued',lease_owner=NULL,lease_expires_at=NULL,cancel_requested=0,
                    completed_at=NULL,result=NULL,exit_code=NULL,updated_at=? WHERE id=?""", (self._now(), row["id"])
                )
                self._audit(connection, "job_reset", job_id=row["id"], campaign_id=row["campaign_id"])
            return len(rows)
