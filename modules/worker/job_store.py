#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  HexStrike Job Store v6.0                                                     ║
║  SQLite-backed persistent job queue with WAL mode & connection pooling         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sqlite3
import uuid
import json
import threading
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from contextlib import contextmanager

# ─── Configuration ───────────────────────────────────────────────────────────
JOB_DIR = Path(os.environ.get("NULLSEC_JOB_DIR", "/opt/nullsec/jobs"))
DB_PATH = Path(os.environ.get("NULLSEC_JOB_DB", str(JOB_DIR / "jobs.db")))
JOB_DIR.mkdir(parents=True, exist_ok=True)

# ─── Schema ──────────────────────────────────────────────────────────────────
CREATE_SQL = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    tool TEXT NOT NULL,
    target TEXT NOT NULL,
    options TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'queued',
    priority INTEGER DEFAULT 5,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    result TEXT,
    exit_code INTEGER,
    log_path TEXT
);
"""

CREATE_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at);
CREATE INDEX IF NOT EXISTS idx_jobs_priority ON jobs(priority, created_at);
"""

# ─── Connection Pool ─────────────────────────────────────────────────────────
class ConnectionPool:
    """Thread-safe SQLite connection pool."""

    def __init__(self, db_path: Path, max_connections: int = 5):
        self.db_path = db_path
        self.max_connections = max_connections
        self._pool: List[sqlite3.Connection] = []
        self._lock = threading.Lock()
        self._count = 0

        # Initialize DB with WAL mode
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA mmap_size=30000000000")
        conn.execute(CREATE_SQL)
        conn.execute(CREATE_INDEXES)
        conn.commit()
        conn.close()

    @contextmanager
    def get(self):
        conn = None
        try:
            with self._lock:
                if self._pool:
                    conn = self._pool.pop()
                elif self._count < self.max_connections:
                    conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
                    conn.row_factory = sqlite3.Row
                    self._count += 1
                else:
                    # Wait for available connection
                    while not self._pool:
                        self._lock.release()
                        threading.Event().wait(0.1)
                        self._lock.acquire()
                    conn = self._pool.pop()

            yield conn

        finally:
            if conn:
                with self._lock:
                    self._pool.append(conn)

# Global pool
_pool = ConnectionPool(DB_PATH)

# ─── JobStore Class ────────────────────────────────────────────────────────────
class JobStore:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path

    def create_job(self, tool: str, target: str, options: str = "", priority: int = 5) -> str:
        """Create a new job and return its ID."""
        job_id = str(uuid.uuid4())

        with _pool.get() as conn:
            conn.execute(
                """INSERT INTO jobs (id, tool, target, options, status, priority)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (job_id, tool, target, options, "queued", priority)
            )
            conn.commit()

        return job_id

    def pop_queued_job(self) -> Optional[str]:
        """Atomically fetch and lock next queued job. Returns job_id or None."""
        with _pool.get() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                cur = conn.execute(
                    """SELECT id FROM jobs 
                       WHERE status = 'queued' 
                       ORDER BY priority ASC, created_at ASC 
                       LIMIT 1"""
                )
                row = cur.fetchone()
                if not row:
                    conn.execute("COMMIT")
                    return None

                job_id = row["id"]
                conn.execute(
                    """UPDATE jobs 
                       SET status = 'running', started_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP 
                       WHERE id = ?""",
                    (job_id,)
                )
                conn.execute("COMMIT")
                return job_id
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def update_job(self, job_id: str, status: str, result: Optional[str] = None,
                   exit_code: Optional[int] = None, log_path: Optional[str] = None):
        """Update job status and results."""
        with _pool.get() as conn:
            fields = ["status = ?", "updated_at = CURRENT_TIMESTAMP"]
            params = [status]

            if result is not None:
                fields.append("result = ?")
                params.append(result)
            if exit_code is not None:
                fields.append("exit_code = ?")
                params.append(exit_code)
            if log_path is not None:
                fields.append("log_path = ?")
                params.append(log_path)
            if status in ("done", "failed"):
                fields.append("completed_at = CURRENT_TIMESTAMP")

            params.append(job_id)

            conn.execute(
                f"UPDATE jobs SET {', '.join(fields)} WHERE id = ?",
                tuple(params)
            )
            conn.commit()

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve job by ID."""
        with _pool.get() as conn:
            cur = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_jobs(self, limit: int = 50, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List recent jobs, optionally filtered by status."""
        with _pool.get() as conn:
            if status:
                cur = conn.execute(
                    "SELECT * FROM jobs WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                    (status, limit)
                )
            else:
                cur = conn.execute(
                    "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?",
                    (limit,)
                )
            return [dict(row) for row in cur.fetchall()]

    def get_stats(self) -> Dict[str, Any]:
        """Get job statistics."""
        with _pool.get() as conn:
            cur = conn.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'queued' THEN 1 ELSE 0 END) as queued,
                    SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running,
                    SUM(CASE WHEN status = 'done' THEN 1 ELSE 0 END) as done,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed
                FROM jobs
            """)
            row = cur.fetchone()
            return dict(row) if row else {}

    def cleanup_old_jobs(self, days: int = 30) -> int:
        """Delete jobs older than specified days. Returns count deleted."""
        with _pool.get() as conn:
            cur = conn.execute(
                "DELETE FROM jobs WHERE created_at < datetime('now', '-{} days')".format(days)
            )
            conn.commit()
            return cur.rowcount
