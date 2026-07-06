#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║ HexStrike Job Store v7.0                                                    ║
║ SQLite-backed persistent job queue with WAL mode & connection pooling     ║
║ Thread-safe • Crash-resistant • Kali Linux Optimized                       ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sqlite3
import uuid
import json
import threading
import time
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from contextlib import contextmanager

# ─── Custom Exception ────────────────────────────────────────────────────────
class JobStoreError(Exception):
    """Raised when job store operations fail."""
    pass

# ─── Configuration ───────────────────────────────────────────────────────────
JOB_DIR = Path(os.environ.get("NULLSEC_JOB_DIR", "/opt/nullsec/jobs"))
DB_PATH = Path(os.environ.get("NULLSEC_JOB_DB", str(JOB_DIR / "jobs.db")))

# Ensure directory exists
try:
    JOB_DIR.mkdir(parents=True, exist_ok=True)
except (PermissionError, OSError) as e:
    # Fallback to temp directory
    JOB_DIR = Path("/tmp/nullsec_jobs")
    JOB_DIR.mkdir(parents=True, exist_ok=True)
    DB_PATH = JOB_DIR / "jobs.db"

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
    """Thread-safe SQLite connection pool with automatic reconnection."""

    def __init__(self, db_path: Path, max_connections: int = 5):
        self.db_path = db_path
        self.max_connections = max_connections
        self._pool: List[sqlite3.Connection] = []
        self._lock = threading.Lock()
        self._count = 0
        self._initialized = False
        self._init_db()

    def _init_db(self):
        """Initialize database with WAL mode and schema."""
        if self._initialized:
            return

        try:
            conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=10)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA mmap_size=30000000000")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute(CREATE_SQL)
            conn.commit()

            # Create indexes separately (sqlite3 doesn't allow multi-statement)
            for stmt in CREATE_INDEXES.strip().split(';\n'):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(stmt)
            conn.commit()
            conn.close()
            self._initialized = True
        except sqlite3.Error as e:
            raise JobStoreError(f"Failed to initialize database: {e}")

    @contextmanager
    def get(self):
        """Get a connection from the pool."""
        conn = None
        acquired = False
        try:
            with self._lock:
                if self._pool:
                    conn = self._pool.pop()
                    acquired = True
                elif self._count < self.max_connections:
                    conn = sqlite3.connect(
                        str(self.db_path), 
                        check_same_thread=False,
                        timeout=10,
                        isolation_level=None  # Autocommit mode for better concurrency
                    )
                    conn.row_factory = sqlite3.Row
                    self._count += 1
                    acquired = True
                else:
                    # Wait for available connection with timeout
                    wait_start = time.time()
                    while not self._pool and (time.time() - wait_start) < 30:
                        self._lock.release()
                        time.sleep(0.1)
                        self._lock.acquire()

                    if self._pool:
                        conn = self._pool.pop()
                        acquired = True
                    else:
                        # Create emergency connection
                        conn = sqlite3.connect(
                            str(self.db_path),
                            check_same_thread=False,
                            timeout=5
                        )
                        conn.row_factory = sqlite3.Row

            if conn is None:
                raise JobStoreError("Could not acquire database connection")

            # Verify connection is alive
            try:
                conn.execute("SELECT 1")
            except sqlite3.Error:
                # Connection is dead, create new one
                conn = sqlite3.connect(
                    str(self.db_path),
                    check_same_thread=False,
                    timeout=10
                )
                conn.row_factory = sqlite3.Row

            yield conn

        except Exception as e:
            raise JobStoreError(f"Database connection error: {e}")
        finally:
            if conn:
                try:
                    with self._lock:
                        if acquired and len(self._pool) < self.max_connections:
                            self._pool.append(conn)
                        else:
                            conn.close()
                            if acquired:
                                self._count -= 1
                except Exception:
                    try:
                        conn.close()
                    except:
                        pass

# ─── Global pool (lazy initialization) ───────────────────────────────────────
_pool: Optional[ConnectionPool] = None
_pool_lock = threading.Lock()

def _get_pool() -> ConnectionPool:
    """Get or create the global connection pool."""
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                _pool = ConnectionPool(DB_PATH)
    return _pool

# ─── JobStore Class ────────────────────────────────────────────────────────────
class JobStore:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._pool = _get_pool()

    def create_job(self, tool: str, target: str, options: str = "", priority: int = 5) -> str:
        """Create a new job and return its ID."""
        if not tool or not isinstance(tool, str):
            raise JobStoreError("Tool name must be a non-empty string")
        if not target or not isinstance(target, str):
            raise JobStoreError("Target must be a non-empty string")

        job_id = str(uuid.uuid4())

        with self._pool.get() as conn:
            try:
                conn.execute(
                    """INSERT INTO jobs (id, tool, target, options, status, priority)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (job_id, tool, target, options, "queued", priority)
                )
                return job_id
            except sqlite3.Error as e:
                raise JobStoreError(f"Failed to create job: {e}")

    def pop_queued_job(self) -> Optional[str]:
        """Atomically fetch and lock next queued job. Returns job_id or None."""
        with self._pool.get() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
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
            except sqlite3.Error as e:
                try:
                    conn.execute("ROLLBACK")
                except:
                    pass
                raise JobStoreError(f"Failed to pop queued job: {e}")

    def update_job(self, job_id: str, status: str, result: Optional[str] = None,
                   exit_code: Optional[int] = None, log_path: Optional[str] = None):
        """Update job status and results."""
        if not job_id:
            raise JobStoreError("Job ID is required")

        with self._pool.get() as conn:
            try:
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
            except sqlite3.Error as e:
                raise JobStoreError(f"Failed to update job {job_id}: {e}")

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve job by ID."""
        if not job_id:
            return None

        with self._pool.get() as conn:
            try:
                cur = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
                row = cur.fetchone()
                return dict(row) if row else None
            except sqlite3.Error as e:
                raise JobStoreError(f"Failed to get job {job_id}: {e}")

    def list_jobs(self, limit: int = 50, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List recent jobs, optionally filtered by status."""
        limit = max(1, min(limit, 1000))  # Clamp limit

        with self._pool.get() as conn:
            try:
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
            except sqlite3.Error as e:
                raise JobStoreError(f"Failed to list jobs: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get job statistics."""
        with self._pool.get() as conn:
            try:
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
                if row:
                    d = dict(row)
                    # SUM over empty table returns None in SQLite
                    return {k: (v if v is not None else 0) for k, v in d.items()}
                return {"total": 0, "queued": 0, "running": 0, "done": 0, "failed": 0}
            except sqlite3.Error as e:
                raise JobStoreError(f"Failed to get stats: {e}")

    def cleanup_old_jobs(self, days: int = 30) -> int:
        """Delete jobs older than specified days. Returns count deleted."""
        if days < 0:
            raise JobStoreError("Days must be non-negative")

        with self._pool.get() as conn:
            try:
                cur = conn.execute(
                    "DELETE FROM jobs WHERE created_at < datetime('now', '-{} days')".format(days)
                )
                return cur.rowcount
            except sqlite3.Error as e:
                raise JobStoreError(f"Failed to cleanup old jobs: {e}")

    def reset_failed_jobs(self) -> int:
        """Reset failed jobs back to queued status. Returns count reset."""
        with self._pool.get() as conn:
            try:
                cur = conn.execute(
                    """UPDATE jobs SET status = 'queued', started_at = NULL, 
                       completed_at = NULL, result = NULL, exit_code = NULL
                    WHERE status = 'failed'"""
                )
                return cur.rowcount
            except sqlite3.Error as e:
                raise JobStoreError(f"Failed to reset failed jobs: {e}")
