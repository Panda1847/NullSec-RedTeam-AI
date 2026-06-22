import sqlite3
import os
import uuid
import json
from pathlib import Path
from typing import Optional, Dict, Any

JOB_DIR = Path(os.environ.get("NULLSEC_JOB_DIR", "/opt/nullsec/jobs"))
DB_PATH = Path(os.environ.get("NULLSEC_JOB_DB", str(JOB_DIR / "jobs.db")))
JOB_DIR.mkdir(parents=True, exist_ok=True)

CREATE_SQL = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    tool TEXT,
    target TEXT,
    options TEXT,
    status TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    result TEXT
);
"""

class JobStore:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(CREATE_SQL)
            conn.commit()
        finally:
            conn.close()

    def create_job(self, tool: str, target: str, options: str = "") -> str:
        job_id = str(uuid.uuid4())
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "INSERT INTO jobs (id, tool, target, options, status) VALUES (?, ?, ?, ?, ?)",
                (job_id, tool, target, options, "queued")
            )
            conn.commit()
        finally:
            conn.close()
        return job_id

    def update_job(self, job_id: str, status: str, result: Optional[str] = None):
        conn = sqlite3.connect(self.db_path)
        try:
            if result is not None:
                conn.execute(
                    "UPDATE jobs SET status = ?, result = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (status, result, job_id)
                )
            else:
                conn.execute(
                    "UPDATE jobs SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (status, job_id)
                )
            conn.commit()
        finally:
            conn.close()

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
            row = cur.fetchone()
            if row:
                return dict(row)
            return None
        finally:
            conn.close()
