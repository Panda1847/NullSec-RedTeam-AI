#!/usr/bin/env python3
"""
NullSec Worker Tests - Job Processing
"""

import pytest
import sys
import tempfile
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.worker.job_store import JobStore

class TestJobStore:
    def setup_method(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_jobs.db"
        os.environ["NULLSEC_JOB_DB"] = str(self.db_path)
        self.store = JobStore(db_path=self.db_path)

    def teardown_method(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_create_job(self):
        job_id = self.store.create_job("nmap", "127.0.0.1", "-sn")
        assert len(job_id) == 36

    def test_get_job(self):
        job_id = self.store.create_job("nmap", "127.0.0.1")
        job = self.store.get_job(job_id)
        assert job is not None
        assert job["tool"] == "nmap"
        assert job["target"] == "127.0.0.1"
        assert job["status"] == "queued"

    def test_update_job(self):
        job_id = self.store.create_job("nmap", "127.0.0.1")
        self.store.update_job(job_id, "running")
        job = self.store.get_job(job_id)
        assert job["status"] == "running"

    def test_update_job_with_result(self):
        job_id = self.store.create_job("nmap", "127.0.0.1")
        self.store.update_job(job_id, "done", result="Scan complete", exit_code=0)
        job = self.store.get_job(job_id)
        assert job["status"] == "done"
        assert job["result"] == "Scan complete"
        assert job["exit_code"] == 0

    def test_pop_queued_job(self):
        job_id = self.store.create_job("nmap", "127.0.0.1")
        popped = self.store.pop_queued_job()
        assert popped == job_id
        job = self.store.get_job(job_id)
        assert job["status"] == "running"

    def test_pop_empty_queue(self):
        popped = self.store.pop_queued_job()
        assert popped is None

    def test_list_jobs(self):
        for i in range(5):
            self.store.create_job("nmap", f"192.168.1.{i}")
        jobs = self.store.list_jobs(limit=10)
        assert len(jobs) == 5

    def test_list_jobs_by_status(self):
        job1 = self.store.create_job("nmap", "127.0.0.1")
        job2 = self.store.create_job("sqlmap", "127.0.0.1")
        self.store.update_job(job2, "done")
        queued = self.store.list_jobs(status="queued")
        done = self.store.list_jobs(status="done")
        assert len(queued) == 1
        assert len(done) == 1

    def test_get_stats(self):
        self.store.create_job("nmap", "127.0.0.1")
        self.store.create_job("sqlmap", "127.0.0.1")
        self.store.pop_queued_job()
        stats = self.store.get_stats()
        assert stats["total"] == 2
        assert stats["running"] == 1

    def test_cleanup_old_jobs(self):
        job_id = self.store.create_job("nmap", "127.0.0.1")
        deleted = self.store.cleanup_old_jobs(days=0)
        assert deleted >= 0

class TestWorkerValidation:
    def test_validate_tool_exists(self):
        result = os.system("which nmap >/dev/null 2>&1")
        assert result == 0

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
