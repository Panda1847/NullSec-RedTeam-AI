from modules.worker.job_store import JobStore
import tempfile
from pathlib import Path

def test_job_store_create(tmp_path):
    db_path = tmp_path / 'jobs.db'
    store = JobStore(db_path)
    job_id = store.create_job('nmap', '127.0.0.1', '-sV')
    assert job_id
    job = store.get_job(job_id)
    assert job['tool'] == 'nmap'
    assert job['status'] == 'queued'
