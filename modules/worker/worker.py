#!/usr/bin/env python3
import time
import subprocess
import os
import shlex
import logging
import resource
from pathlib import Path

from modules.worker.job_store import JobStore

LOG_DIR = Path(os.environ.get("NULLSEC_LOG_DIR", "/var/log/nullsec"))
JOB_DIR = Path(os.environ.get("NULLSEC_JOB_DIR", "/opt/nullsec/jobs"))
CONTAINER_RUNTIME = os.environ.get("CONTAINER_RUNTIME", "docker")

def _limit_resources():
    # 512MB address space
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    # 60 seconds CPU
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    # File descriptors
    resource.setrlimit(resource.RLIMIT_NOFILE, (512, 512))

class Worker:
    def __init__(self, poll_interval: int = 2):
        self.store = JobStore()
        self.poll_interval = poll_interval
        self._running = True

    def _pop_job(self):
        # naive approach: query for queued job and set to running
        conn = None
        import sqlite3
        db = sqlite3.connect(self.store.db_path)
        try:
            cur = db.execute("SELECT id FROM jobs WHERE status = 'queued' ORDER BY created_at LIMIT 1")
            row = cur.fetchone()
            if not row:
                return None
            job_id = row[0]
            db.execute("UPDATE jobs SET status = 'running', updated_at = CURRENT_TIMESTAMP WHERE id = ?", (job_id,))
            db.commit()
            return job_id
        finally:
            db.close()

    def _run_job_local(self, job):
        tool = job['tool']
        target = job['target']
        options = job['options'] or ""
        cmd = [tool]
        if options:
            cmd.extend(shlex.split(options))
        cmd.append(target)
        log_path = LOG_DIR / f"{job['id']}.log"
        with open(log_path, 'w') as lf:
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, preexec_fn=_limit_resources)
                lf.write(proc.stdout or proc.stderr)
                return proc.returncode, lf.name
            except subprocess.TimeoutExpired:
                lf.write("[ERROR] Timeout expired\n")
                return 124, lf.name
            except Exception as e:
                lf.write(f"[ERROR] {e}\n")
                return 1, lf.name

    def _run_job_container(self, job):
        # This example assumes a base image that has the tools available; otherwise fallback
        image = os.environ.get('TOOL_IMAGE', 'nullsec/toolbox:latest')
        workspace = JOB_DIR / job['id']
        workspace.mkdir(parents=True, exist_ok=True)
        log_path = LOG_DIR / f"{job['id']}.log"
        # Build docker run command
        run_cmd = [CONTAINER_RUNTIME, 'run', '--rm', '-v', f"{workspace}:/work", image]
        tool_cmd = [job['tool']] + (shlex.split(job['options']) if job['options'] else []) + [job['target']]
        run_cmd.extend(tool_cmd)
        with open(log_path, 'w') as lf:
            try:
                proc = subprocess.run(run_cmd, capture_output=True, text=True, timeout=600)
                lf.write(proc.stdout or proc.stderr)
                return proc.returncode, lf.name
            except subprocess.TimeoutExpired:
                lf.write("[ERROR] Container execution timed out\n")
                return 124, lf.name
            except Exception as e:
                lf.write(f"[ERROR] Container exec failed: {e}\n")
                return 1, lf.name

    def run_once(self, job_id):
        job = self.store.get_job(job_id)
        if not job:
            return
        # Try containerized execution first
        try:
            subprocess.run([CONTAINER_RUNTIME, '--version'], check=True, capture_output=True)
            code, log = self._run_job_container(job)
        except Exception:
            code, log = self._run_job_local(job)

        if code == 0:
            self.store.update_job(job_id, 'done', result=f'log:{log}')
        else:
            self.store.update_job(job_id, 'failed', result=f'log:{log}')

    def run(self):
        logging.info('Worker started')
        while self._running:
            job_id = self._pop_job()
            if job_id:
                logging.info(f'Picked job {job_id}')
                self.run_once(job_id)
            else:
                time.sleep(self.poll_interval)

    def stop(self):
        self._running = False

if __name__ == '__main__':
    w = Worker()
    try:
        w.run()
    except KeyboardInterrupt:
        w.stop()
