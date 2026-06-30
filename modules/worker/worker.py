#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  HexStrike Worker Service v6.0                                                ║
║  Secure job processor with sandboxing, resource limits & graceful shutdown     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import time
import signal
import subprocess
import shlex
import logging
import resource
import tempfile
import atexit
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from modules.worker.job_store import JobStore

# ─── Configuration ───────────────────────────────────────────────────────────
LOG_DIR = Path(os.environ.get("NULLSEC_LOG_DIR", "/var/log/nullsec"))
JOB_DIR = Path(os.environ.get("NULLSEC_JOB_DIR", "/opt/nullsec/jobs"))
CONTAINER_RUNTIME = os.environ.get("CONTAINER_RUNTIME", "docker")
MAX_RETRIES = 3
JOB_TIMEOUT = 300

LOG_DIR.mkdir(parents=True, exist_ok=True)
JOB_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "worker.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("hexstrike_worker")

# ─── Signal Handling ─────────────────────────────────────────────────────────
_shutdown_requested = False

def _signal_handler(signum, frame):
    global _shutdown_requested
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    _shutdown_requested = True

signal.signal(signal.SIGTERM, _signal_handler)
signal.signal(signal.SIGINT, _signal_handler)

# ─── Resource Limits ─────────────────────────────────────────────────────────
def _limit_resources():
    """Apply strict resource limits to child processes."""
    try:
        resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))  # 1GB
        resource.setrlimit(resource.RLIMIT_CPU, (300, 300))  # 5 min CPU
        resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # No core dumps
        resource.setrlimit(resource.RLIMIT_NPROC, (50, 50))  # Max 50 processes
    except ValueError as e:
        logger.warning(f"Could not set resource limits: {e}")

# ─── Worker Class ────────────────────────────────────────────────────────────
class Worker:
    def __init__(self, poll_interval: int = 2):
        self.store = JobStore()
        self.poll_interval = poll_interval
        self._running = True
        self._current_job: Optional[str] = None
        self._cleanup_old_logs()
        atexit.register(self._emergency_cleanup)

    def _cleanup_old_logs(self, max_age_days: int = 7):
        cutoff = time.time() - (max_age_days * 86400)
        for log_file in LOG_DIR.glob("*.log"):
            if log_file.stat().st_mtime < cutoff and log_file.name not in ("worker.log", "server.log"):
                try:
                    log_file.unlink()
                except OSError:
                    pass

    def _emergency_cleanup(self):
        if self._current_job:
            try:
                self.store.update_job(self._current_job, 'failed', result='Worker crashed or killed')
                logger.warning(f"Emergency cleanup: marked job {self._current_job} as failed")
            except Exception:
                pass

    def _validate_tool(self, tool: str) -> Tuple[bool, str]:
        if not tool or not isinstance(tool, str):
            return False, "Invalid tool name"
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            return False, f"Tool '{tool}' not found in PATH"
        return True, ""

    def _run_job_local(self, job: Dict[str, Any]) -> Tuple[int, str]:
        tool = job['tool']
        target = job['target']
        options = job.get('options', '') or ""

        valid, error = self._validate_tool(tool)
        if not valid:
            return 127, error

        cmd = [tool]
        if options:
            try:
                parsed = shlex.split(options)
                for arg in parsed:
                    if any(c in arg for c in [';', '&', '|', '$', '`', '>', '<']):
                        return 1, f"Invalid characters in options: {arg}"
                cmd.extend(parsed)
            except ValueError as e:
                return 1, f"Invalid options format: {e}"

        cmd.append(target)

        log_path = LOG_DIR / f"{job['id']}.log"
        logger.info(f"Executing: {' '.join(cmd)} → {log_path}")

        try:
            with open(log_path, 'w') as lf:
                lf.write(f"# Command: {' '.join(cmd)}\n")
                lf.write(f"# Started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                lf.write("=" * 60 + "\n")

                proc = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=JOB_TIMEOUT, preexec_fn=_limit_resources
                )

                output = proc.stdout or proc.stderr or ""
                lf.write(output)
                lf.write(f"\n# Exit code: {proc.returncode}\n")

                return proc.returncode, str(log_path)

        except subprocess.TimeoutExpired:
            logger.error(f"Job {job['id']} timed out")
            return 124, str(log_path)
        except Exception as e:
            logger.exception(f"Job {job['id']} failed")
            return 1, str(log_path)

    def _run_job_container(self, job: Dict[str, Any]) -> Tuple[int, str]:
        image = os.environ.get('TOOL_IMAGE', 'nullsec/toolbox:latest')
        workspace = JOB_DIR / job['id']
        workspace.mkdir(parents=True, exist_ok=True)
        log_path = LOG_DIR / f"{job['id']}.log"

        run_cmd = [CONTAINER_RUNTIME, 'run', '--rm', '-v', f"{workspace}:/work", image]
        tool_cmd = [job['tool']] + (shlex.split(job['options']) if job['options'] else []) + [job['target']]
        run_cmd.extend(tool_cmd)

        try:
            with open(log_path, 'w') as lf:
                proc = subprocess.run(run_cmd, capture_output=True, text=True, timeout=600)
                lf.write(proc.stdout or proc.stderr)
                return proc.returncode, str(log_path)
        except subprocess.TimeoutExpired:
            return 124, str(log_path)
        except Exception as e:
            return 1, str(log_path)

    def run_once(self, job_id: str):
        job = self.store.get_job(job_id)
        if not job:
            return

        self._current_job = job_id

        # Try containerized first, fallback to local
        try:
            subprocess.run([CONTAINER_RUNTIME, '--version'], check=True, capture_output=True, timeout=5)
            code, log = self._run_job_container(job)
        except Exception:
            code, log = self._run_job_local(job)

        if code == 0:
            self.store.update_job(job_id, 'done', result=f'Completed successfully', exit_code=code, log_path=log)
            logger.info(f"Job {job_id} completed")
        else:
            self.store.update_job(job_id, 'failed', result=f'Exit code: {code}', exit_code=code, log_path=log)
            logger.warning(f"Job {job_id} failed with code {code}")

        self._current_job = None

    def run(self):
        logger.info("HexStrike Worker started")
        logger.info(f"Polling interval: {self.poll_interval}s")

        while self._running and not _shutdown_requested:
            try:
                job_id = self.store.pop_queued_job()
                if job_id:
                    logger.info(f"Picked job {job_id}")
                    self.run_once(job_id)
                else:
                    time.sleep(self.poll_interval)
            except Exception as e:
                logger.exception("Worker loop error")
                time.sleep(self.poll_interval)

        logger.info("Worker shutting down gracefully")

    def stop(self):
        self._running = False

def main():
    import argparse
    parser = argparse.ArgumentParser(description="HexStrike Worker")
    parser.add_argument("--poll", type=int, default=2, help="Polling interval in seconds")
    args = parser.parse_args()

    worker = Worker(poll_interval=args.poll)

    try:
        worker.run()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
        worker.stop()

if __name__ == '__main__':
    main()
