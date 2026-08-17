#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║ HexStrike Worker Service v7.0                                               ║
║ Secure job processor with sandboxing, resource limits & graceful shutdown ║
║ Kali Linux Optimized • Container-aware • Fault-tolerant                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import atexit
import logging
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent.parent.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

try:
    from modules.runners.sandbox import (
        SandboxCancelled,
        SandboxExecutionError,
        SandboxProfile,
        SandboxRequiredRunner,
        SandboxUnavailable,
    )
    from modules.worker.job_store import JobStore, JobStoreError
except ImportError as e:
    logging.critical(f"Failed to import JobStore: {e}")
    sys.exit(1)

# ─── Configuration ───────────────────────────────────────────────────────────
LOG_DIR = Path(os.environ.get("NULLSEC_LOG_DIR", "/var/log/nullsec"))
JOB_DIR = Path(os.environ.get("NULLSEC_JOB_DIR", "/opt/nullsec/jobs"))
CONTAINER_RUNTIME = os.environ.get("CONTAINER_RUNTIME", "docker")
MAX_RETRIES = 3
JOB_TIMEOUT = 300

# Ensure directories exist
try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    JOB_DIR.mkdir(parents=True, exist_ok=True)
except (PermissionError, OSError):
    # Fallback to temp
    LOG_DIR = Path(tempfile.gettempdir()) / "nullsec_logs"
    JOB_DIR = Path(tempfile.gettempdir()) / "nullsec_jobs"
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    JOB_DIR.mkdir(parents=True, exist_ok=True)

# Logging
try:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s",
        handlers=[
            logging.FileHandler(LOG_DIR / "worker.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )
except (PermissionError, OSError):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
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
        import resource as _resource
        # Memory: 1GB
        _resource.setrlimit(_resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
        # CPU: 5 minutes
        _resource.setrlimit(_resource.RLIMIT_CPU, (300, 300))
        # File descriptors
        _resource.setrlimit(_resource.RLIMIT_NOFILE, (1024, 1024))
        # No core dumps
        _resource.setrlimit(_resource.RLIMIT_CORE, (0, 0))
        # Max 50 processes
        _resource.setrlimit(_resource.RLIMIT_NPROC, (50, 50))
    except ImportError:
        logger.warning("resource module not available (non-Linux platform). Skipping resource limits.")
    except ValueError as e:
        logger.warning(f"Could not set resource limits: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error setting resource limits: {e}")

# ─── Worker Class ────────────────────────────────────────────────────────────
class Worker:
    def __init__(self, poll_interval: int = 2):
        try:
            self.store = JobStore()
        except Exception as e:
            logger.critical(f"Failed to initialize JobStore: {e}")
            raise

        self.poll_interval = max(1, poll_interval)  # Minimum 1 second
        self.worker_id = os.environ.get("NULLSEC_WORKER_ID", f"{os.uname().nodename}-{os.getpid()}")
        self._running = True
        self._current_job: str | None = None
        self._cleanup_old_logs()
        atexit.register(self._emergency_cleanup)

    def _cleanup_old_logs(self, max_age_days: int = 7):
        """Clean up old log files."""
        try:
            cutoff = time.time() - (max_age_days * 86400)
            for log_file in LOG_DIR.glob("*.log"):
                if log_file.name not in ("worker.log", "server.log"):
                    try:
                        if log_file.stat().st_mtime < cutoff:
                            log_file.unlink()
                    except OSError:
                        pass
        except Exception as e:
            logger.warning(f"Log cleanup failed: {e}")

    def _emergency_cleanup(self):
        """Mark current job as failed on unexpected exit."""
        if self._current_job:
            try:
                self.store.update_job(self._current_job, 'failed', 
                                    result='Worker crashed or killed during execution')
                logger.warning(f"Emergency cleanup: marked job {self._current_job} as failed")
            except Exception:
                pass

    def _validate_tool(self, tool: str) -> tuple[bool, str]:
        """Validate tool name and availability."""
        if not isinstance(tool, str) or not tool.strip():
            return False, "Invalid tool name"
        if len(tool) > 64:
            return False, "Tool name too long"

        # Check for path traversal
        if "/" in tool or "\\" in tool or ".." in tool:
            return False, "Tool name contains invalid characters"

        # Check if tool exists in PATH
        try:
            result = subprocess.run(["which", tool], capture_output=True, timeout=5)
            if result.returncode != 0:
                return False, f"Tool '{tool}' not found in PATH"
        except Exception as e:
            return False, f"Could not verify tool: {e}"

        return True, ""

    def _sanitize_options(self, options: str) -> tuple[bool, str, list[str]]:
        """Sanitize and parse options. Returns (valid, error, parsed_args)."""
        if not options:
            return True, "", []

        # Check for dangerous characters
        dangerous = [";", "|", "&", "$", "`", ">", "<", "(", ")", "{", "}", "\\", "\n", "\r"]
        if any(c in options for c in dangerous):
            return False, "Options contain forbidden characters", []

        # Check for path traversal
        if ".." in options:
            return False, "Options contain path traversal", []

        # Check for shell execution
        if any(pattern in options for pattern in ["$(", "${", "`", "eval", "exec"]):
            return False, "Options contain shell execution patterns", []

        try:
            parsed = shlex.split(options)
            return True, "", parsed
        except ValueError as e:
            return False, f"Invalid options format: {e}", []

    def _run_job_local(self, job: dict[str, Any]) -> tuple[int, str]:
        """Run job locally with resource limits."""
        tool = job.get('tool', '')
        target = job.get('target', '')
        options = job.get('options', '') or ""
        job_id = job.get('id', 'unknown')

        # Validate tool
        valid, error = self._validate_tool(tool)
        if not valid:
            logger.error(f"Job {job_id}: {error}")
            return 127, error

        # Validate and parse options
        opts_valid, opts_error, parsed_opts = self._sanitize_options(options)
        if not opts_valid:
            logger.error(f"Job {job_id}: {opts_error}")
            return 1, opts_error

        # Build command
        cmd = [tool]
        cmd.extend(parsed_opts)
        cmd.append(target)

        log_path = LOG_DIR / f"{job_id}.log"
        logger.info(f"Executing job {job_id}: {' '.join(cmd)} → {log_path}")

        try:
            with open(log_path, 'w') as lf:
                lf.write(f"# Command: {' '.join(cmd)}\n")
                lf.write(f"# Started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                lf.write("=" * 60 + "\n")
                lf.flush()

                proc = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True,
                    timeout=JOB_TIMEOUT, 
                    preexec_fn=_limit_resources
                )

                output = proc.stdout or proc.stderr or ""
                lf.write(output)
                lf.write(f"\n# Exit code: {proc.returncode}\n")
                lf.write(f"# Completed: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

            return proc.returncode, str(log_path)

        except subprocess.TimeoutExpired:
            logger.error(f"Job {job_id} timed out after {JOB_TIMEOUT}s")
            with open(log_path, 'a') as lf:
                lf.write(f"\n# TIMEOUT after {JOB_TIMEOUT} seconds\n")
            return 124, str(log_path)
        except FileNotFoundError:
            logger.error(f"Job {job_id}: Tool '{tool}' not found")
            return 127, str(log_path)
        except PermissionError:
            logger.error(f"Job {job_id}: Permission denied executing '{tool}'")
            return 126, str(log_path)
        except Exception as e:
            logger.exception(f"Job {job_id} failed with unexpected error")
            with open(log_path, 'a') as lf:
                lf.write(f"\n# ERROR: {str(e)}\n")
            return 1, str(log_path)

    def _run_job_container(self, job: dict[str, Any]) -> tuple[int, str]:
        """Run only in a hardened sandbox; containment failures never fall back locally."""
        job_id = str(job.get("id", "unknown"))
        tool = str(job.get("tool", ""))
        target = str(job.get("target", ""))
        options = str(job.get("options", "") or "")
        log_path = LOG_DIR / f"{job_id}.log"

        valid, error = self._validate_tool(tool)
        if not valid:
            return 127, error
        options_valid, options_error, parsed_options = self._sanitize_options(options)
        if not options_valid:
            return 1, options_error

        image = os.environ.get("TOOL_IMAGE", "")
        network = os.environ.get("NULLSEC_SANDBOX_NETWORK", "none")
        workspace = JOB_DIR / job_id
        try:
            workspace.mkdir(parents=True, exist_ok=True)
            runner = SandboxRequiredRunner(
                SandboxProfile(
                    image=image,
                    network=network,
                    timeout_seconds=JOB_TIMEOUT,
                ),
                runtime=CONTAINER_RUNTIME,
            )
            completed = runner.run(
                job_id,
                workspace,
                [tool, *parsed_options, target],
                cancel_check=lambda: self.store.is_cancel_requested(job_id),
            )
            with open(log_path, "w", encoding="utf-8") as log_file:
                log_file.write("# Sandboxed execution completed\n")
                log_file.write(completed.stdout or "")
                log_file.write("\n# Exit code: 0\n")
            return 0, str(log_path)
        except SandboxCancelled as error:
            logger.info("Sandboxed job %s was cancelled: %s", job_id, error)
            with open(log_path, "w", encoding="utf-8") as log_file:
                log_file.write("# Sandboxed execution cancelled\n")
                log_file.write(f"# Reason: {error}\n")
            return 130, str(log_path)
        except (SandboxUnavailable, SandboxExecutionError, ValueError, OSError) as error:
            logger.error("Sandbox-required job %s was not executed: %s", job_id, error)
            with open(log_path, "w", encoding="utf-8") as log_file:
                log_file.write("# Sandbox-required execution failed closed\n")
                log_file.write(f"# Error: {error}\n")
            return 125, str(log_path)

    def _development_mode_enabled(self) -> bool:
        """Local execution is an explicit test/development opt-in only."""
        return os.environ.get("NULLSEC_EXECUTION_MODE", "").lower() == "development"

    def run_once(self, job_id: str):
        """Process a single job."""
        try:
            job = self.store.get_job(job_id)
            if not job:
                logger.warning(f"Job {job_id} not found")
                return

            self._current_job = job_id
            if job.get("status") == "leased":
                self.store.mark_running(job_id, self.worker_id)
                job = self.store.get_job(job_id) or job
            if self.store.is_cancel_requested(job_id):
                self.store.update_job(job_id, "cancelled", result="Cancelled before execution")
                return

            execution_mode = str(job.get("execution_mode", "sandbox_required"))
            if execution_mode == "development":
                if not self._development_mode_enabled():
                    code, log = 125, "Development execution mode is disabled"
                else:
                    code, log = self._run_job_local(job)
            elif execution_mode == "sandbox_required":
                code, log = self._run_job_container(job)
            else:
                code, log = 125, f"Unknown execution mode: {execution_mode}"

            if code == 130:
                self.store.update_job(job_id, "cancelled", result="Cancelled during execution", log_path=log)
                logger.info("Job %s cancelled", job_id)
            elif code == 0:
                self.store.update_job(
                    job_id, 'done', 
                    result='Completed successfully', 
                    exit_code=code, 
                    log_path=log
                )
                logger.info(f"Job {job_id} completed successfully")
            else:
                self.store.update_job(
                    job_id, 'failed', 
                    result=f'Exit code: {code}', 
                    exit_code=code, 
                    log_path=log
                )
                logger.warning(f"Job {job_id} failed with exit code {code}")

        except JobStoreError as e:
            logger.error(f"JobStore error for {job_id}: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error processing job {job_id}")
            try:
                self.store.update_job(job_id, 'failed', result=f'Worker error: {str(e)}')
            except JobStoreError as store_error:
                logger.error("Could not record worker failure for %s: %s", job_id, store_error)
        finally:
            self._current_job = None

    def run(self):
        """Main worker loop."""
        logger.info("HexStrike Worker v7.0 started")
        logger.info(f"Polling interval: {self.poll_interval}s")
        logger.info(f"Job timeout: {JOB_TIMEOUT}s")
        logger.info("Worker identity: %s", self.worker_id)
        logger.info("Execution mode defaults to sandbox_required; local mode is development-only")

        consecutive_errors = 0
        max_consecutive_errors = 10

        while self._running and not _shutdown_requested:
            try:
                leased_job = self.store.lease_next_job(self.worker_id, lease_seconds=JOB_TIMEOUT + 30)
                if leased_job:
                    job_id = str(leased_job["id"])
                    logger.info(f"Leased job {job_id}")
                    self.run_once(job_id)
                    consecutive_errors = 0
                else:
                    time.sleep(self.poll_interval)
                    consecutive_errors = 0
            except JobStoreError as e:
                consecutive_errors += 1
                logger.error(f"JobStore error (consecutive: {consecutive_errors}): {e}")
                if consecutive_errors >= max_consecutive_errors:
                    logger.critical("Too many consecutive errors, shutting down")
                    break
                time.sleep(self.poll_interval * min(consecutive_errors, 5))
            except Exception:
                consecutive_errors += 1
                logger.exception(f"Worker loop error (consecutive: {consecutive_errors})")
                if consecutive_errors >= max_consecutive_errors:
                    logger.critical("Too many consecutive errors, shutting down")
                    break
                time.sleep(self.poll_interval * min(consecutive_errors, 5))

        logger.info("Worker shutting down gracefully")

    def stop(self):
        """Stop the worker."""
        self._running = False
        logger.info("Worker stop requested")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="HexStrike Worker v7.0")
    parser.add_argument("--poll", type=int, default=2, help="Polling interval in seconds")
    parser.add_argument("--timeout", type=int, default=300, help="Job timeout in seconds")
    args = parser.parse_args()

    global JOB_TIMEOUT
    JOB_TIMEOUT = args.timeout

    worker = Worker(poll_interval=args.poll)

    try:
        worker.run()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
        worker.stop()
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
