#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║ HexStrike AI Orchestration Server v7.0                                      ║
║ Flask-based REST API for security tool execution & job management           ║
║ Stress-tested • Hardened • Production-ready • Kali Linux Optimized         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import re
import ipaddress
import logging
import signal
import tempfile
import atexit
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from functools import wraps
from datetime import datetime, timezone
from contextlib import contextmanager

from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ─── Ensure modules are importable ───────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent.parent.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

try:
    from modules.worker.job_store import JobStore, JobStoreError
except ImportError as e:
    logging.critical(f"Failed to import JobStore: {e}")
    # Fallback: create a minimal in-memory store
    class JobStoreError(Exception):
        pass

    class JobStore:
        """Fallback in-memory job store."""
        def __init__(self):
            self._jobs: Dict[str, Dict[str, Any]] = {}
            self._lock = __import__('threading').Lock()

        def create_job(self, tool: str, target: str, options: str = "", priority: int = 5) -> str:
            import uuid
            job_id = str(uuid.uuid4())
            with self._lock:
                self._jobs[job_id] = {
                    "id": job_id, "tool": tool, "target": target,
                    "options": options, "status": "queued", "priority": priority,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "result": None, "exit_code": None, "log_path": None
                }
            return job_id

        def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
            with self._lock:
                return self._jobs.get(job_id)

        def update_job(self, job_id: str, status: str, **kwargs) -> None:
            with self._lock:
                if job_id in self._jobs:
                    self._jobs[job_id]["status"] = status
                    self._jobs[job_id]["updated_at"] = datetime.now(timezone.utc).isoformat()
                    for k, v in kwargs.items():
                        self._jobs[job_id][k] = v

        def list_jobs(self, limit: int = 50, status: Optional[str] = None) -> List[Dict[str, Any]]:
            with self._lock:
                jobs = list(self._jobs.values())
                if status:
                    jobs = [j for j in jobs if j["status"] == status]
                return sorted(jobs, key=lambda x: x["created_at"], reverse=True)[:limit]

        def get_stats(self) -> Dict[str, Any]:
            with self._lock:
                total = len(self._jobs)
                queued = sum(1 for j in self._jobs.values() if j["status"] == "queued")
                running = sum(1 for j in self._jobs.values() if j["status"] == "running")
                done = sum(1 for j in self._jobs.values() if j["status"] == "done")
                failed = sum(1 for j in self._jobs.values() if j["status"] == "failed")
                return {"total": total, "queued": queued, "running": running, "done": done, "failed": failed}

# ─── Configuration ───────────────────────────────────────────────────────────
LOG_DIR = Path(os.environ.get("NULLSEC_LOG_DIR", "/var/log/nullsec"))

# Safe logging setup — handles permission errors gracefully
log_file = None
try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / "server.log"
except (PermissionError, OSError) as e:
    # Fallback to temp directory
    LOG_DIR = Path(tempfile.gettempdir()) / "nullsec_logs"
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_file = LOG_DIR / "server.log"
    except (PermissionError, OSError):
        log_file = None

try:
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s",
        handlers=handlers
    )
except Exception as e:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )
    logging.warning(f"Could not configure file logging: {e}. Logging to stdout only.")

logger = logging.getLogger("hexstrike")

# ─── Flask App ───────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16KB max request
app.config["JSON_SORT_KEYS"] = False

# Rate limiting with fallback
try:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://",
    )
except Exception as e:
    logger.warning(f"Rate limiter init failed: {e}. Running without rate limiting.")
    # Dummy limiter that does nothing
    class DummyLimiter:
        def limit(self, *args, **kwargs):
            def decorator(f):
                return f
            return decorator
    limiter = DummyLimiter()

# ─── Tool Registry ───────────────────────────────────────────────────────────
AVAILABLE_TOOLS = {
    "nmap": {"desc": "Network discovery & port scanning", "category": "recon"},
    "sqlmap": {"desc": "Automated SQL injection testing", "category": "web"},
    "gobuster": {"desc": "Directory/file brute-forcing", "category": "web"},
    "hydra": {"desc": "Password brute-forcing", "category": "auth"},
    "metasploit": {"desc": "Exploitation framework", "category": "exploit"},
    "nuclei": {"desc": "Vulnerability scanning", "category": "scan"},
    "subfinder": {"desc": "Subdomain enumeration", "category": "recon"},
    "amass": {"desc": "Attack surface mapping", "category": "recon"},
    "ffuf": {"desc": "Web fuzzing", "category": "web"},
    "nikto": {"desc": "Web server scanning", "category": "web"},
    "dirsearch": {"desc": "Web path discovery", "category": "web"},
    "john": {"desc": "Password hash cracking", "category": "auth"},
    "hashcat": {"desc": "GPU password cracking", "category": "auth"},
    "whois": {"desc": "Domain registration lookup", "category": "recon"},
    "dig": {"desc": "DNS lookup utility", "category": "recon"},
}
ALLOWED_TOOLS = set(AVAILABLE_TOOLS.keys())

# ─── Security Utilities ──────────────────────────────────────────────────────

class SecurityError(Exception):
    """Raised when security validation fails."""
    pass

def get_api_token() -> Optional[str]:
    """Retrieve API token from environment or secure file."""
    token = os.environ.get("API_TOKEN")
    if token:
        return token.strip()

    token_file = Path("/etc/nullsec/api_token")
    try:
        if token_file.exists() and token_file.is_file():
            return token_file.read_text().strip()
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError) as e:
        logger.warning(f"API token read error: {e}")
    return None

def require_token(f):
    """Bearer token authentication decorator."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            logger.warning(f"Unauthorized request from {request.remote_addr}")
            return jsonify({
                "error": "Unauthorized",
                "message": "Bearer token required. Set API_TOKEN environment variable or create /etc/nullsec/api_token"
            }), 401

        parts = auth.split(None, 1)
        token = parts[1] if len(parts) > 1 else ""
        expected = get_api_token()

        if expected is None:
            logger.error("Server API token not configured")
            return jsonify({
                "error": "Server Misconfigured",
                "message": "API token not set on server. Run: sudo guardian --repair"
            }), 500

        if not token or token != expected:
            logger.warning(f"Invalid token from {request.remote_addr}")
            return jsonify({"error": "Forbidden", "message": "Invalid token"}), 403

        return f(*args, **kwargs)
    return wrapper

def sanitize_input(text: str, allow_spaces: bool = True, max_len: int = 1024) -> str:
    """
    Aggressive input sanitization. Prevents command injection & path traversal.
    Only allows: alphanumeric, hyphen, underscore, dot, slash (for paths), and optionally spaces.
    """
    if text is None or not isinstance(text, str):
        return ""

    text = str(text)[:max_len]

    # Strip path traversal sequences
    text = text.replace("..", "").replace("//", "").replace("\\\\", "")

    allowed = set("-_./")
    if allow_spaces:
        allowed.add(" ")

    result = "".join(c for c in text if c.isalnum() or c in allowed)
    result = result.strip()

    # Prevent leading dash (command flag injection)
    while result.startswith("-"):
        result = result[1:].lstrip()

    return result

def validate_target(target: str) -> Tuple[bool, Optional[str]]:
    """
    Validate target is a legitimate IP, hostname, or URL.
    Returns (is_valid, error_message).
    """
    if not target or not isinstance(target, str):
        return False, "Target must be a string"

    if len(target) > 512:
        return False, "Target exceeds maximum length (512 chars)"

    # Block path traversal and shell metacharacters
    forbidden = ["..", "~", "$", "`", "|", ";", "&", ">", "<", "(", ")", "{", "}", "\\", "\n", "\r", "\t"]
    if any(c in target for c in forbidden):
        return False, "Target contains forbidden characters"

    if target.startswith("/") or target.startswith("-"):
        return False, "Invalid target format"

    # Try IP address
    try:
        ipaddress.ip_address(target)
        return True, None
    except ValueError:
        pass

    # Try hostname/domain
    hostname_re = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
        r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
    )
    if hostname_re.match(target):
        return True, None

    # Try URL
    url_re = re.compile(
        r"^https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
        r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?::\d{1,5})?(?:/.*)?$"
    )
    if url_re.match(target):
        return True, None

    return False, "Target must be a valid IP address, hostname, or URL"

def validate_options(options: str) -> Tuple[bool, Optional[str]]:
    """Validate tool options to prevent injection."""
    if not options or not isinstance(options, str):
        return True, None

    # Block dangerous characters
    dangerous = [";", "|", "&", "$", "`", ">", "<", "(", ")", "{", "}", "\\", "\n", "\r"]
    if any(c in options for c in dangerous):
        return False, "Options contain forbidden characters"

    # Block path traversal in options
    if ".." in options:
        return False, "Options contain path traversal"

    # Block shell execution
    if any(pattern in options for pattern in ["$(", "${", "`", "eval", "exec"]):
        return False, "Options contain shell execution patterns"

    return True, None

# ─── Store ───────────────────────────────────────────────────────────────────
_store_initialized = False
try:
    store = JobStore()
    _store_initialized = True
    logger.info("JobStore initialized successfully")
except Exception as e:
    logger.critical(f"Failed to initialize JobStore: {e}. Using in-memory fallback.")
    # Use the inline fallback class defined at the top of imports
    class _FallbackJobStore:
        """Fallback in-memory job store when SQLite fails."""
        def __init__(self):
            self._jobs = {}
            self._lock = __import__('threading').Lock()

        def create_job(self, tool, target, options="", priority=5):
            import uuid
            from datetime import datetime, timezone
            job_id = str(uuid.uuid4())
            with self._lock:
                self._jobs[job_id] = {
                    "id": job_id, "tool": tool, "target": target,
                    "options": options, "status": "queued", "priority": priority,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "result": None, "exit_code": None, "log_path": None
                }
            return job_id

        def get_job(self, job_id):
            with self._lock:
                return self._jobs.get(job_id)

        def update_job(self, job_id, status, **kwargs):
            from datetime import datetime, timezone
            with self._lock:
                if job_id in self._jobs:
                    self._jobs[job_id]["status"] = status
                    self._jobs[job_id]["updated_at"] = datetime.now(timezone.utc).isoformat()
                    for k, v in kwargs.items():
                        self._jobs[job_id][k] = v

        def list_jobs(self, limit=50, status=None):
            with self._lock:
                jobs = list(self._jobs.values())
                if status:
                    jobs = [j for j in jobs if j["status"] == status]
                return sorted(jobs, key=lambda x: x["created_at"], reverse=True)[:limit]

        def get_stats(self):
            with self._lock:
                total = len(self._jobs)
                queued = sum(1 for j in self._jobs.values() if j.get("status") == "queued")
                running = sum(1 for j in self._jobs.values() if j.get("status") == "running")
                done = sum(1 for j in self._jobs.values() if j.get("status") == "done")
                failed = sum(1 for j in self._jobs.values() if j.get("status") == "failed")
                return {"total": total, "queued": queued, "running": running, "done": done, "failed": failed}

    store = _FallbackJobStore()
    logger.warning("Using in-memory fallback JobStore — jobs will NOT persist across restarts!")

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health_check():
    """Public health check endpoint."""
    try:
        stats = store.get_stats()
        return jsonify({
            "status": "ok",
            "version": "7.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {k: v["desc"] for k, v in AVAILABLE_TOOLS.items()},
            "tool_count": len(AVAILABLE_TOOLS),
            "uptime": "active",
            "stats": stats
        }), 200
    except Exception as e:
        logger.exception("Health check failed")
        return jsonify({
            "status": "degraded",
            "version": "7.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e),
            "tools": {k: v["desc"] for k, v in AVAILABLE_TOOLS.items()},
            "tool_count": len(AVAILABLE_TOOLS),
        }), 200

@app.route("/api/tools/execute", methods=["POST"])
@require_token
@limiter.limit("200 per minute")
def execute_tool():
    """Queue a security tool execution job."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    try:
        data = request.get_json(silent=True)
    except Exception as e:
        logger.warning(f"JSON parse error: {e}")
        return jsonify({"error": "Invalid JSON data", "message": str(e)}), 400

    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON data", "message": "Expected JSON object"}), 400

    tool_name = data.get("tool")
    target = data.get("target")
    options = data.get("options", "")

    # Validate tool
    if not tool_name or not isinstance(tool_name, str):
        return jsonify({"error": "Invalid tool name", "message": "Tool name must be a string"}), 400

    if tool_name not in ALLOWED_TOOLS:
        logger.warning(f"Invalid tool requested: {tool_name}")
        return jsonify({
            "error": "Tool not allowed",
            "message": f"Tool '{tool_name}' not found or not allowed",
            "available_tools": list(ALLOWED_TOOLS)
        }), 404

    # Validate target
    is_valid, error_msg = validate_target(target)
    if not is_valid:
        return jsonify({"error": "Invalid target", "message": error_msg}), 400

    # Validate options
    opts_valid, opts_error = validate_options(options)
    if not opts_valid:
        return jsonify({"error": "Invalid options", "message": opts_error}), 400

    # Sanitize
    target = sanitize_input(target, allow_spaces=False, max_len=512)
    options = sanitize_input(options, allow_spaces=True, max_len=1024)

    # Create job
    try:
        job_id = store.create_job(tool_name, target, options)
        logger.info(f"Queued job {job_id}: {tool_name} → {target}")

        return jsonify({
            "status": "queued",
            "job_id": job_id,
            "tool": tool_name,
            "target": target,
            "message": "Job queued. Poll /api/jobs/<job_id> for status."
        }), 202

    except JobStoreError as e:
        logger.error(f"JobStore error: {e}")
        return jsonify({"error": "Database error", "message": str(e)}), 500
    except Exception as e:
        logger.exception("Failed to create job")
        return jsonify({"error": "Internal error", "message": str(e)}), 500

@app.route("/api/jobs/<job_id>", methods=["GET"])
@require_token
def get_job(job_id: str):
    """Retrieve job status and results by ID."""
    if not job_id or not re.match(r"^[a-f0-9-]{36}$", job_id):
        return jsonify({"error": "Invalid job ID format (expected UUID)"}), 400

    try:
        job = store.get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        return jsonify(job), 200
    except Exception as e:
        logger.exception(f"Failed to get job {job_id}")
        return jsonify({"error": "Internal error", "message": str(e)}), 500

@app.route("/api/jobs", methods=["GET"])
@require_token
def list_jobs():
    """List recent jobs (last 50)."""
    try:
        status_filter = request.args.get("status")
        limit = request.args.get("limit", 50, type=int)
        limit = min(max(limit, 1), 100)  # Clamp between 1 and 100

        jobs = store.list_jobs(limit=limit, status=status_filter)
        return jsonify({
            "jobs": jobs,
            "count": len(jobs),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200
    except Exception as e:
        logger.exception("Failed to list jobs")
        return jsonify({"error": "Internal error", "message": str(e)}), 500

@app.route("/api/tools", methods=["GET"])
@require_token
def list_tools():
    """List all available tools with metadata."""
    return jsonify({
        "tools": AVAILABLE_TOOLS,
        "count": len(AVAILABLE_TOOLS)
    }), 200

@app.route("/api/stats", methods=["GET"])
@require_token
def get_stats():
    """Get system statistics."""
    try:
        stats = store.get_stats()
        return jsonify({
            "stats": stats,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200
    except Exception as e:
        logger.exception("Failed to get stats")
        return jsonify({"error": "Internal error", "message": str(e)}), 500

# ─── Error Handlers ──────────────────────────────────────────────────────────

@app.errorhandler(429)
def ratelimit_handler(e):
    retry_after = getattr(e, 'description', 'unknown')
    return jsonify({"error": "Rate limit exceeded", "retry_after": str(retry_after)}), 429

@app.errorhandler(413)
def request_too_large(e):
    return jsonify({"error": "Request too large", "max_size": "16KB"}), 413

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found", "path": request.path}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed", "method": request.method}), 405

@app.errorhandler(500)
def internal_error(e):
    logger.exception("Internal server error")
    return jsonify({"error": "Internal server error", "message": "An unexpected error occurred"}), 500

@app.errorhandler(Exception)
def catch_all_error(e):
    logger.exception("Unhandled exception")
    return jsonify({"error": "Internal server error", "message": str(e)}), 500

# ─── Graceful Shutdown ──────────────────────────────────────────────────────
_shutdown_requested = False

def _signal_handler(signum, frame):
    global _shutdown_requested
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    _shutdown_requested = True

signal.signal(signal.SIGTERM, _signal_handler)
signal.signal(signal.SIGINT, _signal_handler)

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="HexStrike AI Server v7.0")
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--workers", type=int, default=1)
    args = parser.parse_args()

    logger.info(f"Starting HexStrike Server v7.0 on {args.host}:{args.port}")
    logger.info(f"Tools available: {len(ALLOWED_TOOLS)}")

    # Validate port
    if not (1024 <= args.port <= 65535):
        logger.error(f"Invalid port: {args.port}. Must be 1024-65535.")
        sys.exit(1)

    if args.workers > 1:
        try:
            from gunicorn.app.base import BaseApplication

            class GunicornApp(BaseApplication):
                def __init__(self, app, options=None):
                    self.options = options or {}
                    self.application = app
                    super().__init__()

                def load_config(self):
                    for key, value in self.options.items():
                        if key in self.cfg.settings and value is not None:
                            self.cfg.set(key.lower(), value)

                def load(self):
                    return self.application

            options = {
                "bind": f"{args.host}:{args.port}",
                "workers": args.workers,
                "timeout": 120,
                "accesslog": str(LOG_DIR / "access.log"),
                "errorlog": str(LOG_DIR / "error.log"),
                "capture_output": True,
            }
            GunicornApp(app, options).run()
        except ImportError:
            logger.warning("Gunicorn not installed, using Flask development server")
            app.run(host=args.host, port=args.port, debug=False, threaded=True)
    else:
        app.run(host=args.host, port=args.port, debug=False, threaded=True)

if __name__ == "__main__":
    main()
