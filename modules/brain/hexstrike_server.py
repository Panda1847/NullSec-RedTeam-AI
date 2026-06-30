#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  HexStrike AI Orchestration Server v6.0                                       ║
║  Flask-based REST API for security tool execution job management               ║
║  Stress-tested • Hardened • Production-ready                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import re
import ipaddress
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
from functools import wraps
from datetime import datetime, timezone

from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Ensure modules are importable
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from modules.worker.job_store import JobStore

# ─── Configuration ───────────────────────────────────────────────────────────
LOG_DIR = Path(os.environ.get("NULLSEC_LOG_DIR", "/var/log/nullsec"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "server.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("hexstrike")

# ─── Flask App ───────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16KB max request

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

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
}
ALLOWED_TOOLS = set(AVAILABLE_TOOLS.keys())

# ─── Security Utilities ──────────────────────────────────────────────────────

def get_api_token() -> Optional[str]:
    """Retrieve API token from environment or secure file."""
    token = os.environ.get("API_TOKEN")
    if token:
        return token.strip()

    token_file = Path("/etc/nullsec/api_token")
    try:
        return token_file.read_text().strip()
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        logger.warning("API token not configured")
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
            return jsonify({"error": "Server Misconfigured", "message": "API token not set on server"}), 500

        if not token or token != expected:
            logger.warning(f"Invalid token from {request.remote_addr}")
            return jsonify({"error": "Forbidden", "message": "Invalid token"}), 403

        return f(*args, **kwargs)
    return wrapper

def sanitize_input(text: str, allow_spaces: bool = True, max_len: int = 1024) -> str:
    """
    Aggressive input sanitization. Prevents command injection & path traversal.
    Only allows: alphanumeric, hyphen, underscore, and optionally spaces.
    """
    if not text:
        return ""

    text = text[:max_len]

    # Strip path traversal sequences
    text = text.replace("..", "").replace("//", "").replace("\\", "")

    allowed = set("-_")
    if allow_spaces:
        allowed.add(" ")

    result = "".join(c for c in text if c.isalnum() or c in allowed)
    result = result.strip()

    # Prevent leading dash (command flag injection)
    if result.startswith("-"):
        result = result.lstrip("- ")

    return result

def validate_target(target: str) -> tuple[bool, Optional[str]]:
    """
    Validate target is a legitimate IP, hostname, or URL.
    Returns (is_valid, error_message).
    """
    if not target:
        return False, "Target is required"

    if len(target) > 512:
        return False, "Target exceeds maximum length (512 chars)"

    # Block path traversal and shell metacharacters
    forbidden = ["..", "~", "$", "`", "|", ";", "&", ">", "<", "(", ")", "{", "}", "\"]
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

# ─── Store ───────────────────────────────────────────────────────────────────
store = JobStore()

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health_check():
    """Public health check endpoint."""
    return jsonify({
        "status": "ok",
        "version": "6.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tools": {k: v["desc"] for k, v in AVAILABLE_TOOLS.items()},
        "tool_count": len(AVAILABLE_TOOLS),
        "uptime": "active"
    }), 200

@app.route("/api/tools/execute", methods=["POST"])
@require_token
@limiter.limit("10 per minute")
def execute_tool():
    """Queue a security tool execution job."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON data"}), 400

    tool_name = data.get("tool")
    target = data.get("target")
    options = data.get("options", "")

    # Validate tool
    if not tool_name or tool_name not in ALLOWED_TOOLS:
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

    except Exception as e:
        logger.exception("Failed to create job")
        return jsonify({"error": "Internal error", "message": str(e)}), 500

@app.route("/api/jobs/<job_id>", methods=["GET"])
@require_token
def get_job(job_id: str):
    """Retrieve job status and results by ID."""
    if not re.match(r"^[a-f0-9-]{36}$", job_id):
        return jsonify({"error": "Invalid job ID format (expected UUID)"}), 400

    job = store.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404

    return jsonify(job), 200

@app.route("/api/jobs", methods=["GET"])
@require_token
def list_jobs():
    """List recent jobs (last 50)."""
    try:
        jobs = store.list_jobs(limit=50)
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
        return jsonify({"error": "Internal error"}), 500

# ─── Error Handlers ──────────────────────────────────────────────────────────

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Rate limit exceeded", "retry_after": str(e.description)}), 429

@app.errorhandler(413)
def request_too_large(e):
    return jsonify({"error": "Request too large", "max_size": "16KB"}), 413

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found", "path": request.path}), 404

@app.errorhandler(500)
def internal_error(e):
    logger.exception("Internal server error")
    return jsonify({"error": "Internal server error"}), 500

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="HexStrike AI Server")
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--workers", type=int, default=1)
    args = parser.parse_args()

    logger.info(f"Starting HexStrike Server on {args.host}:{args.port}")

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
