#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║ HexStrike MCP Bridge v7.0                                                   ║
║ Claude Desktop ↔ HexStrike Server Integration                               ║
║ Fault-tolerant • Auto-retry • Auth-aware • Kali Linux Optimized          ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ─── Logging ───────────────────────────────────────────────────────────────
LOG_DIR = Path(os.environ.get("NULLSEC_LOG_DIR", "/var/log/nullsec"))
log_file = None

try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / "mcp.log"
except (PermissionError, OSError):
    import tempfile
    LOG_DIR = Path(tempfile.gettempdir()) / "nullsec_logs"
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_file = LOG_DIR / "mcp.log"
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

logger = logging.getLogger("hexstrike_mcp")

# ─── FastMCP Import ──────────────────────────────────────────────────────────
try:
    from fastmcp import FastMCP
except ImportError:
    try:  # Compatibility with the earlier MCP-provided FastMCP location.
        from mcp.server.fastmcp import FastMCP
    except ImportError as error:
        raise RuntimeError("FastMCP 3.2 or newer is required for the MCP bridge") from error

# ─── Configuration ───────────────────────────────────────────────────────────
HEXSTRIKE_SERVER_URL = os.environ.get("HEXSTRIKE_SERVER_URL", "http://localhost:8888")
API_TOKEN = os.environ.get("API_TOKEN", "")

# Cache
_AVAILABLE_TOOLS: list[str] | None = None
_CACHE_TIME: float = 0
_CACHE_TTL: float = 300

# ─── HTTP Session with Retry Logic ─────────────────────────────────────────
_session = requests.Session()
_retries = Retry(
    total=5,
    backoff_factor=1,
    status_forcelist=[500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "POST"]
)
_session.mount("http://", HTTPAdapter(max_retries=_retries))
_session.mount("https://", HTTPAdapter(max_retries=_retries))

def _get_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"
    return headers

def _fetch_tools() -> list[str]:
    """Fetch available tools from HexStrike server with caching."""
    global _AVAILABLE_TOOLS, _CACHE_TIME

    now = time.time()
    if _AVAILABLE_TOOLS is not None and (now - _CACHE_TIME) < _CACHE_TTL:
        return _AVAILABLE_TOOLS

    try:
        resp = _session.get(
            f"{HEXSTRIKE_SERVER_URL}/health",
            headers=_get_headers(),
            timeout=10
        )
        resp.raise_for_status()
        data = resp.json()
        tools = list(data.get("tools", {}).keys()) if isinstance(data.get("tools"), dict) else data.get("tools", [])
        _AVAILABLE_TOOLS = tools
        _CACHE_TIME = now
        logger.info(f"Fetched {len(tools)} tools from server")
        return tools
    except requests.exceptions.ConnectionError:
        logger.warning("Cannot connect to HexStrike server for tool fetch")
        return ["nmap", "sqlmap", "gobuster", "hydra", "nuclei", "ffuf", "nikto", "dirsearch"]
    except requests.exceptions.Timeout:
        logger.warning("Timeout fetching tools from HexStrike server")
        return ["nmap", "sqlmap", "gobuster", "hydra", "nuclei", "ffuf", "nikto", "dirsearch"]
    except Exception as e:
        logger.warning(f"Could not fetch tools: {e}")
        return ["nmap", "sqlmap", "gobuster", "hydra", "nuclei", "ffuf", "nikto", "dirsearch"]

def _make_request(method: str, endpoint: str, payload: dict | None = None, timeout: int = 30) -> dict[str, Any]:
    """Make a request to the HexStrike server with comprehensive error handling."""
    url = f"{HEXSTRIKE_SERVER_URL}{endpoint}"

    try:
        if method.upper() == "GET":
            resp = _session.get(url, headers=_get_headers(), timeout=timeout)
        else:
            resp = _session.post(url, json=payload, headers=_get_headers(), timeout=timeout)

        resp.raise_for_status()
        return {"success": True, "data": resp.json(), "status": resp.status_code}

    except requests.exceptions.ConnectionError:
        logger.error(f"Cannot connect to HexStrike server at {HEXSTRIKE_SERVER_URL}")
        return {
            "success": False,
            "error": "Connection Error",
            "message": f"Cannot reach HexStrike Server at {HEXSTRIKE_SERVER_URL}.\n\n**Fix it:**\n```bash\nsudo systemctl status hexstrike\nsudo systemctl start hexstrike\n```"
        }
    except requests.exceptions.Timeout:
        logger.error(f"Request to {url} timed out")
        return {"success": False, "error": "Timeout", "message": "Server is overloaded. Try again later."}
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response else 0
        responses = {
            401: {"success": False, "error": "Authentication Failed", "message": "Check API token configuration."},
            403: {"success": False, "error": "Forbidden", "message": "Invalid permissions."},
            429: {"success": False, "error": "Rate Limited", "message": "Too many requests. Wait a moment."},
        }
        return responses.get(status, {"success": False, "error": f"HTTP {status}", "message": str(e)})
    except Exception as e:
        logger.exception(f"Unexpected error in request to {url}")
        return {"success": False, "error": "Unexpected Error", "message": str(e)}

# ─── Initialize MCP ──────────────────────────────────────────────────────────
mcp = FastMCP("NullSec Red Team")

@mcp.tool()
def run_security_tool(tool_name: str, target: str, options: str = "") -> str:
    """
    Execute a security tool via the HexStrike orchestration server.

    Args:
        tool_name: Tool to run (nmap, sqlmap, gobuster, hydra, nuclei, ffuf, nikto, dirsearch)
        target: Target IP, hostname, or URL
        options: Additional command-line options

    Returns:
        Job status and polling instructions
    """
    if not tool_name or not isinstance(tool_name, str):
        return "❌ Invalid tool name. Must be a non-empty string."

    if not target or not isinstance(target, str):
        return "❌ Invalid target. Must be a non-empty string."

    if len(target) > 512:
        return "❌ Target exceeds maximum length (512 chars)."

    forbidden_chars = ["..", "$", "`", "|", ";", "&", ">", "<", "\n", "\r"]
    if any(c in target for c in forbidden_chars):
        return "❌ Target contains forbidden characters."

    if options and len(options) > 1024:
        return "❌ Options exceed maximum length (1024 chars)."

    available = _fetch_tools()
    if tool_name not in available:
        return f"❌ Tool '{tool_name}' not available. Available: {', '.join(available)}"

    result = _make_request("POST", "/api/tools/execute", {
        "tool": tool_name,
        "target": target,
        "options": options
    })

    if not result.get("success"):
        return f"❌ **{result.get('error', 'Error')}**: {result.get('message', 'Unknown error')}"

    data = result["data"]
    job_id = data.get("job_id", "unknown")
    status = data.get("status", "unknown")

    return (
        f"### 🛠️ Tool: {tool_name}\n"
        f"**Target**: `{target}`\n"
        f"**Status**: {status}\n"
        f"**Job ID**: `{job_id}`\n\n"
        f"📊 Check results with: `get_job_status('{job_id}')`"
    )

@mcp.tool()
def get_job_status(job_id: str) -> str:
    """Check status of a previously queued job."""
    if not job_id or not isinstance(job_id, str):
        return "❌ Invalid job ID. Expected string."

    if len(job_id) != 36:
        return "❌ Invalid job ID. Expected UUID format (36 characters)."

    result = _make_request("GET", f"/api/jobs/{job_id}", timeout=10)

    if not result.get("success"):
        if result.get("error") == "HTTP 404":
            return f"❌ Job `{job_id[:8]}...` not found."
        return f"❌ **{result.get('error', 'Error')}**: {result.get('message', 'Unknown error')}"

    job = result["data"]
    status = job.get("status", "unknown")
    tool = job.get("tool", "unknown")
    target = job.get("target", "unknown")
    result_text = job.get("result", "No result yet")
    created = job.get("created_at", "unknown")
    exit_code = job.get("exit_code")

    emojis = {"queued": "⏳", "running": "🔄", "done": "✅", "failed": "❌"}
    emoji = emojis.get(status, "❓")

    exit_info = f"\n**Exit Code**: {exit_code}" if exit_code is not None else ""

    return (
        f"### 📋 Job Status: `{job_id[:8]}...`\n"
        f"**Tool**: {tool}\n"
        f"**Target**: `{target}`\n"
        f"**Status**: {emoji} {status.upper()}\n"
        f"**Created**: {created}{exit_info}\n\n"
        f"**Result**:\n```\n{result_text}\n```"
    )

@mcp.tool()
def get_system_status() -> str:
    """Check health of all NullSec components."""
    components = []

    result = _make_request("GET", "/health", timeout=5)
    if result.get("success"):
        data = result["data"]
        tools = list(data.get("tools", {}).keys()) if isinstance(data.get("tools"), dict) else data.get("tools", [])
        version = data.get("version", "unknown")
        components.append(f"✅ HexStrike Server v{version}")
        components.append(f" 🛠️ Tools: {len(tools)} available")
    else:
        components.append(f"❌ HexStrike Server: {result.get('error', 'Offline')}")

    try:
        import subprocess
        worker_result = subprocess.run(
            ["systemctl", "is-active", "hexstrike-worker"],
            capture_output=True, text=True, timeout=2
        )
        if worker_result.stdout.strip() == "active":
            components.append("✅ Worker: Active")
        else:
            components.append("⚠️ Worker: Inactive")
    except FileNotFoundError:
        components.append("❓ Worker: systemctl not available")
    except Exception:
        components.append("❓ Worker: Status unknown")

    if API_TOKEN:
        components.append("🔐 API Token: Configured")
    else:
        components.append("⚠️ API Token: Not configured")

    try:
        import shutil
        stat = shutil.disk_usage("/opt/nullsec")
        free_gb = stat.free / (1024**3)
        if free_gb < 1:
            components.append(f"🔴 Disk Space: {free_gb:.1f}GB free (LOW)")
        else:
            components.append(f"✅ Disk Space: {free_gb:.1f}GB free")
    except Exception:
        pass

    return "\n".join(components)

@mcp.tool()
def list_available_tools() -> str:
    """List all available security tools with descriptions."""
    tools = _fetch_tools()

    descriptions = {
        "nmap": "Network discovery & port scanning",
        "sqlmap": "Automated SQL injection testing",
        "gobuster": "Directory/file brute-forcing",
        "hydra": "Password brute-forcing & credential testing",
        "metasploit": "Exploitation framework (elevated mode)",
        "nuclei": "Vulnerability scanning with templates",
        "subfinder": "Subdomain enumeration",
        "amass": "Attack surface mapping",
        "ffuf": "Web fuzzing & discovery",
        "nikto": "Web server vulnerability scanning",
        "dirsearch": "Web path discovery",
        "john": "Password hash cracking",
        "hashcat": "GPU password cracking",
        "whois": "Domain registration lookup",
        "dig": "DNS lookup utility",
    }

    lines = ["### 🛠️ Available Security Tools\n"]
    for tool in sorted(tools):
        desc = descriptions.get(tool, "Security testing tool")
        lines.append(f"- **{tool}**: {desc}")

    return "\n".join(lines)

@mcp.tool()
def scan_target(target: str, scan_type: str = "quick") -> str:
    """
    Run a comprehensive security scan on a target.

    Args:
        target: IP or hostname to scan
        scan_type: quick, full, or stealth
    """
    if scan_type not in ["quick", "full", "stealth"]:
        return "❌ scan_type must be: quick, full, or stealth"

    if not target or len(target) > 512:
        return "❌ Invalid target"

    forbidden = ["..", "$", "`", "|", ";", "&", ">", "<"]
    if any(c in target for c in forbidden):
        return "❌ Target contains forbidden characters"

    scans = {
        "quick": [
            ("nmap", "-sV -T4 --top-ports 100"),
            ("nikto", "-h"),
        ],
        "full": [
            ("nmap", "-sV -sC -O -T4 -p-"),
            ("nikto", "-h -C all"),
            ("gobuster", "dir -w /usr/share/wordlists/dirb/common.txt"),
        ],
        "stealth": [
            ("nmap", "-sS -T2 -p- --randomize-hosts"),
            ("subfinder", "-d"),
        ],
    }

    results = []
    for tool, opts in scans[scan_type]:
        result = run_security_tool(tool, target, opts)
        results.append(result)

    return "\n\n".join([
        f"### 🔍 {scan_type.upper()} Scan Results for {target}",
        *results,
        "\n📊 Use `get_job_status('<job_id>')` for each job to retrieve full results."
    ])

@mcp.tool()
def diagnose_issue(error_message: str) -> str:
    """Diagnose a specific error and suggest fixes."""
    error_lower = error_message.lower()

    diagnostics = {
        "connection refused": [
            "HexStrike server is not running.",
            "Fix: `sudo systemctl start hexstrike`",
            "Check: `sudo systemctl status hexstrike`",
        ],
        "connection error": [
            "Cannot reach HexStrike server.",
            "Fix: `sudo systemctl start hexstrike`",
            "Verify: `curl http://localhost:8888/health`",
        ],
        "unauthorized": [
            "API token missing or invalid.",
            "Fix: `cat /etc/nullsec/api_token`",
            "Regenerate: `sudo openssl rand -hex 32 > /etc/nullsec/api_token`",
        ],
        "forbidden": [
            "Permission denied. Token mismatch between server and MCP.",
            "Fix: Ensure API_TOKEN env var matches /etc/nullsec/api_token",
        ],
        "module not found": [
            "Missing Python package in virtual environment.",
            f"Fix: `sudo {sys.executable} -m pip install <missing_package>`",
        ],
        "port": [
            "Port 8888 may be in use.",
            "Fix: `sudo lsof -i :8888 && sudo kill <PID>`",
            "Or: Edit /etc/systemd/system/hexstrike.service port",
        ],
        "virtual environment": [
            "Virtual environment corrupted or missing.",
            "Fix: `sudo rm -rf /opt/nullsec/venv && sudo ./install.sh --core`",
        ],
        "claude": [
            "MCP configuration issue.",
            "Fix: `sudo ./install.sh --mcp`",
            "Check: `~/.config/Claude/claude_desktop_config.json`",
        ],
    }

    lines = [f"### 🔍 Diagnosis: {error_message}", ""]

    matched = False
    for keyword, suggestions in diagnostics.items():
        if keyword in error_lower:
            lines.extend(suggestions)
            matched = True
            break

    if not matched:
        lines.extend([
            "Unknown error. Running full system check...",
            "If issues persist, re-run: `sudo ./install.sh --full`",
            "Or run: `sudo guardian --check`",
        ])

    lines.append("")
    lines.append("For more help, check logs: `sudo tail -f /var/log/nullsec/mcp.log`")

    return "\n".join(lines)

def main():
    logger.info("=" * 60)
    logger.info("Starting HexStrike MCP Bridge v7.0")
    logger.info(f"Server URL: {HEXSTRIKE_SERVER_URL}")
    logger.info(f"API Token: {'✓ Configured' if API_TOKEN else '✗ Missing'}")
    logger.info("=" * 60)

    try:
        tools = _fetch_tools()
        logger.info(f"Connected to HexStrike. {len(tools)} tools available.")
    except Exception as e:
        logger.warning(f"Pre-connection check failed: {e}")
        logger.warning("MCP will start but tools may be unavailable initially.")

    mcp.run()

if __name__ == "__main__":
    main()
