#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  HexStrike MCP Bridge v6.0                                                    ║
║  Claude Desktop ↔ HexStrike Server Integration                                ║
║  Fault-tolerant • Auto-retry • Auth-aware                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import logging
import time
from pathlib import Path
from typing import Optional, Dict, Any, List

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ─── Logging ───────────────────────────────────────────────────────────────
LOG_DIR = Path(os.environ.get("NULLSEC_LOG_DIR", "/var/log/nullsec"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "mcp.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("hexstrike_mcp")

# ─── FastMCP Import with Robust Fallback ───────────────────────────────────
try:
    from mcp.server.fastmcp import FastMCP
    logger.info("✓ FastMCP imported successfully")
except ImportError as e:
    logger.error(f"FastMCP import failed: {e}")
    logger.error("Install: pip install fastmcp>=0.4.0")

    class _DummyMCP:
        def __init__(self, name: str):
            self.name = name
            logger.warning("Running in DUMMY mode — MCP functionality disabled")

        def tool(self, *args, **kwargs):
            def decorator(f):
                def wrapper(*args, **kwargs):
                    return "❌ ERROR: MCP server not available. Install fastmcp package."
                return wrapper
            return decorator

        def run(self):
            logger.error("Cannot run MCP server: fastmcp not installed")
            while True:
                time.sleep(60)

    FastMCP = _DummyMCP

# ─── Configuration ───────────────────────────────────────────────────────────
HEXSTRIKE_SERVER_URL = os.environ.get("HEXSTRIKE_SERVER_URL", "http://localhost:8888")
API_TOKEN = os.environ.get("API_TOKEN", "")

# Cache
_AVAILABLE_TOOLS: Optional[List[str]] = None
_CACHE_TIME: float = 0
_CACHE_TTL: float = 300

# ─── HTTP Session with Retry Logic ─────────────────────────────────────────
_session = requests.Session()
_retries = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "POST"]
)
_session.mount("http://", HTTPAdapter(max_retries=_retries))
_session.mount("https://", HTTPAdapter(max_retries=_retries))

def _get_headers() -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"
    return headers

def _fetch_tools() -> List[str]:
    global _AVAILABLE_TOOLS, _CACHE_TIME

    now = time.time()
    if _AVAILABLE_TOOLS is not None and (now - _CACHE_TIME) < _CACHE_TTL:
        return _AVAILABLE_TOOLS

    try:
        resp = _session.get(
            f"{HEXSTRIKE_SERVER_URL}/health",
            headers=_get_headers(),
            timeout=5
        )
        resp.raise_for_status()
        data = resp.json()
        tools = list(data.get("tools", {}).keys()) if isinstance(data.get("tools"), dict) else data.get("tools", [])
        _AVAILABLE_TOOLS = tools
        _CACHE_TIME = now
        return tools
    except Exception as e:
        logger.warning(f"Could not fetch tools: {e}")
        return ["nmap", "sqlmap", "gobuster", "hydra", "nuclei", "ffuf", "nikto"]

# ─── Initialize MCP ────────────────────────────────────────────────────────
mcp = FastMCP("NullSec Red Team")

@mcp.tool()
def run_security_tool(tool_name: str, target: str, options: str = "") -> str:
    """
    Execute a security tool via the HexStrike orchestration server.

    Args:
        tool_name: Tool to run (nmap, sqlmap, gobuster, hydra, nuclei, ffuf, nikto)
        target: Target IP, hostname, or URL
        options: Additional command-line options

    Returns:
        Job status and polling instructions
    """
    available = _fetch_tools()
    if tool_name not in available:
        return f"❌ Tool '{tool_name}' not available. Available: {', '.join(available)}"

    if not target or len(target) > 512:
        return "❌ Invalid target (empty or exceeds 512 chars)"

    if any(c in target for c in ["..", "$", "`", "|", ";", "&", ">", "<"]):
        return "❌ Target contains forbidden characters"

    url = f"{HEXSTRIKE_SERVER_URL}/api/tools/execute"
    payload = {"tool": tool_name, "target": target, "options": options}

    try:
        response = _session.post(url, json=payload, headers=_get_headers(), timeout=30)
        response.raise_for_status()
        result = response.json()

        job_id = result.get("job_id", "unknown")
        status = result.get("status", "unknown")

        return (
            f"### 🛠️ Tool: {tool_name}\n"
            f"**Target**: `{target}`\n"
            f"**Status**: {status}\n"
            f"**Job ID**: `{job_id}`\n\n"
            f"📊 Check results with: `get_job_status('{job_id}')`"
        )

    except requests.exceptions.ConnectionError:
        logger.error("Cannot connect to HexStrike server")
        return (
            "❌ **Connection Error**: Cannot reach HexStrike Server.\n\n"
            "**Fix it:**\n"
            "```bash\n"
            "sudo systemctl status hexstrike\n"
            "sudo systemctl start hexstrike\n"
            "```"
        )
    except requests.exceptions.Timeout:
        return "⏱️ **Timeout**: Server is overloaded. Try again later."
    except requests.exceptions.HTTPError as e:
        if response.status_code == 401:
            return "🔒 **Authentication Failed**: Check API token configuration."
        elif response.status_code == 403:
            return "🚫 **Forbidden**: Invalid permissions."
        elif response.status_code == 429:
            return "🐌 **Rate Limited**: Too many requests. Wait a moment."
        return f"❌ **HTTP {response.status_code}**: {str(e)}"
    except Exception as e:
        logger.exception("Unexpected error")
        return f"❌ **Error**: {str(e)}\n\nCheck logs: {LOG_DIR}/mcp.log"

@mcp.tool()
def get_job_status(job_id: str) -> str:
    """Check status of a previously queued job."""
    if not job_id or len(job_id) != 36:
        return "❌ Invalid job ID. Expected UUID format."

    try:
        response = _session.get(
            f"{HEXSTRIKE_SERVER_URL}/api/jobs/{job_id}",
            headers=_get_headers(),
            timeout=10
        )
        response.raise_for_status()
        job = response.json()

        status = job.get("status", "unknown")
        tool = job.get("tool", "unknown")
        target = job.get("target", "unknown")
        result = job.get("result", "No result yet")
        created = job.get("created_at", "unknown")

        emojis = {"queued": "⏳", "running": "🔄", "done": "✅", "failed": "❌"}
        emoji = emojis.get(status, "❓")

        return (
            f"### 📋 Job Status: `{job_id[:8]}...`\n"
            f"**Tool**: {tool}\n"
            f"**Target**: `{target}`\n"
            f"**Status**: {emoji} {status.upper()}\n"
            f"**Created**: {created}\n\n"
            f"**Result**:\n```\n{result}\n```"
        )

    except requests.exceptions.ConnectionError:
        return "❌ Cannot connect to HexStrike server."
    except requests.exceptions.HTTPError as e:
        if response.status_code == 404:
            return f"❌ Job `{job_id[:8]}...` not found."
        return f"❌ HTTP Error: {response.status_code}"
    except Exception as e:
        logger.exception("Error checking job")
        return f"❌ Error: {str(e)}"

@mcp.tool()
def get_system_status() -> str:
    """Check health of all NullSec components."""
    components = []

    # HexStrike Server
    try:
        response = _session.get(f"{HEXSTRIKE_SERVER_URL}/health", headers=_get_headers(), timeout=5)
        if response.status_code == 200:
            data = response.json()
            tools = list(data.get("tools", {}).keys()) if isinstance(data.get("tools"), dict) else data.get("tools", [])
            version = data.get("version", "unknown")
            components.append(f"✅ HexStrike Server v{version}")
            components.append(f"   🛠️ Tools: {len(tools)} available")
        else:
            components.append(f"⚠️ HexStrike Server: HTTP {response.status_code}")
    except requests.exceptions.ConnectionError:
        components.append("❌ HexStrike Server: Offline")
    except Exception as e:
        components.append(f"❌ HexStrike Server: {str(e)}")

    # Worker
    try:
        import subprocess
        result = subprocess.run(["systemctl", "is-active", "hexstrike-worker"],
                                  capture_output=True, text=True, timeout=2)
        if result.stdout.strip() == "active":
            components.append("✅ Worker: Active")
        else:
            components.append("⚠️ Worker: Inactive")
    except Exception:
        components.append("❓ Worker: Status unknown")

    # API Token
    if API_TOKEN:
        components.append("🔐 API Token: Configured")
    else:
        components.append("⚠️ API Token: Not configured")

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

    scans = {
        "quick": [("nmap", "-sV -T4 --top-ports 100"), ("nikto", "-h")],
        "full": [("nmap", "-sV -sC -O -T4 -p-"), ("nikto", "-h -C all"), ("gobuster", "dir -w /usr/share/wordlists/dirb/common.txt")],
        "stealth": [("nmap", "-sS -T2 -p- --randomize-hosts"), ("subfinder", "-d")],
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

def main():
    logger.info("=" * 60)
    logger.info("Starting HexStrike MCP Bridge v6.0")
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
