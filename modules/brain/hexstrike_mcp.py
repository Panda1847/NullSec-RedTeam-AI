#!/usr/bin/env python3
import sys
import os
import logging
import requests
from typing import Optional

# Try to import FastMCP and provide a lightweight fallback if it's not installed
try:
    from mcp.server.fastmcp import FastMCP
except Exception:
    FastMCP = None
    logging.error("fastmcp import failed: 'fastmcp' is not installed or importable. Install with `pip install fastmcp`.")

# Lightweight dummy MCP implementation so module can be imported without crashing
if FastMCP is not None:
    mcp = FastMCP("NullSec Red Team")
else:
    class _DummyMCP:
        def tool(self, *args, **kwargs):
            def decorator(f):
                return f
            return decorator
        def run(self):
            logging.error("fastmcp not installed: MCP server will not run. Install fastmcp to enable MCP functionality.")
    mcp = _DummyMCP()

HEXSTRIKE_SERVER_URL = os.environ.get("HEXSTRIKE_SERVER_URL", "http://localhost:8888")

@mcp.tool()
def run_security_tool(tool_name: str, target: str, options: str = "") -> str:
    """
    Execute a security tool via the HexStrike orchestration server.
    Available tools: nmap, sqlmap, gobuster, hydra, metasploit, nuclei, subfinder, amass, ffuf, nikto
    """
    url = f"{HEXSTRIKE_SERVER_URL}/api/tools/execute"
    payload = {
        "tool": tool_name,
        "target": target,
        "options": options
    }
    
    try:
        response = requests.post(url, json=payload, timeout=310)
        response.raise_for_status()
        result = response.json()
        
        status = result.get("status", "unknown")
        output = result.get("output", "No output provided")
        
        return f"### Tool: {tool_name}\n**Status**: {status}\n\n**Output**:\n```\n{output}\n```"
        
    except requests.exceptions.ConnectionError:
        return "Error: Could not connect to HexStrike Server. Ensure the service is running (`systemctl status hexstrike`)."
    except Exception as e:
        logging.exception("Error during tool execution via MCP")
        return f"Error during tool execution: {str(e)}"

@mcp.tool()
def get_system_status() -> str:
    """Check the health and status of the NullSec Red Team components."""
    try:
        response = requests.get(f"{HEXSTRIKE_SERVER_URL}/health", timeout=5)
        data = response.json()
        tools = ", ".join(data.get("tools", []))
        return f"✅ HexStrike Server: Online\n🛠️ Available Tools: {tools}"
    except Exception:
        return "❌ HexStrike Server: Offline"

def main():
    mcp.run()

if __name__ == "__main__":
    main()
