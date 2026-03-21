#!/usr/bin/env python3
"""
HexStrike AI MCP Client - Enhanced AI Agent Communication Interface
"""

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional
import requests
import time
from datetime import datetime

# Add parent directory to path to import utils
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.core import with_pacman, self_heal

from mcp.server.fastmcp import FastMCP

class HexStrikeColors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# Initialize FastMCP server
mcp = FastMCP("HexStrike AI")

# Configuration
HEXSTRIKE_SERVER_URL = "http://localhost:8888"

def get_server_url():
    return os.environ.get("HEXSTRIKE_SERVER_URL", HEXSTRIKE_SERVER_URL)

@mcp.tool()
@self_heal(max_retries=3)
@with_pacman("Executing Tool")
def run_security_tool(tool_name: str, target: str, options: str = "") -> str:
    """
    Run a security tool from the HexStrike arsenal.
    """
    url = f"{get_server_url()}/api/tools/execute"
    payload = {
        "tool": tool_name,
        "target": target,
        "options": options
    }
    
    response = requests.post(url, json=payload, timeout=3600)
    if response.status_code == 200:
        result = response.json()
        return f"Tool: {tool_name}\nOutput:\n{result.get('output', 'No output')}"
    else:
        return f"Error: Server returned status code {response.status_code}\n{response.text}"

@mcp.tool()
@self_heal(max_retries=3)
@with_pacman("Analyzing Target")
def analyze_target(target: str, analysis_type: str = "comprehensive") -> str:
    """
    Perform an AI-powered security analysis of a target.
    """
    url = f"{get_server_url()}/api/intelligence/analyze-target"
    payload = {
        "target": target,
        "analysis_type": analysis_type
    }
    
    response = requests.post(url, json=payload, timeout=300)
    if response.status_code == 200:
        result = response.json()
        return f"Analysis Results for {target}:\n{result.get('analysis', 'No analysis provided')}"
    else:
        return f"Error: Server returned status code {response.status_code}\n{response.text}"

@mcp.tool()
@self_heal(max_retries=3)
@with_pacman("Listing Tools")
def list_available_tools() -> str:
    """List all available security tools in the HexStrike arsenal."""
    url = f"{get_server_url()}/api/tools/list"
    
    response = requests.get(url, timeout=30)
    if response.status_code == 200:
        tools = response.json().get('tools', [])
        return "Available Tools:\n" + "\n".join([f"- {t}" for t in tools])
    else:
        return f"Error: Server returned status code {response.status_code}"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HexStrike AI MCP Client")
    parser.add_argument("--server", default=HEXSTRIKE_SERVER_URL, help="HexStrike server URL")
    args = parser.parse_args()
    
    os.environ["HEXSTRIKE_SERVER_URL"] = args.server
    mcp.run()
