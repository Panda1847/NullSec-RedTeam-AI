#!/usr/bin/env python3
"""
HexStrike AI MCP Client - Enhanced AI Agent Communication Interface

Enhanced with AI-Powered Intelligence & Automation
🚀 Bug Bounty | CTF | Red Team | Security Research

RECENT ENHANCEMENTS (v6.0):
✅ Complete color consistency with reddish hacker theme
✅ Enhanced visual output with consistent styling
✅ Improved error handling and recovery systems
✅ FastMCP integration for seamless AI communication
✅ 100+ security tools with intelligent parameter optimization
✅ Advanced logging with colored output and emojis

Architecture: MCP Client for AI agent communication with HexStrike server
Framework: FastMCP integration for tool orchestration
"""

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional
import requests
import time
from datetime import datetime

from mcp.server.fastmcp import FastMCP

class HexStrikeColors:
    """Enhanced color palette matching the server's ModernVisualEngine.COLORS"""
    
    # Basic colors (for backward compatibility)
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Core enhanced colors
    MATRIX_GREEN = '\033[38;5;46m'
    NEON_BLUE = '\033[38;5;51m'
    ELECTRIC_PURPLE = '\033[38;5;129m'
    CYBER_ORANGE = '\033[38;5;208m'
    HACKER_RED = '\033[38;5;196m'
    TERMINAL_GRAY = '\033[38;5;240m'
    BRIGHT_WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Enhanced reddish tones and highlighting colors
    BLOOD_RED = '\033[38;5;124m'
    CRIMSON = '\033[38;5;160m'
    DARK_RED = '\033[38;5;88m'
    FIRE_RED = '\033[38;5;202m'
    ROSE_RED = '\033[38;5;167m'
    BURGUNDY = '\033[38;5;52m'
    SCARLET = '\033[38;5;197m'
    RUBY = '\033[38;5;161m'
    
    # Highlighting colors
    HIGHLIGHT_RED = '\033[48;5;196m\033[38;5;15m'  # Red background, white text
    HIGHLIGHT_YELLOW = '\033[48;5;226m\033[38;5;16m' # Yellow background, black text
    HIGHLIGHT_GREEN = '\033[48;5;46m\033[38;5;16m'   # Green background, black text

# Initialize FastMCP server
mcp = FastMCP("HexStrike AI")

# Configuration
HEXSTRIKE_SERVER_URL = "http://localhost:8888"

def get_server_url():
    return os.environ.get("HEXSTRIKE_SERVER_URL", HEXSTRIKE_SERVER_URL)

@mcp.tool()
def run_security_tool(tool_name: str, target: str, options: str = "") -> str:
    """
    Run a security tool from the HexStrike arsenal.
    
    Args:
        tool_name: Name of the tool to run (e.g., nmap, sqlmap, gobuster)
        target: Target IP, domain, or URL
        options: Additional command-line options for the tool
    """
    url = f"{get_server_url()}/api/tools/execute"
    payload = {
        "tool": tool_name,
        "target": target,
        "options": options
    }
    
    try:
        response = requests.post(url, json=payload, timeout=3600)
        if response.status_code == 200:
            result = response.json()
            return f"Tool: {tool_name}\nOutput:\n{result.get('output', 'No output')}"
        else:
            return f"Error: Server returned status code {response.status_code}\n{response.text}"
    except Exception as e:
        return f"Exception occurred while running tool: {str(e)}"

@mcp.tool()
def analyze_target(target: str, analysis_type: str = "comprehensive") -> str:
    """
    Perform an AI-powered security analysis of a target.
    
    Args:
        target: Target IP, domain, or URL
        analysis_type: Type of analysis (recon, web, vuln, comprehensive)
    """
    url = f"{get_server_url()}/api/intelligence/analyze-target"
    payload = {
        "target": target,
        "analysis_type": analysis_type
    }
    
    try:
        response = requests.post(url, json=payload, timeout=300)
        if response.status_code == 200:
            result = response.json()
            return f"Analysis Results for {target}:\n{result.get('analysis', 'No analysis provided')}"
        else:
            return f"Error: Server returned status code {response.status_code}\n{response.text}"
    except Exception as e:
        return f"Exception occurred during analysis: {str(e)}"

@mcp.tool()
def list_available_tools() -> str:
    """List all available security tools in the HexStrike arsenal."""
    url = f"{get_server_url()}/api/tools/list"
    
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            tools = response.json().get('tools', [])
            return "Available Tools:\n" + "\n".join([f"- {t}" for t in tools])
        else:
            return f"Error: Server returned status code {response.status_code}"
    except Exception as e:
        return f"Exception occurred: {str(e)}"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HexStrike AI MCP Client")
    parser.add_index("--server", default=HEXSTRIKE_SERVER_URL, help="HexStrike server URL")
    args = parser.parse_args()
    
    os.environ["HEXSTRIKE_SERVER_URL"] = args.server
    mcp.run()
