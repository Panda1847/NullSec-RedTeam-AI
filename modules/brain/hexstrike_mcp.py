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

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Add parent directory to path to import utils
try:
    # Attempt direct import first
    from utils.core import with_pacman, self_heal
except ImportError:
    try:
        # Fallback for common deployment scenarios (e.g., installed in /opt/hexstrike-ai)
        sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'utils'))
        from core import with_pacman, self_heal
    except ImportError:
        try:
            # Another fallback for when utils might be directly in /opt/hexstrike-ai
            sys.path.append("/opt/hexstrike-ai/utils")
            from core import with_pacman, self_heal
        except ImportError:
            logging.warning("Could not import utils.core. Proceeding with dummy functions.")
            # Dummy functions if import fails completely
            def with_pacman(msg): return lambda f: f
            def self_heal(**kwargs): return lambda f: f

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    logging.error("FastMCP not found. Please ensure it is installed (pip install fastmcp).")
    sys.exit(1)

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
    
    try:
        response = requests.post(url, json=payload, timeout=3600)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        result = response.json()
        return f"Tool: {tool_name}\nOutput:\n{result.get(\'output\', \'No output\')}"
    except requests.exceptions.Timeout:
        logging.error(f"Request to {url} timed out after 3600 seconds.")
        return f"Error: Request timed out for tool {tool_name}."
    except requests.exceptions.ConnectionError as e:
        logging.error(f"Connection error to HexStrike server at {url}: {e}")
        return f"Error: Could not connect to HexStrike server. Is it running? ({e})"
    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP error during tool execution: {e} - {e.response.text}")
        return f"Error: Server returned an HTTP error for tool {tool_name}: {e.response.status_code} - {e.response.text}"
    except Exception as e:
        logging.error(f"An unexpected error occurred during tool execution: {e}")
        return f"Error: An unexpected error occurred: {e}"

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
    
    try:
        response = requests.post(url, json=payload, timeout=300)
        response.raise_for_status()
        result = response.json()
        return f"Analysis Results for {target}:\n{result.get(\'analysis\', \'No analysis provided\')}"
    except requests.exceptions.Timeout:
        logging.error(f"Request to {url} timed out after 300 seconds.")
        return f"Error: Request timed out for analysis of {target}."
    except requests.exceptions.ConnectionError as e:
        logging.error(f"Connection error to HexStrike server at {url}: {e}")
        return f"Error: Could not connect to HexStrike server for analysis. Is it running? ({e})"
    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP error during target analysis: {e} - {e.response.text}")
        return f"Error: Server returned an HTTP error for analysis of {target}: {e.response.status_code} - {e.response.text}"
    except Exception as e:
        logging.error(f"An unexpected error occurred during target analysis: {e}")
        return f"Error: An unexpected error occurred during analysis: {e}"

@mcp.tool()
@self_heal(max_retries=3)
@with_pacman("Listing Tools")
def list_available_tools() -> str:
    """List all available security tools in the HexStrike arsenal."""
    url = f"{get_server_url()}/api/tools/list"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        tools = response.json().get(\'tools\', [])
        return "Available Tools:\n" + "\n".join([f"- {t}" for t in tools])
    except requests.exceptions.Timeout:
        logging.error(f"Request to {url} timed out after 30 seconds.")
        return "Error: Request timed out while listing tools."
    except requests.exceptions.ConnectionError as e:
        logging.error(f"Connection error to HexStrike server at {url}: {e}")
        return f"Error: Could not connect to HexStrike server to list tools. Is it running? ({e})"
    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP error during tool listing: {e} - {e.response.text}")
        return f"Error: Server returned an HTTP error while listing tools: {e.response.status_code} - {e.response.text}"
    except Exception as e:
        logging.error(f"An unexpected error occurred during tool listing: {e}")
        return f"Error: An unexpected error occurred while listing tools: {e}"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HexStrike AI MCP Client")
    parser.add_argument("--server", default=HEXSTRIKE_SERVER_URL, help="HexStrike server URL")
    args = parser.parse_args()
    
    os.environ["HEXSTRIKE_SERVER_URL"] = args.server
    try:
        mcp.run()
    except Exception as e:
        logging.critical(f"Failed to start HexStrike MCP server: {e}")
        sys.exit(1)
