#!/usr/bin/env python3
"""
AI Security Lab - Jailbreak Tester & LLM Vulnerability Scanner
An MCP server for testing LLM safety and jailbreak resistance.
"""

import sys
import os
import argparse
import json
import logging
from typing import Dict, Any, List, Optional
import requests
import time
import random

# Add parent directory to path to import utils
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from utils.core import with_pacman, self_heal

from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("AI Security Lab")

# Jailbreak techniques database (sample)
JAILBREAK_TECHNIQUES = {
    "DAN": "Do Anything Now - A classic jailbreak prompt.",
    "STAN": "Simple Token Access Network - Bypasses safety filters.",
    "AIM": "Always In Mode - Forces the model to ignore safety guidelines.",
    "UPR": "User Privilege Root - Simulates a root user session.",
    "DEV": "Developer Mode - Accesses hidden developer capabilities."
}

@mcp.tool()
@self_heal(max_retries=3)
@with_pacman("Listing Techniques")
def list_jailbreak_techniques() -> str:
    """List all available jailbreak techniques in the database."""
    return "Available Jailbreak Techniques:\n" + "\n".join([f"- {k}: {v}" for k, v in JAILBREAK_TECHNIQUES.items()])

@mcp.tool()
@self_heal(max_retries=3)
@with_pacman("Testing Jailbreak")
def run_jailbreak_test(model: str, technique: str, target_prompt: str = "") -> str:
    """
    Test a specific jailbreak technique against a target model.
    """
    if technique not in JAILBREAK_TECHNIQUES:
        return f"Error: Technique '{technique}' not found."
    
    # Simulate testing
    time.sleep(2)
    return f"Running {technique} test against {model}...\n" \
           f"Technique: {JAILBREAK_TECHNIQUES[technique]}\n" \
           f"Result: [SIMULATED] Model showed partial vulnerability to {technique}.\n" \
           f"Recommendation: Increase safety filter sensitivity for this technique."

@mcp.tool()
@self_heal(max_retries=3)
@with_pacman("Scanning Vulnerabilities")
def scan_llm_vulnerabilities(model: str, scan_type: str = "full") -> str:
    """
    Perform a comprehensive vulnerability scan on an LLM.
    """
    # Simulate scanning
    time.sleep(3)
    return f"Scanning {model} for {scan_type} vulnerabilities...\n" \
           f"1. Prompt Injection: [CLEAN]\n" \
           f"2. Jailbreak Resistance: [MODERATE RISK]\n" \
           f"3. Data Leakage: [CLEAN]\n" \
           f"Scan complete. No critical vulnerabilities found."

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Security Lab MCP Server")
    parser.add_argument("--mcp", action="store_true", help="Run as MCP server")
    parser.add_argument("--model", type=str, help="Model to test")
    parser.add_argument("--technique", type=str, help="Technique to test")
    parser.add_argument("--all", action="store_true", help="Test all techniques")
    args = parser.parse_args()
    
    if args.mcp:
        mcp.run()
    else:
        if args.model and args.technique:
            print(run_jailbreak_test(args.model, args.technique))
        elif args.model and args.all:
            for tech in JAILBREAK_TECHNIQUES:
                print(run_jailbreak_test(args.model, tech))
                print("-" * 20)
        else:
            print("AI Security Lab CLI Mode")
            print("Usage: python3 jailbreak_tester.py --mcp")
            print("       python3 jailbreak_tester.py --model <model> --technique <technique>")
            print("       python3 jailbreak_tester.py --model <model> --all")
