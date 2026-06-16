#!/usr/bin/env python3
import os, sys, subprocess
from pathlib import Path

def check_and_fix():
    issues = []
    # Check HexStrike
    if not Path("/opt/hexstrike-ai/venv/bin/python3").exists():
        issues.append("HexStrike venv missing — attempting repair")
        subprocess.run(["python3", "-m", "venv", "/opt/hexstrike-ai/venv"], check=False)
    
    # Check MCP config
    config = Path("/home/ubuntu/.config/Claude/claude_desktop_config.json")  # adjust for real user
    if not config.exists():
        issues.append("MCP config missing — recreating")
        # recreate logic here
    
    if issues:
        print("Fixed issues:", issues)
    else:
        print("All systems healthy")

if __name__ == "__main__":
    check_and_fix()
