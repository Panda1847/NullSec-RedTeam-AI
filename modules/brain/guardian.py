#!/usr/bin/env python3
import os
import sys
import subprocess
import logging
from pathlib import Path

# Configure logging
LOG_DIR = Path("/var/log/nullsec")
LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "guardian.log"),
        logging.StreamHandler()
    ]
)

class Guardian:
    def __init__(self):
        self.install_dir = Path("/opt/nullsec")
        self.venv_python = self.install_dir / "venv" / "bin" / "python3"
        self.service_name = "hexstrike"

    def check_system(self):
        logging.info("--- NullSec Guardian: System Integrity Check ---")
        issues = []

        # 1. Check Install Directory
        if not self.install_dir.exists():
            issues.append(f"Install directory missing: {self.install_dir}")

        # 2. Check Virtual Environment
        if not self.venv_python.exists():
            issues.append("Python virtual environment missing or broken")

        # 3. Check Systemd Service
        try:
            status = subprocess.run(
                ["systemctl", "is-active", self.service_name],
                capture_output=True, text=True
            ).stdout.strip()
            if status != "active":
                issues.append(f"Service '{self.service_name}' is not active (Status: {status})")
        except Exception as e:
            issues.append(f"Could not check systemd service: {e}")

        # 4. Check MCP Config
        real_user = os.environ.get("SUDO_USER") or os.environ.get("USER")
        if real_user:
            home = Path(f"/home/{real_user}")
            mcp_config = home / ".config" / "Claude" / "claude_desktop_config.json"
            if not mcp_config.exists():
                issues.append(f"Claude Desktop MCP config missing at {mcp_config}")

        if not issues:
            logging.info("✅ All systems healthy.")
            return True
        else:
            logging.warning(f"⚠️ Found {len(issues)} issues:")
            for issue in issues:
                logging.warning(f"  - {issue}")
            return False

    def repair(self):
        logging.info("--- NullSec Guardian: Attempting Auto-Repair ---")
        
        # Ensure we are root
        if os.geteuid() != 0:
            logging.error("Repair requires root privileges. Please run with sudo.")
            return

        # Try to fix service
        logging.info(f"Attempting to restart {self.service_name}...")
        subprocess.run(["systemctl", "restart", self.service_name])
        
        # Check if we need to re-run installer
        logging.info("If issues persist, please re-run: sudo ./install.sh")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="NullSec Guardian Diagnostic Tool")
    parser.add_argument("--check", action="store_true", help="Run system integrity check")
    parser.add_argument("--repair", action="store_true", help="Attempt to repair identified issues")
    args = parser.parse_args()

    guardian = Guardian()
    
    if args.repair:
        guardian.repair()
    elif args.check or len(sys.argv) == 1:
        guardian.check_system()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
