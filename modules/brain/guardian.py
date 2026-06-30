#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  NullSec Guardian v6.0                                                        ║
║  System Integrity Checker & Automated Repair Tool                             ║
║  Self-healing • Diagnostic • Hardened                                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import subprocess
import logging
import argparse
import json
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

# ─── Configuration ───────────────────────────────────────────────────────────
LOG_DIR = Path("/var/log/nullsec")
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "guardian.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("guardian")

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Issue:
    component: str
    severity: Severity
    message: str
    fix: str
    auto_fixable: bool = False

# ─── Guardian Class ──────────────────────────────────────────────────────────
class Guardian:
    VERSION = "6.0.0"

    def __init__(self):
        self.install_dir = Path("/opt/nullsec")
        self.venv_path = self.install_dir / "venv"
        self.venv_python = self.venv_path / "bin" / "python3"
        self.venv_pip = self.venv_path / "bin" / "pip"
        self.service_name = "hexstrike"
        self.worker_service = "hexstrike-worker"
        self.api_token_file = Path("/etc/nullsec/api_token")
        self.config_dir = Path("/etc/nullsec")
        self.required_tools = ["nmap", "sqlmap", "gobuster", "ffuf", "nikto", "hydra", "john"]
        self.required_packages = ["flask", "requests", "fastmcp", "Pillow", "psutil"]

    def _run_cmd(self, cmd: List[str], timeout: int = 10, check: bool = False) -> Tuple[int, str, str]:
        """Run command safely and return (rc, stdout, stderr)."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=check)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return 1, "", str(e)

    def check_system(self) -> List[Issue]:
        """Run comprehensive system integrity check."""
        logger.info("=" * 70)
        logger.info(f"NullSec Guardian v{self.VERSION} — System Integrity Check")
        logger.info("=" * 70)

        issues = []

        # 1. Install Directory
        if not self.install_dir.exists():
            issues.append(Issue(
                "install_dir", Severity.CRITICAL,
                f"Install directory missing: {self.install_dir}",
                "sudo ./install.sh --core", True
            ))
        else:
            logger.info("✓ Install directory exists")

        # 2. Virtual Environment
        if not self.venv_python.exists():
            issues.append(Issue(
                "venv", Severity.CRITICAL,
                "Python virtual environment missing",
                f"sudo python3 -m venv {self.venv_path}", True
            ))
        else:
            logger.info("✓ Virtual environment exists")

            # Check packages
            for pkg in self.required_packages:
                rc, _, _ = self._run_cmd([str(self.venv_python), "-c", f"import {pkg}"], timeout=5)
                if rc != 0:
                    issues.append(Issue(
                        f"venv_pkg_{pkg}", Severity.HIGH,
                        f"Package '{pkg}' not installed in venv",
                        f"sudo {self.venv_pip} install {pkg}", True
                    ))
                else:
                    logger.info(f"  ✓ Package {pkg}")

        # 3. Systemd Services
        for svc in [self.service_name, self.worker_service]:
            svc_file = Path(f"/etc/systemd/system/{svc}.service")
            if not svc_file.exists():
                issues.append(Issue(
                    f"service_file_{svc}", Severity.HIGH,
                    f"Service file missing: {svc_file}",
                    "sudo ./install.sh --core", False
                ))
            else:
                rc, stdout, _ = self._run_cmd(["systemctl", "is-active", svc], timeout=5)
                status = stdout.strip()
                if status == "active":
                    logger.info(f"✓ Service {svc} is active")
                else:
                    issues.append(Issue(
                        f"service_{svc}", Severity.MEDIUM,
                        f"Service '{svc}' is {status}",
                        f"sudo systemctl restart {svc}", True
                    ))

        # 4. API Token
        if not self.api_token_file.exists():
            issues.append(Issue(
                "api_token", Severity.HIGH,
                "API token file missing",
                f"sudo openssl rand -hex 32 > {self.api_token_file} && sudo chmod 600 {self.api_token_file}", True
            ))
        else:
            perms = oct(self.api_token_file.stat().st_mode)[-3:]
            if perms != "600":
                issues.append(Issue(
                    "api_token_perms", Severity.MEDIUM,
                    f"API token permissions are {perms}, expected 600",
                    f"sudo chmod 600 {self.api_token_file}", True
                ))
            else:
                logger.info("✓ API token file exists with correct permissions")

        # 5. MCP Config
        real_user = os.environ.get("SUDO_USER") or os.environ.get("USER")
        if real_user:
            home = Path(f"/home/{real_user}")
            mcp_config = home / ".config" / "Claude" / "claude_desktop_config.json"
            if not mcp_config.exists():
                issues.append(Issue(
                    "mcp_config", Severity.MEDIUM,
                    f"Claude MCP config missing at {mcp_config}",
                    "sudo ./install.sh --mcp", False
                ))
            else:
                logger.info("✓ MCP config exists")

        # 6. System Tools
        for tool in self.required_tools:
            rc, _, _ = self._run_cmd(["which", tool], timeout=3)
            if rc != 0:
                issues.append(Issue(
                    f"tool_{tool}", Severity.MEDIUM,
                    f"Required tool '{tool}' not in PATH",
                    f"sudo apt-get install {tool}", True
                ))
            else:
                logger.info(f"✓ Tool {tool} available")

        # 7. Log Directory
        if not LOG_DIR.exists():
            issues.append(Issue(
                "log_dir", Severity.MEDIUM,
                f"Log directory missing: {LOG_DIR}",
                f"sudo mkdir -p {LOG_DIR} && sudo chmod 755 {LOG_DIR}", True
            ))
        else:
            logger.info("✓ Log directory exists")

        # 8. Workspace
        workspace = Path.home() / "NullSec_RedTeam_Lab"
        if not workspace.exists():
            issues.append(Issue(
                "workspace", Severity.LOW,
                f"Workspace missing: {workspace}",
                f"mkdir -p {workspace}", True
            ))

        # Summary
        logger.info("=" * 70)
        if not issues:
            logger.info("✅ ALL SYSTEMS HEALTHY")
        else:
            critical = sum(1 for i in issues if i.severity == Severity.CRITICAL)
            high = sum(1 for i in issues if i.severity == Severity.HIGH)
            logger.warning(f"⚠️ FOUND {len(issues)} ISSUE(S) — Critical: {critical}, High: {high}")
        logger.info("=" * 70)

        return issues

    def repair(self, issues: Optional[List[Issue]] = None) -> bool:
        """Automated repair of identified issues."""
        logger.info("=" * 70)
        logger.info("NullSec Guardian — Automated Repair")
        logger.info("=" * 70)

        if os.geteuid() != 0:
            logger.error("❌ Repair requires root. Run with sudo.")
            return False

        if issues is None:
            issues = self.check_system()

        if not issues:
            logger.info("No issues to repair.")
            return True

        fixed = 0
        failed = 0
        skipped = 0

        for issue in issues:
            if not issue.auto_fixable:
                logger.info(f"⏭️  Skipping (manual fix required): {issue.message}")
                logger.info(f"   Manual fix: {issue.fix}")
                skipped += 1
                continue

            logger.info(f"🔧 Fixing: {issue.message}")

            # Safety: only allow known-safe commands
            safe_cmds = ["apt-get", "systemctl", "mkdir", "chmod", "chown",
                        "openssl", "python3", "pip", "install.sh", "cp", "mv",
                        "rm", "touch", "useradd", "groupadd"]
            is_safe = any(cmd in issue.fix for cmd in safe_cmds)

            if not is_safe:
                logger.warning(f"   Fix not in safe list. Manual: {issue.fix}")
                skipped += 1
                continue

            try:
                if "install.sh" in issue.fix:
                    subprocess.run(["sudo", "./install.sh", "--core"],
                                   check=True, cwd=str(self.install_dir), timeout=300)
                else:
                    subprocess.run(issue.fix, shell=True, check=True,
                                   capture_output=True, timeout=60)

                logger.info(f"   ✅ Fixed: {issue.component}")
                fixed += 1

            except subprocess.CalledProcessError as e:
                logger.error(f"   ❌ Failed: {e}")
                failed += 1
            except subprocess.TimeoutExpired:
                logger.error(f"   ❌ Timeout during repair")
                failed += 1

        logger.info("=" * 70)
        logger.info(f"Repair complete: {fixed} fixed, {failed} failed, {skipped} skipped")
        logger.info("=" * 70)

        return failed == 0

    def diagnose_error(self, error_message: str) -> str:
        """Diagnose a specific error and suggest fixes."""
        error_lower = error_message.lower()
        lines = [f"🔍 DIAGNOSIS: {error_message}", "=" * 50]

        diagnostics = {
            "connection refused": [
                "HexStrike server is not running.",
                "Fix: sudo systemctl start hexstrike",
                "Check: sudo systemctl status hexstrike"
            ],
            "connection error": [
                "Cannot reach HexStrike server.",
                "Fix: sudo systemctl start hexstrike",
                "Verify: curl http://localhost:8888/health"
            ],
            "unauthorized": [
                "API token missing or invalid.",
                "Fix: cat /etc/nullsec/api_token",
                "Regenerate: sudo openssl rand -hex 32 > /etc/nullsec/api_token"
            ],
            "forbidden": [
                "Permission denied. Token mismatch between server and MCP.",
                "Fix: Ensure API_TOKEN env var matches /etc/nullsec/api_token"
            ],
            "module not found": [
                "Missing Python package in virtual environment.",
                "Fix: sudo /opt/nullsec/venv/bin/pip install <missing_module>"
            ],
            "port": [
                "Port 8888 may be in use.",
                "Fix: sudo lsof -i :8888 && sudo kill <PID>",
                "Or: Edit /etc/systemd/system/hexstrike.service port"
            ],
            "virtual environment": [
                "Virtual environment corrupted or missing.",
                "Fix: sudo rm -rf /opt/nullsec/venv && sudo ./install.sh --core"
            ],
            "claude": [
                "MCP configuration issue.",
                "Fix: sudo ./install.sh --mcp",
                "Check: ~/.config/Claude/claude_desktop_config.json"
            ],
        }

        matched = False
        for keyword, suggestions in diagnostics.items():
            if keyword in error_lower:
                lines.extend(suggestions)
                matched = True
                break

        if not matched:
            lines.extend([
                "Unknown error. Running full system check...",
                "If issues persist, re-run: sudo ./install.sh --full"
            ])
            self.check_system()

        lines.append("=" * 50)
        return "\n".join(lines)

    def generate_report(self, issues: List[Issue]) -> str:
        """Generate JSON report of system status."""
        report = {
            "version": self.VERSION,
            "timestamp": str(datetime.now()),
            "summary": {
                "total_issues": len(issues),
                "critical": sum(1 for i in issues if i.severity == Severity.CRITICAL),
                "high": sum(1 for i in issues if i.severity == Severity.HIGH),
                "medium": sum(1 for i in issues if i.severity == Severity.MEDIUM),
                "low": sum(1 for i in issues if i.severity == Severity.LOW),
            },
            "issues": [asdict(i) for i in issues],
            "healthy": len(issues) == 0
        }
        return json.dumps(report, indent=2)

# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="NullSec Guardian — System Diagnostic & Repair Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  guardian --check              Full system check
  guardian --repair             Auto-repair issues
  guardian --report             Generate JSON report
  guardian "connection error"   Diagnose specific error
  guardian --version            Show version
        """
    )
    parser.add_argument("--check", action="store_true", help="Run system check")
    parser.add_argument("--repair", action="store_true", help="Auto-repair")
    parser.add_argument("--report", action="store_true", help="Generate JSON report")
    parser.add_argument("--version", action="store_true", help="Show version")
    parser.add_argument("error_message", nargs="?", help="Error to diagnose")

    args = parser.parse_args()

    if args.version:
        print(f"NullSec Guardian v{Guardian.VERSION}")
        sys.exit(0)

    guardian = Guardian()

    if args.repair:
        success = guardian.repair()
        sys.exit(0 if success else 1)
    elif args.report:
        issues = guardian.check_system()
        print(guardian.generate_report(issues))
    elif args.error_message:
        print(guardian.diagnose_error(args.error_message))
    elif args.check or len(sys.argv) == 1:
        issues = guardian.check_system()
        sys.exit(0 if not issues else 1)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
