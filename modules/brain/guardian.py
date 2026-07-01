#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║ NullSec Guardian v7.0                                                       ║
║ System Integrity Checker & Automated Repair Tool                          ║
║ Self-healing • Diagnostic • Hardened • Kali Linux Optimized              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import subprocess
import logging
import argparse
import json
import shutil
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime

# ─── Configuration ───────────────────────────────────────────────────────────
LOG_DIR = Path("/var/log/nullsec")
log_file = None

try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / "guardian.log"
except (PermissionError, OSError) as e:
    import tempfile
    LOG_DIR = Path(tempfile.gettempdir()) / "nullsec_logs"
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_file = LOG_DIR / "guardian.log"
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
    VERSION = "7.0.0"

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
        self.required_packages = ["flask", "requests", "fastmcp", "Pillow", "psutil", "urllib3"]

    def _run_cmd(self, cmd: List[str], timeout: int = 10, check: bool = False, 
                 shell: bool = False, cwd: Optional[Path] = None) -> Tuple[int, str, str]:
        """Run command safely and return (rc, stdout, stderr)."""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, 
                check=check, shell=shell, cwd=cwd
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"Command timed out after {timeout}s"
        except FileNotFoundError:
            return 127, "", f"Command not found: {cmd[0] if cmd else 'unknown'}"
        except PermissionError:
            return 126, "", "Permission denied"
        except Exception as e:
            return 1, "", str(e)

    def _get_python_cmd(self) -> str:
        """Find the best available Python command."""
        for cmd in [str(self.venv_python), "python3.12", "python3.11", "python3.10", "python3"]:
            rc, _, _ = self._run_cmd([cmd, "--version"], timeout=3)
            if rc == 0:
                return cmd
        return "python3"

    def check_system(self) -> List[Issue]:
        """Run comprehensive system integrity check."""
        logger.info("=" * 70)
        logger.info(f"NullSec Guardian v{self.VERSION} — System Integrity Check")
        logger.info("=" * 70)

        issues = []
        python_cmd = self._get_python_cmd()

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
            rc, _, _ = self._run_cmd([python_cmd, "-c", f"import {pkg}"], timeout=5)
            if rc != 0:
                issues.append(Issue(
                    f"venv_pkg_{pkg}", Severity.HIGH,
                    f"Package '{pkg}' not installed in venv",
                    f"sudo {self.venv_pip} install {pkg}", True
                ))
            else:
                logger.info(f" ✓ Package {pkg}")

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
            try:
                perms = oct(self.api_token_file.stat().st_mode)[-3:]
                if perms != "600":
                    issues.append(Issue(
                        "api_token_perms", Severity.MEDIUM,
                        f"API token permissions are {perms}, expected 600",
                        f"sudo chmod 600 {self.api_token_file}", True
                    ))
                else:
                    logger.info("✓ API token file exists with correct permissions")
            except (OSError, PermissionError) as e:
                issues.append(Issue(
                    "api_token_access", Severity.MEDIUM,
                    f"Cannot read API token file: {e}",
                    f"sudo chmod 600 {self.api_token_file}", True
                ))

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

        # 9. Disk space check
        try:
            stat = shutil.disk_usage("/opt/nullsec")
            free_gb = stat.free / (1024**3)
            if free_gb < 1:
                issues.append(Issue(
                    "disk_space", Severity.HIGH,
                    f"Low disk space: {free_gb:.1f}GB free",
                    "Clean up disk space", False
                ))
            else:
                logger.info(f"✓ Disk space: {free_gb:.1f}GB free")
        except Exception:
            pass

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
                logger.info(f"⏭️ Skipping (manual fix required): {issue.message}")
                logger.info(f" Manual fix: {issue.fix}")
                skipped += 1
                continue

            logger.info(f"🔧 Fixing: {issue.message}")

            # Safety: only allow known-safe commands
            safe_cmds = ["apt-get", "systemctl", "mkdir", "chmod", "chown",
                        "openssl", "python3", "pip", "install.sh", "cp", "mv",
                        "rm", "touch", "useradd", "groupadd", "apt", "dpkg"]
            is_safe = any(cmd in issue.fix for cmd in safe_cmds)

            if not is_safe:
                logger.warning(f" Fix not in safe list. Manual: {issue.fix}")
                skipped += 1
                continue

            try:
                if "install.sh" in issue.fix:
                    subprocess.run(["sudo", "./install.sh", "--core"],
                                 check=True, cwd=str(self.install_dir), timeout=300)
                else:
                    subprocess.run(issue.fix, shell=True, check=True,
                                 capture_output=True, timeout=120)

                logger.info(f" ✅ Fixed: {issue.component}")
                fixed += 1

            except subprocess.CalledProcessError as e:
                logger.error(f" ❌ Failed: {e}")
                failed += 1
            except subprocess.TimeoutExpired:
                logger.error(f" ❌ Timeout during repair")
                failed += 1
            except Exception as e:
                logger.error(f" ❌ Unexpected error: {e}")
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
                f"Fix: sudo {self.venv_pip} install <missing_package>",
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
            "permission denied": [
                "Insufficient permissions.",
                "Fix: Run with sudo",
                "Or: Check file permissions with ls -la"
            ],
            "no such file": [
                "File or directory not found.",
                "Fix: Re-run installer: sudo ./install.sh --full",
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

    def stress_test(self) -> bool:
        """Run a quick stress test on the system."""
        logger.info("=" * 70)
        logger.info("NullSec Guardian — Quick Stress Test")
        logger.info("=" * 70)

        passed = 0
        failed = 0

        # Test 1: API health
        logger.info("Test 1: API Health Check...")
        try:
            import requests
            api_token = self.api_token_file.read_text().strip() if self.api_token_file.exists() else ""
            resp = requests.get(
                "http://localhost:8888/health",
                headers={"Authorization": f"Bearer {api_token}"} if api_token else {},
                timeout=5
            )
            if resp.status_code == 200:
                logger.info(" ✅ API Health: PASSED")
                passed += 1
            else:
                logger.warning(f" ⚠️ API Health: HTTP {resp.status_code}")
                failed += 1
        except Exception as e:
            logger.error(f" ❌ API Health: {e}")
            failed += 1

        # Test 2: Job store
        logger.info("Test 2: Job Store...")
        try:
            sys.path.insert(0, str(self.install_dir))
            from modules.worker.job_store import JobStore
            store = JobStore()
            job_id = store.create_job("test", "127.0.0.1", "-sn")
            job = store.get_job(job_id)
            if job and job["tool"] == "test":
                logger.info(" ✅ Job Store: PASSED")
                passed += 1
            else:
                logger.warning(" ⚠️ Job Store: Retrieval failed")
                failed += 1
            store.cleanup_old_jobs(days=0)
        except Exception as e:
            logger.error(f" ❌ Job Store: {e}")
            failed += 1

        # Test 3: Python packages
        logger.info("Test 3: Python Packages...")
        python_cmd = self._get_python_cmd()
        all_ok = True
        for pkg in self.required_packages:
            rc, _, _ = self._run_cmd([python_cmd, "-c", f"import {pkg}"], timeout=5)
            if rc != 0:
                all_ok = False
                break
        if all_ok:
            logger.info(" ✅ Python Packages: PASSED")
            passed += 1
        else:
            logger.warning(" ⚠️ Python Packages: Some missing")
            failed += 1

        logger.info("=" * 70)
        logger.info(f"Stress Test: {passed} passed, {failed} failed")
        logger.info("=" * 70)

        return failed == 0

# ─── Main ────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="NullSec Guardian — System Diagnostic & Repair Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  guardian --check       Full system check
  guardian --repair      Auto-repair issues
  guardian --report      Generate JSON report
  guardian --stress      Run stress test
  guardian "connection error"  Diagnose specific error
  guardian --version     Show version
"""
    )
    parser.add_argument("--check", action="store_true", help="Run system check")
    parser.add_argument("--repair", action="store_true", help="Auto-repair")
    parser.add_argument("--report", action="store_true", help="Generate JSON report")
    parser.add_argument("--stress", action="store_true", help="Run stress test")
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
    elif args.stress:
        success = guardian.stress_test()
        sys.exit(0 if success else 1)
    elif args.error_message:
        print(guardian.diagnose_error(args.error_message))
    elif args.check or len(sys.argv) == 1:
        issues = guardian.check_system()
        sys.exit(0 if not issues else 1)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
