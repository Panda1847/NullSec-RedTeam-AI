#!/usr/bin/env python3
"""NullSec Guardian: read-only deployment diagnostics.

Guardian reports configuration and integrity observations. It never executes
repairs, installs packages, starts services, or interprets exception text as a
command. Maintenance must be performed through a reviewed, explicit runbook.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

LOG_DIR = Path(os.environ.get("NULLSEC_LOG_DIR", str(Path.home() / ".local/state/nullsec/logs")))
LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s",
    handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler(LOG_DIR / "guardian.log")],
)
logger = logging.getLogger("guardian")


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class Issue:
    component: str
    severity: Severity
    message: str
    recommended_action: str
    runbook: str | None = None


class Guardian:
    """Read-only deployment health checks with no repair side effects."""

    VERSION = "7.1.0"

    def __init__(self, install_dir: Path | None = None) -> None:
        self.install_dir = install_dir or Path(os.environ.get("NULLSEC_INSTALL_DIR", "/opt/nullsec"))
        self.config_dir = Path(os.environ.get("NULLSEC_CONFIG_DIR", "/etc/nullsec"))
        self.token_file = self.config_dir / "api_token"
        self.environment_file = self.config_dir / "nullsec.env"
        self.job_dir = Path(os.environ.get("NULLSEC_JOB_DIR", str(Path.home() / ".local/state/nullsec/jobs")))
        self.expected_files = ("pyproject.toml", "RESPONSIBLE_USE.md", "SECURITY.md")

    @staticmethod
    def _run(argv: Sequence[str], timeout: int = 5) -> tuple[int, str, str]:
        """Run an immutable diagnostic command without a shell."""
        try:
            result = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, check=False)
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1, "", f"Diagnostic command timed out after {timeout}s"
        except OSError as error:
            return 127, "", str(error)

    def check_system(self) -> list[Issue]:
        """Collect deterministic deployment observations without altering the host."""
        issues: list[Issue] = []
        if not self.install_dir.exists():
            issues.append(Issue(
                "install_dir", Severity.HIGH, f"Install directory is absent: {self.install_dir}",
                "Run the reviewed installer in the intended mode or set NULLSEC_INSTALL_DIR.",
                "docs/runbooks/deployment.md",
            ))
        else:
            for filename in self.expected_files:
                if not (self.install_dir / filename).is_file():
                    issues.append(Issue(
                        f"install_file_{filename}", Severity.MEDIUM, f"Required project file is absent: {filename}",
                        "Reinstall from a verified release artifact; do not copy individual files from unverified sources.",
                        "docs/runbooks/deployment.md",
                    ))

        if self.token_file.exists():
            mode = self.token_file.stat().st_mode & 0o777
            if mode & 0o007:
                issues.append(Issue(
                    "api_token_permissions", Severity.HIGH,
                    f"API token has world-accessible mode {oct(mode)}.",
                    "Restrict the token to the service owner and approved group; review the system installer’s ownership model.",
                    "docs/runbooks/credential-rotation.md",
                ))
        else:
            issues.append(Issue(
                "api_token", Severity.MEDIUM, "No system API token file was found.",
                "For a system deployment, provision a unique token through a protected secret-management process.",
                "docs/runbooks/credential-rotation.md",
            ))

        if self.environment_file.exists():
            content = self.environment_file.read_text(encoding="utf-8", errors="replace")
            if "TOOL_IMAGE=" in content and "@sha256:" not in content:
                issues.append(Issue(
                    "tool_image", Severity.HIGH,
                    "The environment file does not declare an immutable sandbox image digest.",
                    "Set TOOL_IMAGE to a reviewed OCI image using an @sha256 digest before enabling a worker.",
                    "docs/runbooks/runner-hardening.md",
                ))
        else:
            issues.append(Issue(
                "environment_file", Severity.MEDIUM, "No system environment file was found.",
                "Create a reviewed configuration file with runner, token, storage, and network policy settings.",
                "docs/runbooks/deployment.md",
            ))

        if not self.job_dir.exists():
            issues.append(Issue(
                "job_dir", Severity.MEDIUM, f"Job state directory is absent: {self.job_dir}",
                "Create the state directory with ownership limited to the worker identity.",
                "docs/runbooks/deployment.md",
            ))

        runtime = os.environ.get("CONTAINER_RUNTIME", "docker")
        if shutil.which(runtime) is None:
            issues.append(Issue(
                "container_runtime", Severity.HIGH, f"Container runtime '{runtime}' is not on PATH.",
                "A sandbox-required worker will fail closed. Install and configure a rootless runtime before enabling it.",
                "docs/runbooks/runner-hardening.md",
            ))
        else:
            code, output, _ = self._run([runtime, "info"], timeout=10)
            if code != 0:
                issues.append(Issue(
                    "container_runtime_access", Severity.HIGH,
                    f"Container runtime '{runtime}' is present but not usable by this identity.",
                    "Verify rootless runtime access and avoid granting untrusted users access to the daemon socket.",
                    "docs/runbooks/runner-hardening.md",
                ))
            elif "rootless" not in output.lower():
                issues.append(Issue(
                    "rootless_runtime", Severity.MEDIUM,
                    "Container runtime is available but did not report a rootless configuration.",
                    "Review a rootless deployment or documented user-namespace isolation before enabling execution.",
                    "docs/runbooks/runner-hardening.md",
                ))

        try:
            available = shutil.disk_usage(self.job_dir.parent if self.job_dir.parent.exists() else Path.home()).free
            if available < 1024**3:
                issues.append(Issue(
                    "disk_space", Severity.MEDIUM, "Less than 1 GiB of free space is available for state and evidence.",
                    "Apply the organization’s retention policy and free capacity before scheduling work.",
                    "docs/runbooks/evidence-retention.md",
                ))
        except OSError as error:
            issues.append(Issue("disk_space", Severity.LOW, f"Disk check unavailable: {error}", "Check storage manually."))
        return issues

    def report(self) -> dict[str, object]:
        issues = self.check_system()
        return {
            "guardian_version": self.VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "read_only",
            "issue_count": len(issues),
            "issues": [{**asdict(issue), "severity": issue.severity.value} for issue in issues],
        }

    def repair(self, issues: list[Issue] | None = None) -> bool:
        """Compatibility method that intentionally refuses automatic remediation."""
        logger.error("Automatic repair is disabled. Review and execute the recommended runbook manually.")
        return False

    def diagnose_error(self, error_message: str) -> str:
        """Provide non-executing guidance for common operational symptoms."""
        normalized = error_message.lower()
        guidance = {
            "connection refused": "Confirm the server binds to loopback and inspect its authenticated service logs.",
            "unauthorized": "Verify the configured token source and avoid placing the token in shell history or logs.",
            "sandbox": "Check the immutable image digest, rootless runtime access, and runner profile. Sandbox jobs fail closed.",
            "database": "Check the worker state directory ownership, disk capacity, and SQLite integrity before restarting services.",
        }
        for pattern, recommendation in guidance.items():
            if pattern in normalized:
                return json.dumps({"symptom": error_message, "recommendation": recommendation, "mode": "advisory"})
        return json.dumps({"symptom": error_message, "recommendation": "Inspect structured logs and the relevant runbook.", "mode": "advisory"})


def main() -> None:
    parser = argparse.ArgumentParser(description="NullSec Guardian read-only diagnostics")
    parser.add_argument("--check", action="store_true", help="Print a human-readable diagnostic summary")
    parser.add_argument("--report", action="store_true", help="Emit a JSON diagnostic report")
    parser.add_argument("--diagnose", metavar="MESSAGE", help="Return non-executing guidance for an error symptom")
    parser.add_argument("--repair", action="store_true", help="Deprecated; automatic repair is intentionally disabled")
    args = parser.parse_args()
    guardian = Guardian()
    if args.report:
        print(json.dumps(guardian.report(), indent=2, sort_keys=True))
    elif args.diagnose:
        print(guardian.diagnose_error(args.diagnose))
    elif args.repair:
        guardian.repair()
        raise SystemExit(2)
    else:
        issues = guardian.check_system()
        if not issues:
            print("No deployment issues detected by read-only Guardian checks.")
        else:
            for issue in issues:
                print(f"[{issue.severity.value}] {issue.component}: {issue.message}\n  Action: {issue.recommended_action}")
        if args.check:
            raise SystemExit(1 if any(issue.severity in {Severity.CRITICAL, Severity.HIGH} for issue in issues) else 0)


if __name__ == "__main__":
    main()
