"""Strict, least-privilege container execution for approved task arguments."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path


class SandboxUnavailable(RuntimeError):
    """Raised when a required sandbox runtime or immutable image is unavailable."""


class SandboxExecutionError(RuntimeError):
    """Raised when a sandboxed process cannot complete safely."""


class SandboxCancelled(SandboxExecutionError):
    """Raised when the control plane cancels a still-running sandboxed task."""


@dataclass(frozen=True)
class SandboxProfile:
    """Immutable controls for one sandboxed task class."""

    image: str
    network: str = "none"
    user: str = "65532:65532"
    memory: str = "1g"
    cpus: str = "1.0"
    pids_limit: int = 64
    timeout_seconds: int = 300

    def __post_init__(self) -> None:
        if "@sha256:" not in self.image:
            raise ValueError("Sandbox image must be pinned by immutable digest")
        if self.network == "host":
            raise ValueError("Host networking is not permitted by the sandbox profile")
        if self.timeout_seconds < 1:
            raise ValueError("Sandbox timeout must be positive")


class SandboxRequiredRunner:
    """Run an approved argv only in a hardened container; never fall back locally."""

    def __init__(self, profile: SandboxProfile, runtime: str | None = None) -> None:
        self.profile = profile
        self.runtime = runtime or os.environ.get("CONTAINER_RUNTIME", "docker")

    def is_available(self) -> bool:
        """Check that a container runtime is present without launching user work."""
        return shutil.which(self.runtime) is not None

    def build_command(self, job_id: str, workspace: Path, argv: Sequence[str]) -> list[str]:
        """Build a non-shell command with restrictive, explicit container controls."""
        if not job_id or not argv:
            raise SandboxExecutionError("Job ID and command arguments are required")
        if not workspace.is_dir():
            raise SandboxExecutionError("Sandbox workspace must exist")
        safe_name = "nullsec-" + "".join(character for character in job_id if character.isalnum())[:40]
        if not safe_name or safe_name == "nullsec-":
            raise SandboxExecutionError("Job ID contains no usable identifier")
        return [
            self.runtime,
            "run",
            "--rm",
            "--name",
            safe_name,
            "--network",
            self.profile.network,
            "--user",
            self.profile.user,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit",
            str(self.profile.pids_limit),
            "--memory",
            self.profile.memory,
            "--cpus",
            self.profile.cpus,
            "--tmpfs",
            # Private container tmpfs, not a host temporary-file path.
            "/tmp:rw,noexec,nosuid,size=64m",  # nosec B108
            "--mount",
            f"type=bind,src={workspace.resolve()},dst=/work",
            "--workdir",
            "/work",
            self.profile.image,
            *argv,
        ]

    def run(
        self,
        job_id: str,
        workspace: Path,
        argv: Sequence[str],
        cancel_check: Callable[[], bool] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run with timeout, process-group cleanup, and cooperative cancellation."""
        if not self.is_available():
            raise SandboxUnavailable(f"Required container runtime '{self.runtime}' is unavailable")
        command = self.build_command(job_id, workspace, argv)
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        deadline = time.monotonic() + self.profile.timeout_seconds
        output = ""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._terminate_process_group(process)
                raise SandboxExecutionError(f"Sandboxed job timed out after {self.profile.timeout_seconds}s")
            if cancel_check and cancel_check():
                self._terminate_process_group(process)
                raise SandboxCancelled("Sandboxed job was cancelled by the control plane")
            try:
                output, _ = process.communicate(timeout=min(1.0, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
        if process.returncode != 0:
            raise SandboxExecutionError(f"Sandboxed job exited {process.returncode}: {output[-500:]}")
        return subprocess.CompletedProcess(command, process.returncode, output, "")

    @staticmethod
    def _terminate_process_group(process: subprocess.Popen[str]) -> None:
        """Terminate all descendants created by the runner before returning control."""
        if process.poll() is not None:
            return
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
