from pathlib import Path

import pytest

from modules.runners.sandbox import SandboxProfile, SandboxRequiredRunner, SandboxUnavailable

DIGEST_IMAGE = "registry.example/nullsec-toolbox@sha256:" + "a" * 64


def test_profile_rejects_mutable_image_and_host_network():
    with pytest.raises(ValueError, match="immutable digest"):
        SandboxProfile(image="nullsec/toolbox:latest")
    with pytest.raises(ValueError, match="Host networking"):
        SandboxProfile(image=DIGEST_IMAGE, network="host")


def test_runner_builds_least_privilege_command(tmp_path: Path):
    runner = SandboxRequiredRunner(SandboxProfile(image=DIGEST_IMAGE))
    command = runner.build_command("job-123", tmp_path, ["tool", "--safe"])

    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--pids-limit" in command
    assert "--network" in command
    assert command[command.index("--network") + 1] == "none"
    assert "--timeout" not in command
    assert command[-2:] == ["tool", "--safe"]


def test_runner_fails_closed_when_runtime_is_missing(tmp_path: Path):
    runner = SandboxRequiredRunner(SandboxProfile(image=DIGEST_IMAGE), runtime="not-a-real-runtime")

    with pytest.raises(SandboxUnavailable):
        runner.run("job-123", tmp_path, ["tool"])
