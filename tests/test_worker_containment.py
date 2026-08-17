from pathlib import Path

from modules.worker import worker as worker_module
from modules.worker.worker import Worker


def test_sandbox_required_job_fails_closed_without_immutable_image(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(worker_module, "JOB_DIR", tmp_path / "jobs")
    monkeypatch.setattr(worker_module, "LOG_DIR", tmp_path / "logs")
    worker_module.LOG_DIR.mkdir()
    candidate = Worker.__new__(Worker)
    monkeypatch.setattr(candidate, "_validate_tool", lambda _: (True, ""))
    monkeypatch.setattr(candidate, "_sanitize_options", lambda _: (True, "", []))
    monkeypatch.delenv("TOOL_IMAGE", raising=False)

    code, log_path = candidate._run_job_container(
        {"id": "job-1", "tool": "safe-tool", "target": "192.0.2.1", "options": ""}
    )

    assert code == 125
    assert "sandbox-required" in Path(log_path).read_text().lower()


def test_development_mode_requires_explicit_environment_opt_in(monkeypatch):
    candidate = Worker.__new__(Worker)
    monkeypatch.delenv("NULLSEC_EXECUTION_MODE", raising=False)
    assert candidate._development_mode_enabled() is False

    monkeypatch.setenv("NULLSEC_EXECUTION_MODE", "development")
    assert candidate._development_mode_enabled() is True
