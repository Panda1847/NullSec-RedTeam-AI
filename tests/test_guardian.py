from modules.brain.guardian import Guardian


def test_guardian_repair_is_disabled_and_diagnostics_are_advisory(tmp_path):
    guardian = Guardian(install_dir=tmp_path / "missing-install")

    assert guardian.repair() is False
    guidance = guardian.diagnose_error("sandbox runtime unavailable")

    assert '"mode": "advisory"' in guidance
    assert "immutable image digest" in guidance


def test_guardian_report_is_read_only(tmp_path):
    guardian = Guardian(install_dir=tmp_path / "missing-install")
    report = guardian.report()

    assert report["mode"] == "read_only"
    assert report["issue_count"] >= 1
