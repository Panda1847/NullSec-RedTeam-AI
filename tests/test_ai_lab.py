import json

from modules.payloads.jailbreak_tester import (
    EvaluationMode,
    EvaluationStatus,
    run_evaluation,
    run_jailbreak_test,
    scan_llm_vulnerabilities,
)


def test_default_ai_lab_result_is_explicit_simulation_not_a_security_finding():
    result = run_evaluation("consented-model", "PROMPT_INJECTION")

    assert result.mode is EvaluationMode.SIMULATION
    assert result.status is EvaluationStatus.NOT_EVALUATED
    assert result.evidence_ref is None
    assert "not a provider call" in result.limitations[0].lower()


def test_provider_mode_without_adapter_reports_configuration_required():
    result = run_evaluation("consented-model", "DATA_BOUNDARY", mode=EvaluationMode.PROVIDER)

    assert result.status is EvaluationStatus.CONFIGURATION_REQUIRED
    assert result.evidence_ref is None


def test_mcp_rendering_and_scan_do_not_claim_simulated_findings():
    rendered = json.loads(run_jailbreak_test("consented-model", "ROLE_BOUNDARY"))
    scan = json.loads(scan_llm_vulnerabilities("consented-model", "standard"))

    assert rendered["status"] == "not_evaluated"
    assert scan["status"] == "not_evaluated"
    assert "risk findings" in scan["limitations"][1].lower()
