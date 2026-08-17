from datetime import datetime, timezone

import pytest

from modules.aura.workflow import AURAWorkflow, TaskStep, WorkflowError, WorkflowStage
from modules.domain.models import CapabilityTier, ExecutionMode, PolicyDecision


def allowed_decision(step_id: str) -> PolicyDecision:
    return PolicyDecision(
        decision_id=f"decision-{step_id}",
        request_id=f"request-{step_id}",
        campaign_id="campaign-aura",
        actor_id="operator-aura",
        allowed=True,
        reason_code="allowed",
        reason="approved for test",
        decided_at=datetime.now(timezone.utc),
    )


def test_aura_requires_policy_before_execution_and_evidence_review_before_completion():
    workflow = AURAWorkflow()
    proposal = workflow.create_plan(
        campaign_id="campaign-aura",
        actor_id="operator-aura",
        steps=(
            TaskStep(
                step_id="step-1",
                tool_name="nmap_discovery",
                target="192.0.2.10",
                arguments={"ports": [443]},
                capability=CapabilityTier.PASSIVE,
                execution_mode=ExecutionMode.SANDBOX_REQUIRED,
            ),
        ),
        runtime_session_id="provider-thread-ephemeral",
    )

    with pytest.raises(WorkflowError, match="before full plan approval"):
        workflow.begin_execution(proposal.session_id, "step-1", "idempotency-1")

    workflow.record_policy_decision(proposal.session_id, "step-1", allowed_decision("step-1"))
    request = workflow.begin_execution(proposal.session_id, "step-1", "idempotency-1")
    assert request.execution_mode is ExecutionMode.SANDBOX_REQUIRED
    assert workflow.stage(proposal.session_id) is WorkflowStage.EXECUTING

    workflow.record_execution_result(proposal.session_id, "step-1", "evidence://job-1")
    workflow.complete_evidence_review(proposal.session_id, "Evidence has provenance and limitations.")

    assert workflow.stage(proposal.session_id) is WorkflowStage.COMPLETED
    assert [event.event_type for event in workflow.events(proposal.session_id)] == [
        "plan_created",
        "policy_approved",
        "plan_approved",
        "execution_authorized",
        "evidence_recorded",
        "evidence_review_completed",
    ]


def test_aura_denial_rejects_entire_workflow():
    workflow = AURAWorkflow()
    proposal = workflow.create_plan(
        campaign_id="campaign-aura",
        actor_id="operator-aura",
        steps=(
            TaskStep("step-1", "nmap_discovery", "192.0.2.10", {}, CapabilityTier.PASSIVE),
        ),
    )
    denial = PolicyDecision(
        decision_id="denied", request_id="request", campaign_id="campaign-aura", actor_id="operator-aura",
        allowed=False, reason_code="target_out_of_scope", reason="not authorized",
    )

    workflow.record_policy_decision(proposal.session_id, "step-1", denial)

    assert workflow.stage(proposal.session_id) is WorkflowStage.REJECTED
    with pytest.raises(WorkflowError):
        workflow.begin_execution(proposal.session_id, "step-1", "idempotency-2")
