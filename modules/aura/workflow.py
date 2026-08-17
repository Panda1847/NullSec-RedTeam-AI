"""Typed, bounded AURA workflow coordination.

This module intentionally does not call tools or model providers. It provides the
state machine and event contracts through which a planner can propose work, a
policy reviewer can authorize it, an executor can receive one approved request,
and an evidence reviewer can close the workflow.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from modules.domain.models import CapabilityTier, ExecutionMode, PolicyDecision, ToolRequest


class WorkflowError(ValueError):
    """Raised when an AURA workflow attempts an invalid or unsafe transition."""


class WorkflowStage(str, Enum):
    PLANNING = "planning"
    AWAITING_POLICY = "awaiting_policy"
    APPROVED = "approved"
    EXECUTING = "executing"
    AWAITING_EVIDENCE_REVIEW = "awaiting_evidence_review"
    COMPLETED = "completed"
    REJECTED = "rejected"


@dataclass(frozen=True)
class TaskStep:
    """One proposed execution step. It is inert until policy approval."""

    step_id: str
    tool_name: str
    target: str
    arguments: Mapping[str, object]
    capability: CapabilityTier
    execution_mode: ExecutionMode = ExecutionMode.SANDBOX_REQUIRED


@dataclass(frozen=True)
class PlanProposal:
    """A planner-owned proposal with a stable product session identity."""

    session_id: str
    campaign_id: str
    actor_id: str
    steps: tuple[TaskStep, ...]
    assumptions: tuple[str, ...] = ()
    runtime_session_id: str | None = None


@dataclass(frozen=True)
class AgentEvent:
    """Append-only, machine-readable handoff between bounded agent roles."""

    event_id: str
    session_id: str
    event_type: str
    actor_role: str
    timestamp: datetime
    details: Mapping[str, object]


@dataclass
class _WorkflowState:
    proposal: PlanProposal
    stage: WorkflowStage = WorkflowStage.PLANNING
    approvals: dict[str, PolicyDecision] = field(default_factory=dict)
    executing_step_id: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
    events: list[AgentEvent] = field(default_factory=list)


class AURAWorkflow:
    """In-memory workflow state machine; persistence can be supplied by an adapter later."""

    def __init__(self) -> None:
        self._sessions: dict[str, _WorkflowState] = {}

    def create_plan(
        self,
        *,
        campaign_id: str,
        actor_id: str,
        steps: tuple[TaskStep, ...],
        assumptions: tuple[str, ...] = (),
        session_id: str | None = None,
        runtime_session_id: str | None = None,
    ) -> PlanProposal:
        """Register a plan proposal without granting any execution capability."""
        if not campaign_id or not actor_id or not steps:
            raise WorkflowError("Campaign, actor, and at least one task step are required")
        if len({step.step_id for step in steps}) != len(steps):
            raise WorkflowError("Task step IDs must be unique")
        identifier = session_id or str(uuid.uuid4())
        if identifier in self._sessions:
            raise WorkflowError("A workflow session with this product ID already exists")
        proposal = PlanProposal(identifier, campaign_id, actor_id, steps, assumptions, runtime_session_id)
        state = _WorkflowState(proposal=proposal)
        self._sessions[identifier] = state
        self._event(state, "plan_created", "planner", {"step_count": len(steps)})
        state.stage = WorkflowStage.AWAITING_POLICY
        return proposal

    def record_policy_decision(self, session_id: str, step_id: str, decision: PolicyDecision) -> None:
        """Record an independently produced policy decision for a specific proposal step."""
        state = self._state(session_id)
        step = self._step(state, step_id)
        if state.stage not in {WorkflowStage.AWAITING_POLICY, WorkflowStage.APPROVED}:
            raise WorkflowError("Policy decisions are not accepted at the current workflow stage")
        if decision.campaign_id != state.proposal.campaign_id or decision.actor_id != state.proposal.actor_id:
            raise WorkflowError("Policy decision identity does not match this workflow")
        if not decision.allowed:
            state.stage = WorkflowStage.REJECTED
            self._event(state, "policy_denied", "policy_reviewer", {"step_id": step.step_id, "code": decision.reason_code})
            return
        state.approvals[step_id] = decision
        self._event(state, "policy_approved", "policy_reviewer", {"step_id": step.step_id, "decision_id": decision.decision_id})
        if len(state.approvals) == len(state.proposal.steps):
            state.stage = WorkflowStage.APPROVED
            self._event(state, "plan_approved", "policy_reviewer", {})

    def begin_execution(self, session_id: str, step_id: str, idempotency_key: str) -> ToolRequest:
        """Allow the executor to receive one typed request only after whole-plan approval."""
        state = self._state(session_id)
        if state.stage is not WorkflowStage.APPROVED:
            raise WorkflowError("Execution is not permitted before full plan approval")
        if not idempotency_key.strip():
            raise WorkflowError("Execution requires an idempotency key")
        step = self._step(state, step_id)
        decision = state.approvals.get(step_id)
        if decision is None or not decision.allowed:
            raise WorkflowError("This task step has no allowed policy decision")
        state.stage = WorkflowStage.EXECUTING
        state.executing_step_id = step_id
        self._event(state, "execution_authorized", "executor", {"step_id": step_id, "decision_id": decision.decision_id})
        return ToolRequest(
            request_id=str(uuid.uuid4()),
            campaign_id=state.proposal.campaign_id,
            actor_id=state.proposal.actor_id,
            tool_name=step.tool_name,
            target=step.target,
            arguments=step.arguments,
            capability=step.capability,
            execution_mode=step.execution_mode,
            idempotency_key=idempotency_key,
        )

    def record_execution_result(self, session_id: str, step_id: str, evidence_ref: str) -> None:
        """Move from execution to evidence review without interpreting the evidence."""
        state = self._state(session_id)
        if state.stage is not WorkflowStage.EXECUTING or state.executing_step_id != step_id:
            raise WorkflowError("Only the active execution step may record a result")
        if not evidence_ref.strip():
            raise WorkflowError("Evidence reference is required")
        state.evidence_refs.append(evidence_ref)
        state.executing_step_id = None
        state.stage = WorkflowStage.AWAITING_EVIDENCE_REVIEW
        self._event(state, "evidence_recorded", "executor", {"step_id": step_id, "evidence_ref": evidence_ref})

    def complete_evidence_review(self, session_id: str, reviewer_note: str) -> None:
        """Close the workflow only after a distinct evidence-review handoff."""
        state = self._state(session_id)
        if state.stage is not WorkflowStage.AWAITING_EVIDENCE_REVIEW:
            raise WorkflowError("Evidence review is not pending")
        if not reviewer_note.strip():
            raise WorkflowError("Evidence reviewer note is required")
        state.stage = WorkflowStage.COMPLETED
        self._event(state, "evidence_review_completed", "evidence_reviewer", {"note": reviewer_note})

    def events(self, session_id: str) -> tuple[AgentEvent, ...]:
        """Return immutable event history for inspection or persistence."""
        return tuple(self._state(session_id).events)

    def stage(self, session_id: str) -> WorkflowStage:
        return self._state(session_id).stage

    @staticmethod
    def _event(state: _WorkflowState, event_type: str, actor_role: str, details: Mapping[str, object]) -> None:
        state.events.append(
            AgentEvent(str(uuid.uuid4()), state.proposal.session_id, event_type, actor_role,
                       datetime.now(timezone.utc), dict(details))
        )

    def _state(self, session_id: str) -> _WorkflowState:
        try:
            return self._sessions[session_id]
        except KeyError as error:
            raise WorkflowError("Workflow session not found") from error

    @staticmethod
    def _step(state: _WorkflowState, step_id: str) -> TaskStep:
        for step in state.proposal.steps:
            if step.step_id == step_id:
                return step
        raise WorkflowError("Task step not found")
