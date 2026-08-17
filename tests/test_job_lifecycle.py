from datetime import datetime, timedelta, timezone

import pytest

from modules.domain.models import Campaign, CapabilityTier
from modules.worker.job_store import JobStore, JobStoreError


def make_campaign() -> Campaign:
    now = datetime.now(timezone.utc)
    return Campaign(
        campaign_id="campaign-lifecycle",
        owner_id="operator-1",
        allowed_targets=frozenset({"192.0.2.0/24"}),
        allowed_capabilities=frozenset({CapabilityTier.PASSIVE}),
        starts_at=now - timedelta(minutes=1),
        ends_at=now + timedelta(hours=1),
    )


def test_job_store_records_idempotent_job_lifecycle_and_audit_events(tmp_path):
    store = JobStore(tmp_path / "jobs.db")
    store.create_campaign(make_campaign())
    decision_id = store.record_policy_decision(
        campaign_id="campaign-lifecycle",
        request_id="request-1",
        actor_id="operator-1",
        allowed=True,
        reason_code="allowed",
        reason="test policy",
    )

    first = store.create_job(
        "nmap_discovery",
        "192.0.2.10",
        campaign_id="campaign-lifecycle",
        actor_id="operator-1",
        policy_decision_id=decision_id,
        trace_id="trace-1",
        idempotency_key="submission-1",
        arguments={"ports": [443]},
    )
    second = store.create_job(
        "nmap_discovery",
        "192.0.2.10",
        campaign_id="campaign-lifecycle",
        actor_id="operator-1",
        policy_decision_id=decision_id,
        trace_id="trace-1",
        idempotency_key="submission-1",
        arguments={"ports": [443]},
    )

    assert first == second
    leased = store.lease_next_job("worker-1", lease_seconds=30)
    assert leased is not None
    assert leased["id"] == first
    assert leased["status"] == "leased"

    store.mark_running(first, "worker-1")
    assert store.heartbeat(first, "worker-1") is True
    store.update_job(first, "done", result="completed", exit_code=0)

    job = store.get_job(first)
    assert job["status"] == "done"
    assert job["trace_id"] == "trace-1"
    assert job["arguments"] == {"ports": [443]}
    assert {event["event_type"] for event in store.list_audit_events(first)} >= {
        "job_created",
        "job_leased",
        "job_running",
        "job_done",
    }


def test_job_store_rejects_invalid_transition_and_supports_cancellation(tmp_path):
    store = JobStore(tmp_path / "jobs.db")
    job_id = store.create_job("nmap_discovery", "192.0.2.20", idempotency_key="submission-2")

    with pytest.raises(JobStoreError, match="Invalid job transition"):
        store.update_job(job_id, "done")

    assert store.request_cancel(job_id, "operator-1") is True
    job = store.get_job(job_id)
    assert job["status"] == "cancelled"
    assert job["cancel_requested"] is True
