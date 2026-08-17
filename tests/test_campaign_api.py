from datetime import datetime, timedelta, timezone

from modules.brain import hexstrike_server as server
from modules.worker.job_store import JobStore


def auth_headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-token", "Content-Type": "application/json"}


def test_campaign_scoped_submission_is_idempotent_and_audited(monkeypatch, tmp_path):
    monkeypatch.setenv("API_TOKEN", "test-token")
    monkeypatch.setenv("NULLSEC_LOCAL_ACTOR_ID", "operator-1")
    monkeypatch.setenv("NULLSEC_LOCAL_ACTOR_ROLES", "operator,elevated_operator")
    monkeypatch.setattr(server, "store", JobStore(tmp_path / "jobs.db"))
    client = server.app.test_client()
    now = datetime.now(timezone.utc)

    campaign_response = client.post(
        "/api/campaigns",
        headers=auth_headers(),
        json={
            "campaign_id": "campaign-api",
            "allowed_targets": ["192.0.2.0/24"],
            "allowed_capabilities": ["passive"],
            "starts_at": (now - timedelta(minutes=1)).isoformat(),
            "ends_at": (now + timedelta(minutes=10)).isoformat(),
        },
    )
    assert campaign_response.status_code == 201

    request = {
        "tool": "nmap",
        "target": "192.0.2.10",
        "options": "-sV",
        "campaign_id": "campaign-api",
        "idempotency_key": "submission-api-1",
        "capability": "passive",
    }
    first = client.post("/api/tools/execute", headers=auth_headers(), json=request)
    second = client.post("/api/tools/execute", headers=auth_headers(), json=request)

    assert first.status_code == 202
    assert second.status_code == 202
    assert first.get_json()["job_id"] == second.get_json()["job_id"]
    events = server.store.list_audit_events(first.get_json()["job_id"])
    assert {event["event_type"] for event in events} >= {"job_created"}


def test_campaign_scoped_submission_denies_out_of_scope_target(monkeypatch, tmp_path):
    monkeypatch.setenv("API_TOKEN", "test-token")
    monkeypatch.setenv("NULLSEC_LOCAL_ACTOR_ID", "operator-1")
    monkeypatch.setenv("NULLSEC_LOCAL_ACTOR_ROLES", "operator")
    monkeypatch.setattr(server, "store", JobStore(tmp_path / "jobs.db"))
    client = server.app.test_client()
    now = datetime.now(timezone.utc)
    client.post(
        "/api/campaigns",
        headers=auth_headers(),
        json={
            "campaign_id": "campaign-deny",
            "allowed_targets": ["192.0.2.0/24"],
            "allowed_capabilities": ["passive"],
            "starts_at": (now - timedelta(minutes=1)).isoformat(),
            "ends_at": (now + timedelta(minutes=10)).isoformat(),
        },
    )

    response = client.post(
        "/api/tools/execute",
        headers=auth_headers(),
        json={
            "tool": "nmap",
            "target": "198.51.100.10",
            "campaign_id": "campaign-deny",
            "idempotency_key": "submission-deny-1",
            "capability": "passive",
        },
    )

    assert response.status_code == 403
    assert response.get_json()["code"] == "target_out_of_scope"
