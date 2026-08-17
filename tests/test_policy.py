from datetime import datetime, timedelta, timezone

from modules.domain.models import Actor, Campaign, CapabilityTier, ExecutionMode, ToolRequest
from modules.domain.policy import CampaignPolicyEngine


def make_campaign() -> Campaign:
    now = datetime.now(timezone.utc)
    return Campaign(
        campaign_id="campaign-1",
        owner_id="owner-1",
        allowed_targets=frozenset({"192.0.2.0/24", "*.example.test"}),
        allowed_capabilities=frozenset({CapabilityTier.PASSIVE}),
        starts_at=now - timedelta(minutes=1),
        ends_at=now + timedelta(minutes=10),
    )


def make_request(target: str, capability: CapabilityTier = CapabilityTier.PASSIVE) -> ToolRequest:
    return ToolRequest(
        request_id="request-1",
        campaign_id="campaign-1",
        actor_id="owner-1",
        tool_name="nmap_discovery",
        target=target,
        arguments={"ports": [443]},
        capability=capability,
        execution_mode=ExecutionMode.SANDBOX_REQUIRED,
        idempotency_key="client-request-1",
    )


def test_policy_allows_in_scope_cidr_target():
    decision = CampaignPolicyEngine().decide(Actor("owner-1"), make_campaign(), make_request("192.0.2.10"))

    assert decision.allowed is True
    assert decision.reason_code == "allowed"


def test_policy_allows_authorized_subdomain_but_not_apex_domain():
    policy = CampaignPolicyEngine()

    assert policy.decide(Actor("owner-1"), make_campaign(), make_request("api.example.test")).allowed
    decision = policy.decide(Actor("owner-1"), make_campaign(), make_request("example.test"))
    assert decision.allowed is False
    assert decision.reason_code == "target_out_of_scope"


def test_policy_denies_unapproved_capability_and_non_operator():
    campaign = make_campaign()
    high_risk = CampaignPolicyEngine().decide(
        Actor("owner-1", frozenset({"elevated_operator"})),
        campaign,
        make_request("192.0.2.20", CapabilityTier.HIGH_RISK),
    )
    outsider = CampaignPolicyEngine().decide(Actor("outsider"), campaign, make_request("192.0.2.20"))

    assert high_risk.allowed is False
    assert high_risk.reason_code == "capability_denied"
    assert outsider.allowed is False
    assert outsider.reason_code == "actor_mismatch"
