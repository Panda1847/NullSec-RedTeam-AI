"""Policy decisions for campaign-scoped, authorization-first tool execution."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from .models import Actor, Campaign, CapabilityTier, PolicyDecision, ToolRequest


class CampaignPolicyEngine:
    """Evaluate a request without performing execution or persistence side effects."""

    def __init__(self, now: datetime | None = None) -> None:
        self._now = now

    def decide(self, actor: Actor, campaign: Campaign, request: ToolRequest) -> PolicyDecision:
        """Return an explicit allow or deny decision for one tool request."""
        if request.campaign_id != campaign.campaign_id:
            return self._deny(request, "campaign_mismatch", "Request does not belong to this campaign")
        if request.actor_id != actor.actor_id:
            return self._deny(request, "actor_mismatch", "Request actor does not match caller context")
        if not campaign.is_active(self._now or datetime.now(timezone.utc)):
            return self._deny(request, "campaign_inactive", "Campaign is outside its approved window")
        if not self._is_operator(actor, campaign):
            return self._deny(request, "role_denied", "Caller is not authorized for this campaign")
        if request.capability not in campaign.allowed_capabilities:
            return self._deny(request, "capability_denied", "Requested capability is not approved")
        if request.capability is CapabilityTier.HIGH_RISK and not actor.has_role("elevated_operator"):
            return self._deny(request, "elevation_required", "High-risk capability requires elevated_operator")
        if not self._target_in_scope(request.target, campaign):
            return self._deny(request, "target_out_of_scope", "Target is outside the approved campaign scope")
        if not request.idempotency_key.strip():
            return self._deny(request, "idempotency_required", "An idempotency key is required")
        return PolicyDecision(
            decision_id=str(uuid.uuid4()),
            request_id=request.request_id,
            campaign_id=campaign.campaign_id,
            actor_id=actor.actor_id,
            allowed=True,
            reason_code="allowed",
            reason="Request satisfies campaign scope and capability policy",
        )

    @staticmethod
    def _is_operator(actor: Actor, campaign: Campaign) -> bool:
        return actor.actor_id == campaign.owner_id or actor.has_role("operator") or actor.has_role("admin")

    @staticmethod
    def _target_in_scope(target: str, campaign: Campaign) -> bool:
        host = CampaignPolicyEngine._extract_host(target)
        if host is None:
            return False
        for entry in campaign.allowed_targets:
            if CampaignPolicyEngine._matches_scope_entry(host, entry):
                return True
        return False

    @staticmethod
    def _extract_host(target: str) -> str | None:
        candidate = target.strip().lower()
        if not candidate:
            return None
        if "://" in candidate:
            parsed = urlparse(candidate)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                return None
            return parsed.hostname.rstrip(".")
        return candidate.rstrip(".")

    @staticmethod
    def _matches_scope_entry(host: str, entry: str) -> bool:
        scope = entry.strip().lower().rstrip(".")
        if not scope:
            return False
        try:
            host_ip = ipaddress.ip_address(host)
        except ValueError:
            host_ip = None
        try:
            network = ipaddress.ip_network(scope, strict=False)
        except ValueError:
            network = None
        if host_ip is not None and network is not None:
            return host_ip in network
        if host_ip is not None:
            return host == scope
        if scope.startswith("*."):
            base = scope[2:]
            return host.endswith(f".{base}") and host != base
        return host == scope

    @staticmethod
    def _deny(request: ToolRequest, code: str, reason: str) -> PolicyDecision:
        return PolicyDecision(
            decision_id=str(uuid.uuid4()),
            request_id=request.request_id,
            campaign_id=request.campaign_id,
            actor_id=request.actor_id,
            allowed=False,
            reason_code=code,
            reason=reason,
        )
