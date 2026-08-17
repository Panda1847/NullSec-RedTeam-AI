"""Immutable domain contracts for authorized security execution."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class CapabilityTier(str, Enum):
    """Risk tiers used by the policy boundary."""

    PASSIVE = "passive"
    ACTIVE = "active"
    HIGH_RISK = "high_risk"


class ExecutionMode(str, Enum):
    """Runner modes. Sandbox-required work must never degrade to host execution."""

    DEVELOPMENT = "development"
    SANDBOX_REQUIRED = "sandbox_required"


class PolicyError(ValueError):
    """Raised when a request cannot satisfy an authorization policy."""


@dataclass(frozen=True)
class Actor:
    """Authenticated caller context supplied by the transport boundary."""

    actor_id: str
    roles: frozenset[str] = field(default_factory=frozenset)

    def has_role(self, role: str) -> bool:
        return role in self.roles


@dataclass(frozen=True)
class Campaign:
    """Authorized operating scope for a bounded engagement."""

    campaign_id: str
    owner_id: str
    allowed_targets: frozenset[str]
    allowed_capabilities: frozenset[CapabilityTier]
    starts_at: datetime
    ends_at: datetime
    active: bool = True

    def is_active(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        return self.active and self.starts_at <= current <= self.ends_at


@dataclass(frozen=True)
class ToolRequest:
    """A typed tool invocation awaiting a policy decision."""

    request_id: str
    campaign_id: str
    actor_id: str
    tool_name: str
    target: str
    arguments: Mapping[str, object]
    capability: CapabilityTier
    execution_mode: ExecutionMode
    idempotency_key: str


@dataclass(frozen=True)
class PolicyDecision:
    """An immutable authorization record consumed by job submission."""

    decision_id: str
    request_id: str
    campaign_id: str
    actor_id: str
    allowed: bool
    reason_code: str
    reason: str
    decided_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
