"""Security primitives shared by the HTTP server and MCP bridge."""

from __future__ import annotations

import hmac
import ipaddress
import os
from pathlib import Path


class ConfigurationError(ValueError):
    """Raised when deployment configuration weakens a required safety boundary."""


def read_api_token(token_file: Path = Path("/etc/nullsec/api_token")) -> str | None:
    """Read a token from the environment or protected file without logging it."""
    environment_token = os.environ.get("API_TOKEN", "").strip()
    if environment_token:
        return environment_token
    try:
        if token_file.is_file():
            token = token_file.read_text(encoding="utf-8").strip()
            return token or None
    except OSError:
        return None
    return None


def verify_bearer_token(candidate: str, expected: str | None) -> bool:
    """Compare credentials in constant time and fail closed for empty values."""
    if not candidate or not expected:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


def is_loopback_host(host: str) -> bool:
    """Return whether a hostname resolves to a loopback bind form without DNS lookup."""
    candidate = host.strip().lower()
    if candidate in {"localhost", "::1"}:
        return True
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def validate_bind_address(host: str) -> str:
    """Require an explicit environment opt-in before binding outside local loopback."""
    if is_loopback_host(host):
        return host
    if os.environ.get("NULLSEC_ALLOW_NON_LOOPBACK", "false").lower() == "true":
        return host
    raise ConfigurationError(
        "Refusing non-loopback bind. Set NULLSEC_ALLOW_NON_LOOPBACK=true only behind an approved "
        "authenticated reverse proxy and network policy."
    )


def redact_secret(value: str, visible: int = 4) -> str:
    """Return a stable redaction for logs and errors that must not disclose secrets."""
    if not value:
        return "<empty>"
    if len(value) <= visible:
        return "<redacted>"
    return f"{value[:visible]}…<redacted>"
