
import pytest

from modules.brain.security import (
    ConfigurationError,
    is_loopback_host,
    validate_bind_address,
    verify_bearer_token,
)


def test_bearer_token_verification_fails_closed_for_empty_values():
    assert verify_bearer_token("candidate", "expected") is False
    assert verify_bearer_token("", "expected") is False
    assert verify_bearer_token("candidate", None) is False
    assert verify_bearer_token("same", "same") is True


def test_loopback_detection_only_accepts_explicit_loopback_forms():
    assert is_loopback_host("127.0.0.1") is True
    assert is_loopback_host("::1") is True
    assert is_loopback_host("localhost") is True
    assert is_loopback_host("0.0.0.0") is False
    assert is_loopback_host("example.test") is False


def test_non_loopback_bind_requires_explicit_opt_in(monkeypatch):
    monkeypatch.delenv("NULLSEC_ALLOW_NON_LOOPBACK", raising=False)
    with pytest.raises(ConfigurationError):
        validate_bind_address("0.0.0.0")

    monkeypatch.setenv("NULLSEC_ALLOW_NON_LOOPBACK", "true")
    assert validate_bind_address("0.0.0.0") == "0.0.0.0"
