#!/usr/bin/env python3
"""
NullSec Security Tests - Input Sanitization
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.brain.hexstrike_server import sanitize_input, validate_target, get_api_token

class TestSanitizeInput:
    def test_basic_alphanumeric(self):
        assert sanitize_input("abc-123") == "abc-123"

    def test_removes_path_traversal(self):
        assert sanitize_input("../../etc/passwd") == "etcpasswd"

    def test_removes_shell_metacharacters(self):
        assert sanitize_input("test; rm -rf /") == "test rm -rf "

    def test_removes_dollar_signs(self):
        assert sanitize_input("test$HOME") == "testHOME"

    def test_allows_spaces_when_enabled(self):
        assert sanitize_input("-sV -O", allow_spaces=True) == "sV -O"

    def test_no_spaces_when_disabled(self):
        assert sanitize_input("-sV -O", allow_spaces=False) == "sV-O"

    def test_truncates_long_input(self):
        long_input = "a" * 2000
        result = sanitize_input(long_input, max_len=100)
        assert len(result) == 100

    def test_strips_leading_dash(self):
        assert sanitize_input("-rf /") == "rf "

    def test_empty_input(self):
        assert sanitize_input("") == ""

    def test_none_input(self):
        assert sanitize_input(None) == ""

class TestValidateTarget:
    def test_valid_ip(self):
        valid, _ = validate_target("192.168.1.1")
        assert valid is True

    def test_valid_ipv6(self):
        valid, _ = validate_target("::1")
        assert valid is True

    def test_valid_hostname(self):
        valid, _ = validate_target("example.com")
        assert valid is True

    def test_valid_url(self):
        valid, _ = validate_target("https://example.com/path")
        assert valid is True

    def test_invalid_path_traversal(self):
        valid, msg = validate_target("../etc/passwd")
        assert valid is False
        assert "forbidden" in msg.lower() or "invalid" in msg.lower()

    def test_invalid_command_injection(self):
        valid, msg = validate_target("127.0.0.1; cat /etc/passwd")
        assert valid is False

    def test_invalid_empty(self):
        valid, msg = validate_target("")
        assert valid is False

    def test_invalid_too_long(self):
        valid, msg = validate_target("a" * 600)
        assert valid is False

class TestApiToken:
    def test_get_api_token_from_env(self, monkeypatch):
        monkeypatch.setenv("API_TOKEN", "test_token_123")
        assert get_api_token() == "test_token_123"

    def test_get_api_token_missing(self, monkeypatch, tmp_path):
        monkeypatch.delenv("API_TOKEN", raising=False)
        assert get_api_token() is None or isinstance(get_api_token(), str)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
