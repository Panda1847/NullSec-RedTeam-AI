#!/usr/bin/env python3
"""Unit tests for HexStrike Server."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.brain.hexstrike_server import validate_target, validate_options, sanitize_input

class TestInputValidation(unittest.TestCase):
    def test_valid_ip(self):
        self.assertTrue(validate_target("192.168.1.1")[0])
        self.assertTrue(validate_target("10.0.0.1")[0])
        self.assertTrue(validate_target("::1")[0])

    def test_valid_hostname(self):
        self.assertTrue(validate_target("example.com")[0])
        self.assertTrue(validate_target("test.example.co.uk")[0])

    def test_valid_url(self):
        self.assertTrue(validate_target("https://example.com")[0])
        self.assertTrue(validate_target("http://test.com:8080/path")[0])

    def test_invalid_targets(self):
        self.assertFalse(validate_target("")[0])
        self.assertFalse(validate_target("../../etc/passwd")[0])
        self.assertFalse(validate_target("127.0.0.1; rm -rf /")[0])
        self.assertFalse(validate_target("-v")[0])
        self.assertFalse(validate_target("/etc/passwd")[0])
        self.assertFalse(validate_target("test\nrm -rf /")[0])

    def test_options_validation(self):
        self.assertTrue(validate_options("-sV -T4")[0])
        self.assertFalse(validate_options("-sV; rm -rf /")[0])
        self.assertFalse(validate_options("-sV | cat /etc/passwd")[0])
        self.assertFalse(validate_options("-sV $(whoami)")[0])

    def test_sanitize_input(self):
        self.assertEqual(sanitize_input("test-value_1.2"), "test-value_1.2")
        self.assertEqual(sanitize_input("../../etc/passwd"), "etc/passwd")
        self.assertEqual(sanitize_input("-bad"), "bad")

if __name__ == "__main__":
    unittest.main()
