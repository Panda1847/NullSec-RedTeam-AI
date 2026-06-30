#!/usr/bin/env python3
"""
NullSec Server Tests - API Endpoints
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.brain.hexstrike_server import app, sanitize_input, validate_target

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client

class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "ok"
        assert "tools" in data

    def test_health_returns_version(self, client):
        response = client.get("/health")
        data = response.get_json()
        assert "version" in data

class TestExecuteEndpoint:
    def test_no_auth_returns_401(self, client):
        response = client.post("/api/tools/execute", json={"tool": "nmap", "target": "127.0.0.1"})
        assert response.status_code == 401

    def test_wrong_auth_returns_403(self, client):
        response = client.post(
            "/api/tools/execute",
            json={"tool": "nmap", "target": "127.0.0.1"},
            headers={"Authorization": "Bearer wrong_token"}
        )
        assert response.status_code in (403, 500)

    def test_invalid_tool_returns_404(self, client):
        response = client.post(
            "/api/tools/execute",
            json={"tool": "badtool", "target": "127.0.0.1"},
            headers={"Authorization": "Bearer test"}
        )
        assert response.status_code == 404

    def test_invalid_target_returns_400(self, client):
        response = client.post(
            "/api/tools/execute",
            json={"tool": "nmap", "target": "../../etc/passwd"},
            headers={"Authorization": "Bearer test"}
        )
        assert response.status_code == 400

    def test_malformed_json_returns_400(self, client):
        response = client.post(
            "/api/tools/execute",
            data="not json",
            headers={"Authorization": "Bearer test", "Content-Type": "application/json"}
        )
        assert response.status_code == 400

class TestJobEndpoint:
    def test_invalid_job_id_format(self, client):
        response = client.get("/api/jobs/invalid-id", headers={"Authorization": "Bearer test"})
        assert response.status_code == 400

    def test_nonexistent_job_returns_404(self, client):
        response = client.get(
            "/api/jobs/12345678-1234-1234-1234-123456789abc",
            headers={"Authorization": "Bearer test"}
        )
        assert response.status_code == 404

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
