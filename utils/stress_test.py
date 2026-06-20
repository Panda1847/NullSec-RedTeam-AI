import requests
import time
import subprocess
import os

SERVER_URL = "http://localhost:8888"

def test_server_up():
    print("[*] Checking if server is up...")
    try:
        r = requests.get(f"{SERVER_URL}/health")
        if r.status_code == 200:
            print("[+] Server is online")
            return True
    except:
        pass
    print("[-] Server is offline")
    return False

def test_command_injection():
    print("[*] Testing for command injection...")
    payloads = [
        {"tool": "nmap", "target": "127.0.0.1; cat /etc/passwd", "options": ""},
        {"tool": "nmap", "target": "127.0.0.1", "options": "-sV; touch /tmp/pwned"},
        {"tool": "nmap", "target": "127.0.0.1 $(whoami)", "options": ""},
        {"tool": "badtool", "target": "127.0.0.1", "options": ""}
    ]
    
    for p in payloads:
        print(f"    Testing payload: {p}")
        r = requests.post(f"{SERVER_URL}/api/tools/execute", json=p)
        print(f"    Response: {r.status_code} - {r.text[:100]}...")
        
        if os.path.exists("/tmp/pwned"):
            print("[!] CRITICAL: Command injection successful!")
            os.remove("/tmp/pwned")
            return False
    print("[+] Security check passed (no simple injection detected)")
    return True

def test_invalid_json():
    print("[*] Testing malformed JSON...")
    r = requests.post(f"{SERVER_URL}/api/tools/execute", data="not json")
    print(f"    Response: {r.status_code}")
    return r.status_code in [400, 415]

def run_all_tests():
    if not test_server_up():
        print("[!] Start the server before running tests: python3 modules/brain/hexstrike_server.py")
        return
        
    results = {
        "Injection": test_command_injection(),
        "Malformed JSON": test_invalid_json()
    }
    
    print("\n=== TEST SUMMARY ===")
    for test, passed in results.items():
        status = "PASSED" if passed else "FAILED"
        print(f"{test}: {status}")

if __name__ == "__main__":
    run_all_tests()
