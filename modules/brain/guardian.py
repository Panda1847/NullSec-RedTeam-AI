#!/usr/bin/env python3
import os, sys, subprocess, json, requests, socket, re, random, time

# Robust import for utils.core
try:
    from utils.core import with_pacman, self_heal, safe_run
except ImportError:
    # Try adding the current directory or /usr/local/bin to path
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    sys.path.append("/usr/local/bin")
    try:
        from utils.core import with_pacman, self_heal, safe_run
    except ImportError:
        # Fallback if still not found
        def with_pacman(msg): return lambda f: f
        def self_heal(**kwargs): return lambda f: f
        def safe_run(cmd, **kwargs):
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                return r.returncode, r.stdout, r.stderr
            except Exception as e: return 1, "", str(e)

LOG_FILE = os.path.join(os.path.expanduser("~"), ".guardian_diagnostics.log")
if not os.path.exists(LOG_FILE):
    try:
        with open(LOG_FILE, 'w') as f: pass
    except: pass

GUARDIAN_DB = {
    "externally-managed-environment": "echo 'Please use a virtual environment or \'pip install --break-system-packages\' if you understand the risks.'",
    "ModuleNotFoundError: No module named 'fastmcp'": "pip install fastmcp",
    "port 8888 is already in use": "fuser -k 8888/tcp",
    "Permission denied": "chmod +x {file} && chown $USER:$USER {file}",
    "Address already in use": "fuser -k {port}/tcp",
    "No space left on device": "echo 'CRITICAL: Disk space full! Please free up space and restart.' && exit 1"
}

def log(msg):
    print(f"[\033[94mGUARDIAN\033[0m] {msg}")
    try:
        with open(LOG_FILE, "a") as f: f.write(f"[GUARDIAN] {msg}\n")
    except:
        pass

@self_heal(max_retries=3)
def search_github(error_msg):
    log(f"Searching GitHub for: {error_msg}")
    query = f"hexstrike-ai OR mcp-terminal {error_msg}"
    api_url = f"https://api.github.com/search/issues?q={query}"
    try:
        resp = requests.get(api_url, timeout=10)
        if resp.status_code == 200:
            items = resp.json().get('items', [])
            return [item['html_url'] for item in items[:3]]
    except:
        pass
    return []

@with_pacman("Diagnosing")
def diagnose_and_fix(error_msg):
    log("Starting Deep Diagnosis...")
    for key, fix in GUARDIAN_DB.items():
        if key in error_msg:
            log(f"Known issue detected: {key}")
            cmd = fix
            if "{port}" in cmd:
                port_match = re.search(r'port (\d+)', error_msg)
                port = port_match.group(1) if port_match else "8888"
                cmd = cmd.replace("{port}", port)
            log(f"Executing fix: {cmd}")
            safe_run(cmd)
            return True
    
    links = search_github(error_msg)
    if links:
        log("Potential solutions found on GitHub:")
        for link in links: log(f" -> {link}")
    return False

@with_pacman("Checking Integrity")
def integrity_check():
    log("Running System Integrity Check...")
    checks = [
        ("python3 --version", "Python 3"),
        ("node --version", "Node.js"),
        ("git --version", "Git"),
        ("command -v claude-desktop || test -f /usr/bin/claude-desktop", "Claude Desktop"),
        ("systemctl is-active hexstrike", "HexStrike Service"),
        ("test -d /opt/hexstrike-ai", "HexStrike Directory"),
        ("test -d /opt/ai-security-lab", "AI Security Lab Directory")
    ]
    all_pass = True
    for cmd, name in checks:
        rc, _, _ = safe_run(cmd)
        status = "\033[92mPASS\033[0m" if rc == 0 else "\033[91mFAIL\033[0m"
        log(f"{name}: {status}")
        if rc != 0: all_pass = False
    return all_pass

if __name__ == "__main__":
    if len(sys.argv) > 1:
        error_msg = " ".join(sys.argv[1:])
        if not diagnose_and_fix(error_msg):
            log("Guardian could not auto-fix this issue. Please check logs.")
            sys.exit(1)
    else:
        if not integrity_check():
            log("System has ISSUES. Run with error message to attempt fix.")
            sys.exit(1)
        log("System is HEALTHY.")
