#!/bin/bash

# ==============================================================================
# NULLSEC RED TEAM AI: ULTIMATE ALL-IN-ONE INSTALLER (v1.2)
# ==============================================================================
# - Installs Claude Desktop (via claude-desktop-debian)
# - Installs HexStrike AI (150+ tools)
# - Installs AI Security Lab (Jailbreaks & LLM Vulns)
# - Configures Claude Desktop with full MCP integration
# - Deploys Advanced Guardian Diagnostic & Repair Tool
# - Full Sudo & System Access for Claude
# - Optimized for Kali Linux & Debian Systems
# ==============================================================================

# --- Configuration ---
INSTALL_DIR_HEX="/opt/hexstrike-ai"
INSTALL_DIR_LAB="/opt/ai-security-lab"
GUARDIAN_PATH="/usr/local/bin/guardian"
LOG_FILE="/tmp/nullsec_install.log"
REAL_USER=${SUDO_USER:-$USER}
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
CLAUDE_CONFIG_DIR="$REAL_HOME/.config/Claude"
CLAUDE_CONFIG_FILE="$CLAUDE_CONFIG_DIR/claude_desktop_config.json"
WORKSPACE="$REAL_HOME/NullSec_RedTeam_Lab"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Initialize log file
touch "$LOG_FILE"
chmod 666 "$LOG_FILE"

log() { echo -e "${GREEN}[INSTALLER]${NC} $1" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; }

# --- Failsafe Error Handler ---
error_handler() {
    error "$1"
    log "Invoking Guardian for emergency repair..."
    sudo python3 "$GUARDIAN_PATH" "$1"
    exit 1
}

# --- 1. Advanced Guardian Tool Deployment ---
deploy_guardian() {
    log "Deploying Advanced Guardian Diagnostic & Repair Tool..."
    cat <<'EOF' > "$GUARDIAN_PATH"
#!/usr/bin/env python3
import os, sys, subprocess, json, requests, socket, re

LOG_FILE = "/tmp/guardian_diagnostics.log"
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, 'w') as f: pass
os.chmod(LOG_FILE, 0o666)

GUARDIAN_DB = {
    "externally-managed-environment": "pip install --break-system-packages",
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
    except PermissionError:
        pass

def run_cmd(cmd, shell=True):
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as e: return 1, "", str(e)

def search_github(error_msg):
    log(f"Searching GitHub for: {error_msg}")
    query = f"hexstrike-ai OR mcp-terminal {error_msg}"
    api_url = f"https://api.github.com/search/issues?q={query}"
    try:
        resp = requests.get(api_url, timeout=10)
        if resp.status_code == 200:
            items = resp.json().get('items', [])
            return [item['html_url'] for item in items[:3]]
    except: pass
    return []

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
            run_cmd(cmd)
            return True
    
    links = search_github(error_msg)
    if links:
        log("Potential solutions found on GitHub:")
        for link in links: log(f" -> {link}")
    return False

def integrity_check():
    log("Running System Integrity Check...")
    checks = [
        ("python3 --version", "Python 3"),
        ("node --version", "Node.js"),
        ("git --version", "Git"),
        ("command -v claude-desktop", "Claude Desktop"),
        ("systemctl is-active hexstrike", "HexStrike Service"),
        ("test -d /opt/hexstrike-ai", "HexStrike Directory"),
        ("test -d /opt/ai-security-lab", "AI Security Lab Directory")
    ]
    all_pass = True
    for cmd, name in checks:
        rc, _, _ = run_cmd(cmd)
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
EOF
    chmod +x "$GUARDIAN_PATH"
}

# --- 2. Main Installation ---

log "Starting NullSec Red Team AI Installation (v1.2)..."

if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (sudo)."
   exit 1
fi

# Disk Space Check
FREE_SPACE=$(df -m / | awk 'NR==2 {print $4}')
if [ "$FREE_SPACE" -lt 3000 ]; then
    warn "Low disk space ($FREE_SPACE MB). 3GB+ is highly recommended."
fi

deploy_guardian

log "Phase 1: System Dependencies & Claude Desktop Setup..."
apt update -y || error_handler "Apt update failed"

if ! command -v curl &> /dev/null || ! command -v gpg &> /dev/null; then
    apt install -y curl gnupg || error_handler "Failed to install curl or gnupg."
fi

# Install Claude Desktop
if ! command -v claude-desktop &> /dev/null; then
    log "Installing Claude Desktop for Linux..."
    curl -fsSL https://aaddrick.github.io/claude-desktop-debian/KEY.gpg -o /tmp/claude-desktop.gpg
    gpg --dearmor -y -o /usr/share/keyrings/claude-desktop.gpg /tmp/claude-desktop.gpg
    echo "deb [signed-by=/usr/share/keyrings/claude-desktop.gpg arch=amd64,arm64] https://aaddrick.github.io/claude-desktop-debian stable main" | tee /etc/apt/sources.list.d/claude-desktop.list
    apt update -y
    apt install -y claude-desktop || error_handler "Claude Desktop installation failed"
fi

# Core Security Arsenal
CORE_DEPS=(
    git python3 python3-venv python3-pip python3-requests 
    nodejs npm curl jq lsof nmap masscan fierce dnsenum 
    gobuster dirsearch ffuf dirb nikto sqlmap wafw00f 
    hydra john hashcat medusa patator gdb binwalk 
    foremost steghide libimage-exiftool-perl
)

# Special handling for Chromium on Kali/Debian
if apt-cache show chromium &>/dev/null; then
    CORE_DEPS+=("chromium" "chromium-driver")
elif apt-cache show chromium-browser &>/dev/null; then
    CORE_DEPS+=("chromium-browser" "chromium-chromedriver")
else
    warn "Chromium not found in repositories. Attempting to install via snap/flatpak if available..."
fi

log "Installing ${#CORE_DEPS[@]} core security tools..."
apt install -y "${CORE_DEPS[@]}" || warn "Some core tools failed to install. Continuing..."

setup_go_env() {
    export GOPATH="$REAL_HOME/go"
    export PATH="$PATH:$GOPATH/bin"
    mkdir -p "$GOPATH/bin"
    chown -R "$REAL_USER":"$REAL_USER" "$REAL_HOME/go"
}

install_external_tool() {
    local tool=$1
    local cmd=$2
    if ! command -v "$tool" &> /dev/null; then
        log "Installing $tool via external method..."
        su -c "export GOPATH=$REAL_HOME/go; export PATH=\$PATH:\$GOPATH/bin; $cmd" - "$REAL_USER" || warn "Failed to install $tool."
    fi
}

if ! command -v go &> /dev/null; then
    apt install -y golang-go || warn "Failed to install golang-go."
fi
setup_go_env

install_external_tool "nuclei" "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_external_tool "subfinder" "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_external_tool "amass" "go install -v github.com/owasp-amass/amass/v4/...@master"

if ! command -v msfconsole &> /dev/null; then
    log "Installing Metasploit Framework..."
    curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb -o /tmp/msfinstall
    if [ -s /tmp/msfinstall ]; then
        chmod 755 /tmp/msfinstall
        /tmp/msfinstall || warn "Metasploit installation failed."
    fi
fi

log "Phase 2: HexStrike AI Deployment..."
if [ ! -d "$INSTALL_DIR_HEX" ]; then
    git clone https://github.com/0x4m4/hexstrike-ai.git "$INSTALL_DIR_HEX" || error_handler "HexStrike clone failed"
fi
cd "$INSTALL_DIR_HEX"
python3 -m venv venv || error_handler "Failed to create HexStrike venv."
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt || error_handler "HexStrike Python deps failed"

log "Phase 3: AI Security Lab Deployment..."
if [ ! -d "$INSTALL_DIR_LAB" ]; then
    git clone https://github.com/Panda1847/ai-security-lab.git "$INSTALL_DIR_LAB" || error_handler "AI Security Lab clone failed"
fi
cd "$INSTALL_DIR_LAB"
python3 -m venv venv || error_handler "Failed to create AI Security Lab venv."
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt || warn "AI Security Lab core deps failed."
./venv/bin/pip install garak pyrit promptfoo || warn "Extra AI security tools failed."

log "Phase 4: Claude Desktop MCP Orchestration..."
TARGET_PORT=8888
while lsof -Pi :$TARGET_PORT -sTCP:LISTEN -t >/dev/null ; do TARGET_PORT=$((TARGET_PORT + 1)); done

mkdir -p "$CLAUDE_CONFIG_DIR"
cat <<EOF > "$CLAUDE_CONFIG_FILE"
{
  "mcpServers": {
    "hexstrike": {
      "command": "$INSTALL_DIR_HEX/venv/bin/python3",
      "args": ["$INSTALL_DIR_HEX/hexstrike_mcp.py", "--server", "http://localhost:$TARGET_PORT"],
      "description": "HexStrike AI Offensive Security Toolkit (150+ tools)",
      "timeout": 3600
    },
    "ai-security-lab": {
      "command": "$INSTALL_DIR_LAB/venv/bin/python3",
      "args": ["$INSTALL_DIR_LAB/tools/jailbreak_tester.py", "--mcp"],
      "description": "AI Security Lab - Jailbreaks & LLM Vulnerability Scanner"
    },
    "terminal": { 
      "command": "npx", 
      "args": ["-y", "@dillip285/mcp-terminal", "--allowed-paths", "/"],
      "description": "Full System Terminal Access"
    },
    "filesystem": { 
      "command": "npx", 
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "$WORKSPACE"],
      "description": "Red Team Lab Workspace"
    },
    "browser": { 
      "command": "npx", 
      "args": ["-y", "@modelcontextprotocol/server-puppeteer"],
      "description": "Web Browser Automation"
    }
  }
}
EOF
chown -R "$REAL_USER":"$REAL_USER" "$CLAUDE_CONFIG_DIR"
mkdir -p "$WORKSPACE"
chown -R "$REAL_USER":"$REAL_USER" "$WORKSPACE"

log "Phase 5: Systemd Service Activation..."
cat <<EOF > /etc/systemd/system/hexstrike.service
[Unit]
Description=HexStrike AI Flask Server
After=network.target

[Service]
User=$REAL_USER
WorkingDirectory=$INSTALL_DIR_HEX
ExecStart=$INSTALL_DIR_HEX/venv/bin/python3 $INSTALL_DIR_HEX/hexstrike_server.py --port $TARGET_PORT
Restart=always
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable hexstrike
systemctl restart hexstrike

log "Phase 6: Final Validation..."
sudo python3 "$GUARDIAN_PATH" || error_handler "Final integrity check failed"

echo -e "${BLUE}================================================================${NC}"
echo -e "${GREEN}  NULLSEC RED TEAM AI: ULTIMATE SETUP COMPLETE${NC}"
echo -e "${BLUE}================================================================${NC}"
echo -e "${CYAN}Claude Desktop:${NC} Installed"
echo -e "${CYAN}HexStrike Port:${NC} $TARGET_PORT"
echo -e "${CYAN}Claude Config:${NC}  $CLAUDE_CONFIG_FILE"
echo -e "${CYAN}Lab Workspace:${NC}  $WORKSPACE"
echo -e "${CYAN}Guardian Tool:${NC}  $GUARDIAN_PATH"
echo -e "${BLUE}================================================================${NC}"
echo -e "${PURPLE}Next Steps:${NC}"
echo -e "1. Launch Claude Desktop from your application menu"
echo -e "2. Log in and verify HexStrike is green in MCP settings"
echo -e "3. Use Claude to launch attacks against your target VM"
echo -e "${BLUE}================================================================${NC}"
