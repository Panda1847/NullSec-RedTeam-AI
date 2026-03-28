#!/bin/bash

# ==============================================================================
# NULLSEC RED TEAM AI: ULTIMATE ALL-IN-ONE INSTALLER (v2.1)
# ==============================================================================
# - Installs Claude Desktop (via claude-desktop-debian)
# - Installs HexStrike AI (150+ tools)
# - Installs AI Security Lab (Jailbreaks & LLM Vulns)
# - Configures Claude Desktop with full MCP integration
# - Deploys Advanced Guardian Diagnostic & Repair Tool
# - Full Sudo & System Access for Claude
# - Optimized for Kali Linux & Debian Systems
# - Self-Healing Logic & BlackArch Pacman Animations
# ==============================================================================

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
    if [ -f "$GUARDIAN_PATH" ]; then
        sudo python3 "$GUARDIAN_PATH" "$1"
    else
        log "Guardian not yet deployed. Manual intervention required."
    fi
    exit 1
}

# --- 1. Advanced Guardian Tool Deployment ---
deploy_guardian() {
    log "Deploying Advanced Guardian Diagnostic & Repair Tool..."
    if [ -f "$SCRIPT_DIR/modules/brain/guardian.py" ]; then
        cp "$SCRIPT_DIR/modules/brain/guardian.py" "$GUARDIAN_PATH"
        chmod +x "$GUARDIAN_PATH"
    else
        error_handler "guardian.py not found in $SCRIPT_DIR/modules/brain/"
    fi
    
    # Ensure utils directory exists for guardian
    mkdir -p /usr/local/bin/utils
    if [ -f "$SCRIPT_DIR/utils/core.py" ]; then
        cp "$SCRIPT_DIR/utils/core.py" /usr/local/bin/utils/
        touch /usr/local/bin/utils/__init__.py
    else
        error_handler "core.py not found in $SCRIPT_DIR/utils/"
    fi
}

# --- 2. Main Installation ---

log "Starting NullSec Red Team AI Installation (v2.1)..."

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
apt update -y || warn "Apt update had some issues, but continuing..."

if ! command -v curl &> /dev/null || ! command -v gpg &> /dev/null; then
    apt install -y curl gnupg || error_handler "Failed to install curl or gnupg."
fi

# Install Claude Desktop
if command -v claude-desktop &> /dev/null; then
    log "Claude Desktop is already installed. Skipping download."
else
    log "Installing Claude Desktop for Linux..."
    curl -fsSL https://aaddrick.github.io/claude-desktop-debian/KEY.gpg -o /tmp/claude-desktop.gpg
    gpg --dearmor -f -o /usr/share/keyrings/claude-desktop.gpg /tmp/claude-desktop.gpg
    echo "deb [signed-by=/usr/share/keyrings/claude-desktop.gpg arch=amd64,arm64] https://aaddrick.github.io/claude-desktop-debian stable main" | tee /etc/apt/sources.list.d/claude-desktop.list
    apt update -y
    apt install -y claude-desktop || warn "Claude Desktop installation failed. You may need to install it manually."
fi

# Core Security Arsenal
CORE_DEPS=(
    git python3 python3-venv python3-pip python3-requests 
    nodejs npm curl lsof nmap masscan fierce dnsenum jq 
    gobuster dirsearch ffuf dirb nikto sqlmap wafw00f 
    hydra john hashcat medusa patator gdb binwalk 
    foremost steghide libimage-exiftool-perl
)

log "Installing ${#CORE_DEPS[@]} core security tools..."
apt install -y "${CORE_DEPS[@]}" || warn "Some core tools failed to install. Continuing..."

log "Phase 2: HexStrike AI Deployment..."
if [ -d "$INSTALL_DIR_HEX" ]; then
    log "HexStrike AI is already installed in $INSTALL_DIR_HEX. Updating files..."
else
    mkdir -p "$INSTALL_DIR_HEX"
fi

# Copy from modules/brain (mapped to hexstrike-ai)
cp -r "$SCRIPT_DIR/modules/brain/"* "$INSTALL_DIR_HEX/"
mkdir -p "$INSTALL_DIR_HEX/utils"
cp "$SCRIPT_DIR/utils/core.py" "$INSTALL_DIR_HEX/utils/"
touch "$INSTALL_DIR_HEX/utils/__init__.py"

cd "$INSTALL_DIR_HEX"
if [ ! -d "venv" ]; then
    python3 -m venv venv || error_handler "Failed to create HexStrike venv."
fi
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt || error_handler "HexStrike Python deps failed"

log "Phase 3: AI Security Lab Deployment..."
if [ -d "$INSTALL_DIR_LAB" ]; then
    log "AI Security Lab is already installed in $INSTALL_DIR_LAB. Updating files..."
else
    mkdir -p "$INSTALL_DIR_LAB"
fi

# Copy from modules/payloads (mapped to ai-security-lab)
cp -r "$SCRIPT_DIR/modules/payloads/"* "$INSTALL_DIR_LAB/"
mkdir -p "$INSTALL_DIR_LAB/utils"
cp "$SCRIPT_DIR/utils/core.py" "$INSTALL_DIR_LAB/utils/"
touch "$INSTALL_DIR_LAB/utils/__init__.py"

cd "$INSTALL_DIR_LAB"
if [ ! -d "venv" ]; then
    python3 -m venv venv || error_handler "Failed to create AI Security Lab venv."
fi
./venv/bin/pip install --upgrade pip
# Check if requirements.txt exists in payloads, if not create a basic one or skip
if [ -f "requirements.txt" ]; then
    ./venv/bin/pip install -r requirements.txt || warn "AI Security Lab core deps failed."
else
    ./venv/bin/pip install requests flask || warn "AI Security Lab basic deps failed."
fi

log "Phase 4: Claude Desktop MCP Orchestration..."
TARGET_PORT=8888
while lsof -Pi :$TARGET_PORT -sTCP:LISTEN -t >/dev/null ; do TARGET_PORT=$((TARGET_PORT + 1)); done

mkdir -p "$CLAUDE_CONFIG_DIR"
# Merge or create config
if [ -f "$CLAUDE_CONFIG_FILE" ]; then
    log "Existing Claude config found. Merging settings..."
    # Simple merge logic using jq if available
    if command -v jq &> /dev/null; then
        jq --arg hex_cmd "$INSTALL_DIR_HEX/venv/bin/python3" \
           --arg hex_script "$INSTALL_DIR_HEX/hexstrike_mcp.py" \
           --arg hex_url "http://localhost:$TARGET_PORT" \
           --arg lab_cmd "$INSTALL_DIR_LAB/venv/bin/python3" \
           --arg lab_script "$INSTALL_DIR_LAB/jailbreak_tester.py" \
           --arg workspace "$WORKSPACE" \
           '.mcpServers.hexstrike = {"command": $hex_cmd, "args": [$hex_script, "--server", $hex_url], "description": "HexStrike AI Offensive Security Toolkit (150+ tools)", "timeout": 3600} | 
            .mcpServers["ai-security-lab"] = {"command": $lab_cmd, "args": [$lab_script, "--mcp"], "description": "AI Security Lab - Jailbreaks & LLM Vulnerability Scanner"} |
            .mcpServers.terminal = {"command": "npx", "args": ["-y", "@dillip285/mcp-terminal", "--allowed-paths", "/"], "description": "Full System Terminal Access"} |
            .mcpServers.filesystem = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", $workspace], "description": "Red Team Lab Workspace"}' \
            "$CLAUDE_CONFIG_FILE" > "$CLAUDE_CONFIG_FILE.tmp" && mv "$CLAUDE_CONFIG_FILE.tmp" "$CLAUDE_CONFIG_FILE"
    else
        # Fallback to overwrite if jq fails
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
      "args": ["$INSTALL_DIR_LAB/jailbreak_tester.py", "--mcp"],
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
    }
  }
}
EOF
    fi
else
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
      "args": ["$INSTALL_DIR_LAB/jailbreak_tester.py", "--mcp"],
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
    }
  }
}
EOF
fi
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
echo -e "${GREEN}  NULLSEC RED TEAM AI: ULTIMATE SETUP COMPLETE (v2.1)${NC}"
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
