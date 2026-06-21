#!/bin/bash
# ==============================================================================
# NULLSEC RED TEAM AI — UNIFIED HARDENED INSTALLER v5.0
# ==============================================================================

set -euo pipefail

# Constants
INSTALL_DIR="/opt/nullsec"
VENV_PATH="$INSTALL_DIR/venv"
LOG_DIR="/var/log/nullsec"
LOG_FILE="$LOG_DIR/install.log"
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6 || echo "/home/$REAL_USER")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE" >&2; exit 1; }

# Check for root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (sudo)"
fi

setup_env() {
    mkdir -p "$INSTALL_DIR" "$LOG_DIR"
    touch "$LOG_FILE"
    chmod 755 "$LOG_DIR"
    chmod 600 "$LOG_FILE"
}

fix_system_deps() {
    log "Fixing system dependencies and broken packages..."
    apt-get update -y
    apt-get --fix-broken install -y
    apt-get install -y ffmpeg curl git python3-pip python3-venv build-essential \
        libavcodec-dev libavformat-dev libavutil-dev libswscale-dev \
        nmap sqlmap gobuster dirsearch ffuf nikto hydra john hashcat rsync
}

install_claude_desktop() {
    log "Installing Claude Desktop (Debian/Linux)..."
    local temp_dir="/tmp/claude-desktop-install"
    rm -rf "$temp_dir"
    git clone https://github.com/aaddrick/claude-desktop-debian.git "$temp_dir"
    cd "$temp_dir"
    chmod +x install.sh
    ./install.sh || warn "Claude Desktop install had issues - check logs"
    cd -
}

install_hexstrike_core() {
    log "Installing HexStrike Core..."
    # Use rsync to preserve permissions and avoid copying .git
    rsync -a --delete --exclude='.git' ./ "$INSTALL_DIR/"
    cd "$INSTALL_DIR"
    
    python3 -m venv "$VENV_PATH"
    "$VENV_PATH/bin/pip" install --upgrade pip
    "$VENV_PATH/bin/pip" install -e .
}

setup_persistence() {
    log "Setting up systemd persistence..."
    
    cat > /etc/systemd/system/hexstrike.service <<EOF
[Unit]
Description=HexStrike AI Orchestration Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_PATH/bin/python3 modules/brain/hexstrike_server.py
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/server.log
StandardError=append:$LOG_DIR/server.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable hexstrike
    systemctl start hexstrike
}

configure_mcp() {
    log "Configuring Claude Desktop MCP bridge..."
    local config_dir="$REAL_HOME/.config/Claude"
    local config_file="$config_dir/claude_desktop_config.json"
    
    mkdir -p "$config_dir"
    
    # Use jq to merge if exists, otherwise create
    if [[ -f "$config_file" ]]; then
        # Simple backup
        cp "$config_file" "${config_file}.bak"
    fi

    cat > "$config_file" <<EOF
{
  "mcpServers": {
    "nullsec": {
      "command": "$VENV_PATH/bin/python3",
      "args": ["$INSTALL_DIR/modules/brain/hexstrike_mcp.py"],
      "env": {
        "HEXSTRIKE_SERVER_URL": "http://localhost:8888"
      }
    }
  }
}
EOF
    chown -R "$REAL_USER":"$REAL_USER" "$config_dir"
}

main() {
    setup_env
    log "=== NULLSEC RED TEAM AI HARDENED INSTALLER STARTED ==="
    fix_system_deps
    install_claude_desktop
    install_hexstrike_core
    setup_persistence
    configure_mcp
    log "✅ INSTALLATION COMPLETE"
    log "Logs available at: $LOG_FILE"
    log "HexStrike Server is running via systemd"
}

main "$@"
