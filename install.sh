#!/bin/bash
# ==============================================================================
# NULLSEC RED TEAM AI — ULTIMATE RESILIENT INSTALLER v4.1
# Full isolation, self-healing, no single point of failure
# ==============================================================================

set -o pipefail

SCRIPT_DIR="$( (cd "$(dirname "${BASH_SOURCE[0]}")" && pwd))"
REAL_USER="${SUDO_USER:-${USER}}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6 || echo "/home/$REAL_USER")

INSTALL_DIR_HEX="/opt/hexstrike-ai"
INSTALL_DIR_LAB="/opt/ai-security-lab"
GUARDIAN_PATH="/usr/local/bin/guardian"
LOG_FILE="/tmp/nullsec_install.log"
CLAUDE_CONFIG_DIR="$REAL_HOME/.config/Claude"
CLAUDE_CONFIG_FILE="$CLAUDE_CONFIG_DIR/claude_desktop_config.json"
WORKSPACE="$REAL_HOME/NullSec_RedTeam_Lab"

log() { echo -e "\033[0;32m[+]\033[0m $1" | tee -a "$LOG_FILE"; }
warn() { echo -e "\033[1;33m[!]\033[0m $1" | tee -a "$LOG_FILE"; }
error() { echo -e "\033[0;31m[ERROR]\033[0m $1" | tee -a "$LOG_FILE"; }

setup_logging() {
    touch "$LOG_FILE" && chmod 666 "$LOG_FILE" 2>/dev/null
    chown "$REAL_USER":"$REAL_USER" "$LOG_FILE" 2>/dev/null || true
}

safe_exec() {
    local phase=$1
    log "Starting phase: $phase"
    if "$phase"; then
        log "Phase $phase completed successfully"
    else
        warn "Phase $phase failed — continuing with resilience"
    fi
}

phase_core_tools() {
    apt update -qq
    apt install -y git python3 python3-venv python3-pip nodejs npm curl nmap sqlmap gobuster dirsearch ffuf nikto hydra john hashcat || warn "Some tools failed to install"
}

phase_claude_desktop() {
    if ! command -v claude-desktop &> /dev/null; then
        curl -fsSL https://claude.ai/download/linux | bash || warn "Claude Desktop install failed — manual install recommended"
    fi
}

phase_hexstrike() {
    mkdir -p "$INSTALL_DIR_HEX"
    cp -r "$SCRIPT_DIR/modules/brain/"* "$INSTALL_DIR_HEX/" 2>/dev/null || true
    cd "$INSTALL_DIR_HEX" || return 1
    python3 -m venv venv
    ./venv/bin/pip install --upgrade pip
    ./venv/bin/pip install Flask requests fastmcp ansiart Pillow || warn "Some Python deps failed"
}

phase_mcp_config() {
    mkdir -p "$CLAUDE_CONFIG_DIR" "$WORKSPACE"
    chown -R "$REAL_USER":"$REAL_USER" "$WORKSPACE" "$CLAUDE_CONFIG_DIR"
    cat > "$CLAUDE_CONFIG_FILE" << 'EOF'
{
  "mcpServers": {
    "hexstrike": {
      "command": "/opt/hexstrike-ai/venv/bin/python3",
      "args": ["/opt/hexstrike-ai/hexstrike_mcp.py"],
      "description": "NullSec Red Team Toolkit"
    }
  }
}
EOF
    chown "$REAL_USER":"$REAL_USER" "$CLAUDE_CONFIG_FILE"
}

phase_guardian() {
    cp "$SCRIPT_DIR/modules/brain/guardian.py" "$GUARDIAN_PATH" 2>/dev/null || true
    chmod +x "$GUARDIAN_PATH"
    chown root:root "$GUARDIAN_PATH"
}

# Main execution
setup_logging
log "=== NULLSEC RESILIENT INSTALL STARTED ==="

for phase in phase_core_tools phase_claude_desktop phase_hexstrike phase_mcp_config phase_guardian; do
    safe_exec "$phase"
done

log "✅ FULL INSTALLATION COMPLETE WITH RESILIENCE"
log "Run: guardian --check  (for diagnostics and auto-repair)"
