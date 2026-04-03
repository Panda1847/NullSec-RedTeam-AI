#!/bin/bash

# ==============================================================================
# NULLSEC RED TEAM AI: OPTIMIZED INSTALLER (v3.0)
# ==============================================================================
# - Modular Installation: --core, --desktop, --mcp, --lab, --full
# - Security Hardened: Workspace-scoped by default, opt-in elevated access
# - Reproducible: Pinned NPX packages and dependency checks
# - Professional: Dry-run mode, robust configuration merging, and distro checks
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

# Pinned Versions
MCP_TERMINAL_VER="@dillip285/mcp-terminal@1.1.0"
MCP_FILESYSTEM_VER="@modelcontextprotocol/server-filesystem@0.6.0"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- State Variables ---
DRY_RUN=false
MODE="core"
ELEVATED_OPT_IN=false

# --- Logging ---
setup_logging() {
    if [ "$DRY_RUN" = false ]; then
        touch "$LOG_FILE"
        chmod 600 "$LOG_FILE"
        chown "$REAL_USER":"$REAL_USER" "$LOG_FILE" 2>/dev/null || true
    fi
}

log() { echo -e "${GREEN}[INSTALLER]${NC} $1" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; }

# --- Helpers ---
check_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        log "Detected OS: $NAME $VERSION_ID"
        if [[ ! "$ID" =~ ^(debian|kali|ubuntu)$ ]]; then
            warn "This script is optimized for Debian/Kali/Ubuntu. Proceed with caution on $ID."
        fi
    else
        warn "Could not determine distribution. Proceeding anyway..."
    fi
}

error_handler() {
    error "$1"
    if [ -f "$GUARDIAN_PATH" ]; then
        log "Guardian is available for diagnostics. Run 'guardian --diagnose' for details."
    fi
    exit 1
}

# --- Modes & Logic ---
usage() {
    echo "Usage: sudo ./install.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --core       Install core security tools only (Default)"
    echo "  --desktop    Install Claude Desktop"
    echo "  --mcp        Configure MCP servers in Claude Desktop"
    echo "  --lab        Install AI Security Lab payloads"
    echo "  --full       Install everything (Core + Desktop + MCP + Lab)"
    echo "  --elevated   Opt-in to elevated system access for Claude"
    echo "  --dry-run    Show what would be done without making changes"
    echo "  --help       Show this help message"
    exit 0
}

# Parse Arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --core) MODE="core"; shift ;;
        --desktop) MODE="desktop"; shift ;;
        --mcp) MODE="mcp"; shift ;;
        --lab) MODE="lab"; shift ;;
        --full) MODE="full"; shift ;;
        --elevated) ELEVATED_OPT_IN=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --help) usage ;;
        *) error "Unknown option: $1"; usage ;;
    esac
done

# --- Execution Phases ---

phase_system_check() {
    log "Phase 0: System Validation..."
    if [[ $EUID -ne 0 ]] && [ "$DRY_RUN" = false ]; then
        error "This script must be run as root (sudo)."
    fi
    check_distro
    
    FREE_SPACE=$(df -m / | awk 'NR==2 {print $4}')
    if [ "$FREE_SPACE" -lt 3000 ]; then
        warn "Low disk space ($FREE_SPACE MB). 3GB+ is recommended."
    fi
}

phase_core_tools() {
    log "Phase 1: Installing Core Security Arsenal..."
    CORE_DEPS=(
        git python3 python3-venv python3-pip python3-requests 
        nodejs npm curl lsof nmap masscan fierce dnsenum jq 
        gobuster dirsearch ffuf dirb nikto sqlmap wafw00f 
        hydra john hashcat medusa patator gdb binwalk 
        foremost steghide libimage-exiftool-perl
    )
    
    if [ "$DRY_RUN" = true ]; then
        log "[DRY-RUN] Would install: ${CORE_DEPS[*]}"
    else
        apt update -y && apt install -y "${CORE_DEPS[@]}" || warn "Some tools failed to install."
    fi
}

phase_claude_desktop() {
    log "Phase 2: Claude Desktop Setup..."
    if command -v claude-desktop &> /dev/null; then
        log "Claude Desktop already installed."
    else
        if [ "$DRY_RUN" = true ]; then
            log "[DRY-RUN] Would install Claude Desktop via aaddrick's repo."
        else
            curl -fsSL https://aaddrick.github.io/claude-desktop-debian/KEY.gpg -o /tmp/claude-desktop.gpg
            gpg --dearmor -f -o /usr/share/keyrings/claude-desktop.gpg /tmp/claude-desktop.gpg
            echo "deb [signed-by=/usr/share/keyrings/claude-desktop.gpg arch=amd64,arm64] https://aaddrick.github.io/claude-desktop-debian stable main" | tee /etc/apt/sources.list.d/claude-desktop.list
            apt update -y && apt install -y claude-desktop || warn "Claude Desktop install failed."
        fi
    fi
}

phase_hexstrike_deploy() {
    log "Phase 3: HexStrike AI Deployment..."
    if [ "$DRY_RUN" = true ]; then
        log "[DRY-RUN] Would deploy HexStrike to $INSTALL_DIR_HEX and setup venv."
    else
        mkdir -p "$INSTALL_DIR_HEX"
        cp -r "$SCRIPT_DIR/modules/brain/"* "$INSTALL_DIR_HEX/"
        mkdir -p "$INSTALL_DIR_HEX/utils"
        cp "$SCRIPT_DIR/utils/core.py" "$INSTALL_DIR_HEX/utils/"
        touch "$INSTALL_DIR_HEX/utils/__init__.py"
        
        cd "$INSTALL_DIR_HEX"
        python3 -m venv venv
        ./venv/bin/pip install --upgrade pip
        ./venv/bin/pip install -r requirements.txt || error_handler "HexStrike deps failed."
    fi
}

phase_mcp_config() {
    log "Phase 4: Claude MCP Orchestration..."
    TARGET_PORT=8888
    while lsof -Pi :$TARGET_PORT -sTCP:LISTEN -t >/dev/null ; do TARGET_PORT=$((TARGET_PORT + 1)); done
    
    if [ "$DRY_RUN" = true ]; then
        log "[DRY-RUN] Would configure Claude MCP at $CLAUDE_CONFIG_FILE"
        log "[DRY-RUN] Using pinned packages: $MCP_TERMINAL_VER, $MCP_FILESYSTEM_VER"
        return
    fi

    mkdir -p "$CLAUDE_CONFIG_DIR"
    mkdir -p "$WORKSPACE"
    chown -R "$REAL_USER":"$REAL_USER" "$WORKSPACE"

    # Initialize config if missing
    if [ ! -f "$CLAUDE_CONFIG_FILE" ] || [ ! -s "$CLAUDE_CONFIG_FILE" ]; then
        echo '{"mcpServers": {}}' > "$CLAUDE_CONFIG_FILE"
    fi

    # Robust JQ Merge
    jq --arg hex_cmd "$INSTALL_DIR_HEX/venv/bin/python3" \
       --arg hex_script "$INSTALL_DIR_HEX/hexstrike_mcp.py" \
       --arg hex_url "http://localhost:$TARGET_PORT" \
       --arg workspace "$WORKSPACE" \
       --arg term_pkg "$MCP_TERMINAL_VER" \
       --arg fs_pkg "$MCP_FILESYSTEM_VER" \
       '.mcpServers.hexstrike = {"command": $hex_cmd, "args": [$hex_script, "--server", $hex_url], "description": "HexStrike AI Offensive Toolkit", "timeout": 3600} | 
        .mcpServers.terminal = {"command": "npx", "args": ["-y", $term_pkg, "--allowed-paths", $workspace], "description": "Workspace Terminal Access"} |
        .mcpServers.filesystem = {"command": "npx", "args": ["-y", $fs_pkg, $workspace], "description": "Red Team Lab Workspace"}' \
        "$CLAUDE_CONFIG_FILE" > "$CLAUDE_CONFIG_FILE.tmp" && mv "$CLAUDE_CONFIG_FILE.tmp" "$CLAUDE_CONFIG_FILE"

    if [ "$ELEVATED_OPT_IN" = true ]; then
        log "Applying elevated access (Full System Terminal)..."
        jq --arg term_pkg "$MCP_TERMINAL_VER" \
           '.mcpServers.terminal.args = ["-y", $term_pkg, "--allowed-paths", "/"]' \
           "$CLAUDE_CONFIG_FILE" > "$CLAUDE_CONFIG_FILE.tmp" && mv "$CLAUDE_CONFIG_FILE.tmp" "$CLAUDE_CONFIG_FILE"
    fi

    chown "$REAL_USER":"$REAL_USER" "$CLAUDE_CONFIG_FILE"
}

phase_systemd() {
    log "Phase 5: Systemd Service Activation..."
    if [ "$DRY_RUN" = true ]; then
        log "[DRY-RUN] Would create and start hexstrike.service"
        return
    fi

    # Pre-checks
    if [ ! -f "$INSTALL_DIR_HEX/hexstrike_server.py" ] || [ ! -d "$INSTALL_DIR_HEX/venv" ]; then
        error_handler "HexStrike deployment incomplete. Cannot start service."
    fi

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
}

phase_guardian_deploy() {
    log "Phase 6: Deploying Guardian Diagnostic Tool..."
    if [ "$DRY_RUN" = true ]; then
        log "[DRY-RUN] Would deploy guardian.py to $GUARDIAN_PATH"
    else
        cp "$SCRIPT_DIR/modules/brain/guardian.py" "$GUARDIAN_PATH"
        chmod +x "$GUARDIAN_PATH"
        mkdir -p /usr/local/bin/utils
        cp "$SCRIPT_DIR/utils/core.py" /usr/local/bin/utils/
        touch /usr/local/bin/utils/__init__.py
    fi
}

# --- Main Execution ---
setup_logging
phase_system_check

case $MODE in
    core)
        phase_core_tools
        ;;
    desktop)
        phase_claude_desktop
        ;;
    mcp)
        phase_hexstrike_deploy
        phase_mcp_config
        phase_systemd
        ;;
    lab)
        log "Phase: AI Security Lab Deployment..."
        if [ "$DRY_RUN" = false ]; then
            mkdir -p "$INSTALL_DIR_LAB"
            cp -r "$SCRIPT_DIR/modules/payloads/"* "$INSTALL_DIR_LAB/"
            cd "$INSTALL_DIR_LAB" && python3 -m venv venv
            ./venv/bin/pip install requests flask
        else
            log "[DRY-RUN] Would deploy Lab payloads to $INSTALL_DIR_LAB"
        fi
        ;;
    full)
        phase_core_tools
        phase_claude_desktop
        phase_hexstrike_deploy
        phase_mcp_config
        phase_systemd
        phase_guardian_deploy
        ;;
esac

log "Installation process finished."
if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}Dry-run complete. No changes were made.${NC}"
else
    echo -e "${GREEN}Setup complete. Mode: $MODE${NC}"
fi
