#!/bin/bash
# ==============================================================================
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  NULLSEC RED TEAM AI — UNIFIED HARDENED INSTALLER v6.0                       ║
# ║  Stress-Tested on Kali 2024.3 • Debian 12 • Ubuntu 24.04                    ║
# ║  Architecture: x86_64 / ARM64                                               ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
# ==============================================================================

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────
INSTALL_DIR="/opt/nullsec"
VENV_PATH="$INSTALL_DIR/venv"
LOG_DIR="/var/log/nullsec"
LOG_FILE="$LOG_DIR/install.log"
WORKSPACE_DIR="NullSec_RedTeam_Lab"
API_TOKEN_FILE="/etc/nullsec/api_token"
CONFIG_DIR="/etc/nullsec"
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" 2>/dev/null | cut -d: -f6 || echo "$HOME")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Installation Modes ──────────────────────────────────────────────────────
MODE_FULL=false
MODE_CORE=false
MODE_DESKTOP=false
MODE_MCP=false
MODE_LAB=false
MODE_ELEVATED=false
DRY_RUN=false
STRESS_TEST=false

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'

# ─── Banner ──────────────────────────────────────────────────────────────────
print_banner() {
    echo -e "${CYAN}"
    cat <<"EOF"
    ███╗   ██╗██╗   ██╗██╗     ███████╗███████╗ ██████╗
    ████╗  ██║██║   ██║██║     ██╔════╝██╔════╝██╔════╝
    ██╔██╗ ██║██║   ██║██║     ███████╗█████╗  ██║     
    ██║╚██╗██║██║   ██║██║     ╚════██║██╔══╝  ██║     
    ██║ ╚████║╚██████╔╝███████╗███████║███████╗╚██████╗
    ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝
EOF
    echo -e "${MAGENTA}    RED TEAM AI PLATFORM v6.0 — AI-Powered Offensive Security${NC}"
    echo -e "${BLUE}    ─────────────────────────────────────────────────────────${NC}"
}

# ─── Logging ─────────────────────────────────────────────────────────────────
log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [+] $1"
    echo -e "${GREEN}${BOLD}[✓]${NC} ${GREEN}$1${NC}"
    [[ "$DRY_RUN" == false ]] && echo "$msg" >> "$LOG_FILE"
}

warn() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [!] $1"
    echo -e "${YELLOW}${BOLD}[!]${NC} ${YELLOW}$1${NC}"
    [[ "$DRY_RUN" == false ]] && echo "$msg" >> "$LOG_FILE"
}

error() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1"
    echo -e "${RED}${BOLD}[✗]${NC} ${RED}$1${NC}"
    [[ "$DRY_RUN" == false ]] && echo "$msg" >> "$LOG_FILE"
    exit 1
}

info() {
    echo -e "${BLUE}${BOLD}[i]${NC} ${BLUE}$1${NC}"
}

# ─── Pre-flight Checks ─────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root. Use: sudo $0 [options]"
    fi
}

check_python() {
    log "Checking Python 3.10+..."
    if ! command -v python3 &>/dev/null; then
        error "Python 3 not found. Install: apt install python3 python3-venv python3-pip"
    fi

    local py_version
    py_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    local major minor
    major=$(echo "$py_version" | cut -d. -f1)
    minor=$(echo "$py_version" | cut -d. -f2)

    if [[ "$major" -lt 3 ]] || [[ "$major" -eq 3 && "$minor" -lt 10 ]]; then
        error "Python $py_version detected. Python 3.10+ required."
    fi
    log "Python $py_version ✓"
}

check_nodejs() {
    log "Checking Node.js 18+..."
    if ! command -v node &>/dev/null; then
        warn "Node.js not found. Installing..."
        if [[ "$DRY_RUN" == false ]]; then
            apt-get update -qq
            apt-get install -y -qq nodejs npm 2>/dev/null || {
                warn "Standard install failed. Using NodeSource..."
                curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
                apt-get install -y nodejs
            }
        fi
    else
        local node_major
        node_major=$(node -v | sed 's/v//' | cut -d. -f1)
        if [[ "$node_major" -lt 18 ]]; then
            warn "Node.js v$(node -v) found. Upgrading to 20.x..."
            if [[ "$DRY_RUN" == false ]]; then
                curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
                apt-get install -y nodejs
            fi
        else
            log "Node.js v$(node -v) ✓"
        fi
    fi
}

check_git() {
    log "Checking Git..."
    if ! command -v git &>/dev/null; then
        warn "Git not found. Installing..."
        [[ "$DRY_RUN" == false ]] && apt-get update -qq && apt-get install -y -qq git
    fi
    log "Git ✓"
}

check_system_deps() {
    log "Installing system dependencies..."

    local deps=(
        ffmpeg curl git python3-pip python3-venv build-essential
        libavcodec-dev libavformat-dev libavutil-dev libswscale-dev
        nmap sqlmap gobuster dirsearch ffuf nikto hydra john hashcat
        rsync sqlite3 libsqlite3-dev openssl jq
    )

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY-RUN: Would install: ${deps[*]}"
        return
    fi

    apt-get update -y
    apt-get --fix-broken install -y

    local failed_deps=()
    for pkg in "${deps[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg "; then
            log "Installing $pkg..."
            apt-get install -y "$pkg" 2>/dev/null || {
                warn "Failed to install $pkg via apt"
                failed_deps+=("$pkg")
            }
        fi
    done

    # Fallback installs for missing packages
    if [[ ${#failed_deps[@]} -gt 0 ]]; then
        warn "Attempting fallback installs for: ${failed_deps[*]}"

        # dirsearch fallback
        if [[ " ${failed_deps[*]} " =~ " dirsearch " ]]; then
            python3 -m pip install dirsearch 2>/dev/null || warn "dirsearch pip fallback failed"
        fi

        # ffuf fallback (download binary)
        if [[ " ${failed_deps[*]} " =~ " ffuf " ]]; then
            local ffuf_url="https://github.com/ffuf/ffuf/releases/latest/download/ffuf_$(uname -s)_$(uname -m).tar.gz"
            curl -fsSL "$ffuf_url" 2>/dev/null | tar -xz -C /tmp/ 2>/dev/null
            [[ -f /tmp/ffuf ]] && mv /tmp/ffuf /usr/local/bin/ && chmod +x /usr/local/bin/ffuf
        fi
    fi
}

# ─── Environment Setup ───────────────────────────────────────────────────────
setup_env() {
    log "Setting up environment..."

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY-RUN: Would create: $INSTALL_DIR, $LOG_DIR, $CONFIG_DIR, $REAL_HOME/$WORKSPACE_DIR"
        return
    fi

    mkdir -p "$INSTALL_DIR" "$LOG_DIR" "$CONFIG_DIR" "$REAL_HOME/$WORKSPACE_DIR"
    touch "$LOG_FILE"
    chmod 755 "$LOG_DIR"
    chmod 600 "$LOG_FILE"
    chown "$REAL_USER:$REAL_USER" "$REAL_HOME/$WORKSPACE_DIR" 2>/dev/null || true

    # Generate secure API token
    if [[ ! -f "$API_TOKEN_FILE" ]]; then
        openssl rand -hex 32 > "$API_TOKEN_FILE"
        chmod 600 "$API_TOKEN_FILE"
        log "Generated API token at $API_TOKEN_FILE"
    fi

    # Create Python package __init__.py files
    for pkg in modules modules/brain modules/worker modules/payloads modules/frontend utils tests; do
        touch "$INSTALL_DIR/$pkg/__init__.py"
    done
}

# ─── Claude Desktop Installation ───────────────────────────────────────────
install_claude_desktop() {
    log "Installing Claude Desktop for Linux..."

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY-RUN: Would install Claude Desktop"
        return
    fi

    local temp_dir="/tmp/claude-desktop-install-$$"
    local install_success=false

    trap 'rm -rf "$temp_dir"' EXIT
    mkdir -p "$temp_dir"

    # PRIMARY: aaddrick's official Debian installer
    log "Attempting primary installer (aaddrick/claude-desktop-debian)..."
    if git clone --depth 1 https://github.com/aaddrick/claude-desktop-debian.git "$temp_dir/primary" 2>/dev/null; then
        cd "$temp_dir/primary"
        if chmod +x install.sh && ./install.sh 2>&1 | tee -a "$LOG_FILE"; then
            install_success=true
            log "Primary installer succeeded ✓"
        fi
        cd "$SCRIPT_DIR"
    fi

    # FALLBACK 1: Direct .deb download
    if [[ "$install_success" == false ]]; then
        log "Fallback 1: Downloading .deb package..."
        local deb_url="https://github.com/aaddrick/claude-desktop-debian/releases/latest/download/claude-desktop-amd64.deb"
        if curl -fsSL --max-time 30 "$deb_url" -o "$temp_dir/claude.deb" 2>/dev/null; then
            dpkg -i "$temp_dir/claude.deb" 2>/dev/null || apt-get install -f -y
            install_success=true
            log "Fallback .deb install succeeded ✓"
        fi
    fi

    # FALLBACK 2: npm global install
    if [[ "$install_success" == false ]]; then
        log "Fallback 2: npm install claude-desktop..."
        npm install -g claude-desktop 2>/dev/null && install_success=true
    fi

    # FALLBACK 3: Browser wrapper (always works)
    if [[ "$install_success" == false ]]; then
        warn "All native installers failed. Creating browser-based wrapper..."
        cat > /usr/local/bin/claude-desktop <<'WRAPPER'
#!/bin/bash
# NullSec Claude Desktop Fallback Wrapper
# Opens Claude.ai in a dedicated browser window

BROWSER=""
for candidate in chromium google-chrome-stable google-chrome firefox; do
    if command -v "$candidate" &>/dev/null; then
        BROWSER="$candidate"
        break
    fi
done

if [[ -z "$BROWSER" ]]; then
    echo "[ERROR] No supported browser found. Install Chromium or Firefox."
    exit 1
fi

echo "[NullSec] Launching Claude.ai via $BROWSER..."
"$BROWSER" --app=https://claude.ai --new-window --no-default-browser-check &>/dev/null &
WRAPPER
        chmod +x /usr/local/bin/claude-desktop
        log "Browser wrapper created at /usr/local/bin/claude-desktop ✓"
    fi

    # Ensure MCP config directory exists
    local mcp_dir="$REAL_HOME/.config/Claude"
    mkdir -p "$mcp_dir"
    chown -R "$REAL_USER:$REAL_USER" "$mcp_dir" 2>/dev/null || true
}

# ─── Core Installation ───────────────────────────────────────────────────────
install_hexstrike_core() {
    log "Installing HexStrike Core..."

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY-RUN: Would rsync $SCRIPT_DIR → $INSTALL_DIR"
        return
    fi

    # Backup existing installation
    if [[ -d "$INSTALL_DIR" && -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]]; then
        local backup_dir="$INSTALL_DIR.backup.$(date +%s)"
        log "Backing up existing install to $backup_dir..."
        cp -a "$INSTALL_DIR" "$backup_dir"
    fi

    # Safe rsync (NO --delete to prevent data loss)
    rsync -av --exclude='.git' --exclude='*.pyc' --exclude='__pycache__' \
          --exclude='venv' --exclude='.env' --exclude='*.backup.*' \
          "$SCRIPT_DIR/" "$INSTALL_DIR/"

    cd "$INSTALL_DIR"

    # Create virtual environment
    if [[ ! -d "$VENV_PATH" ]]; then
        python3 -m venv "$VENV_PATH"
    fi

    # Upgrade pip with retry
    local pip_ok=false
    for i in 1 2 3; do
        if "$VENV_PATH/bin/pip" install --upgrade pip setuptools wheel 2>&1 | tee -a "$LOG_FILE"; then
            pip_ok=true
            break
        fi
        warn "Pip upgrade attempt $i/3 failed. Retrying..."
        sleep 2
    done
    [[ "$pip_ok" == true ]] || error "Failed to upgrade pip after 3 attempts"

    # Install requirements with fallback
    for req_file in requirements.txt modules/brain/requirements.txt modules/payloads/requirements.txt; do
        if [[ -f "$req_file" ]]; then
            log "Installing from $req_file..."
            "$VENV_PATH/bin/pip" install -r "$req_file" 2>&1 | tee -a "$LOG_FILE" || \
                warn "Some packages from $req_file failed"
        fi
    done

    # Install package in editable mode
    if [[ -f "setup.py" ]]; then
        log "Installing NullSec package (editable)..."
        "$VENV_PATH/bin/pip" install -e . 2>&1 | tee -a "$LOG_FILE" || {
            warn "Editable install failed. Trying direct install..."
            "$VENV_PATH/bin/pip" install . 2>&1 | tee -a "$LOG_FILE" || \
                error "Package installation failed"
        }
    fi

    # Make entry points executable
    for script in hexstrike-server hexstrike-mcp guardian nullsec-worker ai-lab; do
        [[ -f "$VENV_PATH/bin/$script" ]] && chmod +x "$VENV_PATH/bin/$script"
    done

    cd "$SCRIPT_DIR"
}

# ─── MCP Configuration ───────────────────────────────────────────────────────
setup_mcp() {
    log "Configuring MCP Bridge..."

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY-RUN: Would configure MCP in Claude Desktop"
        return
    fi

    local mcp_config="$REAL_HOME/.config/Claude/claude_desktop_config.json"
    local api_token
    api_token=$(cat "$API_TOKEN_FILE" 2>/dev/null || echo "")

    # Merge with existing config or create new
    local new_config
    new_config=$(cat <<MCPJSON
{
    "mcpServers": {
        "nullsec-hexstrike": {
            "command": "$VENV_PATH/bin/python3",
            "args": ["$INSTALL_DIR/modules/brain/hexstrike_mcp.py"],
            "env": {
                "HEXSTRIKE_SERVER_URL": "http://localhost:8888",
                "API_TOKEN": "$api_token",
                "NULLSEC_LOG_DIR": "$LOG_DIR",
                "PYTHONPATH": "$INSTALL_DIR"
            }
        },
        "nullsec-ai-lab": {
            "command": "$VENV_PATH/bin/python3",
            "args": ["$INSTALL_DIR/modules/payloads/jailbreak_tester.py", "--mcp"],
            "env": {
                "NULLSEC_LOG_DIR": "$LOG_DIR",
                "PYTHONPATH": "$INSTALL_DIR"
            }
        }
    }
}
MCPJSON
)

    if [[ -f "$mcp_config" ]] && command -v jq &>/dev/null; then
        local existing
        existing=$(cat "$mcp_config")
        echo "$existing" | jq --argjson new "$new_config" '. * $new' > "$mcp_config.tmp"
        mv "$mcp_config.tmp" "$mcp_config"
    else
        echo "$new_config" > "$mcp_config"
    fi

    chmod 600 "$mcp_config"
    chown "$REAL_USER:$REAL_USER" "$mcp_config" 2>/dev/null || true
    log "MCP configuration written to $mcp_config ✓"
}

# ─── Systemd Services ────────────────────────────────────────────────────────
setup_persistence() {
    log "Setting up systemd services..."

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY-RUN: Would create systemd services"
        return
    fi

    # HexStrike Server Service
    cat > /etc/systemd/system/hexstrike.service <<EOF
[Unit]
Description=HexStrike AI Orchestration Server
Documentation=https://github.com/Panda1847/NullSec-RedTeam-AI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$VENV_PATH/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=PYTHONPATH=$INSTALL_DIR
Environment=NULLSEC_LOG_DIR=$LOG_DIR
Environment=NULLSEC_JOB_DIR=$INSTALL_DIR/jobs
EnvironmentFile=-$CONFIG_DIR/environment
ExecStart=$VENV_PATH/bin/python3 -m modules.brain.hexstrike_server --host 127.0.0.1 --port 8888
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
Restart=on-failure
RestartSec=10
StartLimitInterval=60s
StartLimitBurst=3
StandardOutput=append:$LOG_DIR/server.log
StandardError=append:$LOG_DIR/server.log
SyslogIdentifier=hexstrike

[Install]
WantedBy=multi-user.target
EOF

    # HexStrike Worker Service
    cat > /etc/systemd/system/hexstrike-worker.service <<EOF
[Unit]
Description=HexStrike Worker Service
Documentation=https://github.com/Panda1847/NullSec-RedTeam-AI
After=network.target hexstrike.service
Requires=hexstrike.service

[Service]
Type=simple
User=hexstrike
Group=hexstrike
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$VENV_PATH/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=PYTHONPATH=$INSTALL_DIR
Environment=NULLSEC_LOG_DIR=$LOG_DIR
Environment=NULLSEC_JOB_DIR=$INSTALL_DIR/jobs
Environment=CONTAINER_RUNTIME=docker
EnvironmentFile=-$CONFIG_DIR/environment
ExecStart=$VENV_PATH/bin/python3 -m modules.worker.worker
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
Restart=always
RestartSec=5
StartLimitInterval=60s
StartLimitBurst=5
MemoryMax=1G
CPUQuota=75%
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR $INSTALL_DIR/jobs
PrivateTmp=true
StandardOutput=append:$LOG_DIR/worker.log
StandardError=append:$LOG_DIR/worker.log
SyslogIdentifier=hexstrike-worker

[Install]
WantedBy=multi-user.target
EOF

    # Environment file
    cat > $CONFIG_DIR/environment <<EOF
API_TOKEN=$(cat "$API_TOKEN_FILE" 2>/dev/null || echo "")
HEXSTRIKE_SERVER_URL=http://localhost:8888
NULLSEC_LOG_DIR=$LOG_DIR
NULLSEC_JOB_DIR=$INSTALL_DIR/jobs
EOF
    chmod 600 $CONFIG_DIR/environment

    systemctl daemon-reload

    if [[ "$MODE_FULL" == true || "$MODE_CORE" == true ]]; then
        systemctl enable hexstrike.service
        systemctl enable hexstrike-worker.service
        log "Services enabled ✓"
    fi
}

# ─── Guardian Installation ───────────────────────────────────────────────────
install_guardian() {
    log "Installing Guardian diagnostic tool..."

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY-RUN: Would install guardian → /usr/local/bin/guardian"
        return
    fi

    cat > /usr/local/bin/guardian <<EOF
#!/bin/bash
export PYTHONPATH="$INSTALL_DIR:\$PYTHONPATH"
exec $VENV_PATH/bin/python3 $INSTALL_DIR/modules/brain/guardian.py "\$@"
EOF
    chmod +x /usr/local/bin/guardian
    log "Guardian installed at /usr/local/bin/guardian ✓"
}

# ─── User Provisioning ───────────────────────────────────────────────────────
provision_user() {
    log "Provisioning hexstrike user..."

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY-RUN: Would create hexstrike system user"
        return
    fi

    if ! id -u hexstrike &>/dev/null; then
        groupadd -f hexstrike
        useradd --system --create-home --home-dir /home/hexstrike \
                --shell /usr/sbin/nologin --gid hexstrike hexstrike
        log "Created hexstrike user ✓"
    else
        log "hexstrike user exists ✓"
    fi

    mkdir -p "$INSTALL_DIR/jobs" "$LOG_DIR"
    chown -R hexstrike:hexstrike "$INSTALL_DIR/jobs"
    chown -R hexstrike:hexstrike "$LOG_DIR"
    chmod 750 "$INSTALL_DIR"
    chmod 750 "$LOG_DIR"
    chmod 770 "$INSTALL_DIR/jobs"
}

# ─── AI Security Lab Deployment ──────────────────────────────────────────────
deploy_lab() {
    log "Deploying AI Security Lab..."

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY-RUN: Would deploy lab payloads"
        return
    fi

    local lab_dir="$INSTALL_DIR/lab"
    mkdir -p "$lab_dir"
    chmod +x "$INSTALL_DIR/modules/payloads/jailbreak_tester.py"
    cp -r "$INSTALL_DIR/modules/payloads" "$lab_dir/" 2>/dev/null || true
    log "AI Security Lab deployed to $lab_dir ✓"
}

# ─── Workspace Isolation ─────────────────────────────────────────────────────
setup_workspace() {
    local workspace="$REAL_HOME/$WORKSPACE_DIR"
    mkdir -p "$workspace"/{tools,reports,targets,logs,wordlists}
    chown -R "$REAL_USER:$REAL_USER" "$workspace"
    chmod 700 "$workspace"

    local config_file="$workspace/.nullsec"

    if [[ "$MODE_ELEVATED" == false ]]; then
        log "Workspace isolation: RESTRICTED mode"
        cat > "$config_file" <<EOF
[settings]
elevated=false
workspace=$workspace
allowed_paths=$workspace
max_concurrent_jobs=5
sandbox=true
EOF
    else
        warn "Workspace isolation: ELEVATED mode (full system access)"
        cat > "$config_file" <<EOF
[settings]
elevated=true
workspace=$workspace
allowed_paths=/
max_concurrent_jobs=10
sandbox=false
EOF
    fi
    chmod 600 "$config_file"
    log "Workspace configured at $workspace ✓"
}

# ─── Verification ────────────────────────────────────────────────────────────
verify_installation() {
    log "Running installation verification..."
    local issues=0

    [[ -d "$INSTALL_DIR" ]] || { warn "Install directory missing"; issues=$((issues+1)); }
    [[ -d "$VENV_PATH" ]] || { warn "Virtual environment missing"; issues=$((issues+1)); }
    [[ -f "$API_TOKEN_FILE" ]] || { warn "API token missing"; issues=$((issues+1)); }

    if [[ -f "$VENV_PATH/bin/python3" ]]; then
        for pkg in flask requests fastmcp; do
            "$VENV_PATH/bin/python3" -c "import $pkg" 2>/dev/null || \
                { warn "Package $pkg missing"; issues=$((issues+1)); }
        done
    fi

    for tool in nmap sqlmap gobuster ffuf nikto; do
        command -v "$tool" &>/dev/null || { warn "$tool not in PATH"; issues=$((issues+1)); }
    done

    if [[ "$MODE_FULL" == true || "$MODE_CORE" == true ]]; then
        if systemctl is-enabled hexstrike.service &>/dev/null; then
            log "hexstrike.service enabled ✓"
        else
            warn "hexstrike.service not enabled"
        fi
    fi

    if [[ $issues -eq 0 ]]; then
        log "✅ Installation verification PASSED"
    else
        warn "⚠️ $issues issue(s) found. Run: sudo guardian --repair"
    fi
}

# ─── Stress Test ─────────────────────────────────────────────────────────────
run_stress_test() {
    log "Running stress tests..."

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY-RUN: Would run stress tests"
        return
    fi

    systemctl start hexstrike.service 2>/dev/null || {
        warn "Could not start hexstrike for testing"
        return
    }
    sleep 3

    local api_token
    api_token=$(cat "$API_TOKEN_FILE" 2>/dev/null || echo "")

    # Health check
    if curl -fsS -H "Authorization: Bearer $api_token" \
         http://localhost:8888/health &>/dev/null; then
        log "API health check PASSED ✓"
    else
        warn "API health check FAILED"
    fi

    # Run Python test suite
    if [[ -f "$INSTALL_DIR/utils/stress_test.py" ]]; then
        cd "$INSTALL_DIR"
        "$VENV_PATH/bin/python3" utils/stress_test.py 2>&1 | tee -a "$LOG_FILE" || \
            warn "Stress tests had failures"
        cd "$SCRIPT_DIR"
    fi

    systemctl stop hexstrike.service 2>/dev/null || true
}

# ─── Usage ───────────────────────────────────────────────────────────────────
usage() {
    cat <<EOF
${CYAN}╔══════════════════════════════════════════════════════════════════╗
║  NullSec Red Team AI Installer v6.0                               ║
╚══════════════════════════════════════════════════════════════════╝${NC}

Usage: sudo $0 [OPTIONS]

${BOLD}Installation Modes:${NC}
    --full          Complete deployment (Core + Desktop + MCP + Lab)
    --core          Security tools + core services only
    --desktop       Install Claude Desktop for Linux
    --mcp           Configure MCP bridge in Claude Desktop
    --lab           Deploy AI Security Lab payloads
    --elevated      Enable full system access (OPSEC WARNING)

${BOLD}Options:${NC}
    --dry-run       Show planned changes without executing
    --stress-test   Run stress tests after installation
    --help, -h      Show this help message

${BOLD}Examples:${NC}
    sudo $0 --full --stress-test
    sudo $0 --core --lab --elevated
    sudo $0 --dry-run --full

${BOLD}Documentation:${NC} https://github.com/Panda1847/NullSec-RedTeam-AI
EOF
    exit 0
}

# ─── Parse Arguments ─────────────────────────────────────────────────────────
parse_args() {
    [[ $# -eq 0 ]] && MODE_FULL=true

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --full) MODE_FULL=true ;;
            --core) MODE_CORE=true ;;
            --desktop) MODE_DESKTOP=true ;;
            --mcp) MODE_MCP=true ;;
            --lab) MODE_LAB=true ;;
            --elevated) MODE_ELEVATED=true ;;
            --dry-run) DRY_RUN=true ;;
            --stress-test) STRESS_TEST=true ;;
            --help|-h) usage ;;
            *) warn "Unknown option: $1"; usage ;;
        esac
        shift
    done

    [[ "$MODE_FULL" == true ]] && { MODE_CORE=true; MODE_DESKTOP=true; MODE_MCP=true; MODE_LAB=true; }
}

# ─── Main ────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    print_banner

    log "Mode: FULL=$MODE_FULL CORE=$MODE_CORE DESKTOP=$MODE_DESKTOP MCP=$MODE_MCP LAB=$MODE_LAB"
    log "Elevated: $MODE_ELEVATED | Dry Run: $DRY_RUN"

    check_root
    check_python
    check_nodejs
    check_git
    check_system_deps
    setup_env
    install_hexstrike_core

    [[ "$MODE_DESKTOP" == true ]] && install_claude_desktop
    provision_user
    [[ "$MODE_MCP" == true ]] && setup_mcp
    setup_persistence
    install_guardian
    [[ "$MODE_LAB" == true ]] && deploy_lab
    setup_workspace
    verify_installation
    [[ "$STRESS_TEST" == true ]] && run_stress_test

    echo -e ""
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}${BOLD}║  INSTALLATION COMPLETE                                          ║${NC}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo -e ""
    log "Next steps:"
    info "  1. Start services:   sudo systemctl start hexstrike hexstrike-worker"
    info "  2. Check status:      sudo systemctl status hexstrike"
    info "  3. Run diagnostics:   sudo guardian --check"
    info "  4. Open Claude Desktop and verify MCP tools appear"
    info "  5. Run stress tests:  sudo $0 --stress-test"
    echo -e ""
    log "Documentation: https://github.com/Panda1847/NullSec-RedTeam-AI"
}

main "$@"
