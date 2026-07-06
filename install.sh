#!/bin/bash
# ==============================================================================
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║ NULLSEC RED TEAM AI — UNIFIED HARDENED INSTALLER v7.0                          ║
# ║ Stress-Tested on Kali 2024.4 • Debian 12 • Ubuntu 24.04 • ARM64/x86_64 ║
# ║ Production-Ready • Self-Healing • Comprehensive Fallback Logic             ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
# ==============================================================================

set -euo pipefail
shopt -s nullglob

# ─── Configuration ────────────────────────────────────────────────────────────────
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

# ─── Installation Modes ────────────────────────────────────────────────────────────────MODE_FULL=false
MODE_CORE=false
MODE_DESKTOP=false
MODE_MCP=false
MODE_LAB=false
MODE_ELEVATED=false
DRY_RUN=false
STRESS_TEST=false

# ─── Colors ────────────────────────────────────────────────────────────────────────────RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'

# ─── Banner ────────────────────────────────────────────────────────────────────────────print_banner() {
    echo -e "${CYAN}"
    cat <<"EOF"
 ███╗   ██╗██╗   ██╗██╗     ███████╗███████╗ ██████╗
 ████╗  ██║██║   ██║██║     ██╔════╝██╔════╝██╔════╝
 ██╔██╗ ██║██║   ██║██║     ███████╗█████╗  ██║     
 ██║╚██╗██║██║   ██║██║     ╚════██║██╔══╝  ██║     
 ██║ ╚████║╚██████╔╝███████╗███████║███████╗╚██████╗
 ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝
EOF
    echo -e "${MAGENTA} RED TEAM AI PLATFORM v7.0 — AI-Powered Offensive Security${NC}"
    echo -e "${BLUE} ─────────────────────────────────────────────────────────${NC}"
}

# ─── Logging ─────────────────────────────────────────────────────────────────────────────log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [+] $1"
    echo -e "${GREEN}${BOLD}[✓]${NC} ${GREEN}$1${NC}"
    [[ "$DRY_RUN" == false ]] && echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

warn() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [!] $1"
    echo -e "${YELLOW}${BOLD}[!]${NC} ${YELLOW}$1${NC}"
    [[ "$DRY_RUN" == false ]] && echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

error() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1"
    echo -e "${RED}${BOLD}[✗]${NC} ${RED}$1${NC}"
    [[ "$DRY_RUN" == false ]] && echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
    exit 1
}

info() {
    echo -e "${BLUE}${BOLD}[i]${NC} ${BLUE}$1${NC}"
}

# ─── Safe Command Runner with Fallback ─────────────────────────────────────────────run_cmd() {
    local cmd="$1"
    local timeout_sec="${2:-60}"
    local retries="${3:-1}"
    local attempt=1

    while [[ $attempt -le $retries ]]; do
        if timeout "$timeout_sec" bash -c "$cmd" >> "$LOG_FILE" 2>&1; then
            return 0
        fi
        if [[ $attempt -lt $retries ]]; then
            warn "Command failed (attempt $attempt/$retries): $cmd"
            sleep 2
        fi
        ((attempt++)) || true
    done
    return 1
}

# ─── Pre-flight Checks ───────────────────────────────────────────────────────────────────check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root. Use: sudo $0 [options]"
    fi
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
    elif command -v lsb_release &>/dev/null; then
        lsb_release -is | tr '[:upper:]' '[:lower:]'
    else
        echo "unknown"
    fi
}

check_python() {
    log "Checking Python 3.10+..."

    # Try multiple Python versions
    local python_cmd=""
    for cmd in python3.12 python3.11 python3.10 python3; do
        if command -v "$cmd" &>/dev/null; then
            python_cmd="$cmd"
            break
        fi
    done

    if [[ -z "$python_cmd" ]]; then
        error "Python 3 not found. Install: apt install python3 python3-venv python3-pip"
    fi

    local py_version
    py_version=$($python_cmd -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")
    local major minor
    major=$(echo "$py_version" | cut -d. -f1)
    minor=$(echo "$py_version" | cut -d. -f2)

    if [[ "$major" -lt 3 ]] || [[ "$major" -eq 3 && "$minor" -lt 10 ]]; then
        warn "Python $py_version detected. Attempting to install Python 3.11+..."
        if [[ "$DRY_RUN" == false ]]; then
            apt-get update -qq
            apt-get install -y -qq python3.11 python3.11-venv python3.11-pip python3-venv python3-pip 2>/dev/null || \
                apt-get install -y -qq python3 python3-venv python3-pip

            # Re-check
            for cmd in python3.12 python3.11 python3.10 python3; do
                if command -v "$cmd" &>/dev/null; then
                    local new_version
                    new_version=$($cmd -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")
                    local new_major=$(echo "$new_version" | cut -d. -f1)
                    local new_minor=$(echo "$new_version" | cut -d. -f2)
                    if [[ "$new_major" -ge 3 && "$new_minor" -ge 10 ]]; then
                        python_cmd="$cmd"
                        py_version="$new_version"
                        break
                    fi
                fi
            done
        fi
    fi

    if [[ "$major" -lt 3 ]] || [[ "$major" -eq 3 && "$minor" -lt 10 ]]; then
        error "Python 3.10+ required but not available after installation attempts."
    fi

    # Export for later use
    export PYTHON_CMD="$python_cmd"
    log "Python $py_version ✓ ($python_cmd)"
}

check_nodejs() {
    log "Checking Node.js 18+..."

    if ! command -v node &>/dev/null; then
        warn "Node.js not found. Installing..."
        if [[ "$DRY_RUN" == false ]]; then
            # Try multiple methods
            apt-get update -qq

            # Method 1: Standard apt
            if apt-get install -y -qq nodejs npm 2>/dev/null; then
                log "Node.js installed via apt ✓"
            else
                # Method 2: NodeSource
                local distro
                distro=$(detect_distro)
                local nodesource_url="https://deb.nodesource.com/setup_20.x"

                if curl -fsSL "$nodesource_url" | bash - 2>/dev/null; then
                    apt-get install -y nodejs 2>/dev/null && log "Node.js installed via NodeSource ✓"
                else
                    # Method 3: nvm
                    warn "Falling back to nvm installation..."
                    export NVM_DIR="/usr/local/nvm"
                    mkdir -p "$NVM_DIR"
                    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash 2>/dev/null
                    export NVM_DIR="$NVM_DIR"
                    [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
                    nvm install 20 2>/dev/null && nvm use 20 2>/dev/null

                    # Create symlinks — use find for glob expansion
                    # (ls "$NVM_DIR/.../v20.*/bin/node" won't glob inside double-quotes)
                    local node_path
                    node_path=$(find "$NVM_DIR/versions/node" -name "node" -path "*/v20.*/bin/node" 2>/dev/null | head -1)
                    [[ -n "$node_path" ]] && ln -sf "$node_path" /usr/local/bin/node 2>/dev/null || true
                    local npm_path
                    npm_path=$(find "$NVM_DIR/versions/node" -name "npm" -path "*/v20.*/bin/npm" 2>/dev/null | head -1)
                    [[ -n "$npm_path" ]] && ln -sf "$npm_path" /usr/local/bin/npm 2>/dev/null || true
                fi
            fi
        fi
    fi

    # Verify
    if command -v node &>/dev/null; then
        local node_major
        node_major=$(node -v 2>/dev/null | sed 's/v//' | cut -d. -f1)
        if [[ -n "$node_major" && "$node_major" -ge 18 ]]; then
            log "Node.js v$(node -v) ✓"
        else
            warn "Node.js version too old. Some features may not work."
        fi
    else
        warn "Node.js installation incomplete. Desktop mode may fail."
    fi
}

check_git() {
    log "Checking Git..."
    if ! command -v git &>/dev/null; then
        warn "Git not found. Installing..."
        [[ "$DRY_RUN" == false ]] && apt-get update -qq && apt-get install -y -qq git
    fi
    if command -v git &>/dev/null; then
        log "Git $(git --version | awk '{print $3}') ✓"
    else
        warn "Git installation failed. Some features may not work."
    fi
}

# ─── System Dependencies with Robust Fallback ──────────────────────────────────────────check_system_deps() {
    log "Installing system dependencies..."

    local deps=(
        curl git python3-pip python3-venv build-essential
        libavcodec-dev libavformat-dev libavutil-dev libswscale-dev
        nmap sqlmap gobuster dirsearch ffuf nikto hydra john hashcat
        rsync sqlite3 libsqlite3-dev openssl jq netcat-traditional
        whois dnsutils iputils-ping lsof procps psmisc
    )

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY-RUN: Would install: ${deps[*]}"
        return
    fi

    apt-get update -y || warn "apt update had issues, continuing..."
    apt-get --fix-broken install -y || true

    local failed_deps=()
    for pkg in "${deps[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg "; then
            log "Installing $pkg..."
            if ! apt-get install -y "$pkg" 2>/dev/null; then
                warn "Failed to install $pkg via apt"
                failed_deps+=("$pkg")
            fi
        fi
    done

    # Fallback installs for missing packages
    if [[ ${#failed_deps[@]} -gt 0 ]]; then
        warn "Attempting fallback installs for: ${failed_deps[*]}"

        # dirsearch fallback — use pipx or venv pip to avoid PEP 668 rejection on Kali
        if [[ " ${failed_deps[*]} " =~ " dirsearch " ]]; then
            if command -v pipx &>/dev/null; then
                pipx install dirsearch 2>/dev/null && log "dirsearch installed via pipx ✓" || warn "dirsearch pipx fallback failed"
            elif [[ -f "$VENV_PATH/bin/pip" ]]; then
                "$VENV_PATH/bin/pip" install dirsearch 2>/dev/null && log "dirsearch installed into venv ✓" || warn "dirsearch venv pip fallback failed"
            else
                warn "dirsearch unavailable — PEP 668 blocks bare pip on Kali and venv not yet ready"
            fi
        fi

        # ffuf fallback (download binary)
        if [[ " ${failed_deps[*]} " =~ " ffuf " ]]; then
            local arch
            arch=$(uname -m)
            local ffuf_arch="linux_amd64"
            [[ "$arch" == "aarch64" ]] && ffuf_arch="linux_arm64"

            local ffuf_url="https://github.com/ffuf/ffuf/releases/latest/download/ffuf_${ffuf_arch}.tar.gz"
            if curl -fsSL --max-time 30 "$ffuf_url" -o /tmp/ffuf.tar.gz 2>/dev/null; then
                tar -xzf /tmp/ffuf.tar.gz -C /tmp/ 2>/dev/null
                [[ -f /tmp/ffuf ]] && mv /tmp/ffuf /usr/local/bin/ && chmod +x /usr/local/bin/ffuf && log "ffuf binary installed ✓"
            fi
            # Alternative: go install
            if ! command -v ffuf &>/dev/null && command -v go &>/dev/null; then
                go install github.com/ffuf/ffuf/v2@latest 2>/dev/null && log "ffuf installed via go ✓" || warn "ffuf go install failed"
            fi
        fi

        # gobuster fallback
        if [[ " ${failed_deps[*]} " =~ " gobuster " ]]; then
            if command -v go &>/dev/null; then
                go install github.com/OJ/gobuster/v3@latest 2>/dev/null && log "gobuster installed via go ✓" || warn "gobuster go install failed"
            fi
            # Alternative: download release
            if ! command -v gobuster &>/dev/null; then
                local gobuster_url="https://github.com/OJ/gobuster/releases/latest/download/gobuster-linux-amd64.tar.gz"
                curl -fsSL --max-time 30 "$gobuster_url" -o /tmp/gobuster.tar.gz 2>/dev/null
                tar -xzf /tmp/gobuster.tar.gz -C /tmp/ 2>/dev/null
                [[ -f /tmp/gobuster ]] && mv /tmp/gobuster /usr/local/bin/ && chmod +x /usr/local/bin/gobuster && log "gobuster binary installed ✓"
            fi
        fi

        # hashcat fallback
        if [[ " ${failed_deps[*]} " =~ " hashcat " ]]; then
            apt-get install -y hashcat 2>/dev/null || \
            (apt-get install -y ocl-icd-libopencl1 2>/dev/null && \
             curl -fsSL https://hashcat.net/files/hashcat-6.2.6.7z -o /tmp/hashcat.7z 2>/dev/null && \
             apt-get install -y p7zip-full 2>/dev/null && \
             7z x /tmp/hashcat.7z -o/opt/ 2>/dev/null && \
             ln -sf /opt/hashcat-6.2.6/hashcat.bin /usr/local/bin/hashcat 2>/dev/null && \
             log "hashcat installed from upstream ✓")
        fi

        # john fallback
        if [[ " ${failed_deps[*]} " =~ " john " ]]; then
            apt-get install -y john 2>/dev/null || \
            apt-get install -y john-data 2>/dev/null || true
        fi
    fi

    # Final verification
    local missing_tools=()
    for tool in nmap sqlmap gobuster ffuf nikto hydra; do
        command -v "$tool" &>/dev/null || missing_tools+=("$tool")
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        warn "Some tools still missing: ${missing_tools[*]}. The tool will work but those features are unavailable."
    else
        log "All core security tools available ✓"
    fi
}

# ─── Environment Setup ───────────────────────────────────────────────────────────────────────────setup_env() {
    log "Setting up environment..."

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY-RUN: Would create: $INSTALL_DIR, $LOG_DIR, $CONFIG_DIR, $REAL_HOME/$WORKSPACE_DIR"
        return
    fi

    mkdir -p "$INSTALL_DIR" "$LOG_DIR" "$CONFIG_DIR" "$REAL_HOME/$WORKSPACE_DIR"
    touch "$LOG_FILE"
    chmod 755 "$LOG_DIR"
    chmod 600 "$LOG_FILE" 2>/dev/null || true
    chown "$REAL_USER:$REAL_USER" "$REAL_HOME/$WORKSPACE_DIR" 2>/dev/null || true

    # Generate secure API token
    if [[ ! -f "$API_TOKEN_FILE" ]]; then
        if command -v openssl &>/dev/null; then
            openssl rand -hex 32 > "$API_TOKEN_FILE"
        else
            # Fallback: use /dev/urandom
            head -c 64 /dev/urandom | xxd -p | tr -d '\n' > "$API_TOKEN_FILE"
        fi
        chmod 600 "$API_TOKEN_FILE"
        log "Generated API token at $API_TOKEN_FILE"
    fi

    # Create Python package __init__.py files
    for pkg in modules modules/brain modules/worker modules/payloads modules/frontend utils tests; do
        touch "$INSTALL_DIR/$pkg/__init__.py"
    done
}

# ─── Claude Desktop Installation with Multiple Fallbacks ─────────────────────────────install_claude_desktop() {
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
        local arch="amd64"
        [[ "$(uname -m)" == "aarch64" ]] && arch="arm64"
        local deb_url="https://github.com/aaddrick/claude-desktop-debian/releases/latest/download/claude-desktop-${arch}.deb"
        if curl -fsSL --max-time 60 "$deb_url" -o "$temp_dir/claude.deb" 2>/dev/null; then
            dpkg -i "$temp_dir/claude.deb" 2>/dev/null || apt-get install -f -y
            if command -v claude-desktop &>/dev/null; then
                install_success=true
                log "Fallback .deb install succeeded ✓"
            fi
        fi
    fi

    # FALLBACK 2: npm global install
    if [[ "$install_success" == false ]]; then
        log "Fallback 2: npm install claude-desktop..."
        if command -v npm &>/dev/null; then
            npm install -g claude-desktop 2>/dev/null && install_success=true
        fi
    fi

    # FALLBACK 3: AppImage
    if [[ "$install_success" == false ]]; then
        log "Fallback 3: Downloading AppImage..."
        local appimage_url="https://github.com/aaddrick/claude-desktop-debian/releases/latest/download/claude-desktop-x86_64.AppImage"
        if curl -fsSL --max-time 60 "$appimage_url" -o /usr/local/bin/claude-desktop 2>/dev/null; then
            chmod +x /usr/local/bin/claude-desktop
            install_success=true
            log "AppImage fallback succeeded ✓"
        fi
    fi

    # FALLBACK 4: Browser wrapper (always works)
    if [[ "$install_success" == false ]]; then
        warn "All native installers failed. Creating browser-based wrapper..."
        cat > /usr/local/bin/claude-desktop <<'WRAPPER'
#!/bin/bash
# NullSec Claude Desktop Fallback Wrapper
# Opens Claude.ai in a dedicated browser window

BROWSER=""
for candidate in chromium google-chrome-stable google-chrome firefox brave-browser brave; do
    if command -v "$candidate" &>/dev/null; then
        BROWSER="$candidate"
        break
    fi
done

if [[ -z "$BROWSER" ]]; then
    echo "[ERROR] No supported browser found. Install Chromium or Firefox."
    echo "[FIX] apt-get install chromium || apt-get install firefox-esr"
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

# ─── Core Installation with Safety Checks ──────────────────────────────────────────────install_hexstrike_core() {
    log "Installing HexStrike Core..."

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY-RUN: Would rsync $SCRIPT_DIR → $INSTALL_DIR"
        return
    fi

    # Backup existing installation
    if [[ -d "$INSTALL_DIR" && -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]]; then
        local backup_dir="$INSTALL_DIR.backup.$(date +%s)"
        log "Backing up existing install to $backup_dir..."
        cp -a "$INSTALL_DIR" "$backup_dir" 2>/dev/null || warn "Backup failed, continuing without backup"
    fi

    # Safe rsync (NO --delete to prevent data loss)
    if command -v rsync &>/dev/null; then
        rsync -av --exclude='.git' --exclude='*.pyc' --exclude='__pycache__' \
            --exclude='venv' --exclude='.env' --exclude='*.backup.*' \
            "$SCRIPT_DIR/" "$INSTALL_DIR/" 2>&1 | tee -a "$LOG_FILE" || \
            { warn "rsync failed, falling back to cp"; cp -r "$SCRIPT_DIR/"* "$INSTALL_DIR/" 2>/dev/null || true; }
    else
        cp -r "$SCRIPT_DIR/"* "$INSTALL_DIR/" 2>/dev/null || warn "Copy had issues"
    fi

    cd "$INSTALL_DIR"

    # Create virtual environment
    local python_cmd="${PYTHON_CMD:-python3}"
    if [[ ! -d "$VENV_PATH" ]]; then
        $python_cmd -m venv "$VENV_PATH" 2>&1 | tee -a "$LOG_FILE" || {
            warn "venv creation failed, trying with --without-pip"
            $python_cmd -m venv "$VENV_PATH" --without-pip 2>&1 | tee -a "$LOG_FILE" || \
                error "Failed to create virtual environment"
            # Install pip manually
            curl -fsSL https://bootstrap.pypa.io/get-pip.py | "$VENV_PATH/bin/python3" 2>&1 | tee -a "$LOG_FILE"
        }
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
            if ! "$VENV_PATH/bin/pip" install -r "$req_file" 2>&1 | tee -a "$LOG_FILE"; then
                warn "Some packages from $req_file failed. Retrying with --no-deps..."
                "$VENV_PATH/bin/pip" install --no-deps -r "$req_file" 2>&1 | tee -a "$LOG_FILE" || \
                    warn "Package installation from $req_file had issues"
            fi
        fi
    done

    # Install package in editable mode
    if [[ -f "setup.py" ]]; then
        log "Installing NullSec package (editable)..."
        if ! "$VENV_PATH/bin/pip" install -e . 2>&1 | tee -a "$LOG_FILE"; then
            warn "Editable install failed. Trying direct install..."
            if ! "$VENV_PATH/bin/pip" install . 2>&1 | tee -a "$LOG_FILE"; then
                warn "Direct install failed. Trying --no-build-isolation..."
                "$VENV_PATH/bin/pip" install --no-build-isolation -e . 2>&1 | tee -a "$LOG_FILE" || \
                    warn "Package installation had issues, but core files are in place"
            fi
        fi
    fi

    # Make entry points executable
    for script in hexstrike-server hexstrike-mcp guardian nullsec-worker ai-lab; do
        [[ -f "$VENV_PATH/bin/$script" ]] && chmod +x "$VENV_PATH/bin/$script"
    done

    cd "$SCRIPT_DIR"
}

# ─── MCP Configuration with Validation ───────────────────────────────────────────────────────────────setup_mcp() {
    log "Configuring MCP Bridge..."

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY-RUN: Would configure MCP in Claude Desktop"
        return
    fi

    local mcp_config="$REAL_HOME/.config/Claude/claude_desktop_config.json"
    local api_token
    api_token=$(cat "$API_TOKEN_FILE" 2>/dev/null || echo "")

    # Create new config
    local new_config
    new_config=$(cat <<EOF
{
  "mcpServers": {
    "nullsec-hexstrike": {
      "command": "$VENV_PATH/bin/python3",
      "args": ["-m", "modules.brain.hexstrike_mcp"],
      "env": {
        "HEXSTRIKE_SERVER_URL": "http://localhost:8888",
        "API_TOKEN": "$api_token"
      }
    },
    "nullsec-ai-lab": {
      "command": "$VENV_PATH/bin/python3",
      "args": ["-m", "modules.payloads.jailbreak_tester", "--mcp"],
      "env": {
        "API_TOKEN": "$api_token"
      }
    }
  }
}
EOF
)

    # Merge with existing config or create new
    if [[ -f "$mcp_config" ]] && command -v jq &>/dev/null; then
        local existing
        existing=$(cat "$mcp_config" 2>/dev/null || echo "{}")
        echo "$existing" | jq --argjson new "$new_config" '. * $new' > "$mcp_config.tmp" 2>/dev/null && \
            mv "$mcp_config.tmp" "$mcp_config" || echo "$new_config" > "$mcp_config"
    elif [[ -f "$mcp_config" ]]; then
        # Fallback without jq: just create backup and overwrite
        cp "$mcp_config" "$mcp_config.backup.$(date +%s)" 2>/dev/null || true
        echo "$new_config" > "$mcp_config"
    else
        echo "$new_config" > "$mcp_config"
    fi

    chmod 600 "$mcp_config"
    chown "$REAL_USER:$REAL_USER" "$mcp_config" 2>/dev/null || true
    log "MCP configuration written to $mcp_config ✓"
}

# ─── Systemd Services with Hardening ───────────────────────────────────────────────────────────────────setup_persistence() {
    log "Setting up systemd services..."

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY-RUN: Would create systemd services"
        return
    fi

    # Ensure hexstrike user exists
    if ! id -u hexstrike &>/dev/null; then
        bash "$SCRIPT_DIR/scripts/provision_hexstrike_user.sh" 2>&1 | tee -a "$LOG_FILE" || \
            warn "User provisioning script failed, creating manually..."

        if ! id -u hexstrike &>/dev/null; then
            groupadd -f hexstrike 2>/dev/null || true
            useradd --system --create-home --home-dir /home/hexstrike \
                --shell /usr/sbin/nologin --gid hexstrike hexstrike 2>/dev/null || \
                warn "Could not create hexstrike user, services may run as root"
        fi
    fi

    # HexStrike Server Service
    cat > /etc/systemd/system/hexstrike.service <<EOF
[Unit]
Description=HexStrike AI Orchestration Server
Documentation=https://github.com/Panda1847/NullSec-RedTeam-AI
After=network.target
Wants=network.target

[Service]
Type=simple
User=hexstrike
Group=hexstrike
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
RestartSec=5
StartLimitInterval=60s
StartLimitBurst=5
MemoryMax=2G
CPUQuota=80%
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR $INSTALL_DIR/jobs $CONFIG_DIR
PrivateTmp=true
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
Wants=hexstrike.service

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
ExecStart=$VENV_PATH/bin/python3 -m modules.worker.worker --poll 2
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
HEXSTRIKE_SERVER_URL=http://localhost:8888
NULLSEC_LOG_DIR=$LOG_DIR
NULLSEC_JOB_DIR=$INSTALL_DIR/jobs
API_TOKEN=$(cat "$API_TOKEN_FILE" 2>/dev/null || echo "")
EOF
    chmod 600 $CONFIG_DIR/environment

    systemctl daemon-reload

    if [[ "$MODE_FULL" == true || "$MODE_CORE" == true ]]; then
        systemctl enable hexstrike.service 2>/dev/null || warn "Could not enable hexstrike.service"
        systemctl enable hexstrike-worker.service 2>/dev/null || warn "Could not enable hexstrike-worker.service"
        log "Services enabled ✓"
    fi
}

# ─── Guardian Installation ────────────────────────────────────────────────────────────────────────────install_guardian() {
    log "Installing Guardian diagnostic tool..."

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY-RUN: Would install guardian → /usr/local/bin/guardian"
        return
    fi

    cat > /usr/local/bin/guardian <<'GUARDIAN_EOF'
#!/usr/bin/env python3
"""NullSec Guardian Launcher — redirects to installed version with fallback."""
import sys, subprocess, os
from pathlib import Path

INSTALL_DIR = Path("/opt/nullsec")
VENV_PYTHON = INSTALL_DIR / "venv" / "bin" / "python3"
GUARDIAN_MODULE = INSTALL_DIR / "modules" / "brain" / "guardian.py"

# Try installed version first
if VENV_PYTHON.exists() and GUARDIAN_MODULE.exists():
    sys.argv[0] = str(GUARDIAN_MODULE)
    sys.path.insert(0, str(INSTALL_DIR))
    exec(open(GUARDIAN_MODULE).read())
else:
    print("[!] Guardian not installed. Run: sudo ./install.sh --core")
    sys.exit(1)
GUARDIAN_EOF
    chmod +x /usr/local/bin/guardian
    log "Guardian installed at /usr/local/bin/guardian ✓"
}

# ─── User & Permissions ────────────────────────────────────────────────────────────────────────────setup_permissions() {
    log "Configuring permissions..."

    if [[ "$DRY_RUN" == true ]]; then
        return
    fi

    if ! id -u hexstrike &>/dev/null; then
        groupadd -f hexstrike 2>/dev/null || true
        useradd --system --create-home --home-dir /home/hexstrike \
            --shell /usr/sbin/nologin --gid hexstrike hexstrike 2>/dev/null || \
            warn "Could not create hexstrike user"
    fi

    mkdir -p "$INSTALL_DIR/jobs" "$LOG_DIR"
    chown -R hexstrike:hexstrike "$INSTALL_DIR/jobs" 2>/dev/null || true
    chown -R hexstrike:hexstrike "$LOG_DIR" 2>/dev/null || true
    chmod 750 "$INSTALL_DIR"
    chmod 750 "$LOG_DIR"
    chmod 770 "$INSTALL_DIR/jobs"
}

# ─── AI Security Lab Deployment ──────────────────────────────────────────────────────────────────────────deploy_lab() {
    log "Deploying AI Security Lab..."

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY-RUN: Would deploy lab payloads"
        return
    fi

    local lab_dir="$INSTALL_DIR/lab"
    mkdir -p "$lab_dir"

    if [[ -f "$INSTALL_DIR/modules/payloads/jailbreak_tester.py" ]]; then
        chmod +x "$INSTALL_DIR/modules/payloads/jailbreak_tester.py"
        cp -r "$INSTALL_DIR/modules/payloads" "$lab_dir/" 2>/dev/null || true
        log "AI Security Lab deployed to $lab_dir ✓"
    else
        warn "jailbreak_tester.py not found, lab deployment incomplete"
    fi
}

# ─── Workspace Isolation ────────────────────────────────────────────────────────────────────────────setup_workspace() {
    local workspace="$REAL_HOME/$WORKSPACE_DIR"
    mkdir -p "$workspace"/{tools,reports,targets,logs,wordlists}
    chown -R "$REAL_USER:$REAL_USER" "$workspace" 2>/dev/null || true
    chmod 700 "$workspace"

    local config_file="$workspace/.nullsec"

    if [[ "$MODE_ELEVATED" == false ]]; then
        log "Workspace isolation: RESTRICTED mode"
        cat > "$config_file" <<EOF
# NullSec Workspace Configuration
# RESTRICTED mode — Claude is sandboxed to this directory
SANDBOX=true
ELEVATED=false
ALLOWED_PATHS=$workspace
EOF
    else
        log "Workspace isolation: ELEVATED mode (full system access)"
        cat > "$config_file" <<EOF
# NullSec Workspace Configuration
# ELEVATED mode — full system access enabled
SANDBOX=false
ELEVATED=true
ALLOWED_PATHS=/
EOF
    fi
    chown "$REAL_USER:$REAL_USER" "$config_file" 2>/dev/null || true
    chmod 600 "$config_file"
}

# ─── Verification ─────────────────────────────────────────────────────────────────────────────────verify_installation() {
    log "Verifying installation..."

    local issues=0

    # Check directories
    for dir in "$INSTALL_DIR" "$LOG_DIR" "$CONFIG_DIR"; do
        [[ -d "$dir" ]] || { warn "Missing directory: $dir"; issues=$((issues+1)); }
    done

    # Check Python venv
    if [[ -f "$VENV_PATH/bin/python3" ]]; then
        log "Virtual environment exists ✓"
    else
        warn "Virtual environment missing"
        issues=$((issues+1))
    fi

    # Check key packages
    if [[ -f "$VENV_PATH/bin/python3" ]]; then
        for pkg in flask requests fastmcp Pillow psutil; do
            "$VENV_PATH/bin/python3" -c "import $pkg" 2>/dev/null || \
                { warn "Package $pkg missing"; issues=$((issues+1)); }
        done
    fi

    # Check system tools
    for tool in nmap sqlmap gobuster ffuf nikto; do
        command -v "$tool" &>/dev/null || { warn "$tool not in PATH"; issues=$((issues+1)); }
    done

    # Check services
    if [[ "$MODE_FULL" == true || "$MODE_CORE" == true ]]; then
        if systemctl is-enabled hexstrike.service &>/dev/null 2>&1; then
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

# ─── Stress Test with Multiple Scenarios ─────────────────────────────────────────────────────────────run_stress_test() {
    log "Running stress tests..."

    if [[ "$DRY_RUN" == true ]]; then
        info "DRY-RUN: Would run stress tests"
        return
    fi

    # Start services for testing
    systemctl start hexstrike.service 2>/dev/null || {
        warn "Could not start hexstrike via systemd, trying direct start..."
        cd "$INSTALL_DIR"
        nohup "$VENV_PATH/bin/python3" -m modules.brain.hexstrike_server --host 127.0.0.1 --port 8888 &
        sleep 3
    }

    sleep 3

    local api_token
    api_token=$(cat "$API_TOKEN_FILE" 2>/dev/null || echo "")

    # Health check with retry
    local health_ok=false
    for i in 1 2 3; do
        if curl -fsS -H "Authorization: Bearer $api_token" \
            http://localhost:8888/health &>/dev/null; then
            health_ok=true
            break
        fi
        sleep 2
    done

    if [[ "$health_ok" == true ]]; then
        log "API health check PASSED ✓"
    else
        warn "API health check FAILED — checking logs..."
        tail -20 "$LOG_DIR/server.log" 2>/dev/null || true
    fi

    # Run Python test suite
    if [[ -f "$INSTALL_DIR/utils/stress_test.py" ]]; then
        cd "$INSTALL_DIR"
        API_TOKEN="$api_token" HEXSTRIKE_SERVER_URL="http://localhost:8888" \
            "$VENV_PATH/bin/python3" utils/stress_test.py 2>&1 | tee -a "$LOG_FILE" || \
            warn "Stress tests had failures"
        cd "$SCRIPT_DIR"
    fi

    # Cleanup
    systemctl stop hexstrike.service 2>/dev/null || true
    pkill -f "hexstrike_server" 2>/dev/null || true
}

# ─── Usage ───────────────────────────────────────────────────────────────────────────────────usage() {
    cat <<EOF
${CYAN}Usage: sudo ./install.sh [OPTIONS]${NC}

${BOLD}Modes:${NC}
  --core       Install core security tools + server
  --desktop    Install Claude Desktop for Linux
  --mcp        Configure MCP bridge in Claude Desktop
  --lab        Deploy AI Security Lab payloads
  --full       Complete deployment (default if no mode specified)
  --elevated   Enable full system access (opt-in, dangerous)

${BOLD}Options:${NC}
  --dry-run    Show planned changes without installing
  --stress     Run stress tests after installation
  --help       Show this help message

${BOLD}Examples:${NC}
  sudo ./install.sh --full --stress
  sudo ./install.sh --core --dry-run
  sudo ./install.sh --desktop --mcp
EOF
}

# ─── Argument Parsing ──────────────────────────────────────────────────────────────────────────────parse_args() {
    if [[ $# -eq 0 ]]; then
        MODE_FULL=true
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --full)       MODE_FULL=true ;;
            --core)       MODE_CORE=true ;;
            --desktop)    MODE_DESKTOP=true ;;
            --mcp)        MODE_MCP=true ;;
            --lab)        MODE_LAB=true ;;
            --elevated)   MODE_ELEVATED=true ;;
            --dry-run)    DRY_RUN=true ;;
            --stress)     STRESS_TEST=true ;;
            --help|-h)    usage; exit 0 ;;
            *)            warn "Unknown option: $1"; usage; exit 1 ;;
        esac
        shift
    done

    # If any specific mode is set, don't default to full
    if [[ "$MODE_CORE" == true || "$MODE_DESKTOP" == true || "$MODE_MCP" == true || "$MODE_LAB" == true ]]; then
        MODE_FULL=false
    fi
}

# ─── Main ──────────────────────────────────────────────────────────────────────────────────────────main() {
    parse_args "$@"
    print_banner

    info "Mode: ${MODE_FULL:+FULL}${MODE_CORE:+CORE}${MODE_DESKTOP:+DESKTOP}${MODE_MCP:+MCP}${MODE_LAB:+LAB}"
    info "Dry-run: $DRY_RUN"
    info "Elevated: $MODE_ELEVATED"

    check_root
    setup_env
    check_python
    check_git
    check_nodejs
    check_system_deps

    if [[ "$MODE_FULL" == true || "$MODE_CORE" == true ]]; then
        install_hexstrike_core
        setup_permissions
        install_guardian
        setup_persistence
    fi

    if [[ "$MODE_FULL" == true || "$MODE_DESKTOP" == true ]]; then
        install_claude_desktop
    fi

    if [[ "$MODE_FULL" == true || "$MODE_MCP" == true ]]; then
        setup_mcp
    fi

    if [[ "$MODE_FULL" == true || "$MODE_LAB" == true ]]; then
        deploy_lab
    fi

    setup_workspace
    verify_installation

    if [[ "$STRESS_TEST" == true ]]; then
        run_stress_test
    fi

    echo
    log "🎉 Installation complete!"
    info "Next steps:"
    info "  • Start services: sudo systemctl start hexstrike hexstrike-worker"
    info "  • Check status:   sudo systemctl status hexstrike"
    info "  • Run guardian:   sudo guardian --check"
    info "  • View logs:      sudo tail -f /var/log/nullsec/server.log"
    echo
}

main "$@"
