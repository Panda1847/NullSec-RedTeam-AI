#!/usr/bin/env bash
# NullSec-RedTeam-AI conservative installer
# This script installs only the reviewed local application source. It does not
# download security tools, install desktop clients, fetch unsigned binaries, or
# start services automatically.

set -euo pipefail

MODE="user"
DRY_RUN=false
ALLOW_NETWORK=false
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR=""
SERVICE_USER="nullsec"

usage() {
  cat <<'EOF'
Usage: ./install.sh [--user|--system] [--source-dir PATH] [--allow-network] [--dry-run]

Modes:
  --user            Install into ~/.local/share/nullsec (default; no root required).
  --system          Install into /opt/nullsec and provision a dedicated service user (root required).

Safety controls:
  --allow-network   Allow pip to resolve dependencies. Without this flag, pip is run with --no-index.
  --dry-run         Print planned operations without modifying the system.

This installer intentionally does not install security tools, download “latest”
artifacts, configure MCP clients, expose a network service, or start systemd
units. Configure a rootless runner, immutable image digest, campaign policy,
and reverse proxy separately after reviewing RESPONSIBLE_USE.md.
EOF
}

log() { printf '[nullsec] %s\n' "$*"; }
fail() { printf '[nullsec] error: %s\n' "$*" >&2; exit 1; }
run() {
  if "$DRY_RUN"; then
    printf '[dry-run]'; printf ' %q' "$@"; printf '\n'
  else
    "$@"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user) MODE="user" ;;
    --system) MODE="system" ;;
    --source-dir) shift; [[ $# -gt 0 ]] || fail "--source-dir requires a path"; SOURCE_DIR="$1" ;;
    --allow-network) ALLOW_NETWORK=true ;;
    --dry-run) DRY_RUN=true ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Unknown option: $1" ;;
  esac
  shift
done

[[ -f "$SOURCE_DIR/pyproject.toml" ]] || fail "Source directory must contain pyproject.toml"
[[ -f "$SOURCE_DIR/RESPONSIBLE_USE.md" ]] || fail "Source directory must contain RESPONSIBLE_USE.md"
command -v python3 >/dev/null || fail "Python 3.10+ is required"
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || fail "Python 3.10+ is required"

if [[ "$MODE" == "system" ]]; then
  [[ ${EUID} -eq 0 ]] || fail "--system must be run as root"
  INSTALL_DIR="/opt/nullsec"
else
  [[ ${EUID} -ne 0 ]] || fail "Do not run --user mode as root; use --system if system installation is intended"
  INSTALL_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/nullsec"
fi

if [[ "$MODE" == "system" ]] && ! id "$SERVICE_USER" >/dev/null 2>&1; then
  run useradd --system --home-dir /var/lib/nullsec --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

log "Installing reviewed source to $INSTALL_DIR in $MODE mode"
run mkdir -p "$INSTALL_DIR"
if [[ "$DRY_RUN" == false ]]; then
  # Copy local source without VCS state, test caches, or local virtual environments.
  tar --exclude-vcs --exclude='.venv' --exclude='__pycache__' --exclude='.pytest_cache' \
    -C "$SOURCE_DIR" -cf - . | tar -C "$INSTALL_DIR" -xf -
fi

VENV="$INSTALL_DIR/venv"
run python3 -m venv "$VENV"
if [[ "$ALLOW_NETWORK" == true ]]; then
  run "$VENV/bin/pip" install --upgrade pip
else
  log "Offline mode: skipping pip upgrade and requiring locally available dependencies."
fi
INSTALL_ARGS=("$VENV/bin/pip" install "$INSTALL_DIR")
if [[ "$ALLOW_NETWORK" == false ]]; then
  INSTALL_ARGS+=(--no-index)
fi
run "${INSTALL_ARGS[@]}"

if [[ "$MODE" == "system" ]]; then
  run install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" /var/lib/nullsec/jobs /var/log/nullsec
  run install -d -m 0750 -o root -g "$SERVICE_USER" /etc/nullsec
  if [[ "$DRY_RUN" == false && ! -f /etc/nullsec/api_token ]]; then
    umask 077
    if command -v openssl >/dev/null; then
      openssl rand -hex 32 > /etc/nullsec/api_token
    else
      head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /etc/nullsec/api_token
    fi
    chown root:"$SERVICE_USER" /etc/nullsec/api_token
    chmod 0640 /etc/nullsec/api_token
  fi
  if [[ "$DRY_RUN" == false ]]; then
    cat > /etc/nullsec/nullsec.env <<'EOF'
# Review before use. Sandbox-required execution is the default.
NULLSEC_JOB_DIR=/var/lib/nullsec/jobs
NULLSEC_LOG_DIR=/var/log/nullsec
NULLSEC_EXECUTION_MODE=
# Set TOOL_IMAGE to a reviewed immutable image, e.g. registry.example/toolbox@sha256:<digest>.
TOOL_IMAGE=
NULLSEC_SANDBOX_NETWORK=none
EOF
    chown root:"$SERVICE_USER" /etc/nullsec/nullsec.env
    chmod 0640 /etc/nullsec/nullsec.env
  fi
fi

log "Installation files prepared. No service was started."
log "Next: review RESPONSIBLE_USE.md, configure a rootless container runtime and immutable image digest, then run tests from $INSTALL_DIR."
if [[ "$MODE" == "system" ]]; then
  log "Before enabling any unit, review its User, EnvironmentFile, network, filesystem, and runner controls."
fi
