#!/bin/bash
# ==============================================================================
# NullSec HexStrike User Provisioning
# Creates unprivileged service user with proper permissions
# ==============================================================================

set -euo pipefail

USERNAME="hexstrike"
GROUP="hexstrike"
HOME_DIR="/home/$USERNAME"
INSTALL_DIR="/opt/nullsec"
LOG_DIR="/var/log/nullsec"

log() { echo "[+] $1"; }
warn() { echo "[!] $1"; }

# Create group if missing
if ! getent group "$GROUP" >/dev/null 2>&1; then
    log "Creating group $GROUP"
    groupadd "$GROUP"
fi

# Create user if missing
if ! id -u "$USERNAME" >/dev/null 2>&1; then
    log "Creating system user $USERNAME"
    useradd --system --create-home \
            --home-dir "$HOME_DIR" \
            --shell /usr/sbin/nologin \
            --gid "$GROUP" \
            "$USERNAME"
else
    log "User $USERNAME already exists"
fi

# Create directories
mkdir -p "$INSTALL_DIR" "$LOG_DIR" "$INSTALL_DIR/jobs"

# Set ownership
chown -R "$USERNAME:$GROUP" "$INSTALL_DIR/jobs"
chown -R "$USERNAME:$GROUP" "$LOG_DIR"

# Set permissions
chmod 750 "$INSTALL_DIR"
chmod 750 "$LOG_DIR"
chmod 770 "$INSTALL_DIR/jobs"

# Ensure API token directory exists
mkdir -p /etc/nullsec
touch /etc/nullsec/api_token 2>/dev/null || true
chmod 600 /etc/nullsec/api_token 2>/dev/null || true

log "Provisioning complete for user $USERNAME"
log "Directories:"
log "  Install:  $INSTALL_DIR (750)"
log "  Logs:     $LOG_DIR (750)"
log "  Jobs:     $INSTALL_DIR/jobs (770)"
