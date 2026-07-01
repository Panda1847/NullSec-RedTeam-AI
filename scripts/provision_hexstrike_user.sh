#!/bin/bash
# NullSec User Provisioning Script v7.0
# Creates hexstrike system user with proper security settings

set -euo pipefail

USER="hexstrike"
GROUP="hexstrike"
HOME_DIR="/home/hexstrike"
SHELL="/usr/sbin/nologin"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "❌ Must run as root"
    exit 1
fi

# Create group if not exists
if ! getent group "$GROUP" &>/dev/null; then
    groupadd --system "$GROUP"
    echo "✓ Created group $GROUP"
fi

# Create user if not exists
if ! id -u "$USER" &>/dev/null; then
    useradd --system \
        --create-home \
        --home-dir "$HOME_DIR" \
        --shell "$SHELL" \
        --gid "$GROUP" \
        --comment "NullSec HexStrike Service User" \
        "$USER"
    echo "✓ Created user $USER"
else
    echo "✓ User $USER already exists"
fi

# Set home directory permissions
if [[ -d "$HOME_DIR" ]]; then
    chown "$USER:$GROUP" "$HOME_DIR"
    chmod 750 "$HOME_DIR"
    echo "✓ Set home directory permissions"
fi

# Add to relevant groups for tool access (if needed)
# usermod -aG docker "$USER" 2>/dev/null || true

echo "✓ User provisioning complete"
