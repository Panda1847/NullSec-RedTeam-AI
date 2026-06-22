#!/bin/bash
# Provision an unprivileged 'hexstrike' user and required directories
set -euo pipefail

USERNAME=hexstrike
GROUP=hexstrike
HOME_DIR=/home/$USERNAME
INSTALL_DIR=/opt/nullsec
LOG_DIR=/var/log/nullsec

if ! id -u $USERNAME >/dev/null 2>&1; then
    echo "Creating user $USERNAME"
    sudo useradd --system --create-home --home-dir $HOME_DIR --shell /usr/sbin/nologin $USERNAME
fi

sudo mkdir -p $INSTALL_DIR $LOG_DIR /opt/nullsec/jobs
sudo chown -R $USERNAME:$GROUP $INSTALL_DIR $LOG_DIR /opt/nullsec/jobs
sudo chmod -R 750 $INSTALL_DIR
sudo chmod -R 750 $LOG_DIR

echo "Provisioning complete. Ensure you have created an API token with mode 600 at /etc/nullsec/api_token or set API_TOKEN in environment for services."
