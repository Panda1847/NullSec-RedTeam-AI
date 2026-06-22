# Operations guide for deployment and maintenance

## Overview
This document explains how to provision a dedicated unprivileged user (`hexstrike`), configure the API token, run the worker service, and manage logs.

## Provision hexstrike user
Run the provisioning script (requires sudo):

```bash
sudo bash scripts/provision_hexstrike_user.sh
```

This creates the `hexstrike` system user and ensures `/opt/nullsec` and `/var/log/nullsec` exist and are owned by that user.

## Configure API token
Create a secure token and place it in `/etc/nullsec/api_token` with restricted permissions:

```bash
sudo mkdir -p /etc/nullsec
sudo sh -c 'echo "YOUR_TOKEN_HERE" > /etc/nullsec/api_token'
sudo chmod 600 /etc/nullsec/api_token
```

Or export `API_TOKEN` in the systemd unit file (not recommended for long-term secrets).

## Start services
After installation, enable and start the systemd services:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now hexstrike-worker
sudo systemctl restart hexstrike
```

## Check logs

```bash
sudo journalctl -u hexstrike -n 200 --no-pager
sudo tail -n 200 /var/log/nullsec/worker.log
sudo tail -n 200 /var/log/nullsec/server.log
```

## Running without container runtime
If docker/podman is not available, the worker will fallback to on-host execution with rlimits applied.
