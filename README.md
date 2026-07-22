# NullSec Red Team AI v7.0 (Hardened)

**NullSec Red Team AI** is an elite offensive security toolkit engineered for seamless integration with **Claude Desktop** via the **Model Context Protocol (MCP)**. This v7.0 hardened version provides enhanced security, stability, and a comprehensive set of tools for red team operations.

## 🚀 Project Overview

This architecture bridges the gap between state-of-the-art Large Language Models and professional-grade security tooling. By granting AI agents direct yet governed access to a specialized security ecosystem, NullSec enables high-velocity workflows for reconnaissance, vulnerability research, and advanced exploitation simulations.

## 🛡️ Core Architecture

| Component | Functionality |
| :--- | :--- |
| **HexStrike AI** | A high-performance Flask orchestration server managing 150+ offensive tools including Nmap, SQLMap, and Metasploit. |
| **AI Security Lab** | A sandbox environment dedicated to LLM jailbreak testing and automated model vulnerability scanning. |
| **Guardian Tool** | A self-healing diagnostic utility for system integrity verification and automated environment repair. |
| **MCP Bridge** | Native, low-latency integration for Claude Desktop to execute complex security workflows. |

## 🛠️ Installation & Deployment

The NullSec deployment process is fully automated and hardened, ensuring a consistent and secure setup across supported Linux distributions.

### Prerequisites

*   **OS:** Kali Linux (Recommended), Debian 12+, or Ubuntu 22.04+.
*   **Hardware:** 4GB+ RAM, 20GB+ Disk Space.
*   **Software:** Python 3.10+, Node.js 18+, Git.

### Automated Setup

```bash
# Clone the elite repository
git clone https://github.com/Panda1847/NullSec-RedTeam-AI.git
cd NullSec-RedTeam-AI

# Execute a dry-run to verify the environment
sudo ./install.sh --dry-run --full

# Perform a comprehensive installation
sudo ./install.sh --full
```

### Complete Command Quickstart

Run these commands in order on Kali Linux, Debian 12+, or Ubuntu 22.04+.

```bash
# 1. Enter the project directory
cd NullSec-RedTeam-AI

# 2. Make the installer executable
chmod +x install.sh

# 3. Review installer options
sudo ./install.sh --help

# 4. Preview changes before installing
sudo ./install.sh --dry-run --full

# 5. Install the full platform
sudo ./install.sh --full
```

Optional install profiles:

```bash
# Core security tooling and server only
sudo ./install.sh --core

# Claude Desktop only
sudo ./install.sh --desktop

# MCP bridge configuration only
sudo ./install.sh --mcp

# AI Security Lab only
sudo ./install.sh --lab

# Desktop plus MCP integration
sudo ./install.sh --desktop --mcp

# Full install plus stress test
sudo ./install.sh --full --stress
```

> `--elevated` enables broader system access and should only be used when you understand the risk:

```bash
sudo ./install.sh --full --elevated
```

### Start and Verify Services

```bash
# Reload systemd and start services
sudo systemctl daemon-reload
sudo systemctl enable --now hexstrike
sudo systemctl enable --now hexstrike-worker

# Check status
sudo systemctl status hexstrike --no-pager
sudo systemctl status hexstrike-worker --no-pager

# Check public health endpoint
curl http://127.0.0.1:8888/health
```

### API Usage

```bash
# Load the generated API token
export API_TOKEN="$(sudo cat /etc/nullsec/api_token)"

# List available tools
curl -H "Authorization: Bearer $API_TOKEN" \
  http://127.0.0.1:8888/api/tools

# List jobs
curl -H "Authorization: Bearer $API_TOKEN" \
  http://127.0.0.1:8888/api/jobs

# Get server statistics
curl -H "Authorization: Bearer $API_TOKEN" \
  http://127.0.0.1:8888/api/stats

# Queue a safe localhost scan example
curl -X POST http://127.0.0.1:8888/api/tools/execute \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tool":"nmap","target":"127.0.0.1","options":"-sV"}'

# Check a queued job, replacing JOB_ID_HERE with the returned job_id
curl -H "Authorization: Bearer $API_TOKEN" \
  http://127.0.0.1:8888/api/jobs/JOB_ID_HERE
```

### CLI Tools

```bash
# HexStrike server
hexstrike-server --host 127.0.0.1 --port 8888

# Worker
nullsec-worker --poll 2 --timeout 300

# MCP bridge
hexstrike-mcp

# Guardian diagnostics
guardian --check
guardian --report
guardian "connection error"
guardian --repair
guardian --stress
guardian --version

# AI Security Lab
ai-lab --list
ai-lab --technique prompt_injection --topic general
ai-lab --model test-model --scan
ai-lab --mcp
```

### Logs and Service Control

```bash
# Logs
sudo tail -f /var/log/nullsec/server.log
sudo tail -f /var/log/nullsec/worker.log
sudo tail -f /var/log/nullsec/install.log

# Restart services
sudo systemctl restart hexstrike hexstrike-worker

# Stop services
sudo systemctl stop hexstrike hexstrike-worker

# Disable autostart
sudo systemctl disable hexstrike hexstrike-worker
```

### Local Development Fallback

Use this if you want to run without the system installer.

```bash
cd NullSec-RedTeam-AI
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install -e .

mkdir -p .nullsec/logs .nullsec/jobs
export NULLSEC_LOG_DIR="$PWD/.nullsec/logs"
export NULLSEC_JOB_DIR="$PWD/.nullsec/jobs"
export API_TOKEN="dev-token-change-me"

# Terminal 1
hexstrike-server --host 127.0.0.1 --port 8888

# Terminal 2
nullsec-worker --poll 2

# Test local API
curl http://127.0.0.1:8888/health
curl -H "Authorization: Bearer dev-token-change-me" \
  http://127.0.0.1:8888/api/tools
```

### Deployment Profiles

| Profile | Flag | Scope |
| :--- | :--- | :--- |
| **Core** | `--core` | Base installation of 150+ security tools (apt/pip). |
| **Desktop** | `--desktop` | Optimized Claude Desktop for Linux installation. |
| **MCP** | `--mcp` | HexStrike MCP server configuration for Claude. |
| **Lab** | `--lab` | Deployment of AI Security Lab payloads and testbeds. |
| **Full** | `--full` | End-to-end deployment of all NullSec components. |

## 🔒 Security & Governance

We maintain the highest standards of operational security (OpSec) and environment isolation.

*   **Workspace Isolation:** AI interactions are strictly confined to the `~/NullSec_RedTeam_Lab` directory by default.
*   **Opt-in Elevation:** Elevated system access is disabled by default and requires the explicit `--elevated` flag.
*   **Audit Logging:** Detailed installation and execution logs are maintained at `/var/log/nullsec/` with restricted access.
*   **Dependency Pinning:** All internal and external packages are version-pinned to prevent supply chain attacks and ensure reproducibility.

### Guardian Diagnostic System

The `guardian` utility (located at `/usr/local/bin/guardian`) provides a read-only-by-default diagnostic layer for the entire toolkit.

*   **Integrity Check:** `guardian --check`
*   **Issue Diagnosis:** `guardian "describe the anomaly"`
*   **Guided Remediation:** `guardian --repair "error signature"` *(Requires manual confirmation)*

Designed for Professionals. Built for the Future of AI Security.
