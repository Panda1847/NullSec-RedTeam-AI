# NullSec Red Team AI

NullSec Red Team AI is an advanced offensive security toolkit designed to integrate seamlessly with Claude Desktop via the Model Context Protocol (MCP). It provides a unified interface for over 150+ security tools, AI-powered vulnerability scanning, and automated jailbreak testing.

## Project Overview

This project bridges the gap between Large Language Models and professional security tooling. By providing Claude with direct, controlled access to a specialized security environment, it enables complex red-teaming workflows, automated reconnaissance, and intelligent payload generation.

### Integrated Capabilities

| Component | Description |
| :--- | :--- |
| **HexStrike AI** | A Flask-based orchestration server managing 150+ offensive tools (Nmap, SQLMap, etc.). |
| **AI Security Lab** | A specialized environment for testing LLM jailbreaks and scanning for model vulnerabilities. |
| **Guardian Tool** | A diagnostic utility for system integrity checks and guided repair of the installation. |
| **MCP Bridge** | Native integration for Claude Desktop to execute commands and manage a local workspace. |

## Installation & Deployment

The installer is modular, allowing you to choose the level of access and components you wish to deploy.

### Prerequisites

*   **Operating System:** Kali Linux, Debian, or Ubuntu (recommended).
*   **Privileges:** Sudo access is required for system-wide tool installation.
*   **Dependencies:** Python 3.10+, Node.js 18+, and Git.

### Automated Installation

Run the installer with the desired mode. By default, it installs core security tools.

```bash
# Clone the repository
git clone https://github.com/Panda1847/NullSec-RedTeam-AI.git
cd NullSec-RedTeam-AI

# Run a dry-run to see planned changes
sudo ./install.sh --dry-run --full

# Perform a full installation (Core + Desktop + MCP + Lab)
sudo ./install.sh --full
```

### Installation Modes

| Mode | Flag | Description |
| :--- | :--- | :--- |
| **Core** | `--core` | Installs only the 150+ security tools (apt/pip). |
| **Desktop** | `--desktop` | Installs Claude Desktop for Linux. |
| **MCP** | `--mcp` | Configures HexStrike MCP servers in Claude. |
| **Lab** | `--lab` | Deploys the AI Security Lab payloads. |
| **Full** | `--full` | Complete deployment of all components. |

## Security & Trust

We prioritize transparency and security in our deployment process.

### Access & Permissions

*   **Workspace Isolation:** By default, Claude is restricted to the `~/NullSec_RedTeam_Lab` directory.
*   **Elevated Access:** Full system access is **opt-in only** via the `--elevated` flag during installation.
*   **Log Privacy:** Installation logs are stored at `/tmp/nullsec_install.log` with restricted permissions (600).
*   **Reproducibility:** All MCP packages are pinned to specific versions to ensure consistent behavior.

### Guardian Diagnostic Tool

The `guardian` tool is deployed to `/usr/local/bin/guardian`. It is designed to be **read-only by default**.

*   **Check Integrity:** `guardian --check`
*   **Diagnose Issues:** `guardian "error message"`
*   **Guided Repair:** `guardian --repair "error message"` (Requires explicit user confirmation)

## Uninstallation

To remove NullSec Red Team AI and its configurations:

1.  **Stop Services:** `sudo systemctl stop hexstrike && sudo systemctl disable hexstrike`
2.  **Remove Files:** `sudo rm -rf /opt/hexstrike-ai /opt/ai-security-lab /usr/local/bin/guardian`
3.  **Clean Config:** Remove the `hexstrike`, `terminal`, and `filesystem` entries from your Claude Desktop config.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines on how to submit pull requests and report issues.

## License

This project is licensed under the MIT License. See [LICENSE](docs/LICENSE) for details.

---

**Lead Developer:** Panda1847  
**Version:** 3.0.0  
**Last Updated:** April 3, 2026
