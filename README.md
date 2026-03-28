# 🦅 Project: NullSec-RedTeam-AI               **A PROJECT BY PANDA1847**
![Status](https://img.shields.io/badge/Status-Classified-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-gold?style=for-the-badge)

> **"Security is an illusion. We provide the reality check."**

## 🌐 Overview

**NullSec-RedTeam-AI** is an advanced, AI-driven offensive security framework designed to bridge the gap between Large Language Models (specifically **Claude Desktop**) and raw penetration testing capabilities. By integrating custom modules for **OSINT**, **Payload Engineering**, and **Adversary Simulation**, this framework automates and streamlines complex stages of red team operations, enhancing efficiency and effectiveness.

## 🛠 Integrated Capabilities

*   🧠 **AI Brain (Claude-3.5 Integration):** Leverages Claude-3.5 for real-time payload generation, logic bypass, and intelligent decision-making during engagements.
*   🗡 **HexStrike Core:** A robust Python-based automation engine tailored for Kali Linux environments, providing a comprehensive suite of offensive security tools.
*   📡 **OSINT Suite:** Automated intelligence gathering capabilities, integrating tools like Nmap and custom scrapers for reconnaissance.
*   💾 **USB Forge:** Provides an integration point for ZeroDay hardware payloads, enabling advanced physical access and exploitation scenarios.
*   🛡 **Advanced Guardian Diagnostic & Repair Tool:** A self-healing mechanism to diagnose and automatically fix common installation and runtime issues, ensuring operational continuity.

## 🚀 Installation & Deployment

This section provides a comprehensive guide to setting up NullSec-RedTeam-AI, including prerequisites, automated installation, and manual verification steps.

### Prerequisites

Before proceeding with the installation, ensure your system meets the following requirements:

*   **Operating System:** Kali Linux or any Debian-based distribution is recommended.
*   **Root Privileges:** The installation script requires `sudo` access.
*   **Git:** For cloning the repository.
*   **Curl & GnuPG:** For adding external repositories and managing GPG keys.
*   **Python 3.x & pip:** Essential for Python-based modules and dependency management.
*   **Node.js & npm/npx:** Required for certain MCP server components and utilities.

### Automated Installation (Recommended)

The `install.sh` script automates the entire setup process, including dependency installation, Claude Desktop setup (if not already present), HexStrike AI deployment, AI Security Lab deployment, and MCP orchestration.

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/Panda1847/NullSec-RedTeam-AI.git
    cd NullSec-RedTeam-AI
    ```

2.  **Run the Installer Script:**
    Execute the `install.sh` script with `sudo` privileges. This script will handle all necessary installations and configurations.
    ```bash
    sudo bash install.sh
    ```
    *The installer will check for existing installations of Claude Desktop and HexStrike and integrate them if found. It will also deploy the Guardian diagnostic tool.* 

3.  **Follow On-Screen Instructions:**
    The script provides detailed output and prompts. Pay attention to any warnings or errors, although the Guardian tool is designed to attempt self-healing for common issues.

### Manual Verification (Optional)

After the automated installation, you can manually verify the setup:

1.  **Check HexStrike Service Status:**
    ```bash
    systemctl status hexstrike
    ```
    The output should show `Active: active (running)`. If not, check the system logs for errors (`journalctl -xeu hexstrike`).

2.  **Verify Claude Desktop Configuration:**
    The installer configures Claude Desktop to integrate with HexStrike and AI Security Lab via MCP. The configuration file is typically located at `~/.config/Claude/claude_desktop_config.json`. You can inspect its contents:
    ```bash
    cat ~/.config/Claude/claude_desktop_config.json
    ```
    Ensure that `hexstrike` and `ai-security-lab` entries are present under `mcpServers`.

3.  **Run Guardian Integrity Check:**
    The Guardian tool can perform a system integrity check to ensure all components are correctly installed and configured.
    ```bash
    sudo guardian
    ```
    Ideally, all checks should pass. If any fail, the Guardian will provide diagnostic information.

## 💡 How to Use NullSec-RedTeam-AI

NullSec-RedTeam-AI is primarily designed to be operated through **Claude Desktop** via its Model Context Protocol (MCP) integration. This allows Claude-3.5 to leverage the framework's capabilities for red team operations.

### 1. Launch Claude Desktop

Start Claude Desktop from your application menu. If it's your first time, you may need to log in or configure your Claude API key.

### 2. Verify MCP Integration

Within Claude Desktop, navigate to its MCP settings (the exact location may vary based on Claude Desktop version). You should see `HexStrike AI Offensive Security Toolkit` and `AI Security Lab` listed as active MCP servers. A green status indicator typically signifies a successful connection.

### 3. Interact with Claude-3.5

Once integrated, you can instruct Claude-3.5 to perform various red team tasks. Claude will automatically invoke the HexStrike and AI Security Lab tools as needed based on your prompts.

**Examples of Prompts for Claude-3.5:**

*   "Perform an OSINT reconnaissance on the domain `example.com` using Nmap and available scrapers. Provide a summary of open ports and discovered subdomains."
*   "Generate a Python payload to exploit a common web vulnerability (e.g., SQL Injection) and test it against a simulated target. Ensure the payload is obfuscated."
*   "Analyze the provided code snippet for potential LLM jailbreak vulnerabilities and suggest mitigation strategies."
*   "Deploy the Guardian diagnostic tool to check the integrity of the HexStrike environment and report any issues."
*   "Access the Red Team Lab Workspace and list its contents."

### 4. Direct Tool Access (Advanced Users)

While interaction through Claude Desktop is the primary method, advanced users can directly access the deployed tools:

*   **HexStrike AI:** Located at `/opt/hexstrike-ai`. You can activate its Python virtual environment and run scripts directly:
    ```bash
    source /opt/hexstrike-ai/venv/bin/activate
    python3 /opt/hexstrike-ai/hexstrike_mcp.py --help
    # Deactivate the venv when done
    deactivate
    ```

*   **AI Security Lab:** Located at `/opt/ai-security-lab`. Similarly, you can activate its virtual environment:
    ```bash
    source /opt/ai-security-lab/venv/bin/activate
    python3 /opt/ai-security-lab/jailbreak_tester.py --help
    # Deactivate the venv when done
    deactivate
    ```

*   **Guardian Tool:** The diagnostic tool can be run from anywhere:
    ```bash
    sudo guardian
    ```

## ⚠️ Troubleshooting

*   **Installation Failures:** If `install.sh` encounters issues, review the output for specific error messages. The Guardian tool attempts to self-heal, but some issues may require manual intervention. Check the log file at `/tmp/nullsec_install.log`.
*   **Claude Desktop MCP Connection Issues:** Ensure the `hexstrike.service` is running (`systemctl status hexstrike`). Verify the `claude_desktop_config.json` file for correct paths and port numbers.
*   **Permission Denied Errors:** Ensure you are running `install.sh` with `sudo`. For other operations, check file and directory permissions and use `chown` or `chmod` as necessary.
*   **Python Dependency Issues:** If a Python module is missing, activate the respective virtual environment (`/opt/hexstrike-ai/venv/bin/activate` or `/opt/ai-security-lab/venv/bin/activate`) and install it using `pip install <module-name>`.

## 🤝 Contributing

We welcome contributions to NullSec-RedTeam-AI! Please refer to `CONTRIBUTING.md` for guidelines on how to submit bug reports, feature requests, and pull requests.

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

** LEAD DEVELOPER:** Panda1847
**Verizon** 2.1
**Last Updated:** March 27, 2026
