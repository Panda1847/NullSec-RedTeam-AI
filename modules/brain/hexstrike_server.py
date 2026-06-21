#!/usr/bin/env python3
from flask import Flask, request, jsonify
import argparse
import os
import subprocess
import shlex
import logging
from pathlib import Path
import shutil   # <-- added
from typing import List

# Configure logging
LOG_DIR = Path("/var/log/nullsec")
LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "server.log"),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)

AVAILABLE_TOOLS = [
    "nmap", "sqlmap", "gobuster", "hydra", "metasploit", "nuclei", "subfinder", "amass", "ffuf", "nikto"
]
ALLOWED_TOOLS = set(AVAILABLE_TOOLS)

def sanitize_input(text: str, allow_spaces: bool = True, max_len: int = 1024) -> str:
    """Sanitize input to prevent command injection while allowing necessary flags."""
    if not text:
        return ""
    allowed = ".-_"
    out_chars: List[str] = []
    for c in text[:max_len]:
        if c.isalnum() or c in allowed or (allow_spaces and c.isspace()):
            out_chars.append(c)
    return "".join(out_chars)

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok", "tools": AVAILABLE_TOOLS}), 200

@app.route("/api/tools/execute", methods=["POST"])
def execute_tool():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    tool_name = data.get("tool")
    target = data.get("target")
    options = data.get("options", "")

    if not tool_name or tool_name not in ALLOWED_TOOLS:
        return jsonify({"error": f"Tool '{tool_name}' not allowed or not found."}), 404

    if not target:
        return jsonify({"error": "Target is required"}), 400

    # Sanitize user inputs
    target = sanitize_input(target, allow_spaces=False, max_len=512)
    options = sanitize_input(options, allow_spaces=True, max_len=1024)

    # Check if tool exists in PATH using shutil.which
    if shutil.which(tool_name) is None:
        logging.warning(f"Tool {tool_name} not found in PATH. Falling back to simulation.")
        return simulate_execution(tool_name, target, options)

    try:
        # Build command safely (list form)
        cmd_args = [tool_name]
        if options:
            cmd_args.extend(shlex.split(options))
        cmd_args.append(target)

        logging.info(f"Executing: {' '.join(cmd_args)}")

        process = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
            timeout=300,
            shell=False
        )

        output = process.stdout if process.stdout else process.stderr
        return jsonify({
            "status": "success",
            "exit_code": process.returncode,
            "output": output
        }), 200

    except subprocess.TimeoutExpired:
        logging.error(f"Execution timed out: {tool_name} on {target}")
        return jsonify({"error": "Tool execution timed out."}), 504
    except FileNotFoundError:
        logging.warning(f"Tool executable disappeared during run: {tool_name}. Simulating output.")
        return simulate_execution(tool_name, target, options)
    except Exception as e:
        logging.exception("Unexpected error during tool execution")
        return jsonify({"error": "Internal server error during execution", "details": str(e)}), 500

def simulate_execution(tool_name, target, options):
    output = f"[SIMULATED] {tool_name} {options} {target}\n"
    output += "Simulation mode active: Real tool not found or failed to initialize."
    return jsonify({"status": "simulated", "exit_code": 0, "output": output}), 200

def main():
    parser = argparse.ArgumentParser(description="HexStrike AI Flask Server")
    parser.add_argument("--port", type=int, default=8888, help="Port to run the Flask server on")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    args = parser.parse_args()

    logging.info(f"Starting HexStrike Server on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)

if __name__ == "__main__":
    main()
