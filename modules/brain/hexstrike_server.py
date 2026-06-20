from flask import Flask, request, jsonify
import argparse
import os
import subprocess
import shlex
import logging
from pathlib import Path

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

def sanitize_input(text):
    """Sanitize input to prevent command injection while allowing necessary flags."""
    if not text:
        return ""
    # Allow alphanumeric, dots, dashes, underscores, and spaces (for flags)
    # This is a basic filter; shlex.split handles the actual safety in subprocess.run
    return "".join(c for c in text if c.isalnum() or c in ".-_ ")

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

    if tool_name not in AVAILABLE_TOOLS:
        return jsonify({"error": f"Tool '{tool_name}' not allowed or not found."}), 404

    if not target:
        return jsonify({"error": "Target is required"}), 400

    # Security Fix: Use list-based subprocess.run and shlex for safe parsing
    # This prevents shell injection because shell=False (default)
    try:
        # Check if tool exists
        subprocess.run(["command", "-v", tool_name], check=True, capture_output=True)
        
        # Build command safely
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
            shell=False # CRITICAL: Ensure shell is False
        )
        
        output = process.stdout if process.stdout else process.stderr
        return jsonify({
            "status": "success",
            "exit_code": process.returncode,
            "output": output
        }), 200

    except subprocess.CalledProcessError:
        # Tool not found in path
        logging.warning(f"Tool {tool_name} not found in system path. Falling back to simulation.")
        return simulate_execution(tool_name, target, options)
    except subprocess.TimeoutExpired:
        logging.error(f"Execution timed out: {tool_name} on {target}")
        return jsonify({"error": "Tool execution timed out."}), 504
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return jsonify({"error": "Internal server error during execution"}), 500

def simulate_execution(tool_name, target, options):
    output = f"[SIMULATED] {tool_name} {options} {target}\n"
    output += "Simulation mode active: Real tool not found or failed to initialize."
    return jsonify({"status": "simulated", "output": output}), 200

def main():
    parser = argparse.ArgumentParser(description="HexStrike AI Flask Server")
    parser.add_argument("--port", type=int, default=8888, help="Port to run the Flask server on")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    args = parser.parse_args()
    
    logging.info(f"Starting HexStrike Server on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)

if __name__ == "__main__":
    main()
