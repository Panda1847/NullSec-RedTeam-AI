#!/usr/bin/env python3
from flask import Flask, request, jsonify
import argparse
import os
import logging
from pathlib import Path
import shutil
from typing import List

# Job store
from modules.worker.job_store import JobStore

# Configure logging
LOG_DIR = Path(os.environ.get("NULLSEC_LOG_DIR", "/var/log/nullsec"))
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

store = JobStore()

def get_api_token():
    token = os.environ.get('API_TOKEN')
    if token:
        return token
    token_file = Path('/etc/nullsec/api_token')
    try:
        return token_file.read_text().strip()
    except Exception:
        return None

from functools import wraps
def require_token(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Unauthorized'}), 401
        token = auth.split(None, 1)[1]
        expected = get_api_token()
        if expected is None:
            return jsonify({'error': 'Server API token not configured'}), 500
        if token != expected:
            return jsonify({'error': 'Forbidden'}), 403
        return f(*args, **kwargs)
    return wrapper

def sanitize_input(text: str, allow_spaces: bool = True, max_len: int = 1024) -> str:
    if not text:
        return ""
    allowed = ".-_"
    out_chars: List[str] = []
    for c in text[:max_len]:
        if c.isalnum() or c in allowed or (allow_spaces and c.isspace()):
            out_chars.append(c)
    return "".join(out_chars)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok', 'tools': AVAILABLE_TOOLS}), 200

@app.route('/api/tools/execute', methods=['POST'])
@require_token
def execute_tool():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    tool_name = data.get('tool')
    target = data.get('target')
    options = data.get('options', '')

    if not tool_name or tool_name not in ALLOWED_TOOLS:
        return jsonify({'error': f"Tool '{tool_name}' not allowed or not found."}), 404
    if not target:
        return jsonify({'error': 'Target is required'}), 400

    target = sanitize_input(target, allow_spaces=False, max_len=512)
    options = sanitize_input(options, allow_spaces=True, max_len=1024)

    job_id = store.create_job(tool_name, target, options)
    return jsonify({'status': 'queued', 'job_id': job_id}), 202

@app.route('/api/jobs/<job_id>', methods=['GET'])
@require_token
def get_job(job_id):
    job = store.get_job(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
    return jsonify(job), 200

def main():
    parser = argparse.ArgumentParser(description='HexStrike AI Flask Server (job API)')
    parser.add_argument('--port', type=int, default=8888)
    parser.add_argument('--host', default='0.0.0.0')
    args = parser.parse_args()
    logging.info(f"Starting HexStrike Server on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)

if __name__ == '__main__':
    main()
