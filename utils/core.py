import sys
import time
import threading
import itertools
import subprocess
import logging
import os
import functools
import traceback

# Configure logging for core utilities
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- BlackArch Style Pacman Animation ---

class PacmanLoading:
    def __init__(self, message="Loading", delay=0.1):
        self.message = message
        self.delay = delay
        self.running = False
        self.thread = None
        self.frames = [
            "C . . .",
            "c . . .",
            "  C . .",
            "  c . .",
            "    C .",
            "    c .",
            "      C",
            "      c",
        ]

    def _animate(self):
        for frame in itertools.cycle(self.frames):
            if not self.running:
                break
            sys.stdout.write(f"\r\033[93m{frame}\033[0m \033[1m{self.message}...\033[0m")
            sys.stdout.flush()
            time.sleep(self.delay)
        sys.stdout.write("\r" + " " * (len(self.message) + 20) + "\r")
        sys.stdout.flush()

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._animate)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()

def with_pacman(message="Processing"):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            loader = PacmanLoading(message)
            loader.start()
            try:
                return func(*args, **kwargs)
            finally:
                loader.stop()
        return wrapper
    return decorator

# --- Self-Healing & Crash Prevention ---

def self_heal(max_retries=3, delay=2):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    retries += 1
                    error_msg = str(e)
                    logging.error(f"[CRASH DETECTED] {func.__name__} failed: {error_msg}")
                    logging.info(f"[GUARDIAN] Attempting self-healing (Retry {retries}/{max_retries})...")
                    
                    # Basic auto-fixes based on error message
                    if "port" in error_msg.lower() and "already in use" in error_msg.lower():
                        import re
                        port_match = re.search(r'port (\d+)', error_msg)
                        port = port_match.group(1) if port_match else "8888"
                        subprocess.run(f"fuser -k {port}/tcp", shell=True, capture_output=True)
                        logging.info(f"[GUARDIAN] Attempted to kill process on port {port}.")
                    elif "ModuleNotFoundError" in error_msg:
                        module = error_msg.split("'")[1]
                        logging.warning(f"[GUARDIAN] Attempting to install missing module: {module}")
                        subprocess.run([sys.executable, "-m", "pip", "install", module], capture_output=True)
                    
                    time.sleep(delay)
            
            logging.critical(f"[FATAL] {func.__name__} failed after {max_retries} retries.")
            traceback.print_exc()
            return None
        return wrapper
    return decorator

def safe_run(cmd, shell=True, timeout=None):
    """Run a command safely with timeout and error handling."""
    try:
        result = subprocess.run(
            cmd, 
            shell=shell, 
            capture_output=True, 
            text=True, 
            timeout=timeout
        )
        if result.returncode != 0:
            logging.error(f"Command failed with exit code {result.returncode}: {cmd}")
            logging.error(f"Stdout: {result.stdout}")
            logging.error(f"Stderr: {result.stderr}")
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        logging.error(f"Command timed out after {timeout} seconds: {cmd}")
        return -1, "", "Command timed out"
    except Exception as e:
        logging.error(f"An unexpected error occurred while running command '{cmd}': {e}")
        return 1, "", str(e)
