#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║ NullSec Core Utilities v7.0                                                 ║
║ Decorators, animations, and safe execution primitives                       ║
║ Kali Linux Optimized • Self-healing • Fault-tolerant                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import sys
import time
import threading
import itertools
import subprocess
import logging
import os
import functools
import traceback
import re
from typing import Callable, Any, Optional, Tuple

# ─── Logger ──────────────────────────────────────────────────────────────────
logger = logging.getLogger("nullsec.core")

# ─── Pacman Animation ────────────────────────────────────────────────────────
class PacmanLoading:
    """BlackArch-style pacman loading animation."""

    FRAMES = [
        "C . . .", "c . . .", "  C . .", "  c . .",
        "    C .", "    c .", "      C", "      c",
    ]

    def __init__(self, message: str = "Loading", delay: float = 0.1):
        self.message = message
        self.delay = delay
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def _animate(self):
        for frame in itertools.cycle(self.FRAMES):
            if not self.running:
                break
            sys.stdout.write(f"\r\033[93m{frame}\033[0m \033[1m{self.message}...\033[0m")
            sys.stdout.flush()
            time.sleep(self.delay)
        sys.stdout.write("\r" + " " * (len(self.message) + 20) + "\r")
        sys.stdout.flush()

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._animate, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)

def with_pacman(message: str = "Processing"):
    """Decorator that shows pacman animation during function execution."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            loader = PacmanLoading(message)
            loader.start()
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.error(f"{func.__name__} failed: {e}")
                raise
            finally:
                loader.stop()
        return wrapper
    return decorator

# ─── Self-Healing Decorator ──────────────────────────────────────────────────
def self_heal(max_retries: int = 3, delay: float = 2.0, backoff: float = 2.0,
              on_error: Optional[Callable] = None):
    """
    Decorator that auto-retries failed functions with exponential backoff.
    Attempts basic fixes for common errors.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            current_delay = delay

            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    retries += 1
                    error_msg = str(e)
                    logger.error(f"[CRASH] {func.__name__} failed: {error_msg}")

                    if retries >= max_retries:
                        logger.critical(f"[FATAL] {func.__name__} failed after {max_retries} retries")
                        traceback.print_exc()
                        if on_error:
                            on_error(e)
                        raise

                    # Auto-fix attempts
                    fixed = False

                    # Port in use
                    if "port" in error_msg.lower() and "in use" in error_msg.lower():
                        match = re.search(r'port (\d+)', error_msg)
                        port = match.group(1) if match else "8888"
                        logger.info(f"[GUARDIAN] Attempting to free port {port}")
                        try:
                            subprocess.run(["fuser", "-k", f"{port}/tcp"],
                                         capture_output=True, timeout=5)
                            fixed = True
                        except Exception:
                            pass

                    # Missing module
                    elif "ModuleNotFoundError" in error_msg or "No module named" in error_msg:
                        match = re.search(r"'(\w+)'", error_msg)
                        module = match.group(1) if match else None
                        if module:
                            logger.info(f"[GUARDIAN] Installing missing module: {module}")
                            try:
                                subprocess.run([sys.executable, "-m", "pip", "install", module],
                                             capture_output=True, timeout=60)
                                fixed = True
                            except Exception:
                                pass

                    # Permission denied
                    elif "permission denied" in error_msg.lower():
                        logger.warning("[GUARDIAN] Permission denied. Try running with sudo.")

                    # Connection refused
                    elif "connection refused" in error_msg.lower():
                        logger.info("[GUARDIAN] Connection refused. Attempting to start service...")
                        try:
                            subprocess.run(["systemctl", "start", "hexstrike"],
                                         capture_output=True, timeout=10)
                            fixed = True
                        except Exception:
                            pass

                    if fixed:
                        logger.info(f"[GUARDIAN] Retry {retries}/{max_retries} in {current_delay}s...")
                    else:
                        logger.info(f"[GUARDIAN] Retry {retries}/{max_retries} in {current_delay}s...")

                    time.sleep(current_delay)
                    current_delay *= backoff

            return None
        return wrapper
    return decorator

# ─── Safe Command Execution ──────────────────────────────────────────────────
def safe_run(cmd, shell: bool = False, timeout: Optional[int] = 30,
             cwd: Optional[str] = None, env: Optional[dict] = None) -> Tuple[int, str, str]:
    """
    Safely execute a command with timeout and error handling.

    Args:
        cmd: Command string or list
        shell: Whether to use shell execution (default: False for security)
        timeout: Maximum execution time in seconds
        cwd: Working directory
        env: Environment variables

    Returns:
        (return_code, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env
        )

        if result.returncode != 0:
            logger.warning(f"Command exited {result.returncode}: {cmd}")
            if result.stderr:
                logger.debug(f"Stderr: {result.stderr[:500]}")

        return result.returncode, result.stdout, result.stderr

    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout}s: {cmd}")
        return -1, "", f"Timeout after {timeout} seconds"
    except FileNotFoundError:
        logger.error(f"Command not found: {cmd}")
        return 127, "", "Command not found"
    except PermissionError:
        logger.error(f"Permission denied: {cmd}")
        return 126, "", "Permission denied"
    except Exception as e:
        logger.error(f"Command failed: {cmd} — {e}")
        return 1, "", str(e)

# ─── Validation Utilities ────────────────────────────────────────────────────
def validate_ip(target: str) -> bool:
    """Validate IPv4 or IPv6 address."""
    import ipaddress
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def validate_hostname(hostname: str) -> bool:
    """Validate hostname format."""
    import re
    if not hostname or len(hostname) > 253:
        return False
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
        r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    return bool(pattern.match(hostname))

def validate_url(url: str) -> bool:
    """Validate URL format."""
    import re
    if not url or len(url) > 2048:
        return False
    pattern = re.compile(
        r'^https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
        r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?::\d{1,5})?(?:/.*)?$'
    )
    return bool(pattern.match(url))

def sanitize_filename(filename: str) -> str:
    """Sanitize a filename to prevent path traversal."""
    import re
    if not filename:
        return "unnamed"
    filename = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '', filename)
    filename = filename.replace('..', '')
    return filename.strip()[:255] or "unnamed"

def sanitize_path(path: str, allowed_base: Optional[str] = None) -> str:
    """Sanitize a path and optionally restrict to allowed base directory."""
    from pathlib import Path

    if not path:
        return "."

    # Check for path traversal before any resolution
    if ".." in path:
        return "."

    # If allowed_base is given and path is relative, join with base
    if allowed_base:
        try:
            base = Path(allowed_base).resolve()
            joined = (base / path).resolve()
            # Verify the resolved path is within the base directory
            if str(joined).startswith(str(base)):
                return str(joined)
            else:
                return str(base)
        except (OSError, ValueError):
            pass

    # Normalize path (no allowed_base, or base handling failed)
    try:
        p = Path(path).resolve()
        return str(p)
    except (OSError, ValueError):
        return "."

# ─── Timer Context Manager ───────────────────────────────────────────────────
class Timer:
    """Context manager for timing operations."""

    def __init__(self, name: str = "Operation"):
        self.name = name
        self.start_time: Optional[float] = None
        self.elapsed: Optional[float] = None

    def __enter__(self):
        self.start_time = time.time()
        return self

    def __exit__(self, *args):
        self.elapsed = time.time() - self.start_time
        logger.info(f"{self.name} completed in {self.elapsed:.3f}s")

# ─── Retry Utility ───────────────────────────────────────────────────────────
def retry(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0,
          exceptions: Tuple[type, ...] = (Exception,)):
    """Retry decorator with configurable exceptions."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 1
            current_delay = delay

            while attempt <= max_attempts:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    if attempt == max_attempts:
                        raise
                    logger.warning(f"{func.__name__} attempt {attempt}/{max_attempts} failed: {e}")
                    time.sleep(current_delay)
                    current_delay *= backoff
                    attempt += 1

            return None
        return wrapper
    return decorator

# ─── Health Check Utility ────────────────────────────────────────────────────
def check_service_health(url: str, timeout: int = 5) -> Tuple[bool, str]:
    """Check if a service is healthy."""
    try:
        import requests
        resp = requests.get(url, timeout=timeout)
        return resp.status_code == 200, f"HTTP {resp.status_code}"
    except requests.exceptions.ConnectionError:
        return False, "Connection refused"
    except requests.exceptions.Timeout:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)
