#!/usr/bin/env python3
"""
NullSec Red Team AI - Setup Configuration
Enterprise-grade AI-powered offensive security platform.
"""
from setuptools import setup, find_packages
from pathlib import Path

VERSION = "6.0.0"

readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

setup(
    name="nullsec-redteam-ai",
    version=VERSION,
    author="NullSec Operations",
    author_email="ops@nullsec.local",
    description="AI-Powered Red Team Platform with MCP Integration",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Panda1847/NullSec-RedTeam-AI",
    license="MIT",

    packages=find_packages(include=["modules", "modules.*", "utils", "utils.*", "tests", "tests.*"]),
    package_dir={"": "."},

    package_data={
        "modules": ["*/requirements.txt"],
        "systemd": ["*.service"],
        "scripts": ["*.sh"],
        "config": ["*.json", "*.yaml", "*.yml"],
    },
    include_package_data=True,

    python_requires=">=3.10",

    install_requires=[
        "flask>=2.3.0",
        "requests>=2.31.0",
        "fastmcp>=0.4.0",
        "Pillow>=10.0.0",
        "psutil>=5.9.0",
        "Werkzeug>=2.3.0",
        "gunicorn>=21.0.0",
        "flask-limiter>=3.5.0",
        "cryptography>=41.0.0",
        "pydantic>=2.0.0",
    ],

    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
            "bandit>=1.7.0",
        ],
        "lab": [
            "openai>=1.0.0",
            "anthropic>=0.8.0",
            "transformers>=4.30.0",
        ],
        "monitoring": [
            "prometheus-client>=0.17.0",
            "grafana-api>=1.0.0",
        ],
    },

    entry_points={
        "console_scripts": [
            "hexstrike-server=modules.brain.hexstrike_server:main",
            "hexstrike-mcp=modules.brain.hexstrike_mcp:main",
            "guardian=modules.brain.guardian:main",
            "nullsec-worker=modules.worker.worker:main",
            "ai-lab=modules.payloads.jailbreak_tester:main",
        ],
    },

    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
        "Natural Language :: English",
    ],

    keywords="redteam pentest ai mcp claude security offensive",
    zip_safe=False,
)
