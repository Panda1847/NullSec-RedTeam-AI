from setuptools import setup, find_packages

setup(
    name="nullsec-redteam-ai",
    version="4.2.0",
    packages=find_packages(),
    install_requires=[
        "flask",
        "requests",
        "fastmcp",
        "ansiart",
        "Pillow",
        "psutil"
    ],
    entry_points={
        "console_scripts": [
            "hexstrike-server=modules.brain.hexstrike_server:main",
            "hexstrike-mcp=modules.brain.hexstrike_mcp:main",
            "guardian=modules.brain.guardian:main",
        ],
    },
)
