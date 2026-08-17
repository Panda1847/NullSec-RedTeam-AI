#!/usr/bin/env python3
"""Compatibility entry point for legacy setuptools invocations.

Authoritative package metadata, dependencies, entry points, and tool settings live
in `pyproject.toml`. New packaging and release automation should use the PEP 517
build backend declared there.
"""

from setuptools import setup

setup()
