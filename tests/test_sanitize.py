import tempfile
from modules.brain.hexstrike_server import sanitize_input, get_api_token
import os

def test_sanitize_basic():
    assert sanitize_input('abc-123') == 'abc-123'
    assert sanitize_input('..../') == '....'

def test_api_token_env(monkeypatch):
    monkeypatch.setenv('API_TOKEN', 'secrettoken')
    assert get_api_token() == 'secrettoken'
