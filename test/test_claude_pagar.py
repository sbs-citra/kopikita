"""Test pagar Claude Code (L2.1): permission, sandbox, dan hook audit."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SETTINGS = ROOT / ".claude" / "settings.json"
HOOK = ROOT / ".claude" / "hooks" / "log-bash.py"


@pytest.fixture(scope="module")
def settings():
    return json.loads(SETTINGS.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "rule",
    ["Read(./.env*)", "Read(~/.ssh/**)", "Read(~/.aws/**)", "Bash(curl *)", "Bash(wget *)"],
)
def test_deny_rules(settings, rule):
    assert rule in settings["permissions"]["deny"]


@pytest.mark.parametrize("rule", ["Bash(git push *)", "Bash(docker *)"])
def test_ask_rules(settings, rule):
    assert rule in settings["permissions"]["ask"]


def test_sandbox_network_is_restricted(settings):
    sandbox = settings["sandbox"]
    assert sandbox["enabled"] is True
    domains = sandbox["network"]["allowedDomains"]
    assert "github.com" in domains
    assert "example.com" not in domains
    assert "*" not in domains


def test_pretooluse_hook_points_to_existing_script(settings):
    commands = [
        h["command"]
        for entry in settings["hooks"]["PreToolUse"]
        if entry["matcher"] == "Bash"
        for h in entry["hooks"]
    ]
    assert any("log-bash.py" in c for c in commands)
    assert HOOK.is_file()


def test_hook_logs_and_never_blocks(tmp_path):
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo halo"},
    }
    result = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(event),
        text=True,
        capture_output=True,
        env={**os.environ, "CLAUDE_PROJECT_DIR": str(tmp_path)},
        timeout=10,
    )
    assert result.returncode == 0
    log = (tmp_path / ".claude" / "logs" / "pretooluse.log").read_text(encoding="utf-8")
    assert '"command":"echo halo"' in log


def test_hook_survives_invalid_input(tmp_path):
    result = subprocess.run(
        [sys.executable, str(HOOK)],
        input="bukan json",
        text=True,
        capture_output=True,
        env={**os.environ, "CLAUDE_PROJECT_DIR": str(tmp_path)},
        timeout=10,
    )
    assert result.returncode == 0
