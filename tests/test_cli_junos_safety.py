"""Tests for CLI Junos syntax guard, show-batch crash prevention, and audit edge cases."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path
import pytest


def test_cli_show_batch_error_handling(tmp_path):
    """When a device fails in show-batch mode, CLI must not crash with JSONDecodeError."""
    devices = tmp_path / "devices.csv"
    devices.write_text("R1,127.0.0.1:1,ssh\n")

    batch_file = tmp_path / "cmds.txt"
    batch_file.write_text("show version\nshow interfaces\n")

    hssh = Path(__file__).resolve().parent.parent / "h-ssh.py"

    res = subprocess.run(
        [sys.executable, str(hssh), "--devices", str(devices), "--batch", str(batch_file),
         "--user", "test", "--password", "test", "--json", "--session-timeout", "1"],
        capture_output=True,
        text=True,
    )
    # Must exit cleanly without an unhandled traceback
    assert "JSONDecodeError" not in res.stderr
    assert "Traceback" not in res.stderr
    # Should produce valid json output with error recorded
    data = json.loads(res.stdout)
    assert len(data) == 1
    assert data[0]["ok"] is False
    assert "error" in data[0]


def test_cli_junos_set_syntax_guard_rejects_bypass(tmp_path):
    """CLI -eC must reject multi-line commands with non-set syntax."""
    devices = tmp_path / "devices.csv"
    devices.write_text("CR1,10.0.1.1,junos\n")

    hssh = Path(__file__).resolve().parent.parent / "h-ssh.py"

    # Multi-line bypass: line 1 starts with 'set', line 2 is 'reboot'
    res = subprocess.run(
        [sys.executable, str(hssh), "--devices", str(devices), "-eC", "set system host-name CR1\nreboot",
         "--user", "test", "--password", "test"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 2
    assert "only accepts 'set ...' commands" in res.stderr or "invalid Junos set command" in res.stderr


def test_cli_junos_set_syntax_guard_broadcast(tmp_path):
    """CLI -eB must validate broadcast files for Junos targets."""
    devices = tmp_path / "devices.csv"
    devices.write_text("CR1,10.0.1.1,junos\n")

    bad_broadcast = tmp_path / "bad.txt"
    bad_broadcast.write_text("interfaces {\n  ge-0/0/0 {}\n}\n")

    hssh = Path(__file__).resolve().parent.parent / "h-ssh.py"

    res = subprocess.run(
        [sys.executable, str(hssh), "--devices", str(devices), "-eB", str(bad_broadcast),
         "--user", "test", "--password", "test"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 2
    assert "only accepts 'set ...' commands" in res.stderr


def test_cli_junos_job_syntax_guard(tmp_path):
    """CLI --job must validate commands for Junos targets."""
    job_file = tmp_path / "job.json"
    job_data = [
        {
            "target": "CR1:10.0.1.1:junos",
            "edit": "reboot",
        }
    ]
    job_file.write_text(json.dumps(job_data))

    hssh = Path(__file__).resolve().parent.parent / "h-ssh.py"

    res = subprocess.run(
        [sys.executable, str(hssh), "--job", str(job_file), "--user", "test", "--password", "test"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 2
    assert "only accepts set-style commands" in res.stderr


def test_cli_audit_logging_preflight_abort(tmp_path):
    """When preflight reachability fails on edit, an audit log entry must be written."""
    devices = tmp_path / "devices.csv"
    devices.write_text("CR1,127.0.0.1:1,ssh\n")

    audit_file = tmp_path / "audit.jsonl"
    hssh = Path(__file__).resolve().parent.parent / "h-ssh.py"

    res = subprocess.run(
        [sys.executable, str(hssh), "--devices", str(devices), "-eC", "uptime", "-y",
         "--user", "test", "--password", "test", "--audit-log", str(audit_file)],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 2
    assert audit_file.exists()
    lines = audit_file.read_text().splitlines()
    assert len(lines) >= 1
    record = json.loads(lines[0])
    assert record["device"] == "CR1"
    assert record["ok"] is False
    assert "preflight" in record["error"]
