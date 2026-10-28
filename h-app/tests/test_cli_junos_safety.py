"""Tests for CLI Junos syntax guard, show-batch crash prevention, and audit edge cases."""

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import types
from pathlib import Path
import pytest

# The password reaches the CLI the way a pipeline hands it over: in the
# environment. There is no --password flag; one would put it in `ps`, the
# shell history and every stored command line.
ENV = {**os.environ, "HSSH_PASSWORD": "test"}


def test_cli_show_batch_error_handling(tmp_path):
    """When a device fails in show-batch mode, CLI must not crash with JSONDecodeError."""
    devices = tmp_path / "devices.csv"
    devices.write_text("R1,127.0.0.1:1,ssh\n")

    batch_file = tmp_path / "cmds.txt"
    batch_file.write_text("show version\nshow interfaces\n")

    hssh = Path(__file__).resolve().parent.parent / "h-ssh.py"

    res = subprocess.run(
        [sys.executable, str(hssh), "--devices", str(devices), "--batch", str(batch_file),
         "--user", "test", "--json", "--session-timeout", "1"],
        capture_output=True,
        text=True,
        env=ENV,
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
         "--user", "test"],
        capture_output=True,
        text=True,
        env=ENV,
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
         "--user", "test"],
        capture_output=True,
        text=True,
        env=ENV,
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
        [sys.executable, str(hssh), "--job", str(job_file), "--user", "test"],
        capture_output=True,
        text=True,
        env=ENV,
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
         "--user", "test", "--audit-log", str(audit_file)],
        capture_output=True,
        text=True,
        env=ENV,
    )
    assert res.returncode == 2
    assert audit_file.exists()
    lines = audit_file.read_text().splitlines()
    assert len(lines) >= 1
    record = json.loads(lines[0])
    assert record["device"] == "CR1"
    assert record["ok"] is False
    assert "preflight" in record["error"]


def test_cli_opt_in_safety_gate_no_file(tmp_path):
    """H2: Without --safety-file, SafetyGate is not active and does not block >10 commands."""
    devices = tmp_path / "devices.csv"
    # 12 targets sharing the same host
    lines = [f"R{i},127.0.0.1:1,ssh" for i in range(1, 13)]
    devices.write_text("\n".join(lines) + "\n")

    hssh = Path(__file__).resolve().parent.parent / "h-ssh.py"

    res = subprocess.run(
        [sys.executable, str(hssh), "--devices", str(devices), "-sC", "uptime",
         "--user", "test", "--session-timeout", "1", "--json"],
        capture_output=True,
        text=True,
        env=ENV,
    )
    # Output should not contain rate limiting error
    assert "rate limited" not in res.stdout
    assert "rate limited" not in res.stderr


def test_cli_audit_show_has_no_diff(tmp_path):
    """M3: Show commands do not record diff in audit log."""
    devices = tmp_path / "devices.csv"
    devices.write_text("R1,127.0.0.1:1,ssh\n")
    audit_file = tmp_path / "audit.jsonl"

    hssh = Path(__file__).resolve().parent.parent / "h-ssh.py"

    res = subprocess.run(
        [sys.executable, str(hssh), "--devices", str(devices), "-sC", "show version",
         "--user", "test", "--session-timeout", "1",
         "--audit-log", str(audit_file)],
        capture_output=True,
        text=True,
        env=ENV,
    )
    if audit_file.exists() and audit_file.stat().st_size > 0:
        lines = audit_file.read_text().splitlines()
        for line in lines:
            record = json.loads(line)
            assert "diff" not in record



def _cli(*extra, tmp_path):
    devices = tmp_path / "devices.csv"
    devices.write_text("CR1,10.0.1.1,junos\n")
    hssh = Path(__file__).resolve().parent.parent / "h-ssh.py"
    return subprocess.run([sys.executable, str(hssh), "--devices", str(devices), "--user", "test",
                           *extra], capture_output=True, text=True, env=ENV)


def test_cli_rollback_number_range_is_a_usage_error(tmp_path):
    res = _cli("--rollback", "50", tmp_path=tmp_path)
    assert res.returncode == 2 and "0 to 49" in res.stderr


def test_cli_rollback_is_one_mode_among_the_others(tmp_path):
    res = _cli("--rollback", "1", "-sC", "show version", tmp_path=tmp_path)
    assert res.returncode == 2 and "exactly one of" in res.stderr and "--rollback" in res.stderr
    res = _cli("--rollback", "1", "--job", "-", tmp_path=tmp_path)
    assert res.returncode == 2 and "--rollback" in res.stderr


def test_cli_comment_show_diff_and_commit_status_usage(tmp_path):
    res = _cli("-sC", "show version", "--comment", "x", tmp_path=tmp_path)
    assert res.returncode == 2 and "--comment goes with an edit" in res.stderr
    res = _cli("-eC", "set system host-name x", "--show-diff", "--dry-run", tmp_path=tmp_path)
    assert res.returncode == 2 and "--show-diff" in res.stderr
    res = _cli("--commit-status", "-sC", "show version", tmp_path=tmp_path)
    assert res.returncode == 2 and "exactly one of" in res.stderr


def _main(monkeypatch, capsys, *argv):
    """main() in-process with the runner replaced (the suite's fake answers the
    probe), so a payload the guard lets through is recorded here and never
    sent anywhere."""
    from hssh import cli, drivers

    sent = []

    async def fake_run(t, transport, mode, show_cmd, edit_cmd, **kw):
        sent.append((t.name, t.vendor, edit_cmd))
        return t.name, True, f"DEVICE: {t.name}\nHOST:   {t.host}\nMODE:   {mode}\nVENDOR: {t.vendor}\n\nok\n", 1

    monkeypatch.setattr(cli, "run_for_target_async", fake_run)
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", types.SimpleNamespace(AVAILABLE=True))
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "test")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "test", "-y", *argv])
    rc = asyncio.run(cli.main())
    return rc, capsys.readouterr().err, sent


def test_cli_junos_set_syntax_guard_applies_through_transport(monkeypatch, capsys):
    """--transport junos makes an undeclared target a Junos one, guard included."""
    rc, err, sent = _main(monkeypatch, capsys, "--transport", "junos", "-eC", "configure",
                          "--target", "R1:192.0.2.1")
    assert rc == 2 and "only accepts 'set ...' commands" in err
    assert sent == [], "a non-set payload must be refused before any device I/O"


def test_cli_junos_job_syntax_guard_applies_through_transport(monkeypatch, capsys, tmp_path):
    job_file = tmp_path / "job.json"
    job_file.write_text(json.dumps([{"target": "R1:192.0.2.1", "edit": "reboot"}]))
    rc, err, sent = _main(monkeypatch, capsys, "--transport", "junos", "--job", str(job_file))
    assert rc == 2 and "only accepts set-style commands" in err
    assert sent == []


def test_diff_goes_with_a_show(monkeypatch, capsys, tmp_path):
    """#140: --diff compares a show's replies across the devices. With an
    edit (`-eC ... --dry-run --diff` printed no diff, exit 0), a job,
    --rollback, --commit-status or --probe alone it was accepted and did
    nothing; refused now, nothing sent, from a run file too. A show and a
    batch keep it."""
    job = tmp_path / "job.json"
    job.write_text(json.dumps([{"target": "R1:192.0.2.1:junos", "show": "show version"},
                               {"target": "R2:192.0.2.2:junos", "show": "show version"}]))
    run_file = tmp_path / "run.yaml"
    run_file.write_text("devices: [R1:192.0.2.1:junos]\nedit: set system location x\ncommit-confirmed: 5\ndiff: true\n")
    two = ["--target", "R1:192.0.2.1:junos", "--target", "R2:192.0.2.2:junos"]
    for argv in (["-eC", "set system location x", "--dry-run", "--diff", *two], ["--rollback", "1", "--diff", *two],
                 ["--commit-status", "--diff", *two], ["--job", str(job), "--diff"], ["--probe", "--diff", *two],
                 ["--run", str(run_file)]):
        rc, err, sent = _main(monkeypatch, capsys, *argv)
        assert rc == 2 and sent == [], (argv, err)
        assert "ERROR: --diff goes with a show (-sC, --batch, --profile): it compares the replies across devices." in err
    batch = tmp_path / "cmds.txt"
    batch.write_text("show version\n")
    for argv in (["-sC", "show version", "--diff", *two], ["--batch", str(batch), "--diff", *two]):
        rc, err, sent = _main(monkeypatch, capsys, *argv)
        assert rc == 0 and sorted(name for name, _, _ in sent) == ["R1", "R2"], (argv, err)
