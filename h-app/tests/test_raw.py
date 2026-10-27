"""--raw output mode and JSON output shape."""
import asyncio
import json
import os
import sqlite3
import sys
import types
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hssh import cli, drivers
from hssh.cli import strip_result_header
from hssh.store import main as store_main

HEADER = "DEVICE: cr1\nHOST:   10.0.1.1\nMODE:   show\nVENDOR: openssh\n\n"


def test_strips_the_runner_header():
    out = HEADER + "Junos: 24.2R1-S2.5"
    assert strip_result_header(out) == "Junos: 24.2R1-S2.5"


def test_strips_the_command_echo():
    out = HEADER + "$ show version\nJunos: 24.2R1-S2.5"
    assert strip_result_header(out, "show version") == "Junos: 24.2R1-S2.5"


def test_keeps_an_echo_that_is_not_the_command():
    """Device output starting with '$ ' must survive."""
    out = HEADER + "$ something else\nJunos: 24.2R1-S2.5"
    assert strip_result_header(out, "show version").startswith("$ something else")


def test_keeps_dollar_lines_inside_output():
    out = HEADER + "$ show version\nprompt$ still output"
    assert "prompt$ still output" in strip_result_header(out, "show version")


def test_multiline_output_is_preserved():
    body = "set routing-options graceful-restart\nset chassis redundancy graceful-switchover"
    out = HEADER + "$ show configuration\n" + body
    assert strip_result_header(out, "show configuration") == body


def test_handles_output_with_no_header():
    assert strip_result_header("Junos: 24.2R1-S2.5") == "Junos: 24.2R1-S2.5"


def test_handles_empty_output():
    assert strip_result_header(HEADER) == ""


def test_blank_lines_inside_output_survive():
    out = HEADER + "$ show version\nfirst\n\nsecond"
    assert strip_result_header(out, "show version") == "first\n\nsecond"


@pytest.mark.parametrize("flags", [["--raw", "-v"], ["--raw", "--json"]])
def test_raw_conflicts_are_refused(flags, tmp_path):
    import subprocess
    hssh = os.path.join(os.path.dirname(__file__), "..", "h-ssh.py")
    proc = subprocess.run(
        [sys.executable, hssh, "--target", "x:1.2.3.4:openssh", "-sC", "show version"] + flags,
        capture_output=True, text=True, timeout=30)
    assert proc.returncode == 2
    assert "mutually exclusive" in proc.stderr


def run_cli(monkeypatch, capsys, argv):
    """cli.main() in-process against the drivers the test put in place;
    nothing is contacted. Returns (rc, stdout, stderr)."""
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", *argv])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    return rc, out, err


def test_a_jobs_show_entry_has_its_command_and_no_echo_as_a_show_has(monkeypatch, capsys, tmp_path):
    """#135: a --job show entry was kept without its command: no `command`
    in --json, and on ssh and openssh the `$ show version` echo the reply
    opens with stayed in `output`, in --raw, in the store and in --log, so
    `h-ssh-store diff` between a -sC run and a job run of the same show
    called the echo a change. A show entry carries its command, resolved
    for its vendor, and its reply is kept as -sC keeps it."""
    # What the ssh transport hands back: the command echoed, then the reply.
    echoing = types.SimpleNamespace(AVAILABLE=True,
                                    show=lambda host, user, passwd, cmd, *a, **kw: f"$ {cmd}\nline one\nline two\n")
    for name in ("none@ssh", "junos@ssh"):
        monkeypatch.setitem(drivers.MODULES, name, echoing)
    db, log, job = tmp_path / "runs.db", tmp_path / "run.jsonl", tmp_path / "job.json"
    job.write_text(json.dumps([{"target": "S1:10.0.0.7:ssh", "show": "show version"},
                               {"target": "S2:10.0.0.8:junos@ssh", "show": "version"}]))     # a shortcut
    rc, out, err = run_cli(monkeypatch, capsys, ["--store", str(db), "-sC", "show version", "S1:10.0.0.7:ssh", "--json"])
    assert rc == 0, err
    (shown,) = json.loads(out)
    assert (shown["command"], shown["output"]) == ("show version", "line one\nline two")
    rc, out, err = run_cli(monkeypatch, capsys, ["--store", str(db), "--job", str(job), "--json", "--log", str(log)])
    assert rc == 0, err
    entries = {e["device"]: e for e in json.loads(out)}
    assert (entries["S1"]["command"], entries["S1"]["output"]) == ("show version", "line one\nline two")
    assert (entries["S2"]["command"], entries["S2"]["output"]) == ("show version | no-more", "line one\nline two")
    logged = {e["device"]: e for e in map(json.loads, log.read_text().splitlines())}
    assert (logged["S1"]["command"], logged["S1"]["output"]) == ("show version", "line one\nline two")
    rc, out, err = run_cli(monkeypatch, capsys, ["--no-store", "--job", str(job), "--raw"])
    assert rc == 0, err
    assert "$ show" not in out and "S1:\nline one\nline two\n" in out
    # The job's row is the -sC row, so the reader finds no difference between them.
    c = sqlite3.connect(str(db))
    try:
        show_run, job_run = [r for (r,) in c.execute("SELECT run_id FROM runs ORDER BY rowid")]
        kept = c.execute("SELECT run_id, command, output FROM results WHERE device = 'S1' ORDER BY rowid").fetchall()
    finally:
        c.close()
    assert kept == [(show_run, "show version", "line one\nline two"), (job_run, "show version", "line one\nline two")]
    assert store_main(["--store", str(db), "diff", "S1", show_run, job_run]) == 0
    assert capsys.readouterr().out == ""
