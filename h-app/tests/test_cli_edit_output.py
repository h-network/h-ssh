"""Default-mode output for edits, the commit-confirmed reminder, the
--show-diff flow, a job that names one device twice (and the file
--save-output keeps of each entry), and the --log file."""
import asyncio
import builtins
import json
import os
import sqlite3
import stat
import sys
import time
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hssh import cli, drivers
from hssh.cli import build_confirm_command, format_edit_result
from hssh.drivers.results import EditResult, as_edit

HEADER = "DEVICE: R1\nHOST:   10.0.0.1\nMODE:   edit-cmd\nVENDOR: junos\n\n"
DIFF = "DIFF:\n[edit system]\n+   host-name R1-new;\n"


@pytest.fixture(autouse=True)
def started_from_the_checkout(monkeypatch):
    """The confirm hint repeats how the run was started; here, the checkout script."""
    monkeypatch.setattr(sys, "argv", ["./h-app/h-ssh.py"])


def test_edit_result_is_indented_under_the_status_line():
    assert format_edit_result(HEADER + "COMMIT OK\n\n" + DIFF) == (
        "  COMMIT OK\n"
        "\n"
        "  DIFF:\n"
        "  [edit system]\n"
        "  +   host-name R1-new;"
    )


def test_edit_result_without_a_diff_is_one_line():
    assert format_edit_result(HEADER + "NO CHANGES\n") == "  NO CHANGES"


def run_cli(monkeypatch, capsys, tmp_path, argv, result=None, driver=None,
            target="R1:10.0.0.1:junos", prog="./h-app/h-ssh.py", password="p"):
    """Run main() in-process against a fake junos driver; nothing is contacted.
    The fake answers every edit with `result`, or is `driver` when a test
    needs to record calls; `password` is HSSH_PASSWORD (None: not set).
    Returns (rc, stdout, stderr)."""
    fake = driver or types.SimpleNamespace(AVAILABLE=True, edit=lambda *a, **kw: result)
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", fake)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    if password is not None:
        monkeypatch.setenv("HSSH_PASSWORD", password)
    monkeypatch.setattr(sys, "argv", [
        prog, "--config", os.devnull, "--user", "u",
        *(["--target", target] if target else []), *argv])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    return rc, out, err


def test_default_mode_prints_the_dry_run_diff(monkeypatch, capsys, tmp_path):
    rc, out, _ = run_cli(monkeypatch, capsys, tmp_path,
                         ["-eC", "set system host-name R1-new", "--dry-run"],
                         "DRY-RUN: commit check passed, nothing committed\n\n" + DIFF)
    assert rc == 0
    assert "  DRY-RUN: commit check passed, nothing committed\n" in out
    assert "  +   host-name R1-new;\n" in out
    assert "--- Output from R1 ---" not in out  # the frame belongs to -v


def test_show_mode_default_output_is_still_the_status_line(monkeypatch, capsys, tmp_path):
    rc, out, _ = run_cli(monkeypatch, capsys, tmp_path, ["-sC", "show version", "--dry-run"], "")
    assert rc == 0
    status = [ln for ln in out.splitlines() if ln.endswith(" OK")]
    assert len(status) == 1 and "R1" in status[0]
    assert "DRY-RUN show" not in out


def test_reminder_repeats_the_run_targets(monkeypatch, capsys, tmp_path):
    rc, out, _ = run_cli(monkeypatch, capsys, tmp_path,
                         ["-eC", "set system host-name R1-new", "--commit-confirmed", "5", "-y"],
                         "COMMIT CONFIRMED (5 minutes)\n\n" + DIFF)
    assert rc == 0
    assert "  COMMIT CONFIRMED (5 minutes)\n" in out
    assert '\n  ./h-app/h-ssh.py -eC "commit" --user u --target R1:10.0.0.1:junos\n' in out


def test_confirm_command_repeats_inline_targets_as_typed():
    cmd = build_confirm_command("admin", ["R1:10.0.1.1:junos", "R2:10.0.1.2:830:junos"],
                                "devices.csv", "ssh")
    assert cmd == ('./h-app/h-ssh.py -eC "commit" --user admin '
                   '--target R1:10.0.1.1:junos --target R2:10.0.1.2:830:junos')


def test_confirm_command_names_the_inventory_file():
    cmd = build_confirm_command("admin", None, "/lab/core.csv", "ssh")
    assert cmd == './h-app/h-ssh.py -eC "commit" --user admin --devices /lab/core.csv'


def test_confirm_command_names_the_program_as_it_was_started(monkeypatch):
    """A pip install has no ./h-app/h-ssh.py: the hint names its console script."""
    monkeypatch.setattr(sys, "argv", ["/opt/venv/bin/h-ssh", "-eC", "set a b"])
    cmd = build_confirm_command("admin", ["R1:10.0.1.1:junos"], "devices.csv", "ssh")
    assert cmd == 'h-ssh -eC "commit" --user admin --target R1:10.0.1.1:junos'
    monkeypatch.setattr(sys, "argv", ["/home/me/h-ssh/h-app/h-ssh.py"])
    cmd = build_confirm_command("admin", ["R1:10.0.1.1:junos"], "devices.csv", "ssh")
    assert cmd.startswith('/home/me/h-ssh/h-app/h-ssh.py -eC "commit"')


@pytest.mark.parametrize("transport", ["ssh", "openssh", "telnet"])
def test_confirm_command_drops_a_transport_that_cannot_confirm(transport):
    cmd = build_confirm_command("admin", ["R1:10.0.1.1:junos"], "devices.csv", transport)
    assert "--transport" not in cmd


def test_confirm_command_keeps_a_transport_that_can():
    cmd = build_confirm_command("admin", ["R1:10.0.1.1:junos"], "devices.csv", "junos")
    assert cmd.endswith(" --target R1:10.0.1.1:junos --transport junos")


def test_confirm_command_quotes_for_the_shell():
    cmd = build_confirm_command("lab admin", None, "/lab/my devices.csv", "ssh")
    assert cmd == """./h-app/h-ssh.py -eC "commit" --user 'lab admin' --devices '/lab/my devices.csv'"""


# --- jobs: the reminder, and one device in several entries ----------------------

class JobDriver:
    """show and edit on one fake, recording the host and the command each saw."""
    AVAILABLE = True

    def __init__(self, delay=0.0):
        self.calls = []
        self.delay = delay

    def show(self, host, user, passwd, cmd, *a, **kw):
        self.calls.append(("show", host, cmd))
        time.sleep(self.delay)
        return "Hostname: R1\nModel: mx960\n"

    def edit(self, host, user, passwd, payload, *a, commit_confirmed=None, **kw):
        self.calls.append(("edit", host, payload))
        time.sleep(self.delay)
        head = f"COMMIT CONFIRMED ({commit_confirmed} minutes)" if commit_confirmed else "COMMIT OK"
        return head + "\n\n" + DIFF


def run_job(monkeypatch, capsys, tmp_path, job, *extra, driver=None, password="p"):
    job_file = tmp_path / "job.json"
    job_file.write_text(json.dumps(job))
    driver = driver or JobDriver()
    rc, out, err = run_cli(monkeypatch, capsys, tmp_path, ["--job", str(job_file), *extra],
                           driver=driver, target=None, password=password)
    return rc, out, err, driver


def test_job_reminder_names_the_jobs_edit_targets(monkeypatch, capsys, tmp_path):
    """The timer is armed on the job's edit entries, so the hint names those:
    not the inventory file, not the show entries, each device once. (A
    --devices typed beside the job is refused since #140.)"""
    rc, out, _, _ = run_job(monkeypatch, capsys, tmp_path, [
        {"target": "R1:10.0.0.1:junos", "show": "show version"},
        {"target": "R2:10.0.0.2:junos", "edit": "set system host-name R2-new", "port": 22},
        {"target": "R2:10.0.0.2:junos", "edit": "set system ntp server 10.0.0.9", "port": 22},
    ], "--commit-confirmed", "5", "-y")
    assert rc == 0
    assert "DON'T FORGET TO CONFIRM THE COMMIT!" in out
    assert '\n  ./h-app/h-ssh.py -eC "commit" --user u --target R2:10.0.0.2:junos:22\n' in out
    assert "--devices" not in out and "--target R1" not in out


def test_job_entries_for_one_device_keep_their_own_mode_and_payload(monkeypatch, capsys, tmp_path):
    audit = tmp_path / "audit.jsonl"
    rc, out, _, driver = run_job(monkeypatch, capsys, tmp_path, [
        {"target": "R1:10.0.0.1:junos", "show": "show version"},
        {"target": "R1:10.0.0.1:junos", "edit": "set system host-name R1-new"},
    ], "--json", "-y", "--audit-log", str(audit))
    assert rc == 0
    assert [c[0] for c in driver.calls] == ["show", "edit"]          # one at a time, in file order
    records = sorted((json.loads(ln) for ln in audit.read_text().splitlines()), key=lambda r: r["mode"])
    assert [(r["mode"], r["payload"]) for r in records] == [
        ("edit-cmd", "set system host-name R1-new"), ("show", "show version")]
    assert "+   host-name R1-new;" in records[0]["diff"] and "diff" not in records[1]
    outputs = sorted(e["output"] for e in json.loads(out))
    assert outputs[0].startswith("COMMIT OK") and outputs[1].startswith("Hostname: R1")


def test_job_results_carry_their_own_entrys_host(monkeypatch, capsys, tmp_path):
    rc, out, _, driver = run_job(monkeypatch, capsys, tmp_path, [
        {"target": "R1:10.0.0.1:junos", "show": "show version"},
        {"target": "R2:10.0.0.2:junos", "show": "show version"},
    ], "--json")
    assert rc == 0
    assert sorted(c[1] for c in driver.calls) == ["10.0.0.1", "10.0.0.2"]
    assert sorted(e["host"] for e in json.loads(out)) == ["10.0.0.1", "10.0.0.2"]


def test_job_entries_for_one_host_take_turns_at_the_safety_gate(monkeypatch, capsys, tmp_path):
    """Run together, the gate would block the second as an "active connection"
    and the run would still say all devices OK."""
    rc, out, err, driver = run_job(monkeypatch, capsys, tmp_path, [
        {"target": "R1:10.0.0.1:junos", "show": "show version"},
        {"target": "R1:10.0.0.1:junos", "show": "show chassis hardware"},
    ], "--json", "--safety-file", str(tmp_path / "safety.json"), driver=JobDriver(delay=0.2))
    assert rc == 0
    assert [c[2] for c in driver.calls] == ["show version", "show chassis hardware"]
    assert all(e["ok"] for e in json.loads(out)) and '"skipped": 0' in err


class EchoDriver(JobDriver):
    """Answers a show with the command and the host, so a saved file says
    which entry it holds; a command in `fail` is refused instead."""

    def __init__(self, fail=()):
        super().__init__()
        self.fail = fail

    def show(self, host, user, passwd, cmd, *a, **kw):
        self.calls.append(("show", host, cmd))
        if cmd in self.fail:
            raise RuntimeError(f"syntax error: {cmd}")
        return f"{cmd} on {host}\n"


def test_save_output_keeps_a_file_for_every_job_entry(monkeypatch, capsys, tmp_path):
    """Every result went to <name>.output, so a job that named R1 three times
    kept only its last entry (#116). The first keeps R1.output, the later
    ones are R1.2.output and R1.3.output, counted per device in file order;
    a job that names each device once keeps the old names."""
    save = tmp_path / "out"
    rc, out, err, _ = run_job(monkeypatch, capsys, tmp_path, [
        {"target": "R1:10.0.0.1:junos", "show": "show version"},
        {"target": "R1:10.0.0.1:junos", "show": "show interfaces terse"},
        {"target": "R2:10.0.0.2:junos", "show": "show version"},
        {"target": "R1:10.0.0.1:junos", "show": "show chassis alarms"},
    ], "--json", "--save-output", str(save), driver=EchoDriver())
    assert rc == 0, err
    saved = {p.name: p.read_text() for p in save.iterdir()}
    assert sorted(saved) == ["R1.2.output", "R1.3.output", "R1.output", "R2.output"]
    assert saved["R1.output"].endswith("\n\nshow version on 10.0.0.1\n")
    assert saved["R1.2.output"].endswith("\n\nshow interfaces terse on 10.0.0.1\n")
    assert saved["R1.3.output"].endswith("\n\nshow chassis alarms on 10.0.0.1\n")
    assert saved["R2.output"].endswith("\n\nshow version on 10.0.0.2\n")
    once = tmp_path / "once"
    rc, out, err, _ = run_job(monkeypatch, capsys, tmp_path, [
        {"target": "R1:10.0.0.1:junos", "show": "show version"},
        {"target": "R2:10.0.0.2:junos", "edit": "set system host-name R2-new"},
    ], "--json", "-y", "--save-output", str(once), driver=EchoDriver())
    assert rc == 0, err
    assert sorted(p.name for p in once.iterdir()) == ["R1.output", "R2.output"]


def test_a_failed_job_entry_saves_its_error_in_its_own_file(monkeypatch, capsys, tmp_path):
    """The error goes to the entry's file as before, no longer over the file
    of the device's entry before it."""
    save = tmp_path / "out"
    rc, out, err, _ = run_job(monkeypatch, capsys, tmp_path, [
        {"target": "R1:10.0.0.1:junos", "show": "show version"},
        {"target": "R1:10.0.0.1:junos", "show": "show bogus"},
    ], "--json", "--save-output", str(save), driver=EchoDriver(fail={"show bogus"}))
    assert rc == 1
    assert (save / "R1.output").read_text().endswith("\n\nshow version on 10.0.0.1\n")
    assert (save / "R1.2.output").read_text().endswith("\n\nERROR: syntax error: show bogus\n")


def test_a_jobs_store_rows_and_saved_files_count_a_devices_entries_alike(monkeypatch, capsys, tmp_path):
    """The store numbers a device's job entries (seq 0, 1, 2) and --save-output
    names their files (R1.output, R1.2.output, R1.3.output). One count feeds
    both, so the entry the store keeps at seq k is the one saved in the
    device's (k+1)th file, a failed entry included."""
    import sqlite3
    db, save = tmp_path / "runs.db", tmp_path / "out"
    rc, out, err, _ = run_job(monkeypatch, capsys, tmp_path, [
        {"target": "R1:10.0.0.1:junos", "show": "show version"},
        {"target": "R1:10.0.0.1:junos", "show": "show interfaces terse"},
        {"target": "R2:10.0.0.2:junos", "show": "show version"},
        {"target": "R1:10.0.0.1:junos", "show": "show bogus"},
    ], "--json", "--store", str(db), "--save-output", str(save), driver=EchoDriver(fail={"show bogus"}))
    assert rc == 1
    con = sqlite3.connect(str(db))
    try:
        rows = con.execute("SELECT device, seq, command FROM results ORDER BY device, seq").fetchall()
    finally:
        con.close()
    assert rows == [("R1", 0, "show version"), ("R1", 1, "show interfaces terse"), ("R1", 2, "show bogus"),
                    ("R2", 0, "show version")]
    files = {"R1": ["R1.output", "R1.2.output", "R1.3.output"], "R2": ["R2.output"]}
    for device, seq, command in rows:
        assert command in (save / files[device][seq]).read_text()


def test_a_job_entry_saved_over_another_devices_file_is_refused(monkeypatch, capsys, tmp_path):
    """R1's second entry is saved as R1.2.output, which is also the file of a
    device named R1.2: one result would replace the other. Refused with the
    job file's other mistakes, before the password prompt, the store, the
    directory and the banner; without --save-output the job runs."""
    job = [
        {"target": "R1:10.0.0.1:junos", "show": "show version"},
        {"target": "R1.2:10.0.0.2:junos", "show": "show version"},
        {"target": "R1:10.0.0.1:junos", "show": "show interfaces terse"},
    ]
    save, db, asked = tmp_path / "out", tmp_path / "s.db", []
    monkeypatch.setattr(cli, "_tty", lambda stream: True)
    monkeypatch.setattr(cli, "_ask", lambda prompt, secret=False: asked.append(prompt) or "typed")
    rc, out, err, driver = run_job(monkeypatch, capsys, tmp_path, job, "--store", str(db), "--save-output", str(save),
                                   driver=EchoDriver(), password=None)
    assert rc == 2 and driver.calls == [] and asked == [] and out == ""
    assert not save.exists() and not db.exists()
    assert "R1.2 and R1's entry 2 would both be saved as R1.2.output" in err and "Nothing was sent" in err
    rc, out, err, driver = run_job(monkeypatch, capsys, tmp_path, job, "--json", driver=EchoDriver())
    assert rc == 0 and len(driver.calls) == 3


# --- --show-diff: what is committed is what was shown ----------------------------

class PreviewDriver:
    """A junos fake for --show-diff: the dry run shows the diff of the payload,
    the commit records the diff it was told to expect and, like the real
    driver, refuses when the device would now produce another one
    (`commit_diff`, or the payload's diff again when None)."""
    AVAILABLE = True

    def __init__(self, commit_diff=None, paint=""):
        self.commit_diff = commit_diff
        # What the device puts in its diff ahead of the line (an escape
        # sequence): an -eC payload may not carry one (#110), a reply may.
        self.paint = paint
        self.calls = []

    def diff_of(self, payload):
        return "[edit system]\n+   " + self.paint + payload.strip() + ";"

    def edit(self, host, user, passwd, payload, *a, dry_run=False, expected_diff=None, **kw):
        self.calls.append({"payload": payload, "dry_run": dry_run, "expected_diff": expected_diff})
        if dry_run:
            return "DRY-RUN: commit check passed, nothing committed\n\nDIFF:\n" + self.diff_of(payload)
        diff = self.commit_diff if self.commit_diff is not None else self.diff_of(payload)
        if expected_diff is not None and expected_diff.strip() != diff.strip():
            raise RuntimeError("diff changed since preview; nothing committed")
        return "COMMIT OK\n\nDIFF:\n" + diff


def answer(monkeypatch, reply):
    """A terminal that answers the one question with `reply`."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(builtins, "input", lambda prompt="": reply() if callable(reply) else reply)


def test_the_preview_diff_is_a_field_of_the_edit_result():
    """--show-diff commits each diff only if the device produces it again; the
    diff is EditResult.diff, no longer read back out of the text (#82)."""
    body = DIFF[len("DIFF:\n"):]
    r = as_edit("DRY-RUN: commit check passed, nothing committed\n\n" + DIFF)
    assert r.status == "dry-run" and r.diff == body == "[edit system]\n+   host-name R1-new;\n"
    assert as_edit("NO CHANGES").diff == "" and as_edit("NO CHANGES").status == "no-changes"
    assert as_edit("ROLLBACK 2: COMMIT CONFIRMED (5 minutes)\n\n" + DIFF) == \
        EditResult("confirmed", diff=body, minutes=5, label="ROLLBACK 2: ")


def test_show_diff_commits_the_diff_it_showed(monkeypatch, capsys, tmp_path):
    answer(monkeypatch, "y")
    driver = PreviewDriver()
    rc, out, _ = run_cli(monkeypatch, capsys, tmp_path,
                         ["-eC", "set system host-name R1-new", "--show-diff"], driver=driver)
    assert rc == 0
    assert "--- R1: diff ---" in out and "  COMMIT OK\n" in out
    assert [c["dry_run"] for c in driver.calls] == [True, False]
    assert driver.calls[0]["expected_diff"] is None
    assert driver.calls[1]["expected_diff"] == driver.diff_of("set system host-name R1-new")


def test_show_diff_refuses_a_diff_that_changed_after_the_preview(monkeypatch, capsys, tmp_path):
    answer(monkeypatch, "y")
    driver = PreviewDriver(commit_diff="[edit system]\n-   host-name SOMEONE-ELSE;\n+   host-name R1-new;")
    rc, out, _ = run_cli(monkeypatch, capsys, tmp_path,
                         ["-eC", "set system host-name R1-new", "--show-diff"], driver=driver)
    assert rc == 1
    assert "ERROR: diff changed since preview; nothing committed" in out
    assert "Done. Failures: 1" in out
    assert [c["dry_run"] for c in driver.calls] == [True, False]


def test_show_diff_commits_and_audits_alike_whether_stdout_is_a_terminal_or_a_pipe(monkeypatch, capsys, tmp_path):
    """On a terminal the diff the commit had to find again was the sanitised
    one, which a device that put an escape sequence in its diff never gives
    again: 'diff changed since preview; nothing committed'. The preview's
    audit entry was the sanitised text too. Both are the reply as it came
    (#111); only the preview as printed is sanitised, for the stream it is
    printed on: with --json, stderr."""
    payload = "set interfaces ge-0/0/0 description red"
    for tty in (False, True):
        answer(monkeypatch, "y")
        monkeypatch.setattr(sys.stdout, "isatty", lambda: tty)
        audit = tmp_path / f"audit-{tty}.jsonl"
        driver = PreviewDriver(paint="\x1b[31m")
        rc, out, err = run_cli(monkeypatch, capsys, tmp_path, ["-eC", payload, "--show-diff", "--audit-log", str(audit)],
                               driver=driver)
        assert rc == 0 and "COMMIT OK" in out, (tty, out)
        assert driver.calls[1]["expected_diff"] == driver.diff_of(payload)
        preview = json.loads(audit.read_text().splitlines()[0])
        assert preview["dry_run"] is True and driver.diff_of(payload) in preview["diff"], tty
        assert ("\x1b" in out) is not tty
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)          # --json | jq, the previews on a terminal
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    rc, out, err = run_cli(monkeypatch, capsys, tmp_path, ["-eC", payload, "--show-diff", "-y", "--json"],
                           driver=PreviewDriver(paint="\x1b[31m"))
    assert rc == 0 and "description red" in err and "\x1b" not in err


def test_a_config_file_edited_after_the_preview_changes_nothing(monkeypatch, capsys, tmp_path):
    """-eD/-eB are read once, after the guard, and that text is what the
    preview, the commit and the audit log all see (#44): a rewrite while the
    run waits at the prompt is ignored, not sent unchecked."""
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    set_file = cfg / "R1.set"
    set_file.write_text("set system host-name PREVIEWED\n")

    def y():
        set_file.write_text("run request system reboot\n")
        return "y"
    answer(monkeypatch, y)
    driver = PreviewDriver()
    rc, out, _ = run_cli(monkeypatch, capsys, tmp_path, ["-eD", str(cfg), "--show-diff"], driver=driver)
    assert rc == 0
    assert [c["payload"] for c in driver.calls] == ["set system host-name PREVIEWED\n"] * 2
    assert driver.calls[1]["expected_diff"] == driver.diff_of("set system host-name PREVIEWED")


def test_show_diff_abort_paths(monkeypatch, capsys, tmp_path):
    audit = tmp_path / "audit.jsonl"
    argv = ["-eC", "set system host-name R1-new", "--show-diff", "--audit-log", str(audit)]
    # n: previewed, not committed, and audited like the plain prompt's abort
    answer(monkeypatch, "n")
    driver = PreviewDriver()
    rc, out, _ = run_cli(monkeypatch, capsys, tmp_path, argv, driver=driver)
    assert rc == 0 and "Aborted by user." in out
    assert [c["dry_run"] for c in driver.calls] == [True]
    preview, record = [json.loads(ln) for ln in audit.read_text().splitlines()]
    assert preview["device"] == "R1" and preview["dry_run"] is True and preview["ok"] is True   # the preview is audited too (#44)
    assert record["device"] == "R1" and record["error"] == "aborted by user confirmation"
    # no terminal and no -y: refused before a dry run reaches any device
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    driver = PreviewDriver()
    rc, _, err = run_cli(monkeypatch, capsys, tmp_path, argv, driver=driver)
    assert rc == 2 and "needs a terminal" in err and driver.calls == []


def test_a_show_diff_edit_that_commits_nothing_leaves_no_run_in_the_store(monkeypatch, capsys, tmp_path):
    """An edit's run row is opened once the edit is past its questions, and
    --show-diff asks after its previews: an N there, or a preview that
    failed, committed nothing and is no run, as an edit stopped at `Proceed
    with changes?` is. The row used to be opened before the previews and
    left open (`?/?`, as a run that could not keep its results reads); a y
    opens it and keeps the commit."""
    def runs():
        con = sqlite3.connect(os.environ["HSSH_STORE"])
        con.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in con.execute("SELECT * FROM runs")]
        finally:
            con.close()
    argv = ["-eC", "set system host-name R1-new", "--show-diff"]
    answer(monkeypatch, "n")
    rc, out, _ = run_cli(monkeypatch, capsys, tmp_path, argv, driver=PreviewDriver())
    assert rc == 0 and "Aborted by user." in out and runs() == []
    failing = types.SimpleNamespace(AVAILABLE=True, edit=lambda *a, **kw: (_ for _ in ()).throw(
        RuntimeError("commit check failed")))
    rc, _, err = run_cli(monkeypatch, capsys, tmp_path, [*argv, "-y"], driver=failing)
    assert rc == 1 and "dry-run failed on R1; nothing committed" in err and runs() == []
    answer(monkeypatch, "y")
    rc, out, _ = run_cli(monkeypatch, capsys, tmp_path, argv, driver=PreviewDriver())
    assert rc == 0 and "COMMIT OK" in out
    run_row, = runs()
    assert run_row["finished"] is not None and (run_row["mode"], run_row["ok"], run_row["failed"]) == ("edit-cmd", 1, 0)


# --- --log: the audit log's file mode and redaction -----------------------------

def test_log_file_is_0600_and_redacted_like_the_audit_log(monkeypatch, capsys, tmp_path):
    log = tmp_path / "logs" / "run.jsonl"
    reply = ("COMMIT OK\n\nDIFF:\n[edit snmp]\n+   community secret123 {\n"
             "+       authorization read-only;\n+   }")
    old = os.umask(0o022)
    try:
        rc, _, _ = run_cli(monkeypatch, capsys, tmp_path,
                           ["-eC", "set snmp community secret123 authorization read-only", "-y",
                            "--log", str(log)], reply)
        assert rc == 0
        failing = types.SimpleNamespace(AVAILABLE=True, edit=lambda *a, **kw: (_ for _ in ()).throw(
            RuntimeError("Config error: community secret123 rejected")))
        rc, _, _ = run_cli(monkeypatch, capsys, tmp_path,
                           ["-eC", "set snmp community secret123 authorization read-only", "-y",
                            "--log", str(log)], driver=failing)
        assert rc == 1
    finally:
        os.umask(old)
    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    committed, failed = [json.loads(ln) for ln in log.read_text().splitlines()]
    assert "secret123" not in log.read_text()
    assert committed["command"] == "set snmp community [REDACTED] authorization read-only"
    assert "+   community [REDACTED] {" in committed["output"]
    assert failed["error"] == "Config error: community [REDACTED] rejected"


# --- #39: the verdict and the exit code count what did not run -----------------

def test_a_run_the_safety_gate_kept_from_every_device_is_not_all_ok(monkeypatch, capsys, tmp_path):
    """A planted <safety-file>.corrupt blocks every device; the headline and
    $? said 'All devices OK' / 0 for a change that touched nothing."""
    sf = tmp_path / "gate.json"
    (tmp_path / "gate.json.corrupt").write_text("x")
    calls = []
    driver = types.SimpleNamespace(AVAILABLE=True, edit=lambda *a, **kw: calls.append(a) or "COMMIT OK")
    rc, out, err = run_cli(monkeypatch, capsys, tmp_path,
                           ["-eC", "set system host-name X", "-y", "--safety-file", str(sf)], driver=driver)
    assert rc == 3 and calls == []
    assert "skipped by the safety gate: 1, nothing applied" in out and "All devices OK" not in out
    assert "gate.json.corrupt" in out        # the reason names the sentinel to clear


def test_commit_confirmed_with_a_confirm_is_refused(monkeypatch, capsys, tmp_path):
    """A confirm is a plain commit: no new timer, so no banner promising one."""
    calls = []
    driver = types.SimpleNamespace(AVAILABLE=True, confirm=lambda *a, **kw: calls.append(a) or "OK",
                                   edit=lambda *a, **kw: calls.append(a) or "OK")
    rc, out, err = run_cli(monkeypatch, capsys, tmp_path, ["-eC", "commit", "--commit-confirmed", "5", "-y"],
                           driver=driver)
    assert rc == 2 and calls == [] and "cannot arm a new timer" in err and "DON'T FORGET" not in out


@pytest.mark.parametrize("spec", ["R1:1.2.3.4:junos:notaport", "R1:1.2.3.4:junos:830:extra", "R1"])
def test_a_malformed_target_is_a_usage_error_not_a_traceback(monkeypatch, capsys, tmp_path, spec):
    rc, out, err = run_cli(monkeypatch, capsys, tmp_path, ["-sC", "show version"], target=spec)
    assert rc == 2 and err.startswith("ERROR:") and "Traceback" not in err

# --- #40: a rollback timer that cannot be armed is a usage error ----------------

@pytest.mark.parametrize("minutes", ["0", "-5", "65536", "ten"])
def test_commit_confirmed_outside_the_junos_range_is_refused_at_the_flag(monkeypatch, capsys, tmp_path, minutes):
    """0 and negative values were committed permanently while the banner
    promised a rollback; now argparse refuses them before anything runs."""
    calls = []
    driver = types.SimpleNamespace(AVAILABLE=True, edit=lambda *a, **kw: calls.append(a) or "COMMIT OK")
    with pytest.raises(SystemExit) as exc:
        run_cli(monkeypatch, capsys, tmp_path, ["-eC", "set system host-name X", "-y",
                                                "--commit-confirmed", minutes], driver=driver)
    err = capsys.readouterr().err
    assert exc.value.code == 2 and calls == [] and "1..65535 minutes" in err

# --- #44: what the guard approved is what is sent ------------------------------

def test_an_edit_payload_is_never_resolved_through_the_template_library(monkeypatch, capsys, tmp_path):
    """A `commit` entry in ~/.h-ssh/commands/junos.json once turned -eC commit
    into an arbitrary text-format load that skipped the guard and the confirm."""
    monkeypatch.setenv("HOME", str(tmp_path))
    cmds = tmp_path / ".h-ssh" / "commands"
    cmds.mkdir(parents=True)
    (cmds / "junos.json").write_text(json.dumps({"commit": {"command": "run request system reboot"}}))
    calls = []
    driver = types.SimpleNamespace(AVAILABLE=True,
                                   confirm=lambda *a, **kw: calls.append(("confirm", a)) or "COMMIT CONFIRMED OK",
                                   edit=lambda *a, **kw: calls.append(("edit", a[3])) or "COMMIT OK")
    rc, out, err = run_cli(monkeypatch, capsys, tmp_path, ["-eC", "commit", "-y"], driver=driver)
    assert rc == 0 and [c[0] for c in calls] == ["confirm"]


def test_a_broadcast_file_rewritten_after_the_check_is_not_what_is_sent(monkeypatch, capsys, tmp_path):
    """-eB was syntax-checked, then re-read after the prompt (#44); here it
    is rewritten while the probe runs, between the check and the send."""
    from hssh import probe
    cfg = tmp_path / "all.set"
    cfg.write_text("set system host-name CHECKED\n")

    async def rewrite_then_live(host, port, banner, seconds):
        cfg.write_text("run request system reboot\n")
        return probe.Answer(probe.LIVE, connect_ms=0.3, banner_ms=7.0, banner="SSH-2.0-OpenSSH_9.6")
    monkeypatch.setattr(probe, "attempt", rewrite_then_live)
    seen = []
    driver = types.SimpleNamespace(AVAILABLE=True, edit=lambda *a, **kw: seen.append(a[3]) or "COMMIT OK")
    audit = tmp_path / "audit.jsonl"
    rc, out, err = run_cli(monkeypatch, capsys, tmp_path, ["-eB", str(cfg), "-y", "--audit-log", str(audit)], driver=driver)
    assert rc == 0 and seen == ["set system host-name CHECKED\n"]
    assert json.loads(audit.read_text().splitlines()[-1])["payload"] == "set system host-name CHECKED\n"


def test_show_diff_json_keeps_stdout_as_json_and_is_probed_first(monkeypatch, capsys, tmp_path, probed):
    """Previews landed on stdout in front of the JSON array (#44). The old
    pre-flight skipped --show-diff, whose previews proved reachability the
    slow way; the probe (#127) runs before them, once per box."""
    driver = PreviewDriver()
    rc, out, err = run_cli(monkeypatch, capsys, tmp_path,
                           ["-eC", "set system host-name R1-new", "--show-diff", "-y", "--json"], driver=driver)
    assert rc == 0 and probed == [("10.0.0.1", 830)]
    data = json.loads(out)
    assert len(data) == 1 and data[0]["ok"] and "R1-new" in err

# --- #45: Ctrl-C keeps what is in flight; the run log is streamed -----------------

def _main_cancelled_after(delay):
    """cli.main() with the main task cancelled after `delay` s, as asyncio.run
    does on SIGINT."""
    async def go():
        asyncio.get_running_loop().call_later(delay, asyncio.current_task().cancel)
        return await cli.main()
    return asyncio.run(go())


def test_ctrl_c_reports_and_audits_the_commit_that_was_in_flight(monkeypatch, capsys, tmp_path):
    """The interrupt cancelled every task; a commit already running in the
    executor landed on the device and left no OK line, no audit entry and
    no log line (#45). The unit that had not started must not start."""
    import threading
    import time
    seen = []

    def edit(host, user, passwd, payload, st, ct, commit_confirmed=None, **kw):
        seen.append(host)
        time.sleep(0.8)                      # the commit is on its way
        return "COMMIT OK\n\nDIFF:\n+ host-name X"
    driver = types.SimpleNamespace(AVAILABLE=True, edit=edit)
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", driver)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    audit, log = tmp_path / "audit.jsonl", tmp_path / "run.jsonl"
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u",
                                      "--target", "R1:10.0.0.1:junos", "--target", "R2:10.0.0.2:junos",
                                      "--workers", "1", "-y", "-eC", "set system host-name X",
                                      "--audit-log", str(audit), "--log", str(log)])
    rc = _main_cancelled_after(0.3)
    out, err = capsys.readouterr()
    assert rc == 130 and seen == ["10.0.0.1"]
    assert "R1" in out and "COMMIT OK" in out
    assert "Interrupted. Completed 1 of 2" in err
    assert [json.loads(l)["device"] for l in audit.read_text().splitlines()] == ["R1"]
    assert [json.loads(l)["device"] for l in log.read_text().splitlines()] == ["R1"]


def test_the_run_log_is_written_as_each_device_finishes(monkeypatch, capsys, tmp_path):
    """--log was written once at the very end (#45): R2 finishes only once R1's
    line is already in the file."""
    import time
    log = tmp_path / "run.jsonl"

    def edit(host, user, passwd, payload, st, ct, commit_confirmed=None, **kw):
        if host == "10.0.0.2":
            for _ in range(100):
                if log.exists() and '"device": "R1"' in log.read_text():
                    return "COMMIT OK"
                time.sleep(0.05)
            return "R1 never reached the log"
        return "COMMIT OK"
    driver = types.SimpleNamespace(AVAILABLE=True, edit=edit)
    rc, out, err = run_cli(monkeypatch, capsys, tmp_path,
                           ["--target", "R2:10.0.0.2:junos", "--workers", "2", "-y",
                            "-eC", "set system host-name X", "--log", str(log)], driver=driver)
    assert rc == 0
    lines = [json.loads(l) for l in log.read_text().splitlines()]
    assert [l["device"] for l in lines] == ["R1", "R2"] and all(l["ok"] for l in lines)

# --- #47: device output cannot drive the operator's terminal -------------------

def test_terminal_safe_strips_what_a_terminal_would_act_on():
    from hssh.cli import terminal_safe
    raw = "line one\x1b[2J\x1b[H\x1b]0;owned\x07\ttab\nline two\x9b31m\x07\x7f\n"
    assert terminal_safe(raw) == "line one\ttab\nline two\n"
    assert terminal_safe("") == "" and terminal_safe("plain") == "plain"


def test_output_shown_on_a_terminal_has_its_escape_sequences_removed(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    driver = types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: "Hostname: R1\x1b[2J\x1b]0;owned\x07\nModel: vmx\n")
    rc, out, err = run_cli(monkeypatch, capsys, tmp_path, ["-sC", "show version", "--raw"], driver=driver)
    assert rc == 0 and "\x1b" not in out and "Hostname: R1" in out and "Model: vmx" in out


def test_a_diff_on_a_terminal_keeps_each_diff_line_on_a_line_of_its_own(monkeypatch, capsys, tmp_path):
    """--diff is made from the replies as they came (#111), where VT, FF and
    NEL end a line. The whole diff was then sanitised for a terminal: the
    line end went with the rest, and a removed line ran into the context
    line before it (' vt-ff', unchanged to the eye). Each diff line is
    sanitised on its own, so a terminal is shown the lines a pipe gets."""
    replies = {"10.0.0.1": "line1\nvt\x0bff\nnel\x85old\nend\n", "10.0.0.2": "line1\nvt\x0bgg\nnel\x85new\nend\n"}
    batch = tmp_path / "cmds.txt"
    batch.write_text("show x\n")
    driver = types.SimpleNamespace(
        AVAILABLE=True, show=lambda host, *a, **kw: replies[host],
        show_batch=lambda host, user, passwd, cmds, *a, **kw: [{"command": c, "ok": True, "output": replies[host]}
                                                             for c in cmds])
    for argv in (["-sC", "show x"], ["--batch", str(batch)]):
        block = {}
        for tty in (False, True):
            monkeypatch.setattr(sys.stdout, "isatty", lambda: tty)
            rc, out, err = run_cli(monkeypatch, capsys, tmp_path, ["--target", "R2:10.0.0.2:junos", "--workers", "1",
                                                                   *argv, "--diff"], driver=driver)
            assert rc == 0, err
            block[tty] = out[out.index("--- Diff"):out.index("--- End diff")]
        assert block[True] == block[False], argv
        assert {"vt", "-ff", "+gg", "nel", "-old", "+new"} <= {ln.strip() for ln in block[True].splitlines()}, argv


EVIL = "\x1b]0;owned\x07desc \x1b[2J\x1b[31mred\x1b[0m\x07 \x9b2Jgone"


class EvilDriver:
    """A junos fake whose every reply carries an OSC retitle, a clear-screen,
    colour, BEL and an 8-bit CSI; a show's first line changes call by call.
    With `fail`, a batch is refused whole, in the same words."""
    AVAILABLE = True

    def __init__(self, fail=False):
        self.calls, self.fail = 0, fail

    def show(self, host, *a, **kw):
        self.calls += 1
        return f"uptime {self.calls} on {host}\n{EVIL}\n"

    def show_batch(self, host, user, passwd, cmds, *a, **kw):
        if self.fail:
            raise RuntimeError(f"refused by the device: {EVIL}")
        return [{"command": c, "ok": True, "output": f"{c} on {host}\n{EVIL}"} for c in cmds]

    def edit(self, *a, **kw):
        return f"COMMIT OK\n\nDIFF:\n[edit system]\n+   host-name {EVIL};"


R2 = ["--target", "R2:10.0.0.2:junos", "--workers", "1"]
SCREENS = {
    "show -v": ["-sC", "show version", "-v"],
    "show --raw": ["-sC", "show version", "--raw"],
    "batch --raw": ["--batch", "BATCH", "--raw"],
    "batch -v": ["--batch", "BATCH", "-v"],
    "failed batch -v": ["--batch", "BATCH", "-v", "--retries", "0"],
    "edit verdict": ["-y", "-eC", "set system host-name x"],
    "--diff": [*R2, "-sC", "show version", "--diff"],
    "--batch --diff": [*R2, "--batch", "BATCH", "--diff"],
    "--every tick": ["--every", "5", "--times", "2", "-sC", "show version"],
    "--show-diff preview": ["-eC", "set system host-name x", "--show-diff"],
}


@pytest.mark.parametrize("shape", SCREENS)
def test_a_reply_reaches_a_terminal_without_what_it_would_act_on_and_a_pipe_as_it_came(shape, monkeypatch,
                                                                                        capsys, tmp_path):
    """Every place h-ssh prints a reply (#47): stdout a terminal gets no ESC,
    BEL or 8-bit CSI, stdout a pipe gets the reply byte for byte. The record
    is the reply as it came (#111) and each print sanitises for itself, so a
    print that forgets puts the device's escape sequences on the screen."""
    batch = tmp_path / "cmds.txt"
    batch.write_text("show version\nshow route\n")
    monkeypatch.setattr(sys, "argv", ["./h-app/h-ssh.py", "--config", os.devnull, "--user", "u",
                                      "--target", "R1:10.0.0.1:junos",
                                      *[str(batch) if a == "BATCH" else a for a in SCREENS[shape]]])
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(cli, "_watch_sleep", lambda seconds: None)
    for tty in (True, False):
        monkeypatch.setattr(sys.stdout, "isatty", lambda: tty)
        if shape == "--show-diff preview":
            answer(monkeypatch, "n")                          # the preview alone, nothing committed
        driver = PreviewDriver(paint=EVIL) if shape == "--show-diff preview" else EvilDriver(fail=shape == "failed batch -v")
        monkeypatch.setitem(drivers.MODULES, "junos@netconf", driver)
        with pytest.raises(SystemExit) as e:
            cli.main_sync()
        out, err = capsys.readouterr()
        assert e.value.code == (1 if shape == "failed batch -v" else 0), err
        assert "desc" in out and "gone" in out, (shape, tty)
        if tty:
            assert not any(c in out for c in "\x1b\x07\x9b"), shape
        else:
            assert EVIL in out, shape
