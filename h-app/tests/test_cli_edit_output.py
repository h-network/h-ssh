"""Default-mode output for edits, the commit-confirmed reminder, the
--show-diff flow, a job that names one device twice, and the --log file."""
import asyncio
import builtins
import json
import os
import stat
import sys
import time
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hssh import cli, vendors
from hssh.cli import build_confirm_command, format_edit_result, preview_diff

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
            target="R1:10.0.0.1:junos", prog="./h-app/h-ssh.py"):
    """Run main() in-process against a fake junos driver; nothing is contacted.
    The fake answers every edit with `result`, or is `driver` when a test
    needs to record calls. Returns (rc, stdout, stderr)."""
    fake = driver or types.SimpleNamespace(AVAILABLE=True, edit=lambda *a, **kw: result)
    monkeypatch.setitem(vendors.VENDORS, "junos", fake)
    monkeypatch.setitem(cli.VENDOR_MODULES, "junos", fake)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(sys, "argv", [
        prog, "--config", str(tmp_path / "no-config"), "--user", "u", "--password", "p",
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


async def _reachable(target, timeout=2):
    return (target.name, True, "reachable")


def test_reminder_repeats_the_run_targets(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(cli, "check_reachability", _reachable)
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


@pytest.mark.parametrize("transport", ["ssh", "openssh", "arista", "telnet"])
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


def run_job(monkeypatch, capsys, tmp_path, job, *extra, driver=None):
    monkeypatch.setattr(cli, "check_reachability", _reachable)
    job_file = tmp_path / "job.json"
    job_file.write_text(json.dumps(job))
    driver = driver or JobDriver()
    rc, out, err = run_cli(monkeypatch, capsys, tmp_path, ["--job", str(job_file), *extra],
                           driver=driver, target=None)
    return rc, out, err, driver


def test_job_reminder_names_the_jobs_edit_targets(monkeypatch, capsys, tmp_path):
    """The timer is armed on the job's edit entries, so the hint names those:
    not the inventory file, not the show entries, each device once."""
    rc, out, _, _ = run_job(monkeypatch, capsys, tmp_path, [
        {"target": "R1:10.0.0.1:junos", "show": "show version"},
        {"target": "R2:10.0.0.2:junos", "edit": "set system host-name R2-new", "port": 22},
        {"target": "R2:10.0.0.2:junos", "edit": "set system ntp server 10.0.0.9", "port": 22},
    ], "--devices", "/lab/not-the-job.csv", "--commit-confirmed", "5", "-y")
    assert rc == 0
    assert "DON'T FORGET TO CONFIRM THE COMMIT!" in out
    assert '\n  ./h-app/h-ssh.py -eC "commit" --user u --target R2:10.0.0.2:junos:22\n' in out
    assert "not-the-job.csv" not in out and "--target R1" not in out


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
        {"target": "R1:10.0.0.2:junos", "show": "show version"},
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


# --- --show-diff: what is committed is what was shown ----------------------------

class PreviewDriver:
    """A junos fake for --show-diff: the dry run shows the diff of the payload,
    the commit records the diff it was told to expect and, like the real
    driver, refuses when the device would now produce another one
    (`commit_diff`, or the payload's diff again when None)."""
    AVAILABLE = True

    def __init__(self, commit_diff=None):
        self.commit_diff = commit_diff
        self.calls = []

    @staticmethod
    def diff_of(payload):
        return "[edit system]\n+   " + payload.strip() + ";"

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
    monkeypatch.setattr(cli, "check_reachability", _reachable)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(builtins, "input", lambda prompt="": reply() if callable(reply) else reply)


def test_preview_diff_is_the_text_under_the_marker():
    assert preview_diff(HEADER + "DRY-RUN: commit check passed, nothing committed\n\n" + DIFF) == \
        "[edit system]\n+   host-name R1-new;"
    assert preview_diff(HEADER + "NO CHANGES\n") == ""


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


# --- --log: the audit log's file mode and redaction -----------------------------

def test_log_file_is_0600_and_redacted_like_the_audit_log(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(cli, "check_reachability", _reachable)
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
    monkeypatch.setattr(cli, "check_reachability", _reachable)
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
    monkeypatch.setattr(cli, "check_reachability", _reachable)
    calls = []
    driver = types.SimpleNamespace(AVAILABLE=True,
                                   confirm=lambda *a, **kw: calls.append(("confirm", a)) or "COMMIT CONFIRMED OK",
                                   edit=lambda *a, **kw: calls.append(("edit", a[3])) or "COMMIT OK")
    rc, out, err = run_cli(monkeypatch, capsys, tmp_path, ["-eC", "commit", "-y"], driver=driver)
    assert rc == 0 and [c[0] for c in calls] == ["confirm"]


def test_a_broadcast_file_rewritten_after_the_check_is_not_what_is_sent(monkeypatch, capsys, tmp_path):
    """-eB was syntax-checked, then re-read after the prompt (#44)."""
    cfg = tmp_path / "all.set"
    cfg.write_text("set system host-name CHECKED\n")

    async def rewrite_then_reachable(target, timeout=2):
        cfg.write_text("run request system reboot\n")
        return (target.name, True, "reachable")
    monkeypatch.setattr(cli, "check_reachability", rewrite_then_reachable)
    seen = []
    driver = types.SimpleNamespace(AVAILABLE=True, edit=lambda *a, **kw: seen.append(a[3]) or "COMMIT OK")
    audit = tmp_path / "audit.jsonl"
    rc, out, err = run_cli(monkeypatch, capsys, tmp_path, ["-eB", str(cfg), "-y", "--audit-log", str(audit)], driver=driver)
    assert rc == 0 and seen == ["set system host-name CHECKED\n"]
    assert json.loads(audit.read_text().splitlines()[-1])["payload"] == "set system host-name CHECKED\n"


def test_show_diff_json_keeps_stdout_as_json_and_skips_the_preflight(monkeypatch, capsys, tmp_path):
    """Previews landed on stdout in front of the JSON array; and the pre-flight
    TCP connect is redundant once every target has been previewed (#44)."""
    probes = []

    async def counting(target, timeout=2):
        probes.append(target.name)
        return (target.name, True, "reachable")
    monkeypatch.setattr(cli, "check_reachability", counting)
    driver = PreviewDriver()
    rc, out, err = run_cli(monkeypatch, capsys, tmp_path,
                           ["-eC", "set system host-name R1-new", "--show-diff", "-y", "--json"], driver=driver)
    assert rc == 0 and probes == []
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
    monkeypatch.setattr(cli, "check_reachability", _reachable)
    seen = []

    def edit(host, user, passwd, payload, st, ct, commit_confirmed=None, **kw):
        seen.append(host)
        time.sleep(0.8)                      # the commit is on its way
        return "COMMIT OK\n\nDIFF:\n+ host-name X"
    driver = types.SimpleNamespace(AVAILABLE=True, edit=edit)
    monkeypatch.setitem(vendors.VENDORS, "junos", driver)
    monkeypatch.setitem(cli.VENDOR_MODULES, "junos", driver)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE"):
        monkeypatch.delenv(var, raising=False)
    audit, log = tmp_path / "audit.jsonl", tmp_path / "run.jsonl"
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", str(tmp_path / "none"), "--user", "u", "--password", "p",
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
    monkeypatch.setattr(cli, "check_reachability", _reachable)
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
