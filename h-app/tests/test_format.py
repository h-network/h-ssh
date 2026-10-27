"""--format json|xml: the router's own reply through rpc() instead of show() text."""
import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hssh import cli, runner, drivers
from hssh.core import Target


class FakeVendor:
    """A transport that records what it was asked for. `replies` maps a
    command to its JSON reply, or to the exception the driver would raise."""
    AVAILABLE = True

    def __init__(self, replies=None, with_rpc=True):
        self.replies = dict(replies or {})
        self.calls = []
        if with_rpc:
            self.rpc = self._rpc
            self.rpc_batch = self._rpc_batch

    def show(self, host, user, passwd, cmd, st, ct, port=None, vendor_hint=None):
        self.calls.append(("show", cmd, None))
        return "text of " + cmd

    def show_batch(self, host, user, passwd, cmds, st, ct, port=None, vendor_hint=None):
        self.calls.append(("show_batch", list(cmds), None))
        return [{"command": c, "ok": True, "output": "text of " + c} for c in cmds]

    def edit(self, host, user, passwd, payload, st, ct, commit_confirmed=None,
             port=None, vendor_hint=None, **kw):
        self.calls.append(("edit", payload, None))
        return "COMMIT OK\n\nDIFF:\n+ " + payload.strip()

    def _reply(self, host, cmd, fmt):
        reply = self.replies.get(cmd, {"reply": cmd, "host": host})
        if isinstance(reply, Exception):
            raise reply
        return reply if fmt == "json" else f"<reply>{cmd}</reply>\n"

    def _rpc(self, host, user, passwd, cmd, st, ct, port=None, vendor_hint=None,
             args=None, fmt="json"):
        self.calls.append(("rpc", cmd, fmt))
        return self._reply(host, cmd, fmt)

    def _rpc_batch(self, host, user, passwd, cmds, st, ct, port=None, vendor_hint=None,
                   fmt="json"):
        self.calls.append(("rpc_batch", list(cmds), fmt))
        results = []
        for cmd in cmds:
            try:
                results.append({"command": cmd, "ok": True, "output": self._reply(host, cmd, fmt)})
            except Exception as e:
                results.append({"command": cmd, "ok": False, "error": str(e)})
        return results


# --- the runner ----------------------------------------------------------------

def run(monkeypatch, vendor_name, mod, mode="show", fmt="text", batch_cmds=None,
        dry_run=False, attempts=1):
    monkeypatch.setitem(drivers.MODULES, drivers.get(vendor_name).name, mod)
    return runner.run_for_target(
        t=Target("R1", "10.0.0.1", vendor_name), transport=vendor_name, mode=mode,
        show_cmd="show version", edit_cmd=None, config_dir=None, broadcast_file=None,
        user="u", passwd="p", session_timeout=5, command_timeout=30,
        dry_run=dry_run, commit_confirmed=None, save_dir=None,
        quiet=True, max_attempts=attempts, batch_cmds=batch_cmds, fmt=fmt)


def test_text_keeps_using_show(monkeypatch):
    v = FakeVendor()
    _, ok, out, _ = run(monkeypatch, "junos", v)
    assert ok and "text of show version" in out
    assert v.calls == [("show", "show version", None)]


def test_json_reaches_rpc_and_is_printed_pretty(monkeypatch):
    reply = {"software-information": [{"host-name": [{"data": "r1"}]}]}
    v = FakeVendor({"show version": reply})
    _, ok, out, _ = run(monkeypatch, "junos", v, fmt="json")
    assert ok and v.calls == [("rpc", "show version", "json")]
    assert cli.strip_result_header(out) == json.dumps(reply, indent=2)


def test_xml_reaches_rpc_and_is_kept_as_is(monkeypatch):
    v = FakeVendor()
    _, ok, out, _ = run(monkeypatch, "junos", v, fmt="xml")
    assert ok and v.calls == [("rpc", "show version", "xml")]
    assert cli.strip_result_header(out) == "<reply>show version</reply>"


@pytest.mark.parametrize("mode", ["show", "show-batch"])
@pytest.mark.parametrize("fmt", ["json", "xml"])
def test_refused_without_rpc_before_any_device_contact(monkeypatch, mode, fmt):
    v = FakeVendor(with_rpc=False)
    _, ok, out, _ = run(monkeypatch, "ssh", v, mode=mode, fmt=fmt, batch_cmds=["show version"])
    assert not ok and "--format json/xml is not supported by the 'ssh' transport" in out
    assert v.calls == []


def test_a_command_with_no_rpc_is_not_retried(monkeypatch):
    monkeypatch.setattr(runner.time, "sleep", lambda s: None)
    v = FakeVendor({"show version": ValueError("no RPC equivalent for CLI command 'show version'")})
    _, ok, out, _ = run(monkeypatch, "junos", v, fmt="json", attempts=3)
    assert not ok and "no RPC equivalent" in out
    assert len(v.calls) == 1


def test_batch_json_is_one_rpc_batch_with_per_command_errors(monkeypatch):
    v = FakeVendor({"show version": {"v": 1},
                    "show nonsense": ValueError("no RPC equivalent for CLI command 'show nonsense'")})
    cmds = ["show version", "show nonsense", "show chassis hardware"]
    _, ok, out, _ = run(monkeypatch, "junos", v, mode="show-batch", fmt="json", batch_cmds=cmds)
    assert not ok and v.calls == [("rpc_batch", cmds, "json")]
    results = json.loads(out)
    assert [r["ok"] for r in results] == [True, False, True]
    assert results[0]["output"] == {"v": 1}
    assert "no RPC equivalent" in results[1]["error"]
    assert results[2]["output"] == {"reply": "show chassis hardware", "host": "10.0.0.1"}


def test_batch_text_keeps_using_show_batch(monkeypatch):
    v = FakeVendor()
    _, ok, out, _ = run(monkeypatch, "junos", v, mode="show-batch", batch_cmds=["show version"])
    assert ok and v.calls == [("show_batch", ["show version"], None)]


# --- the CLI's output shapes, in-process on the fake --------------------------

R1 = ["--target", "R1:10.0.0.1:junos"]


def run_cli(monkeypatch, capsys, fake, *argv):
    """h-ssh main() in this process; the fake is the junos module for both the
    CLI's availability check and the runner."""
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", fake)
    monkeypatch.delenv("HSSH_AUDIT_LOG", raising=False)
    monkeypatch.delenv("HSSH_SAFETY_FILE", raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u",
                                      "--retries", "0", *argv])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    return rc, out, err


def test_cli_json_carries_the_reply_as_data(monkeypatch, capsys):
    v = FakeVendor({"show version": {"a": 1}})
    rc, out, _ = run_cli(monkeypatch, capsys, v, "-sC", "show version", "--format", "json", "--json", *R1)
    assert rc == 0
    [entry] = json.loads(out)
    assert entry["command"] == "show version" and entry["output"] == {"a": 1}


def test_cli_json_carries_the_xml_as_text(monkeypatch, capsys):
    rc, out, _ = run_cli(monkeypatch, capsys, FakeVendor(), "-sC", "show version", "--format", "xml",
                         "--json", *R1)
    assert rc == 0
    [entry] = json.loads(out)
    assert entry["output"] == "<reply>show version</reply>"


def test_cli_raw_prints_the_document_only(monkeypatch, capsys):
    v = FakeVendor({"show version": {"a": 1}})
    rc, out, _ = run_cli(monkeypatch, capsys, v, "-sC", "show version", "--format", "json", "--raw", *R1)
    assert rc == 0
    assert out == "R1:\n" + json.dumps({"a": 1}, indent=2) + "\n\n"


def test_cli_verbose_prints_the_document_pretty(monkeypatch, capsys):
    v = FakeVendor({"show version": {"a": 1}})
    _, out, _ = run_cli(monkeypatch, capsys, v, "-sC", "show version", "--format", "json", "-v", *R1)
    assert json.dumps({"a": 1}, indent=2) in out


def test_cli_dry_run_stays_text(monkeypatch, capsys):
    v = FakeVendor()
    _, out, _ = run_cli(monkeypatch, capsys, v, "-sC", "show version", "--format", "json", "--json",
                        "--dry-run", *R1)
    [entry] = json.loads(out)
    assert entry["output"] == "DRY-RUN show: show version" and v.calls == []


def test_cli_batch_json_answers_per_command(monkeypatch, capsys, tmp_path):
    batch = tmp_path / "cmds.txt"
    batch.write_text("show version\nshow nonsense\n")
    v = FakeVendor({"show version": {"a": 1}, "show nonsense": ValueError("no RPC equivalent")})
    rc, out, _ = run_cli(monkeypatch, capsys, v, "--batch", str(batch), "--format", "json", "--json", *R1)
    assert rc == 1
    [entry] = json.loads(out)
    assert entry["commands"][0] == {"command": "show version", "ok": True, "output": {"a": 1}}
    assert entry["commands"][1]["ok"] is False
    assert "no RPC equivalent" in entry["error"]


def test_cli_batch_raw_and_verbose_print_the_document_pretty(monkeypatch, capsys, tmp_path):
    batch = tmp_path / "cmds.txt"
    batch.write_text("show version\n")
    v = FakeVendor({"show version": {"a": 1}})
    pretty = json.dumps({"a": 1}, indent=2)
    _, out, _ = run_cli(monkeypatch, capsys, v, "--batch", str(batch), "--format", "json", "--raw", *R1)
    assert out == "R1:\n" + pretty + "\n\n"
    _, out, _ = run_cli(monkeypatch, capsys, v, "--batch", str(batch), "--format", "json", "-v", *R1)
    assert pretty in out


def test_cli_diff_compares_the_pretty_printed_json(monkeypatch, capsys):
    rc, out, _ = run_cli(monkeypatch, capsys, FakeVendor(), "-sC", "show version", "--format", "json",
                         "--diff", "--json", *R1, "--target", "R2:10.0.0.2:junos")
    assert rc == 0
    other = next(e for e in json.loads(out) if e["diff"] != "(baseline)")
    assert '-  "host": "10.0.0.' in other["diff"] and '+  "host": "10.0.0.' in other["diff"]


class TwoRouters(FakeVendor):
    """R1 and R2, each with its own reply to every show, ended with a newline
    as a router ends it; the CLI trims a reply, so its last line has none."""

    def __init__(self, r1, r2):
        super().__init__()
        self.by_host = {"10.0.0.1": r1, "10.0.0.2": r2}

    def show(self, host, user, passwd, cmd, st, ct, port=None, vendor_hint=None):
        return self.by_host[host]

    def show_batch(self, host, user, passwd, cmds, st, ct, port=None, vendor_hint=None):
        return [{"command": c, "ok": True, "output": self.by_host[host]} for c in cmds]


VMX = "Model: vmx\nJunos: 24.2R1-S2.5\n"

# R1's reply, R2's, and the hunk of R2 against R1: the last line changed (a
# new release), a line added after it (one more peer), or the line after it
# taken away (one peer fewer).
LAST_LINE = {
    "changed": (VMX, "Model: vmx\nJunos: 23.4R2.13\n",
                "@@ -1,2 +1,2 @@\n Model: vmx\n-Junos: 24.2R1-S2.5\n+Junos: 23.4R2.13"),
    "added": (VMX, VMX + "Peer: 10.9.9.8\n",
              "@@ -1,2 +1,3 @@\n Model: vmx\n Junos: 24.2R1-S2.5\n+Peer: 10.9.9.8"),
    "removed": (VMX + "Peer: 10.9.9.8\n", VMX,
                "@@ -1,3 +1,2 @@\n Model: vmx\n Junos: 24.2R1-S2.5\n-Peer: 10.9.9.8"),
}

TWO = [*R1, "--target", "R2:10.0.0.2:junos"]


def answers_last(monkeypatch, last):
    """The runner as it is, except that device `last` answers only once the
    other one has, and some turns of the event loop later, so the other's
    answer is taken in first: a slower router, made certain."""
    other_in = asyncio.Event()

    async def run(**kw):
        result = await runner.run_for_target_async(**kw)
        if kw["t"].name != last:
            other_in.set()
            return result
        await other_in.wait()
        for _ in range(20):
            await asyncio.sleep(0)
        return result

    monkeypatch.setattr(cli, "run_for_target_async", run)


def show_or_batch(tmp_path, batch):
    if not batch:
        return ["-sC", "show version"]
    cmds = tmp_path / "cmds.txt"
    cmds.write_text("show version\n")
    return ["--batch", str(cmds)]


@pytest.mark.parametrize("batch", [False, True], ids=["show", "batch"])
def test_cli_diff_baseline_is_the_first_device_given_whoever_answers_first(monkeypatch, capsys, tmp_path, batch):
    """R1 is given first and is the baseline whether it answers first or last,
    and --json lists it first: one command line diffs the same way every run,
    in --json and on screen."""
    what = show_or_batch(tmp_path, batch)
    r1, r2, _ = LAST_LINE["changed"]
    diffs = []
    for last in ("R1", "R2"):
        answers_last(monkeypatch, last)
        rc, out, _ = run_cli(monkeypatch, capsys, TwoRouters(r1, r2), *what, "--diff", "--json", *TWO)
        results = json.loads(out)
        assert rc == 0 and [e["device"] for e in results] == ["R1", "R2"] and results[0]["diff"] == "(baseline)"
        diffs.append(results[1]["diff"])
        answers_last(monkeypatch, last)
        rc, out, _ = run_cli(monkeypatch, capsys, TwoRouters(r1, r2), *what, "--diff", *TWO)
        assert rc == 0 and "--- Diff (baseline: R1) ---" in out and "  R1 vs R2:" in out
    assert diffs[0] == diffs[1]
    diff = diffs[0][0]["diff"] if batch else diffs[0]
    assert "-Junos: 24.2R1-S2.5" in diff and "+Junos: 23.4R2.13" in diff      # R1's line is the one taken away


@pytest.mark.parametrize("shape", LAST_LINE)
@pytest.mark.parametrize("batch", [False, True], ids=["show", "batch"])
def test_cli_diff_treats_the_trimmed_last_line_like_any_other(monkeypatch, capsys, tmp_path, batch, shape):
    """A trimmed reply has no newline after its last line; the diff still
    takes it as a line like any other, in the --json field and on screen.
    Changed, it is a line taken away and a line put in, a line each; left as
    it was, with a line added or taken away after it, it is no change."""
    r1, r2, hunk = LAST_LINE[shape]
    diff = "--- R1\n+++ R2\n" + hunk
    what = show_or_batch(tmp_path, batch)
    rc, out, _ = run_cli(monkeypatch, capsys, TwoRouters(r1, r2), *what, "--diff", "--json", *TWO)
    got = {e["device"]: e for e in json.loads(out)}["R2"]["diff"]
    assert rc == 0 and (got[0]["diff"] if batch else got) == diff
    rc, out, _ = run_cli(monkeypatch, capsys, TwoRouters(r1, r2), *what, "--diff", *TWO)
    indent = " " * (6 if batch else 4)
    assert rc == 0 and "".join(f"{indent}{ln}\n" for ln in diff.split("\n")) in out


def test_cli_job_show_entries_are_data_and_edit_entries_text(monkeypatch, capsys, tmp_path):
    job = tmp_path / "job.json"
    job.write_text(json.dumps([
        {"target": "R1:10.0.0.1:junos", "show": "show version"},
        {"target": "R2:10.0.0.2:junos", "edit": "set system host-name r2"},
    ]))

    v = FakeVendor({"show version": {"a": 1}})
    rc, out, _ = run_cli(monkeypatch, capsys, v, "--job", str(job), "--format", "json", "--json", "-y")
    assert rc == 0
    by_name = {e["device"]: e for e in json.loads(out)}
    assert by_name["R1"]["output"] == {"a": 1}
    assert by_name["R2"]["output"].startswith("COMMIT OK")


def test_cli_format_is_refused_where_nothing_is_shown(monkeypatch, capsys, tmp_path):
    """An edit, --rollback or --commit-status has no reply for --format to
    shape; so has a job without a show entry. Refused before any driver call."""
    job = tmp_path / "job.json"
    job.write_text(json.dumps([{"target": "R1:10.0.0.1:junos", "edit": "set system host-name r1"}]))
    for argv in (["-eC", "set system host-name x", "-y", *R1],
                 ["--rollback", "1", "-y", *R1],
                 ["--commit-status", *R1],
                 ["--job", str(job), "-y"]):
        v = FakeVendor()
        rc, _, err = run_cli(monkeypatch, capsys, v, "--format", "json", *argv)
        assert rc == 2 and "--format goes with a show" in err and v.calls == []


def test_cli_a_batch_under_format_is_reads_only_before_any_device(monkeypatch, capsys, tmp_path):
    """#110: -sC "request system reboot" was refused under --format; a --batch
    line like it went to rpc_batch with the rest. Both are now a usage error
    before anything is opened or sent; as text the line is sent, once."""
    batch = tmp_path / "cmds.txt"
    batch.write_text("show version\nrequest system reboot\n")
    for argv in (["--batch", str(batch), "--format", "json"], ["--batch", str(batch), "--format", "xml"],
                 ["-sC", "request system reboot", "--format", "json"]):
        v = FakeVendor()
        rc, _, err = run_cli(monkeypatch, capsys, v, *argv, *R1)
        assert rc == 2 and v.calls == [], err
        assert "runs reads only (show …, get-*); 'request system reboot' would act on the device" in err
        assert not Path(os.environ["HSSH_STORE"]).exists()             # no run was kept: none began
    v = FakeVendor()
    rc, _, err = run_cli(monkeypatch, capsys, v, "--batch", str(batch), *R1)
    assert rc == 0 and v.calls == [("show_batch", ["show version", "request system reboot"], None)], err


def test_structured_and_format_is_a_usage_error():
    hssh = os.path.join(os.path.dirname(__file__), "..", "h-ssh.py")
    proc = subprocess.run(
        [sys.executable, hssh, "--target", "x:1.2.3.4:junos", "-sC", "show version",
         "--structured", "--format", "json"],
        capture_output=True, text=True, timeout=30)
    assert proc.returncode == 2
    assert "mutually exclusive" in proc.stderr
