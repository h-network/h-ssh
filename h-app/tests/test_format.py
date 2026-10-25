"""--format json|xml: the router's own reply through rpc() instead of show() text."""
import asyncio
import json
import os
import subprocess
import sys

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


def test_cli_job_show_entries_are_data_and_edit_entries_text(monkeypatch, capsys, tmp_path):
    job = tmp_path / "job.json"
    job.write_text(json.dumps([
        {"target": "R1:10.0.0.1:junos", "show": "show version"},
        {"target": "R2:10.0.0.2:junos", "edit": "set system host-name r2"},
    ]))

    async def reachable(target, timeout=2):
        return target.name, True, "reachable"

    monkeypatch.setattr(cli, "check_reachability", reachable)
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


def test_structured_and_format_is_a_usage_error():
    hssh = os.path.join(os.path.dirname(__file__), "..", "h-ssh.py")
    proc = subprocess.run(
        [sys.executable, hssh, "--target", "x:1.2.3.4:junos", "-sC", "show version",
         "--structured", "--format", "json"],
        capture_output=True, text=True, timeout=30)
    assert proc.returncode == 2
    assert "mutually exclusive" in proc.stderr
