"""#67: the transports agree on what a password means, an edit's verdict
comes from the reply as well as the exit status, a delete of what is not
there is not a failure, and the open-file limit is checked before it bites."""
import asyncio
import os
import stat
import sys
import types
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hssh import cli, vendors
from hssh.core import refusal_line
from hssh.vendors import openssh


# --- M5: the password is the credential on every transport ------------------------

def test_openssh_offers_no_key_when_a_password_is_given():
    with_pw = openssh._base_opts(5, None, None, True)
    without = openssh._base_opts(5, None, None, False)
    assert "PubkeyAuthentication=no" in with_pw and "IdentitiesOnly=yes" in with_pw
    assert "BatchMode=yes" not in with_pw
    assert "PubkeyAuthentication=no" not in without and "BatchMode=yes" in without


# --- M6: the device's own refusal ------------------------------------------------

def test_refusal_line_reads_junos_and_ios_refusals():
    assert refusal_line("", "error: syntax error, expecting <statement>\n") == "error: syntax error, expecting <statement>"
    assert refusal_line("% Invalid input detected at '^' marker.\n", "") == "% Invalid input detected at '^' marker."
    assert refusal_line("ok\n  error: unknown command\n") == "error: unknown command"
    assert refusal_line("no error: here\n", "100% done\n", None) is None
    # the Junos CLI over an exec channel answers with a leading blank line
    assert refusal_line("", "\nerror: syntax error, expecting <command>: bad-line\n") == \
        "error: syntax error, expecting <command>: bad-line"


def test_refused_reply_is_a_refusal_that_opens_the_reply():
    """#88: a show the CLI refuses says so first and nothing else; the same
    words further down a reply are output (a log)."""
    from hssh.core import refused_reply
    assert refused_reply("", "error: unknown command: uptime\n") == "error: unknown command: uptime"
    assert refused_reply("", "\n  error: syntax error, expecting <command>: x\n") == "error: syntax error, expecting <command>: x"
    assert refused_reply("", "           ^\n% Invalid input detected at '^' marker.\n") == "% Invalid input detected at '^' marker."
    assert refused_reply("% Bad command\n", "") == "% Bad command"
    assert refused_reply("", "Oct 24 12:00:00 r1 rpd[1]: error: link down\n") is None
    assert refused_reply("", "line one\nerror: later\n") is None
    assert refused_reply("", "") is None and refused_reply("", "100% done\n") is None


@pytest.fixture
def fake_ssh(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "ssh"
    script.write_text("#!/bin/sh\n"
                      'for arg in "$@"; do last="$arg"; done\n'
                      'case "$last" in *bad*) echo "error: syntax error"; exit 0;; esac\n'
                      'echo "ok: $last"\n')
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ["PATH"])
    monkeypatch.setattr(openssh, "AVAILABLE", True)
    return script


def test_openssh_edit_stops_at_the_refused_line(fake_ssh):
    with pytest.raises(RuntimeError, match="'set bad line' was refused by the device: error: syntax error"):
        openssh.edit("h", "u", None, "set good line\nset bad line\nset never sent\n", 5, 5)
    # A show the CLI refuses is failed too, not handed back as its output (#88).
    with pytest.raises(RuntimeError, match="'show bad' was refused by the device: error: syntax error"):
        openssh.show("h", "u", None, "show bad", 5, 5)
    assert "ok: show good" in openssh.show("h", "u", None, "show good", 5, 5)


def test_a_server_that_closes_after_the_password_is_a_failed_login():
    proc = openssh._Result(["ssh"], 255, "", "", "Connection closed by 10.0.0.1 port 22",
                           "debug1: read_passphrase: requested to askpass\nConnection closed by 10.0.0.1 port 22\n")
    assert openssh._describe_failure("10.0.0.1", proc) == (
        "Authentication failed: 10.0.0.1 closed the connection after the password was offered "
        "(wrong password, or password login is off on the server).")
    before_auth = openssh._Result(["ssh"], 255, "", "", "Connection closed by 10.0.0.1 port 22",
                                  "debug1: Connecting to 10.0.0.1 port 22.\nConnection closed by 10.0.0.1 port 22\n")
    assert openssh._describe_failure("10.0.0.1", before_auth) == "ssh exit 255: Connection closed by 10.0.0.1 port 22"


# --- L10: the open-file limit --------------------------------------------------

def _rlimits(monkeypatch, soft, hard, settable=True):
    import resource
    state = {"soft": soft, "hard": hard, "set": []}

    def getrlimit(which):
        assert which == resource.RLIMIT_NOFILE
        return state["soft"], state["hard"]

    def setrlimit(which, limits):
        state["set"].append(limits)
        if not settable:
            raise ValueError("not permitted")
        state["soft"], state["hard"] = limits
    monkeypatch.setattr(resource, "getrlimit", getrlimit)
    monkeypatch.setattr(resource, "setrlimit", setrlimit)
    return state


def test_a_short_soft_limit_is_raised_towards_the_hard_one_first(monkeypatch):
    state = _rlimits(monkeypatch, 1024, 65536)
    assert cli.fit_workers_to_open_files(256) == (256, None)
    assert state["set"] == [(256 * cli.FDS_PER_WORKER + cli.FDS_BASE, 65536)]
    assert cli.fit_workers_to_open_files(8) == (8, None) and len(state["set"]) == 1   # enough already


def test_workers_are_lowered_to_what_the_limit_carries(monkeypatch):
    _rlimits(monkeypatch, 64, 64, settable=False)
    fit, note = cli.fit_workers_to_open_files(64)
    assert fit == (64 - cli.FDS_BASE) // cli.FDS_PER_WORKER == 5
    assert note == "the open-file limit of 64 (ulimit -n) carries 5 workers at ~6 descriptors each, not 64; running 5"
    import resource
    _rlimits(monkeypatch, resource.RLIM_INFINITY, resource.RLIM_INFINITY)
    assert cli.fit_workers_to_open_files(256) == (256, None)


async def _reachable(target, timeout=2):
    return (target.name, True, "reachable")


def test_the_run_warns_once_and_runs_with_the_lowered_workers(monkeypatch, capsys):
    _rlimits(monkeypatch, 64, 64, settable=False)
    driver = types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: "ok")
    monkeypatch.setitem(vendors.VENDORS, "junos", driver)
    monkeypatch.setitem(cli.VENDOR_MODULES, "junos", driver)
    monkeypatch.setattr(cli, "check_reachability", _reachable)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "--password", "p",
                                      "--target", "R1:10.0.0.1:junos", "--workers", "64", "-sC", "show version"])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    assert rc == 0
    assert err.count("WARNING: the open-file limit of 64 (ulimit -n) carries 5 workers") == 1
    assert "Workers: 5" in out
