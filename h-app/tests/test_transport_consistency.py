"""#67: the transports agree on what a password means, an edit's verdict
comes from the reply as well as the exit status, a delete of what is not
there is not a failure, and the open-file limit is checked before it bites;
#133: and none sends a set file's comment line as a command; #139: nor a
set file with a control character in it, and a Tab only where no CLI is
typed at."""
import asyncio
import json
import os
import stat
import sys
import types
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hssh import cli, drivers
from hssh.core import refusal_line
from hssh.transports import openssh


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


def test_a_line_on_stderr_does_not_hide_a_refusal_that_opens_stdout():
    """#143: refused_reply stopped at the first line of the first text it
    was given, stderr's: a warning there, or a login message, hid the
    refusal opening stdout, and `show foo` was an OK show with the refusal
    for its output, stored as the baseline. The reply is stdout, judged
    first; stderr only when stdout says nothing."""
    from hssh.core import refused_reply
    refusal = "error: syntax error, expecting <command>"
    assert refused_reply("warning: y", refusal) == refusal
    assert refused_reply("Welcome to r1\n", "\n" + refusal + ": foo\n", dialect=drivers.JUNOS) == refusal + ": foo"
    assert refused_reply("error: in maintenance window\n", "Hostname: r1\n", dialect=drivers.JUNOS) is None
    assert refused_reply("% Invalid input detected\n", "\n   \n") == "% Invalid input detected"


@pytest.fixture
def fake_ssh(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "ssh"
    script.write_text("#!/bin/sh\n"
                      'case " $* " in *" -G "*) for a; do h="$a"; done; echo "hostname ${h#*@}"; exit 0;; esac\n'   # ssh -G, as OpenSSH answers it
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


def test_the_sessions_the_pool_keeps_are_counted_in_the_open_file_limit(monkeypatch):
    """#147: the fit budgeted the workers alone, and every junos device of a
    Fleet or a --job keeps a pooled session of ~4 descriptors beside them:
    300 routers at the common soft limit of 1024 failed 46 of them with
    "Too many open files". The soft limit is raised for those sessions too."""
    from hssh import limits
    state = _rlimits(monkeypatch, 1024, 65536)
    assert cli.fit_workers_to_open_files(8, pooled=300) == (8, None)
    assert state["set"] == [(8 * cli.FDS_PER_WORKER + 300 * limits.FDS_PER_SESSION + cli.FDS_BASE, 65536)]
    assert limits.FDS_PER_SESSION == 4
    assert cli.fit_workers_to_open_files(8, pooled=300) == (8, None) and len(state["set"]) == 1    # enough now


def test_a_hard_limit_short_of_the_pooled_sessions_lowers_no_workers_and_says_what_it_keeps(monkeypatch):
    """What even the hard limit cannot hold is not failed as healthy
    routers, nor taken out of the workers: the pool keeps what fits and
    closes its least recently used idle session for the next one."""
    state = _rlimits(monkeypatch, 1024, 1024)
    fit, note = cli.fit_workers_to_open_files(8, pooled=300)
    assert fit == 8 and state["set"] == []                  # nothing to raise it to
    assert note == ("the open-file limit of 1024 (ulimit -n) keeps 236 of the 300 pooled sessions open at "
                    "~4 descriptors each: the least recently used idle one is closed when another must open, "
                    "and opened again when it is wanted")
    _rlimits(monkeypatch, 64, 64, settable=False)
    fit, note = cli.fit_workers_to_open_files(64, pooled=10)
    assert fit == 5 and note.startswith("the open-file limit of 64 (ulimit -n) carries 5 workers at ~6 descriptors "
                                        "each, not 64; running 5, and it keeps 0 of the 10 pooled sessions open")


def test_the_run_warns_once_and_runs_with_the_lowered_workers(monkeypatch, capsys):
    _rlimits(monkeypatch, 64, 64, settable=False)
    driver = types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: "ok")
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", driver)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u",
                                      "--target", "R1:10.0.0.1:junos", "--workers", "64", "-sC", "show version"])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    assert rc == 0
    assert err.count("WARNING: the open-file limit of 64 (ulimit -n) carries 5 workers") == 1
    assert "Workers: 5" in out


# --- #133: a set file's comment lines are no command on any driver -----------------

SET_FILE = ("# change 42\n"
            "set snmp community ab#12 authorization read-only\n"
            "\n"
            "   # indented, a comment all the same\n"
            'set interfaces ge-0/0/0 description "uplink #3"\n'
            "# end\n")


@pytest.mark.parametrize("flag", ["-eD", "-eB"])
@pytest.mark.parametrize("transport", ["ssh", "openssh"])
def test_a_set_files_comment_lines_are_not_sent_as_commands(monkeypatch, capsys, tmp_path, transport, flag):
    """-eD and -eB on the plain ssh and openssh drivers ran every line of the
    file as a command of its own, a full-line '#' comment too, where junos
    and the dialects' CLI engine dropped it. Blank and comment lines are now
    dropped before any driver gets the payload; a '#' inside a line is part
    of it, as written."""
    from hssh.drivers import results as R
    from hssh.transports import ssh
    module = ssh if transport == "ssh" else openssh
    sent = []

    def run_commands(host, user, passwd, commands, *a, **kw):
        sent.append(list(commands))
        return R.EditResult(R.APPLIED, message="".join(f"$ {c}\n" for c in commands))
    monkeypatch.setattr(module, "_run_commands", run_commands)
    monkeypatch.setattr(module, "AVAILABLE", True)
    (tmp_path / "R1.set").write_text(SET_FILE)
    source = ["-eD", str(tmp_path)] if flag == "-eD" else ["-eB", str(tmp_path / "R1.set")]
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", *source, "-y",
                                      f"R1:10.0.0.1:{transport}"])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    assert rc == 0, err
    assert sent == [["set snmp community ab#12 authorization read-only",
                     'set interfaces ge-0/0/0 description "uplink #3"']]


@pytest.mark.parametrize("flag", ["-eD", "-eB"])
@pytest.mark.parametrize("transport", ["ssh", "openssh"])
def test_a_set_file_with_nothing_but_comments_is_refused_before_anything_is_sent(monkeypatch, capsys, tmp_path,
                                                                                 transport, flag, probed):
    """#133 review: a -eD or -eB file of blank and '#' lines alone left the
    plain ssh and openssh drivers nothing to send: they logged in, sent
    nothing and said OK, exit 0, where the Junos guard refuses such a file.
    Refused on every driver now: exit 2 naming the file, before anything is
    probed, written or sent."""
    from hssh.drivers import results as R
    from hssh.transports import ssh
    module = ssh if transport == "ssh" else openssh
    sent = []

    def run_commands(host, user, passwd, commands, *a, **kw):
        sent.append(list(commands))
        return R.EditResult(R.APPLIED, message="".join(f"$ {c}\n" for c in commands))
    monkeypatch.setattr(module, "_run_commands", run_commands)
    monkeypatch.setattr(module, "AVAILABLE", True)
    (tmp_path / "R1.set").write_text("# change 42, to come\n\n   # nothing yet\n")
    source = ["-eD", str(tmp_path)] if flag == "-eD" else ["-eB", str(tmp_path / "R1.set")]
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", *source, "-y",
                                      f"R1:10.0.0.1:{transport}"])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    assert rc == 2 and "nothing but blank lines and '#' comments" in err and "Nothing was sent." in err, err
    assert ("R1.set" if flag == "-eD" else str(tmp_path / "R1.set")) in err
    assert sent == [] and probed == [] and not os.path.exists(os.environ["HSSH_STORE"])


@pytest.mark.parametrize("line, what", [("set system host-name x\x03commit comment y", "a control character '\\x03'"),
                                        ("set a\x15commit", "a control character '\\x15'"),
                                        ("set " + "\x7f" * 4 + "commit", "a DEL")])
def test_a_set_file_with_a_control_character_is_refused_before_anything_is_sent(monkeypatch, capsys, tmp_path,
                                                                                line, what, probed):
    """#139: -eB and -eD files (and a run file's edit-broadcast and
    edit-dir, which name them) were never held to -eC's rule. The Junos line
    editor acts on ^C, ^U and DEL as they arrive and ran the rest of the line
    on its own: `commit comment y` committed for good while --dry-run said
    DRY-RUN, exit 0. Refused on every driver now, exit 2 naming the file and
    the line, before anything is probed, written or sent."""
    sent = []

    async def fake_run(t, transport, mode, *a, **kw):
        sent.append(t.name)
        return t.name, True, "ok\n", 1
    monkeypatch.setattr(cli, "run_for_target_async", fake_run)
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", types.SimpleNamespace(AVAILABLE=True))
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    sets = tmp_path / "sets"
    sets.mkdir()
    (sets / "R1.set").write_text("set system domain-name lab\n" + line + "\n")
    for vendor in ("junos@ssh", "junos", "ssh"):
        target = f"R1:10.0.0.1:{vendor}"
        for i, how in enumerate((["-eB", str(sets / "R1.set")], ["-eD", str(sets)],
                                 {"edit-broadcast": "sets/R1.set"}, {"edit-dir": "sets"})):
            if isinstance(how, dict):
                run = tmp_path / f"run{i}.json"
                run.write_text(json.dumps({"devices": [target], "dry-run": True, **how}))
                argv = ["--run", str(run)]
            else:
                argv = [*how, "--dry-run", target]
            monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "-y", *argv])
            rc = asyncio.run(cli.main())
            out, err = capsys.readouterr()
            flag = "-eB" if "-eB" in argv or "edit-broadcast" in how else "-eD"
            assert rc == 2 and f"ERROR: {flag} {sets / 'R1.set'}: line 2 has {what} ({line!r}); " \
                                f"a payload is plain text." in err, (vendor, how, err)
    assert sent == [] and probed == [] and not os.path.exists(os.environ["HSSH_STORE"])


def test_a_tab_is_text_to_netconf_and_a_key_to_a_cli_typed_at(monkeypatch, capsys, tmp_path):
    """#139: NETCONF's `load set` reads a Tab as a space, so a Tab-indented
    set file works on junos as it always did. Typed at a CLI, a Tab
    completes the word: junos@ssh and every driver that types at a CLI
    refuse the file themselves, before they connect, a FAIL of that device
    with nothing sent, beside the junos device that got the file as written."""
    from hssh.transports import ssh
    got = []

    def netconf_edit(host, user, passwd, payload, *a, **kw):
        got.append(payload)
        return "DRY-RUN\n\nDIFF:\n[edit system]\n+   host-name x;"

    class NeverConnects:
        def __init__(self, *a, **kw):
            raise AssertionError("connected although the payload was refused before any device I/O")
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", types.SimpleNamespace(AVAILABLE=True, edit=netconf_edit))
    monkeypatch.setattr(ssh.paramiko, "SSHClient", NeverConnects)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    broadcast = tmp_path / "all.set"
    broadcast.write_text("\tset system host-name x\n")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "-eB", str(broadcast),
                                      "--dry-run", "-y", "--json", "R1:10.0.0.1:junos", "R2:10.0.0.2:junos@ssh"])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    by_name = {r["device"]: r for r in json.loads(out)}
    assert rc == 1, err
    assert got == ["\tset system host-name x\n"] and by_name["R1"]["ok"] is True
    assert by_name["R2"]["ok"] is False and by_name["R2"]["error"] == (
        "'\\tset system host-name x' has a Tab, which a CLI takes as a key, not as text; "
        "nothing was sent to the device")


# --- #142: an edit with nothing to apply, by the target's dialect -------------------

class RecordingEdit:
    """A driver's module that records every edit it is asked for."""
    AVAILABLE = True

    def __init__(self):
        self.sent = []

    def edit(self, host, user, passwd, payload, *a, **kw):
        self.sent.append(payload)
        return "(config applied)"


def _main(monkeypatch, capsys, *argv, ask=None):
    """cli.main() as typed at a terminal with no HSSH_PASSWORD: the password
    would be asked, and `ask` lists every question."""
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_USER", "HSSH_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(cli, "_tty", lambda stream: True)
    monkeypatch.setattr(cli, "_ask", lambda prompt, secret=False: ask.append(prompt) or "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "-y", *argv])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    return rc, err


def test_an_edit_of_nothing_but_the_dialects_comments_is_refused_before_anything_is_sent(monkeypatch, capsys,
                                                                                        tmp_path, probed):
    """#142: a -eB or -eD file of `!` lines passed the check for blank and
    '#' lines, and ios@ssh typed `configure terminal` and `end` and said OK,
    exit 0; so did -eC '! x' and -eC '# x', which had no such check, a run
    file's `edit` and a job's edit of `!` lines. A comment is the target
    dialect's ('#', and '!' for an IOS-shaped one): a payload of nothing
    else is refused per target, exit 2, before anything is probed, asked,
    written or sent, a run file's said as its key. Where only some targets
    would get nothing, they are named; to the plain ssh driver a '!' line
    is a line, sent as written."""
    ios, plain = RecordingEdit(), RecordingEdit()
    monkeypatch.setitem(drivers.MODULES, "ios@ssh", ios)
    monkeypatch.setitem(drivers.MODULES, "none@ssh", plain)
    bangs = tmp_path / "bang.cfg"
    bangs.write_text("! nothing but IOS comments\n\n  ! a second one\n")
    sets = tmp_path / "sets"
    sets.mkdir()
    (sets / "SW1.set").write_text(bangs.read_text())
    job = tmp_path / "job.json"
    job.write_text(json.dumps([{"target": "SW1:10.0.0.1:ios@ssh", "edit": "! x\n# y"}]))
    kinds = "nothing but blank lines and '#' or '!' comments"
    for argv, said in (
            (["-eB", str(bangs)], f"ERROR: -eB {bangs}: {kinds} in it. Nothing was sent."),
            (["-eD", str(sets)], f"ERROR: -eD {sets}: {kinds} in SW1.set. Nothing was sent."),
            (["-eC", "! x"], f"ERROR: -eC '! x' has {kinds} in it. Nothing was sent."),
            (["-eC", "# x"], f"ERROR: -eC '# x' has {kinds} in it. Nothing was sent."),
            (["-eB", str(bangs), "R2:10.0.0.2:ssh"], f"ERROR: -eB {bangs}: {kinds} in it for SW1. Nothing was sent.")):
        asked = []
        rc, err = _main(monkeypatch, capsys, *argv, "SW1:10.0.0.1:ios@ssh", ask=asked)
        assert rc == 2 and said in err, (argv, err)
        assert asked == [] and ios.sent == plain.sent == [] and probed == [], argv
    asked = []
    rc, err = _main(monkeypatch, capsys, "--job", str(job), ask=asked)
    assert rc == 2 and (f"ERROR: Invalid job file: Job entry 0 (SW1): 'edit' has {kinds} in it. "
                        "Nothing was sent.") in err, err
    run = tmp_path / "run.json"
    run.write_text(json.dumps({"devices": ["SW1:10.0.0.1:ios@ssh"], "edit": "! x\n! y"}))
    rc, err = _main(monkeypatch, capsys, "--run", str(run), ask=asked)
    assert rc == 2 and f"ERROR: run file '{run}': 'edit' has {kinds} in it. Nothing was sent." in err, err
    assert asked == [] and ios.sent == [] and probed == [] and not os.path.exists(os.environ["HSSH_STORE"])
    rc, err = _main(monkeypatch, capsys, "-eB", str(bangs), "R2:10.0.0.2:ssh", ask=asked)
    assert rc == 0 and plain.sent == ["! nothing but IOS comments\n  ! a second one\n"], err


def test_a_job_edit_of_whitespace_is_refused_before_anything_is_sent(monkeypatch, capsys, tmp_path, probed):
    """#142: a --job edit of whitespace on a plain ssh target logged in,
    sent nothing and came back `ok: true`, exit 0: only a show was checked
    for emptiness. Refused with the job file's other mistakes, exit 2,
    before the password prompt and the probe; no driver is called."""
    from hssh.transports import ssh
    calls = []
    monkeypatch.setattr(ssh, "_run_commands", lambda *a, **kw: calls.append(a) or "")
    job = tmp_path / "job.json"
    for edit in ("", "  \n "):
        job.write_text(json.dumps([{"target": "R1:10.0.0.1:ssh", "show": "uptime"},
                                   {"target": "R2:10.0.0.2:ssh", "edit": edit}]))
        asked = []
        rc, err = _main(monkeypatch, capsys, "--job", str(job), "--json", ask=asked)
        assert rc == 2 and "ERROR: Invalid job file: Job entry 1 (R2): 'edit' is empty" in err, err
        assert calls == [] and asked == [] and probed == []


# --- #143: a NETCONF show answered with an error as its output text ----------------

import re
import socket
import threading

from hssh import runner
from hssh.core import Target

_NETCONF_HELLO = (b'<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities>'
                  b'<capability>urn:ietf:params:netconf:base:1.0</capability></capabilities>'
                  b'<session-id>1</session-id></hello>]]>]]>')


@pytest.fixture
def netconf_sshd():
    """netconf_sshd(output) -> (port, commands): a NETCONF server on
    127.0.0.1 (paramiko's, the netconf subsystem, anyone in with a password)
    that answers every <command> RPC with `output` as the <output> text of
    its reply, as Junos carries what its CLI said, and <close-session> with
    <ok/>; `commands` is every <command> it answered."""
    paramiko = pytest.importorskip("paramiko")
    pytest.importorskip("jnpr.junos")
    from hssh.transports import netconf
    key = paramiko.ECDSAKey.generate()
    opened = []

    class Sshd(paramiko.ServerInterface):
        def __init__(self, output, commands):
            self.output, self.commands = output, commands

        def get_allowed_auths(self, username):
            return "password"

        def check_auth_password(self, username, password):
            return paramiko.AUTH_SUCCESSFUL

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED

        def check_channel_subsystem_request(self, channel, name):
            if name != "netconf":
                return False
            threading.Thread(target=self.serve, args=(channel,), daemon=True).start()
            return True

        def serve(self, channel):
            channel.sendall(_NETCONF_HELLO)
            pending = b""
            while True:
                data = channel.recv(65536)
                if not data:
                    return
                pending += data
                while b"]]>]]>" in pending:
                    message, pending = pending.split(b"]]>]]>", 1)
                    mid = re.search(rb'message-id="([^"]+)"', message)
                    if mid is None:
                        continue                         # the client's hello
                    reply = (b'<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="'
                             + mid.group(1) + b'">')
                    if b"close-session" in message:
                        channel.sendall(reply + b"<ok/></rpc-reply>]]>]]>")
                        channel.close()
                        return
                    command = re.search(rb"<command[^>]*>(.*?)</command>", message, re.S)
                    if command:
                        self.commands.append(command.group(1).decode())
                    channel.sendall(reply + b"<output>" + self.output.encode() + b"</output></rpc-reply>]]>]]>")

    def make(output):
        commands = []
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        opened.append(srv)

        def serve():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                t = paramiko.Transport(conn)
                t.add_server_key(key)
                opened.append(t)
                try:
                    t.start_server(server=Sshd(output, commands))
                except (paramiko.SSHException, EOFError, OSError):
                    pass
        threading.Thread(target=serve, daemon=True).start()
        return srv.getsockname()[1], commands
    yield make
    netconf.wait_for_closes(5)
    for each in opened:
        each.close()


def test_a_netconf_show_answered_with_an_error_for_its_output_is_refused(netconf_sshd):
    """netconf.show handed back the text of the <command> reply with no
    look at it, where ssh and openssh run the reply verdict: a router that
    answered `show log nosuchfile` with `error: could not resolve file:
    nosuchfile` as its <output> was an OK show (most refusals come as an
    rpc-error, and fail as one). Refused now, alone and in a batch, and the
    runner sends it once."""
    from hssh.transports import netconf
    port, commands = netconf_sshd("\nerror: could not resolve file: nosuchfile\n")
    refused = "'show log nosuchfile' was refused by the device: error: could not resolve file: nosuchfile"
    with pytest.raises(RuntimeError) as failed:
        netconf.show("127.0.0.1", "u", "p", "show log nosuchfile", 10, 10, port=port)
    assert str(failed.value) == refused
    assert list(netconf.show_batch("127.0.0.1", "u", "p", ["show log nosuchfile"], 10, 10, port=port)) == [
        {"command": "show log nosuchfile", "ok": False, "error": refused}]
    assert commands == ["show log nosuchfile"] * 2
    result = runner.run_for_target(
        t=Target("R1", "127.0.0.1", "junos", port), transport="junos", mode="show",
        show_cmd="show log nosuchfile", edit_cmd=None, config_dir=None, broadcast_file=None, user="u",
        passwd="p", session_timeout=10, command_timeout=10, dry_run=False, commit_confirmed=None,
        save_dir=None, quiet=True, max_attempts=3)
    assert not result.ok and result.error == refused
    assert commands == ["show log nosuchfile"] * 3                 # one attempt: a refusal is not tried again
