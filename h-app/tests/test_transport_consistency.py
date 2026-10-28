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
