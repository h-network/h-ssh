"""#83: the dialect drivers on the OpenSSH transport. junos@openssh,
ios@openssh, nxos@openssh and eos@openssh run their shows on an exec like
the plain `openssh` driver, and their edits and confirms through the CLI
engine on `ssh -tt`. The ssh here is a fake on PATH that plays a device CLI
on its pipes; no live device is needed."""
import os
import stat
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hssh import drivers, runner
from hssh.core import Target
from hssh.drivers import contract
from hssh.drivers import results as R
from hssh.errors import ConnectTimeoutError, NotAppliedError, NothingToConfirmError
from hssh.transports import openssh

FAKE_SSH = r'''
"""A fake ssh. `ssh -V` prints a version. With -tt it plays a device CLI on
its stdin and stdout, a Junos one unless FAKE_SSH_FLAVOUR is ios, and appends
every line typed at it to the file FAKE_SSH_TYPED names. Without -tt it
answers the command on its command line the way the plain fake in
test_openssh.py does, and a `| json` command with JSON. A password is checked
through SSH_ASKPASS: anything but FAKE_SSH_PASSWORD is refused in the -E log
the way OpenSSH refuses one."""
import os
import subprocess
import sys
import time

args = sys.argv[1:]
if args == ["-V"]:
    sys.stderr.write("OpenSSH_9.6p1 fake\n")
    sys.exit(0)

LOG = args[args.index("-E") + 1] if "-E" in args else None


def log(text):
    if LOG:
        with open(LOG, "a") as fh:
            fh.write(text)


def typed(line):
    with open(os.environ["FAKE_SSH_TYPED"], "a") as fh:
        fh.write(line + "\n")


def say(text):
    os.write(1, text.encode())


log("debug1: Connecting to 10.0.0.1 port 22.\n")
if os.environ.get("FAKE_SSH_HANG") == "tcp":          # the TCP connect gets no answer
    time.sleep(30)
    sys.exit(255)
log("debug1: Connection established.\n")
if os.environ.get("FAKE_SSH_HANG") == "silent":       # connected, and no banner
    time.sleep(30)
    sys.exit(255)
if os.environ.get("FAKE_SSH_HANG") == "kex":
    log("debug1: Remote protocol version 2.0, remote software version fake\n")
    time.sleep(30)
    sys.exit(255)

helper = os.environ.get("SSH_ASKPASS")
if helper:
    if os.environ.get("SSH_ASKPASS_REQUIRE") != "force":
        log("no askpass configured\n")
        sys.exit(255)
    log("debug1: read_passphrase: requested to askpass\n")
    got = subprocess.run([helper, "lab@10.0.0.1's password: "], capture_output=True, text=True).stdout.strip()
    if got != os.environ.get("FAKE_SSH_PASSWORD", "hunter2"):
        if os.environ.get("FAKE_SSH_REFUSAL") == "close":
            log("Connection closed by 10.0.0.1 port 22\n")      # Junos sshd after a refused password
        else:
            log("lab@10.0.0.1: Permission denied (publickey,password).\n")
        sys.exit(255)
log("Authenticated to 10.0.0.1 ([10.0.0.1]:22) using publickey.\ndebug1: Entering interactive session.\n")

if "-tt" not in args:
    # An exec: the command is the last argument.
    last = args[-1]
    if os.environ.get("FAKE_SSH_STDERR"):
        sys.stderr.write(os.environ["FAKE_SSH_STDERR"] + "\n")
    rc = int(os.environ.get("FAKE_SSH_RC") or 0)
    if rc:
        sys.exit(rc)
    text = os.environ.get("FAKE_SSH_STDOUT")
    if text:
        say((text % last if "%s" in text else text) + "\n")
    elif last.endswith("| json"):
        say('{"modelName": "DCS-7050SX3", "sent": "%s"}\n' % last)
    else:
        say("output-for: %s\n" % last)
    sys.exit(0)

# A pty session: the device CLI.
if os.environ.get("FAKE_SSH_HANG") == "banner":
    say("\r\nWarning: unauthorized access is prohibited\r\n")
    time.sleep(30)
    sys.exit(0)

OP = "lab@r1> "
CFG = "\r\n[edit]\r\nlab@r1# "
state = {"mode": "op", "pending": os.environ.get("FAKE_SSH_PENDING") == "1", "candidate": []}


def junos(line):
    word = line.split(" ")[0]
    if state["mode"] == "op":
        if line == "configure exclusive":
            if os.environ.get("FAKE_SSH_LOCKED") == "1":
                return ("\r\nerror: configuration database locked by:\r\n"
                        "  admin terminal p0 (pid 1234) on since 2026-10-22 08:00:00 UTC, idle 00:01:02\r\n"
                        "      exclusive\r\n\r\n" + OP)
            state["mode"] = "cfg"
            return "\r\nEntering configuration mode" + CFG
        if line == "show system commit":
            note = " commit confirmed, rollback in 5mins" if state["pending"] else ""
            return ("\r\n0   2026-10-22 08:00:00 UTC by lab via cli" + note +
                    "\r\n1   2026-10-21 17:10:03 UTC by lab via cli\r\n\r\n" + OP)
        if line == "show version":
            return "\r\nHostname: r1\r\nModel: mx204\r\nJunos: 23.4R2.13\r\n\r\n" + OP
        if line == "exit":
            return None
        if line == "":
            return "\r\n" + OP
        return "\r\nerror: unknown command: %s\r\n\r\n" % word + OP
    if word in ("set", "delete"):
        if "bogus" in line:
            return "\r\n" + " " * 20 + "^\r\nsyntax error." + CFG
        state["candidate"].append(line)
        return CFG
    if line == "show | compare":
        diff = ""
        for ln in state["candidate"]:
            words = ln.split(" ")
            diff += "\r\n[edit %s]\r\n+  %s;" % (words[1], " ".join(words[2:]))
        return diff + CFG
    if line == "rollback 0":
        state["candidate"] = []
        return "\r\nload complete" + CFG
    if word == "commit":
        if os.environ.get("FAKE_SSH_COMMIT") == "fail":
            return "\r\nerror: configuration check-out failed" + CFG
        state["candidate"] = []
        words = line.split(" ")
        if len(words) >= 3 and words[1] == "confirmed":
            state["pending"] = True
            return ("\r\ncommit confirmed will be automatically rolled back in %s minutes unless confirmed"
                    "\r\ncommit complete" % words[2] + CFG)
        state["pending"] = False
        return "\r\ncommit complete" + CFG
    if line == "exit":
        state["mode"] = "op"
        return "\r\nExiting configuration mode\r\n\r\n" + OP
    if line == "":
        return CFG
    return "\r\n" + " " * 20 + "^\r\nsyntax error, expecting <command>." + CFG


def ios(line):
    if state["mode"] == "op":
        if line == "configure terminal":
            state["mode"] = "cfg"
            return "\r\nEnter configuration commands, one per line.  End with CNTL/Z.\r\nRouter(config)#"
        if line == "show version":
            return "\r\nCisco IOS XE Software, Version 17.09.04a\r\nRouter#"
        if line == "exit":
            return None
        if line == "":
            return "\r\nRouter#"
        return "\r\n" + " " * 8 + "^\r\n% Invalid input detected at '^' marker.\r\n\r\nRouter#"
    if line == "end":
        state["mode"] = "op"
        return "\r\nRouter#"
    if "bogus" in line:
        return "\r\n" + " " * 8 + "^\r\n% Invalid input detected at '^' marker.\r\n\r\nRouter(config)#"
    return "\r\nRouter(config)#"


device = ios if os.environ.get("FAKE_SSH_FLAVOUR") == "ios" else junos
if device is ios:
    say("\r\nRouter#")
else:
    say("--- JUNOS 23.4R2.13 Kernel 64-bit  JNPR-12.1-20240711.ae2a6ee_buil\r\n" + OP)

buf = b""
while True:
    chunk = os.read(0, 4096)
    if not chunk:
        sys.exit(0)
    buf += chunk
    while b"\n" in buf:
        raw, buf = buf.split(b"\n", 1)
        line = raw.decode().rstrip("\r")
        typed(line)
        reply = device(line)
        if reply is None:
            sys.exit(0)
        say(line + reply)          # the pty's echo of the line, then the device's reply
'''


@pytest.fixture
def device(tmp_path, monkeypatch):
    """The fake ssh on PATH. Returns a handle: `.typed` is every line the
    device CLI was sent, `.knobs(...)` sets the fake's FAKE_SSH_* switches."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "ssh"
    script.write_text("#!" + sys.executable + "\n" + FAKE_SSH)
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    typed_path = tmp_path / "typed"
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("FAKE_SSH_TYPED", str(typed_path))
    for var in ("FLAVOUR", "PENDING", "LOCKED", "COMMIT", "HANG", "RC", "STDERR", "STDOUT", "PASSWORD", "REFUSAL"):
        monkeypatch.delenv("FAKE_SSH_" + var, raising=False)
    monkeypatch.delenv("HSSH_PASSWORD", raising=False)
    monkeypatch.setattr(openssh, "AVAILABLE", True)

    class Device:
        @property
        def typed(self):
            return typed_path.read_text().splitlines() if typed_path.exists() else []

        @staticmethod
        def knobs(**switches):
            for name, value in switches.items():
                monkeypatch.setenv("FAKE_SSH_" + name.upper(), str(value))
    return Device()


@pytest.fixture
def no_ssh(tmp_path, monkeypatch):
    """No ssh anywhere on PATH: a request refused before any device I/O must not need one."""
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    monkeypatch.setattr(openssh, "AVAILABLE", True)


def junos_edit(payload="set system host-name test\n", passwd="hunter2", **kw):
    return openssh.edit("10.0.0.1", "lab", passwd, payload, 5, 10, vendor_hint="junos@openssh", **kw)


# --- a Junos edit on the pty --------------------------------------------------------

def test_a_junos_edit_over_openssh_commits_through_the_cli_engine_on_a_pty(device, tmp_path, monkeypatch):
    monkeypatch.setattr(openssh.tempfile, "tempdir", str(tmp_path))
    result = junos_edit()
    assert isinstance(result, R.EditResult) and result.status == R.COMMITTED
    assert result.diff == "[edit system]\n+  host-name test;" and result.startswith("COMMIT OK\n\nDIFF:\n")
    assert device.typed == ["configure exclusive", "set system host-name test", "show | compare", "commit", "exit"]
    # the -E log and the askpass helper went with the session
    assert not [p.name for p in tmp_path.iterdir() if p.name.startswith("hssh-")]


def test_the_shell_is_ssh_tt_on_pipes_with_the_password_through_askpass(device, monkeypatch):
    seen = []
    real = subprocess.Popen

    def spy(argv, **kwargs):
        if "-tt" in argv:
            seen.append((argv, kwargs))
        return real(argv, **kwargs)
    monkeypatch.setattr(subprocess, "Popen", spy)
    junos_edit()
    junos_edit(passwd=None)
    (argv, kwargs), (keyed, keyed_kwargs) = seen
    assert argv[:2] == ["ssh", "-tt"] and "-v" in argv and "-E" in argv and "-n" not in argv
    assert argv[-2:] == ["--", "lab@10.0.0.1"]            # no command: the engine types them
    assert "PubkeyAuthentication=no" in argv and "BatchMode=yes" not in argv
    assert kwargs["stdin"] is subprocess.PIPE and kwargs["stdout"] is subprocess.PIPE
    env = kwargs["env"]
    assert env["SSH_ASKPASS_REQUIRE"] == "force" and env["HSSH_ASKPASS_SECRET"] == "hunter2"
    assert env["TERM"] == "vt100" and "HSSH_PASSWORD" not in env
    assert "hunter2" not in " ".join(argv)
    assert "BatchMode=yes" in keyed and "SSH_ASKPASS" not in keyed_kwargs["env"]


def test_the_shell_ssh_has_no_escape_character(device, monkeypatch):
    """#139: with a forced tty ssh reads a ~ at the start of a typed line as
    a command to itself (~R rekeys, ~B sends a break) and types the rest, so
    `~Rcommit comment x` reached the device as `commit comment x`, past the
    commit rail, under a dry run. The shell's ssh has no escape character."""
    seen = []
    real = subprocess.Popen

    def spy(argv, **kwargs):
        if "-tt" in argv:
            seen.append(argv)
        return real(argv, **kwargs)
    monkeypatch.setattr(subprocess, "Popen", spy)
    junos_edit()
    (argv,) = seen
    assert argv[argv.index("-e") + 1] == "none"

def test_a_dry_run_shows_the_diff_and_rolls_the_candidate_back(device):
    result = junos_edit(dry_run=True)
    assert result.status == R.DRY_RUN and result.diff == "[edit system]\n+  host-name test;"
    assert device.typed[-2:] == ["rollback 0", "exit"] and "commit" not in device.typed


def test_a_commit_confirmed_arms_the_timer(device):
    result = junos_edit(commit_confirmed=2)
    assert result.status == R.CONFIRMED and result.minutes == 2 and result.pending
    assert device.typed[-2:] == ["commit confirmed 2", "exit"]


def test_a_changed_diff_commits_nothing_and_the_same_diff_commits(device):
    with pytest.raises(RuntimeError, match="diff changed since preview; nothing committed"):
        junos_edit(expected_diff="[edit system]\n+  host-name other;")
    assert "commit" not in device.typed and device.typed[-2:] == ["rollback 0", "exit"]
    assert junos_edit(expected_diff="[edit system]\n+  host-name test;\n").status == R.COMMITTED


def test_a_refused_set_line_fails_with_the_devices_words_and_rolls_back(device):
    with pytest.raises(RuntimeError, match=r"^'set system bogus 1': syntax error\.$"):
        junos_edit("set system host-name test\nset system bogus 1\n")
    assert "commit" not in device.typed and device.typed[-2:] == ["rollback 0", "exit"]


def test_a_refused_lock_is_not_applied_and_nothing_more_is_sent(device):
    device.knobs(locked=1)
    with pytest.raises(NotAppliedError, match="Failed to lock config: error: configuration database locked"):
        junos_edit()
    assert device.typed == ["configure exclusive"]


def test_a_refused_commit_is_failed_and_the_candidate_discarded(device):
    device.knobs(commit="fail")
    with pytest.raises(RuntimeError, match="Commit failed: error: configuration check-out failed"):
        junos_edit()
    assert device.typed[-3:] == ["commit", "rollback 0", "exit"]


def test_a_commit_line_in_the_payload_is_refused_before_connecting(no_ssh):
    with pytest.raises(ValueError, match="'commit' is not configuration"):
        junos_edit("set system host-name test\ncommit\n")


def test_a_payload_or_comment_the_cli_would_take_as_keys_is_refused_before_connecting(no_ssh):
    """#139: ^C, ^U and DEL in a set line are keys to the Junos line editor
    on the pty, and what follows them ran as a line of its own, a commit
    for good under a dry run too; a Tab completes the word; a line break or
    a double quote in a confirm's comment typed more than the comment.
    Refused before ssh is started, on every dialect typed at the pty."""
    for payload in ("set system host-name x\x03commit comment y\n", "set a\x15commit\n",
                    "set " + "\x7f" * 4 + "commit\n", "set system\thost-name x\n"):
        with pytest.raises(ValueError, match="which a CLI takes as a key, not as text; nothing was sent to the device"):
            junos_edit(payload, dry_run=True)
        with pytest.raises(ValueError, match="nothing was sent to the device"):
            openssh.edit("10.0.0.1", "u", "p", payload, 5, 10, vendor_hint="eos@openssh")
    for comment in ('x"\nrollback 1\ncommit', 'x"'):
        with pytest.raises(ValueError, match="the comment .* nothing was sent to the device"):
            openssh.confirm("10.0.0.1", "lab", "hunter2", 5, 10, vendor_hint="junos@openssh", comment=comment)


# --- confirm ----------------------------------------------------------------------------

def test_confirm_commits_the_pending_commit_confirmed(device):
    device.knobs(pending=1)
    result = openssh.confirm("10.0.0.1", "lab", "hunter2", 5, 10, vendor_hint="junos@openssh")
    assert isinstance(result, R.EditResult) and result.status == R.CONFIRMED_OK
    assert device.typed == ["show system commit", "configure exclusive", "commit", "exit"]
    openssh.confirm("10.0.0.1", "lab", "hunter2", 5, 10, vendor_hint="junos@openssh", comment="ok")
    assert device.typed[-2:] == ['commit comment "ok"', "exit"]


def test_confirm_with_nothing_pending_sends_only_the_history_read(device):
    with pytest.raises(NothingToConfirmError, match="nothing to confirm"):
        openssh.confirm("10.0.0.1", "lab", "hunter2", 5, 10, vendor_hint="junos@openssh")
    assert device.typed == ["show system commit"]


def test_confirm_is_only_for_a_junos_dialect(no_ssh):
    with pytest.raises(ValueError, match="confirm is only for a Junos dialect, not ios@openssh; nothing was sent"):
        openssh.confirm("10.0.0.1", "u", "p", 5, 10, vendor_hint="ios@openssh")
    with pytest.raises(ValueError, match="not openssh; nothing was sent"):
        openssh.confirm("10.0.0.1", "u", "p", 5, 10, vendor_hint="openssh")


# --- the IOS-shaped dialects -------------------------------------------------------------

@pytest.mark.parametrize("hint", ["ios@openssh", "nxos@openssh", "eos@openssh"])
def test_an_ios_shaped_edit_types_the_lines_in_config_mode(device, hint):
    device.knobs(flavour="ios")
    result = openssh.edit("10.0.0.1", "u", "hunter2", "hostname x\n! a comment\n", 5, 10, vendor_hint=hint)
    assert result == "(config applied)" and result.status == R.APPLIED
    assert device.typed == ["configure terminal", "hostname x", "end"]


def test_an_ios_shaped_edit_reports_the_refused_line_and_still_leaves_config_mode(device):
    device.knobs(flavour="ios")
    with pytest.raises(RuntimeError, match=r"^'hostname bogus': % Invalid input detected at '\^' marker\.$"):
        openssh.edit("10.0.0.1", "u", "hunter2", "hostname bogus\n", 5, 10, vendor_hint="ios@openssh")
    assert device.typed == ["configure terminal", "hostname bogus", "end"]


def test_an_ios_shaped_dialect_refuses_what_only_a_candidate_can_do_before_connecting(no_ssh):
    with pytest.raises(ValueError, match="not supported by ios@openssh; nothing was sent"):
        openssh.edit("10.0.0.1", "u", "p", "hostname x\n", 5, 10, vendor_hint="ios@openssh", dry_run=True)
    with pytest.raises(ValueError, match="not supported by nxos@openssh"):
        openssh.edit("10.0.0.1", "u", "p", "hostname x\n", 5, 10, vendor_hint="nxos@openssh", commit_confirmed=5)
    with pytest.raises(ValueError, match="not supported by eos@openssh"):
        openssh.edit("10.0.0.1", "u", "p", "hostname x\n", 5, 10, vendor_hint="eos@openssh", expected_diff="+ x")


# --- shows and structured reads stay on the exec ---------------------------------------------

def test_eos_show_structured_runs_the_command_with_json_on_an_exec(device):
    data = openssh.show_structured("10.0.0.1", "u", "hunter2", "show version", 5, 10, vendor_hint="eos@openssh")
    assert data == {"modelName": "DCS-7050SX3", "sent": "show version | json"}
    assert device.typed == []                                   # nothing was typed at a shell
    device.knobs(stdout="Arista DCS-7050SX3 (%s)")
    with pytest.raises(RuntimeError, match=r"'show version \| json' did not return JSON: 'Arista DCS-7050SX3"):
        openssh.show_structured("10.0.0.1", "u", "hunter2", "show version", 5, 10, vendor_hint="eos@openssh")
    device.knobs(stdout="%% Invalid input (%s)")
    with pytest.raises(RuntimeError, match="was refused by the device: % Invalid input"):
        openssh.show_structured("10.0.0.1", "u", "hunter2", "show version", 5, 10, vendor_hint="eos@openssh")
    device.knobs(rc=255, stderr="Connection refused")
    with pytest.raises(RuntimeError, match=r"^Connection refused by 10.0.0.1\.$"):
        openssh.show_structured("10.0.0.1", "u", "hunter2", "show version", 5, 10, vendor_hint="eos@openssh")


def test_show_structured_is_refused_on_any_other_dialect(no_ssh):
    with pytest.raises(ValueError, match="--structured is not supported by junos@openssh; nothing was sent"):
        openssh.show_structured("10.0.0.1", "u", "p", "show version", 5, 10, vendor_hint="junos@openssh")
    with pytest.raises(ValueError, match="--structured is not supported by openssh; nothing was sent"):
        openssh.show_structured("10.0.0.1", "u", "p", "show version", 5, 10)


def test_a_show_is_refused_by_the_dialects_own_rule(device):
    """The Junos CLI says "syntax error, expecting <command>" with no "error:"
    in front: a refusal for junos@openssh, output for the none dialect, which
    knows only "error:" and "% "."""
    device.knobs(stdout="syntax error, expecting <command>: %s")
    with pytest.raises(RuntimeError, match="'show versionx' was refused by the device: syntax error, expecting"):
        openssh.show("10.0.0.1", "u", None, "show versionx", 5, 10, vendor_hint="junos@openssh")
    assert "syntax error" in openssh.show("10.0.0.1", "u", None, "show versionx", 5, 10)
    assert openssh.show_batch("10.0.0.1", "u", None, ["show versionx"], 5, 10, vendor_hint="junos@openssh")[0]["ok"] is False
    assert openssh.show_batch("10.0.0.1", "u", None, ["show versionx"], 5, 10)[0]["ok"] is True
    assert device.typed == []


def test_the_none_dialect_refuses_as_before_with_nothing_sent(no_ssh):
    with pytest.raises(RuntimeError, match="^--commit-confirmed is not supported by the 'openssh' transport; "
                                           "use the 'junos' transport for confirmed commits$"):
        openssh.edit("10.0.0.1", "u", "p", "set a b\n", 5, 10, commit_confirmed=5)
    for kw in ({"dry_run": True}, {"expected_diff": "+ x"}):
        with pytest.raises(ValueError, match="^dry_run, commit_confirmed and expected_diff are not supported by "
                                             "openssh; nothing was sent to the device$"):
            openssh.edit("10.0.0.1", "u", "p", "set a b\n", 5, 10, **kw)


# --- what ends a session, and why ---------------------------------------------------------------

def test_a_wrong_password_on_the_pty_is_an_authentication_failure_not_a_closed_connection(device):
    with pytest.raises(ConnectionError, match=r"^Authentication failed\.$"):
        junos_edit(passwd="wrong")
    assert device.typed == []
    device.knobs(refusal="close")
    with pytest.raises(ConnectionError, match="^Authentication failed: 10.0.0.1 closed the connection after the "
                                              "password was offered"):
        junos_edit(passwd="wrong")


def test_a_login_that_gets_no_session_or_no_prompt_is_bounded_by_the_session_timeout(device, monkeypatch):
    procs = []
    real = subprocess.Popen

    def spy(argv, **kwargs):
        proc = real(argv, **kwargs)
        if "-tt" in argv:
            procs.append(proc)
        return proc
    monkeypatch.setattr(subprocess, "Popen", spy)
    started = time.monotonic()
    device.knobs(hang="kex")
    with pytest.raises(RuntimeError, match="^no SSH session to 10.0.0.1 within 1s: the banner came, but key "
                                           "exchange or authentication did not finish$"):
        openssh.edit("10.0.0.1", "lab", "hunter2", "set system host-name test\n", 1, 10, vendor_hint="junos@openssh")
    device.knobs(hang="banner")
    # (the engine's second read, after its one Enter, starts empty: the banner line it saw first is not quoted)
    with pytest.raises(NotAppliedError, match="^login failed: no prompt within 1s$"):
        openssh.edit("10.0.0.1", "lab", "hunter2", "set system host-name test\n", 1, 10, vendor_hint="junos@openssh")
    assert time.monotonic() - started < 8              # the wait, one Enter, the wait again: about 2 s each
    assert len(procs) == 2 and all(p.returncode is not None for p in procs)     # neither ssh was left behind


@pytest.mark.parametrize("hang, said", [("tcp", "TCP connect to 10.0.0.1:22 timed out after 1s"),
                                        ("silent", "no SSH banner from 10.0.0.1:22 within 1s")])
def test_a_shell_whose_connect_phase_runs_out_is_given_up_at_the_connect_timeout(device, monkeypatch, hang, said):
    """#126: the pty session had the whole session timeout for this. Now the
    channel keeps the connect phase's clock, says which part ran out, and it
    is a NotAppliedError: nothing was typed, the runner may try again."""
    procs = []
    real = subprocess.Popen

    def spy(argv, **kwargs):
        proc = real(argv, **kwargs)
        if "-tt" in argv:
            procs.append((argv, proc))
        return proc
    monkeypatch.setattr(subprocess, "Popen", spy)
    device.knobs(hang=hang)
    started = time.monotonic()
    with pytest.raises(ConnectTimeoutError) as failed:
        openssh.edit("10.0.0.1", "lab", "hunter2", "set system host-name test\n", 30, 10,
                     vendor_hint="junos@openssh", connect_timeout=1)
    assert str(failed.value) == said and isinstance(failed.value, NotAppliedError)
    assert time.monotonic() - started < 3.0
    assert device.typed == []
    (argv, proc), = procs
    assert "ConnectTimeout=1" in argv and proc.returncode is not None      # and the ssh was not left behind


def test_the_process_channel_times_out_echoes_closes_and_reads_sshs_verdict(tmp_path):
    """The channel itself, on processes that are not ssh: a cat echoes; a
    script that exits 255 after writing OpenSSH's refusal to the -E log is
    that refusal; one that exits 0 is the device hanging up."""
    log = tmp_path / "ssh.log"
    log.write_text("")
    proc = subprocess.Popen(["cat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, bufsize=0)
    ch = openssh.ProcessChannel(proc, "10.0.0.1", str(log), ["cat"])
    with pytest.raises(TimeoutError, match="nothing from 10.0.0.1 within 0.1s"):
        ch.recv(100, 0.1)
    ch.send(b"hello\n")
    assert ch.recv(100, 2.0) == b"hello\n"
    ch.close()
    ch.close()                                                  # a second close is nothing
    assert proc.returncode == 0 and not log.exists()
    with pytest.raises(ConnectionError):
        ch.send(b"x")

    def script(code, text):
        log.write_text("")
        p = subprocess.Popen([sys.executable, "-c",
                              f"import sys; open(sys.argv[1], 'a').write({text!r}); sys.exit({code})", str(log)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        return openssh.ProcessChannel(p, "10.0.0.1", str(log), ["ssh"])

    ch = script(255, "lab@10.0.0.1: Permission denied (publickey,password).\n")
    with pytest.raises(ConnectionError, match=r"^Authentication failed\.$"):
        ch.recv(100, 5.0)
    ch.close()
    ch = script(255, "debug1: Connecting to 10.0.0.1 port 22.\nssh: connect to host 10.0.0.1 port 22: Connection refused\n")
    with pytest.raises(ConnectionError, match=r"^Connection refused by 10.0.0.1\.$"):
        ch.recv(100, 5.0)
    ch.close()
    ch = script(0, "debug1: Exit status 0\n")
    assert ch.recv(100, 5.0) == b""                             # a clean exit: the device ended the session
    ch.close()


# --- the registry ---------------------------------------------------------------------------

def test_the_four_dialect_drivers_exist_on_the_openssh_transport():
    for name in ("junos@openssh", "ios@openssh", "nxos@openssh", "eos@openssh"):
        d = drivers.get(name)
        assert d.name == name and d.aliases == () and d.transport is drivers.OPENSSH
        assert name not in drivers.ALIASES and drivers.module_of(d) is openssh
        assert contract.violations(d, openssh) == []
        assert runner.bind(name).caps == d.supports
    assert drivers.get("junos@openssh").supports == drivers.get("junos@ssh").supports == {
        "show", "show_batch", "edit", "confirm", "dry_run", "commit_confirmed"}
    assert drivers.get("ios@openssh").supports == drivers.get("nxos@openssh").supports == {"show", "show_batch", "edit"}
    assert drivers.get("eos@openssh").supports == {"show", "show_batch", "edit", "show_structured"}
    assert "show_structured" not in runner.bind("openssh").caps and "confirm" not in runner.bind("openssh").caps
    assert drivers.get("junos@openssh").dialect is drivers.JUNOS


def test_the_runner_reaches_a_junos_dry_run_over_openssh_through_the_registry(device):
    name, ok, out, _ = runner.run_for_target(
        t=Target("R1", "10.0.0.1", "junos@openssh"), transport="junos@openssh", mode="edit-cmd",
        show_cmd=None, edit_cmd="set system host-name test", config_dir=None, broadcast_file=None,
        user="lab", passwd="hunter2", session_timeout=5, command_timeout=30,
        dry_run=True, commit_confirmed=None, save_dir=None, quiet=True, max_attempts=1)
    assert ok is True and "DRY-RUN" in out and "+  host-name test;" in out
    assert device.typed[-2:] == ["rollback 0", "exit"] and "commit" not in device.typed
