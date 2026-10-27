"""Telnet transport tests — mock socket server, no live devices needed."""
import json
import socket
import subprocess
import sys
import os
import threading
import time
import pytest

HSSH = os.path.join(os.path.dirname(__file__), "..", "h-ssh.py")
CWD = os.path.join(os.path.dirname(__file__), "..")


class MockTelnetServer:
    """Minimal mock telnet server for testing."""

    def __init__(self, vendor="ios"):
        self.vendor = vendor
        self.received = []   # every command line a client sent, in order
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.port = self.server.getsockname()[1]
        self.server.listen(5)
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while self._running:
            try:
                self.server.settimeout(1.0)
                conn, _ = self.server.accept()
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle(self, conn: socket.socket):
        try:
            conn.settimeout(10.0)
            if self.vendor == "ios":
                prompt = "Router#"
            elif self.vendor == "junos":
                prompt = "user@Router>"
            elif self.vendor == "arista":
                prompt = "Switch#"
            else:
                prompt = "Router#"

            conn.sendall(f"\r\n{prompt} ".encode())

            while True:
                try:
                    data = conn.recv(4096).decode("utf-8", errors="replace").strip()
                    if not data:
                        continue
                    self.received.append(data)

                    if data == "show version":
                        response = f"Mock {self.vendor} device\nVersion: 1.0.0\nUptime: 1 day\r\n{prompt} "
                    elif data == "show ip route":
                        response = f"Gateway of last resort is 10.0.0.1\n10.0.0.0/24 is directly connected\n192.168.1.0/24 via 10.0.0.1\r\n{prompt} "
                    elif data == "show interfaces":
                        response = f"GigabitEthernet0/0 is up, line protocol is up\n  Internet address is 10.0.0.1/24\r\n{prompt} "
                    elif data.startswith("configure") or data == "conf t":
                        response = f"Entering configuration mode\r\n{prompt.replace('#', '(config)#').replace('>', '#')} "
                    elif data == "end":
                        response = f"\r\n{prompt} "
                    elif data == "exit":
                        response = f"\r\n{prompt} "
                    elif data.startswith(("set ", "interface ", "ip ", "description ")):
                        response = f"\r\n{prompt.replace('#', '(config)#').replace('>', '#')} "
                    elif data == "show | compare":
                        response = f"[edit system]\n+  host-name test;\r\n{prompt.replace('>', '#')} "
                    elif data.startswith("rollback"):
                        response = f"Rolled back\r\n{prompt.replace('>', '#')} "
                    elif data == "commit":
                        response = f"commit complete\r\n{prompt.replace('>', '#')} "
                    else:
                        response = f"% Unknown command: {data}\r\n{prompt} "

                    conn.sendall(response.encode())
                except socket.timeout:
                    break
                except (ConnectionError, OSError):
                    break
        finally:
            conn.close()

    def stop(self):
        self._running = False
        self.server.close()


@pytest.fixture(scope="module")
def ios_server():
    server = MockTelnetServer(vendor="ios")
    yield server
    server.stop()


@pytest.fixture(scope="module")
def junos_server():
    server = MockTelnetServer(vendor="junos")
    yield server
    server.stop()


@pytest.fixture(scope="module")
def arista_server():
    server = MockTelnetServer(vendor="arista")
    yield server
    server.stop()


# ---- Unit tests for ANSI stripping ----

def test_ansi_strip():
    """ANSI escape codes are stripped from output."""
    from hssh.transports.telnet import _strip_ansi

    assert _strip_ansi("\x1b[32mgreen\x1b[0m") == "green"
    assert _strip_ansi("no escapes here") == "no escapes here"
    assert _strip_ansi("\x1b[1;31mred bold\x1b[0m text") == "red bold text"


# ---- Functional tests via mock telnet ----

def test_ios_show_version(ios_server):
    """Show command via IOS telnet returns device output."""
    from hssh.transports.telnet import show
    result = show("127.0.0.1", "admin", "admin", "show version",
                  session_timeout=5, command_timeout=5,
                  port=ios_server.port, vendor_hint="telnet-ios")
    assert "Mock ios device" in result
    assert "Version: 1.0.0" in result


def test_ios_show_ip_route(ios_server):
    """Show ip route via IOS telnet."""
    from hssh.transports.telnet import show
    result = show("127.0.0.1", "admin", "admin", "show ip route",
                  session_timeout=5, command_timeout=5,
                  port=ios_server.port, vendor_hint="telnet-ios")
    assert "10.0.0" in result


def test_arista_show_interfaces(arista_server):
    """Show interfaces via Arista telnet."""
    from hssh.transports.telnet import show
    result = show("127.0.0.1", "admin", "admin", "show interfaces",
                  session_timeout=5, command_timeout=5,
                  port=arista_server.port, vendor_hint="telnet-arista")
    assert "GigabitEthernet" in result


def test_show_batch(ios_server):
    """Multiple commands on a single connection."""
    from hssh.transports.telnet import show_batch
    results = show_batch("127.0.0.1", "admin", "admin",
                         ["show version", "show ip route"],
                         session_timeout=5, command_timeout=5,
                         port=ios_server.port, vendor_hint="telnet-ios")
    assert len(results) == 2
    assert all(r["ok"] for r in results)
    assert "Mock ios device" in results[0]["output"]
    assert "10.0.0" in results[1]["output"]


def _junos_edit(server, **kw):
    from hssh.transports.telnet import edit
    return edit("127.0.0.1", "admin", "admin", "set system host-name test\n",
                session_timeout=5, command_timeout=5, port=server.port,
                vendor_hint="telnet-junos", **kw)


def test_junos_edit_commits_only_the_diff_the_dry_run_showed(junos_server):
    """--show-diff over telnet: `show | compare` must say what the preview
    said, or the candidate is rolled back and nothing is committed."""
    start = len(junos_server.received)
    with pytest.raises(RuntimeError, match="diff changed since preview; nothing committed"):
        _junos_edit(junos_server, expected_diff="[edit system]\n+  host-name OTHER;")
    sent = junos_server.received[start:]
    assert "rollback 0" in sent and "commit" not in sent
    start = len(junos_server.received)
    out = _junos_edit(junos_server, expected_diff="[edit system]\n+  host-name test;\n")
    assert out.startswith("COMMIT OK") and "commit" in junos_server.received[start:]


def test_telnet_always_available():
    """Raw socket telnet is always available (no external deps)."""
    from hssh.transports.telnet import AVAILABLE
    assert AVAILABLE is True


# ---- Scripted fake: a login step, a refused lock, a commit that never answers ----

class ScriptedTelnetServer:
    """One scripted connection on 127.0.0.1, for the dialogues the mock above
    cannot hold. `handler(srv)` plays the device with srv.send()/srv.readline();
    every line the client sent is kept in srv.received and, with echo=True,
    echoed back first, as a tty or console port does."""

    def __init__(self, handler, echo=True):
        self.handler = handler
        self.echo = echo
        self.received = []
        self.done = threading.Event()
        self._buf = b""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.port = self.server.getsockname()[1]
        self.server.listen(1)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        try:
            self.conn, _ = self.server.accept()
        except OSError:
            self.done.set()
            return
        try:
            self.conn.settimeout(10.0)
            self.handler(self)
        except (EOFError, OSError):
            pass
        finally:
            self.conn.close()
            self.done.set()

    def send(self, text):
        self.conn.sendall(text.encode())

    def readline(self):
        while b"\n" not in self._buf:
            data = self.conn.recv(4096)
            if not data:
                raise EOFError
            self._buf += data
        line, _, self._buf = self._buf.partition(b"\n")
        line = line.decode(errors="replace").rstrip("\r")
        self.received.append(line)
        if self.echo:
            self.send(line + "\r\n")
        return line

    def stop(self):
        self.server.close()


def _received(srv):
    """The lines the fake got, once the client has hung up."""
    srv.done.wait(5)
    srv.stop()
    return srv.received


OP = "lab@R1> "
CFG = "\r\n[edit]\r\nlab@R1# "


HISTORY_PENDING = ("\r\n0   2026-10-22 08:00:00 UTC by lab via cli commit confirmed, rollback in 5mins"
                   "\r\n1   2026-10-21 17:10:03 UTC by lab via cli\r\n")
HISTORY_CLEAN = "\r\n0   2026-10-22 08:00:00 UTC by lab via cli\r\n1   2026-10-21 17:10:03 UTC by lab via cli\r\n"


def junos_cli(login=False, lock_reply=None, commit_reply="\r\ncommit complete",
              hang_on=None, hang_up_on=None, history=HISTORY_PENDING):
    """A Junos-looking CLI: a login step when asked, then the operational
    prompt. lock_reply answers `configure exclusive` in place of entering
    configuration mode; hang_on names a command (`commit`, `exit`, ...) left
    unanswered, hang_up_on one answered by closing the connection."""
    def handler(srv):
        if login:
            srv.send("\r\nR1 (ttyp0)\r\n\r\nlogin: ")
            srv.readline()
            echo, srv.echo = srv.echo, False      # a tty does not echo the password
            srv.send("Password:")
            srv.readline()
            srv.echo = echo
            srv.send("\r\nLast login: Tue Oct 20 09:12:01 2026 from 10.0.0.5\r\n"
                     "--- JUNOS 23.4R2.13 Kernel 64-bit ---\r\n")
        srv.send("\r\n" + OP)
        while True:
            line = srv.readline()
            if line.split(" ")[0] == hang_up_on:
                return
            if line.split(" ")[0] == hang_on:
                srv.readline()                    # nothing, until the client gives up
            if line.startswith("configure"):
                srv.send(lock_reply + "\r\n" + OP if lock_reply
                         else "\r\nEntering configuration mode" + CFG)
            elif line.startswith("set "):
                srv.send(CFG)
            elif line == "show version":
                srv.send("\r\nHostname: R1\r\nModel: mx204\r\n" + OP)
            elif line == "show system commit":
                srv.send(history + OP)
            elif line == "show | compare":
                srv.send("\r\n[edit system]\r\n+  host-name test;" + CFG)
            elif line.startswith("rollback"):
                srv.send("\r\nload complete" + CFG)
            elif line.startswith("commit"):
                srv.send(commit_reply + CFG)
            elif line == "exit":
                srv.send("\r\nExiting configuration mode\r\n\r\n" + OP)
            else:
                srv.send("\r\nsyntax error, expecting <command>." + CFG)
    return handler


def rejects_every_login(srv):
    """FreeBSD-style login (Junos) that takes no password."""
    srv.send("\r\nR1 (ttyp0)\r\n\r\nlogin: ")
    while True:
        srv.readline()
        echo, srv.echo = srv.echo, False
        srv.send("Password:")
        srv.readline()
        srv.echo = echo
        srv.send("\r\nLogin incorrect\r\nlogin: ")


def ios_rejects_every_login(srv):
    srv.send("\r\nUser Access Verification\r\n\r\nUsername: ")
    while True:
        srv.readline()
        echo, srv.echo = srv.echo, False
        srv.send("Password: ")
        srv.readline()
        srv.echo = echo
        srv.send("\r\n% Login invalid\r\n\r\nUsername: ")


def _edit(srv, payload="set system host-name test\n", **kw):
    from hssh.transports.telnet import edit
    return edit("127.0.0.1", "lab", "secret", payload, session_timeout=5, command_timeout=5,
                port=srv.port, vendor_hint="telnet-junos", **kw)


# ---- The readers never hand back a partial read as the reply ----

def test_reader_raises_on_timeout_and_on_eof():
    """A deadline is a TimeoutError naming the last line seen, a closed peer a
    ConnectionError; neither returns what happened to arrive."""
    from hssh.transports.telnet import PROMPT_PATTERNS, _read_until_prompt
    ours, theirs = socket.socketpair()
    try:
        theirs.sendall(b"Building configuration...\r\n")
        with pytest.raises(TimeoutError) as exc:
            _read_until_prompt(ours, PROMPT_PATTERNS["ios"], timeout=1)
        assert str(exc.value) == "no prompt within 1s; last line: 'Building configuration...'"
        theirs.close()
        with pytest.raises(ConnectionError, match="closed by the device"):
            _read_until_prompt(ours, PROMPT_PATTERNS["ios"], timeout=1)
    finally:
        ours.close()


@pytest.mark.parametrize("vendor, prompt", [
    ("ios", "Router(config)# "),
    ("ios", "Router(config-if)# "),
    ("ios", "Router(config-sg-tacacs+)# "),
    ("arista", "Switch(config-if-Et1/1)# "),
    ("nxos", "N9K(config-if-range)# "),
])
def test_ios_style_config_prompts_are_recognised(vendor, prompt):
    """A reader that does not know the config-mode prompt waits out its
    timeout on every config line."""
    from hssh.transports.telnet import PROMPT_PATTERNS
    assert PROMPT_PATTERNS[vendor].search(prompt)


def test_login_prompt_is_not_the_last_login_line():
    from hssh.transports.telnet import LOGIN_RE
    assert LOGIN_RE.search("R1 (ttyp0)\r\n\r\nlogin: ")
    assert LOGIN_RE.search("User Access Verification\r\n\r\nUsername: ")
    assert LOGIN_RE.search("debian login: ")
    assert not LOGIN_RE.search("Last login: ")


def test_ios_edit_applies_config_lines(ios_server):
    """A telnet-ios edit against config-mode prompts: every line is answered
    at once, no prompt-timeout wait per line."""
    from hssh.transports.telnet import edit
    t0 = time.monotonic()
    result = edit("127.0.0.1", "admin", "admin",
                  "interface GigabitEthernet0/0\ndescription error-disabled uplink\n",
                  session_timeout=5, command_timeout=5,
                  port=ios_server.port, vendor_hint="telnet-ios")
    assert result == "(config applied)"
    assert time.monotonic() - t0 < 5          # not a 10 s read timeout per line


# ---- Login ----

@pytest.mark.parametrize("hint, handler, said", [
    ("telnet-junos", rejects_every_login, "Login incorrect"),
    ("telnet-ios", ios_rejects_every_login, "% Login invalid"),
])
def test_failed_login_is_an_error_not_output(hint, handler, said):
    """A login prompt back after the password is a failed login: show() raises
    with the device's words, and the command is never typed in as a username."""
    from hssh.errors import NotAppliedError
    from hssh.transports.telnet import show
    srv = ScriptedTelnetServer(handler)
    with pytest.raises(NotAppliedError, match="login failed") as exc:
        show("127.0.0.1", "admin", "wrong", "show version",
             session_timeout=2, command_timeout=2, port=srv.port, vendor_hint=hint)
    assert said in str(exc.value)
    assert _received(srv) == ["admin", "wrong"]


def test_connection_dropped_during_login_is_retried_not_permanent():
    """A device that hangs up after the username is a reset after connecting:
    the ConnectionError reaches the runner unwrapped, so the run is retried,
    unlike a refused login which is final."""
    from hssh.transports.telnet import show

    def hangs_up_after_username(srv):
        srv.send("\r\nR1 (ttyp0)\r\n\r\nlogin: ")
        srv.readline()

    srv = ScriptedTelnetServer(hangs_up_after_username)
    with pytest.raises(ConnectionError):
        show("127.0.0.1", "lab", "secret", "show version",
             session_timeout=2, command_timeout=1, port=srv.port, vendor_hint="telnet-junos")
    assert _received(srv) == ["lab"]


def test_silent_device_is_a_failed_login():
    """A port that answers with nothing gets one Enter after a session_timeout
    of silence; still nothing is a failed login, not an empty read handed back
    as the command's output."""
    from hssh.errors import NotAppliedError
    from hssh.transports.telnet import show
    srv = ScriptedTelnetServer(lambda srv: (srv.readline(), srv.readline()), echo=False)
    with pytest.raises(NotAppliedError, match="login failed: no prompt within 1s"):
        show("127.0.0.1", "lab", "secret", "show version",
             session_timeout=1, command_timeout=1, port=srv.port, vendor_hint="telnet-junos")
    assert _received(srv) == [""]


def test_console_line_at_a_prompt_wakes_on_enter():
    """The README's console server: a line left at a logged-in prompt prints
    nothing until Enter, and the Enter comes only once the wait is up, so a
    slow login prompt never finds it typed ahead as the username."""
    from hssh.transports.telnet import show
    def console_line(srv):
        srv.readline()                            # nothing until Enter
        srv.send("\r\nSW1#")
        srv.readline()
        srv.send("\r\nMock ios device\r\nSW1#")
    srv = ScriptedTelnetServer(console_line)
    t0 = time.monotonic()
    out = show("127.0.0.1", "lab", "secret", "show version",
               session_timeout=1, command_timeout=2, port=srv.port, vendor_hint="telnet-ios")
    assert "Mock ios device" in out
    assert time.monotonic() - t0 >= 1
    assert _received(srv) == ["", "show version"]


def test_login_then_show():
    """The real thing: login, password, MOTD with its "Last login:" line, prompt."""
    from hssh.transports.telnet import show
    srv = ScriptedTelnetServer(junos_cli(login=True))
    out = show("127.0.0.1", "lab", "secret", "show version",
               session_timeout=5, command_timeout=5, port=srv.port, vendor_hint="telnet-junos")
    assert "Model: mx204" in out
    assert _received(srv) == ["lab", "secret", "show version"]


# ---- Junos edits: an exclusive candidate, errors matched on the reply ----

def test_junos_edit_locks_the_candidate_and_commits():
    srv = ScriptedTelnetServer(junos_cli())
    out = _edit(srv)
    assert out.startswith("COMMIT OK")
    assert "+  host-name test;" in out
    assert _received(srv) == ["configure exclusive", "set system host-name test",
                              "show | compare", "commit", "exit"]


def test_junos_commit_confirmed_on_the_wire():
    srv = ScriptedTelnetServer(junos_cli())
    out = _edit(srv, commit_confirmed=5)
    assert out.startswith("COMMIT CONFIRMED (5 minutes)")
    assert "commit confirmed 5" in _received(srv)


def test_junos_dry_run_discards_only_its_own_candidate():
    """rollback 0 is still how a dry run ends, but inside exclusive mode it
    can only ever discard what this session staged."""
    srv = ScriptedTelnetServer(junos_cli())
    out = _edit(srv, dry_run=True)
    assert out.startswith("DRY-RUN")
    assert _received(srv) == ["configure exclusive", "set system host-name test",
                              "show | compare", "rollback 0", "exit"]


def test_junos_refused_lock_sends_nothing_else():
    """Someone else holds the candidate: reported before any set line, and
    nothing is committed or rolled back on their behalf."""
    from hssh.errors import NotAppliedError
    locked = ("\r\nerror: configuration database locked by:\r\n"
              "  ops terminal p0 (pid 4242) on since 2026-10-21 09:00:00 UTC\r\n"
              "      exclusive [edit]")
    srv = ScriptedTelnetServer(junos_cli(lock_reply=locked))
    with pytest.raises(NotAppliedError, match="Failed to lock config") as exc:
        _edit(srv)
    assert "locked by:" in str(exc.value)
    assert _received(srv) == ["configure exclusive"]


def test_junos_description_saying_error_is_committed():
    """The echoed line is not the device's verdict on it."""
    srv = ScriptedTelnetServer(junos_cli(), echo=True)
    out = _edit(srv, 'set interfaces ge-0/0/0 description "error-disabled uplink"\n')
    assert out.startswith("COMMIT OK")
    got = _received(srv)
    assert "commit" in got and "rollback 0" not in got


def test_junos_syntax_error_rolls_back():
    srv = ScriptedTelnetServer(junos_cli())
    with pytest.raises(RuntimeError, match="syntax error") as exc:
        _edit(srv, "set system host-name test\nbogus statement here\n")
    assert "'bogus statement here'" in str(exc.value)
    got = _received(srv)
    assert "rollback 0" in got and "commit" not in got


def test_junos_refused_commit_is_a_failure_and_discarded():
    refused = ("\r\n[edit interfaces]\r\n  'ge-9/9/9'\r\n    not a valid interface\r\n"
               "error: configuration check-out failed")
    srv = ScriptedTelnetServer(junos_cli(commit_reply=refused))
    with pytest.raises(RuntimeError, match="Commit failed") as exc:
        _edit(srv)
    assert "check-out failed" in str(exc.value)
    assert _received(srv) == ["configure exclusive", "set system host-name test",
                              "show | compare", "commit", "rollback 0", "exit"]


@pytest.mark.parametrize("how", ["hang_on", "hang_up_on"])
def test_junos_unanswered_commit_is_outcome_unknown(monkeypatch, how):
    """No reply to commit - the deadline passes, or the device hangs up - is
    neither COMMIT OK nor a failure, and nothing is rolled back."""
    from hssh.transports import telnet
    from hssh.errors import AmbiguousCommitError
    real = telnet._read_until_prompt
    monkeypatch.setattr(telnet, "_read_until_prompt",
                        lambda sock, prompt_re, timeout, buffer="":
                        real(sock, prompt_re, min(timeout, 1), buffer))
    srv = ScriptedTelnetServer(junos_cli(**{how: "commit"}))
    with pytest.raises(AmbiguousCommitError, match="commit outcome unknown") as exc:
        _edit(srv)
    assert "COMMIT OK" not in str(exc.value)
    got = _received(srv)
    assert got[-1] == "commit" and "rollback 0" not in got


@pytest.mark.parametrize("how", ["hang_on", "hang_up_on"])
def test_junos_commit_that_drops_the_session_is_still_ok(monkeypatch, how):
    """commit complete, then the exit goes unanswered or the device hangs up:
    the change took the management address or the telnet service with it, the
    --commit-confirmed use. The commit was seen to land, so it is COMMIT OK."""
    from hssh.transports import telnet
    real = telnet._read_until_prompt
    monkeypatch.setattr(telnet, "_read_until_prompt",
                        lambda sock, prompt_re, timeout, buffer="":
                        real(sock, prompt_re, min(timeout, 1), buffer))
    srv = ScriptedTelnetServer(junos_cli(**{how: "exit"}))
    out = _edit(srv)
    assert out.startswith("COMMIT OK")
    got = _received(srv)
    assert got[-2:] == ["commit", "exit"] and "rollback 0" not in got


def test_junos_refused_commit_keeps_its_words_when_the_rollback_drops():
    """The device's verdict is not replaced by the cleanup's failure."""
    refused = "\r\nerror: configuration check-out failed"
    srv = ScriptedTelnetServer(junos_cli(commit_reply=refused, hang_up_on="rollback"))
    with pytest.raises(RuntimeError, match="Commit failed") as exc:
        _edit(srv)
    assert "check-out failed" in str(exc.value)
    assert _received(srv)[-2:] == ["commit", "rollback 0"]


# --- #40: the library edit() on an IOS flavour cannot fake a dry run ------------

@pytest.mark.parametrize("kw", [{"dry_run": True}, {"commit_confirmed": 5}, {"expected_diff": "+ x"}])
def test_ios_flavour_refuses_dry_run_timer_and_diff_check_before_connecting(monkeypatch, kw):
    """dry_run=True once applied the config and returned '(config applied)'."""
    from hssh.transports import telnet

    def never(*a, **k):
        raise AssertionError("connected although the request could not be honoured")
    monkeypatch.setattr(telnet, "_connect_and_login", never)
    with pytest.raises(ValueError, match="not supported by telnet-ios; nothing was sent"):
        telnet.edit("127.0.0.1", "admin", "admin", "interface Et1\n", 5, 5, port=2323, vendor_hint="telnet-ios", **kw)


@pytest.mark.parametrize("minutes", [0, -3])
def test_junos_flavour_refuses_a_timer_it_cannot_arm(monkeypatch, minutes):
    from hssh.transports import telnet

    def never(*a, **k):
        raise AssertionError("connected although the timer could not be armed")
    monkeypatch.setattr(telnet, "_connect_and_login", never)
    with pytest.raises(ValueError, match="commit_confirmed must be 1..65535"):
        telnet.edit("127.0.0.1", "lab", "secret", "set system host-name x\n", 5, 5, port=2323,
                    vendor_hint="telnet-junos", commit_confirmed=minutes)

def test_a_console_that_echoes_the_password_does_not_put_it_in_the_error():
    """The timeout message quoted the last line seen; an echoing console
    line after 'Password:' made that the operator's password (#42)."""
    from hssh.errors import NotAppliedError
    from hssh.transports.telnet import show

    def echoing_console(srv):
        srv.send("Password: ")
        typed = srv.readline()
        srv.send(typed + "\r\n")          # echoed back, then silence
        srv.readline()
    srv = ScriptedTelnetServer(echoing_console, echo=False)
    with pytest.raises(NotAppliedError) as exc:
        show("127.0.0.1", "lab", "Pa55w0rd-FROM-PROMPT", "show version",
             session_timeout=1, command_timeout=1, port=srv.port, vendor_hint="telnet-junos")
    assert "Pa55w0rd-FROM-PROMPT" not in str(exc.value) and "***" in str(exc.value)

# --- #46: the reader cannot be fooled by prompt-shaped text ----------------------

REFUSED = "\r\nerror: configuration check-out failed: daemon file propagation failed"


def junos_cli_slow(commit_reply=REFUSED):
    """junos_cli with a tty's timing: the echo lands first, the reply a
    moment later, in its own packet."""
    def handler(srv):
        srv.send("\r\n" + OP)
        while True:
            line = srv.readline()
            time.sleep(0.05)
            if line.startswith("configure"):
                srv.send("\r\nEntering configuration mode" + CFG)
            elif line.startswith("set "):
                srv.send(CFG)
            elif line == "show | compare":
                srv.send("\r\n[edit interfaces xe-0/0/0]\r\n+   description noc@example.com>;" + CFG)
            elif line.startswith("rollback"):
                srv.send("\r\nload complete" + CFG)
            elif line.startswith("commit"):
                srv.send(commit_reply + CFG)
            elif line == "exit":
                srv.send("\r\nExiting configuration mode\r\n\r\n" + OP)
                return
            elif line == "show version":
                srv.send("\r\nHostname: R1\r\nModel: mx204\r\n" + OP)
            else:
                srv.send("\r\nsyntax error, expecting <command>." + CFG)
    return handler


def test_a_set_line_ending_in_prompt_shaped_text_does_not_hide_a_refused_commit():
    """The echo of `description noc@example.com>` satisfied the prompt match;
    every later read was one reply behind and the refused commit came back
    as COMMIT OK (#46)."""
    from hssh.transports.telnet import edit
    srv = ScriptedTelnetServer(junos_cli_slow())
    with pytest.raises(RuntimeError, match="Commit failed: error: configuration check-out failed"):
        edit("127.0.0.1", "lab", "secret",
             'set system host-name R1-NEW\nset interfaces xe-0/0/0 description noc@example.com>\n',
             session_timeout=5, command_timeout=5, port=srv.port, vendor_hint="telnet-junos")
    assert _received(srv) == ["configure exclusive", "set system host-name R1-NEW",
                              "set interfaces xe-0/0/0 description noc@example.com>",
                              "show | compare", "commit", "rollback 0", "exit"]


def test_the_learned_prompt_ignores_a_reply_line_that_looks_like_one():
    from hssh.transports.telnet import show

    def handler(srv):
        srv.send("\r\n" + OP)
        srv.readline()
        srv.send("\r\nnoc@example.com>")          # a line of output, ending like a prompt
        time.sleep(0.1)
        srv.send("\r\nmore output\r\n" + OP)
        srv.readline()
    srv = ScriptedTelnetServer(handler)
    out = show("127.0.0.1", "lab", "secret", "show interfaces descriptions",
               session_timeout=5, command_timeout=5, port=srv.port, vendor_hint="telnet-junos")
    assert "more output" in out and out.strip().endswith("more output")


def test_more_keeps_what_followed_the_marker_in_the_same_chunk():
    from hssh.transports.telnet import show

    def handler(srv):
        srv.send("\r\n" + OP)
        srv.readline()
        srv.send("\r\npart one\r\n--More--part two\r\n" + OP)
        srv.conn.recv(16)                          # the space the client sends
    srv = ScriptedTelnetServer(handler)
    out = show("127.0.0.1", "lab", "secret", "show log messages",
               session_timeout=5, command_timeout=5, port=srv.port, vendor_hint="telnet-junos")
    assert "part one" in out and "part two" in out and "--More--" not in out


def test_confirm_is_one_bare_commit_in_exclusive_mode():
    """-eC commit on telnet-junos went through the edit path: configure
    exclusive, commit as a config line, show | compare, commit again (#46)."""
    from hssh.transports import telnet
    assert hasattr(telnet, "confirm")
    srv = ScriptedTelnetServer(junos_cli(commit_reply="\r\ncommit complete"))
    out = telnet.confirm("127.0.0.1", "lab", "secret", session_timeout=5, command_timeout=5,
                         port=srv.port, vendor_hint="telnet-junos")
    assert out == "COMMIT CONFIRMED OK"
    assert _received(srv) == ["show system commit", "configure exclusive", "commit", "exit"]


def test_confirm_refused_lock_is_not_applied():
    from hssh.errors import NotAppliedError
    from hssh.transports import telnet
    srv = ScriptedTelnetServer(junos_cli(lock_reply="\r\nerror: configuration database locked by: other"))
    with pytest.raises(NotAppliedError, match="Failed to lock config"):
        telnet.confirm("127.0.0.1", "lab", "secret", session_timeout=5, command_timeout=5,
                       port=srv.port, vendor_hint="telnet-junos")
    assert _received(srv) == ["show system commit", "configure exclusive"]


def test_a_commit_line_inside_a_payload_is_refused_before_anything_is_sent(monkeypatch):
    """A dry run of -eC commit sent the commit (#46); now the word is never
    accepted as configuration, dry run or not."""
    from hssh.transports import telnet
    sent = []
    srv = ScriptedTelnetServer(junos_cli())
    for payload in ("commit\n", "set system host-name x\ncommit confirmed 5\n"):
        with pytest.raises(ValueError, match="'commit' is not configuration"):
            telnet.edit("127.0.0.1", "lab", "secret", payload, 5, 5, port=srv.port,
                        vendor_hint="telnet-junos", dry_run=True)
    srv.stop()
    assert srv.received == []
