"""#83: the CLI engine, hssh.transports.cli, types at any channel in a
dialect's shape. Here the channel is a script in memory: the telnet tests
drive the same engine over a real socket, the paramiko tests over a fake
shell channel."""
import re
import time

import pytest

from hssh import dialects
from hssh.drivers import results as R
from hssh.errors import AmbiguousCommitError, NotAppliedError, NothingToConfirmError
from hssh.transports.cli import Cli, edit_policy, pending_in, refuse_commit_lines, strip_ansi, complaint

OP = "lab@R1> "
CFG = "\r\n[edit]\r\nlab@R1# "
PENDING = ("\r\n0   2026-10-22 08:00:00 UTC by lab via cli commit confirmed, rollback in 5mins"
           "\r\n1   2026-10-21 17:10:03 UTC by lab via cli\r\n")
CLEAN = "\r\n0   2026-10-22 08:00:00 UTC by lab via cli\r\n1   2026-10-21 17:10:03 UTC by lab via cli\r\n"
# In what a ScriptChannel device says, a read ends at a PAUSE: what follows comes in the next one.
PAUSE = "<pause>"


def later(seconds):
    """A PAUSE that takes time: what follows it comes `seconds` after the
    read that reached it, as from a device that says nothing for that long."""
    return f"<pause {seconds}>"


_PAUSES = re.compile(rb"<pause(?: ([0-9.]+))?>")


class ScriptChannel:
    """A device played from a dict: what it says first, then a reply per
    command (a callable gets the line). Typed lines are echoed as a tty does,
    or as `echo` draws them when it is a callable.
    `hang_on` names a command left unanswered, `close_on` one answered by
    hanging up. `split_at` makes the first read that holds that text end
    right after it, as a device pausing there would; a PAUSE in what it
    says ends a read there every time, and a later() one also holds back
    what follows it for its time, a read until then waiting as long as its
    timeout lets it. `lag` is the time the device takes to echo and answer
    each line typed. With `blocking`, a read that finds nothing waits out
    its timeout first, as a socket's does, and `waits` notes the line typed
    last before each such wait."""

    def __init__(self, first, replies, echo=True, hang_on=None, close_on=None, split_at=None, blocking=False,
                 lag=0):
        self.queue = bytearray(first.encode())
        self.split_at = split_at
        self.blocking = blocking
        self.lag = lag
        self.ready_at = 0.0          # what follows a later() pause is not there before this
        self.waits = []
        self.replies = replies
        self.echo = echo
        self.hang_on = hang_on
        self.close_on = close_on
        self.typed = []
        self.closed = False
        self.eof = False

    def recv(self, n, timeout):
        head = _PAUSES.match(bytes(self.queue))
        if head:
            del self.queue[:head.end()]
            if head.group(1):
                self.ready_at = time.monotonic() + float(head.group(1))
        wait = self.ready_at - time.monotonic()
        if wait > 0:
            time.sleep(min(wait, timeout))
            if wait > timeout:
                raise TimeoutError("nothing to read yet")
        pause = _PAUSES.search(self.queue)
        if pause:
            n = min(n, pause.start())
        if self.split_at and self.split_at.encode() in self.queue:
            n = min(n, self.queue.index(self.split_at.encode()) + len(self.split_at))
            self.split_at = None
        if self.queue:
            data = bytes(self.queue[:n])
            del self.queue[:n]
            return data
        if self.eof:
            return b""
        if self.blocking:
            self.waits.append(self.typed[-1] if self.typed else None)
            time.sleep(timeout)
        raise TimeoutError("nothing to read")

    def send(self, data):
        text = data.decode()
        if text == " ":          # paging: the engine asked for more
            self.queue += self.replies["<more>"].encode()
            return
        line = text.rstrip("\n")
        self.typed.append(line)
        word = line.split(" ")[0]
        if word == self.close_on:
            self.eof = True
            return
        if word == self.hang_on:
            return
        if self.lag:
            self.queue += later(self.lag).encode()
        if self.echo:
            self.queue += ((self.echo(line) if callable(self.echo) else line) + "\r\n").encode()
        reply = self.replies.get(line, self.replies.get(word, self.replies.get("<else>", "")))
        self.queue += (reply(line) if callable(reply) else reply).encode()

    def close(self):
        self.closed = True

    def unread(self):
        """What the device said that nothing read, the pauses left out."""
        return _PAUSES.sub(b"", bytes(self.queue)).decode()


def junos_device(**over):
    replies = {
        "configure": "\r\nEntering configuration mode" + CFG,
        "set": CFG,
        "show | compare": "\r\n[edit system]\r\n+  host-name test;" + CFG,
        "show system commit": PENDING + OP,
        "show version": "\r\nHostname: R1\r\nModel: mx204\r\n" + OP,
        "rollback": "\r\nload complete" + CFG,
        "commit": "\r\ncommit complete" + CFG,
        "exit": "\r\nExiting configuration mode\r\n\r\n" + OP,
        "<else>": "\r\nsyntax error, expecting <command>." + CFG,
    }
    replies.update(over)
    return replies


def junos_session(first="\r\n" + OP, **kw):
    over = {k: kw.pop(k) for k in list(kw) if k not in ("echo", "hang_on", "close_on")}
    ch = ScriptChannel(first, junos_device(**over), **kw)
    s = Cli(ch, dialects.junos.DIALECT, 5)
    s.login("lab", "secret")
    return s, ch


# --- login and the prompt ------------------------------------------------------------

def test_login_answers_the_dialogue_and_learns_the_devices_own_prompt():
    first = "\r\nR1 (ttyp0)\r\n\r\nlogin: "
    replies = junos_device(**{"lab": "Password:", "secret": "\r\nLast login: Tue Oct 20\r\n--- JUNOS 23.4R2.13 ---\r\n\r\n" + OP})
    ch = ScriptChannel(first, replies, echo=False)
    s = Cli(ch, dialects.junos.DIALECT, 5)
    s.login("lab", "secret", dialogue=True)
    assert ch.typed == ["lab", "secret"]
    assert s.prompt_re.pattern.startswith("^lab@R1") and s.prompt_re.search("lab@R1# ")
    assert not s.prompt_re.search("other@R1> ") and not s.prompt_re.search("description noc@example.com>")


def test_a_username_or_password_the_prompt_would_take_as_keys_is_never_typed():
    """#139 review: the login dialogue typed the username and the password
    as they were. A password of `pw`, CR, `configure exclusive`, CR, ...,
    `commit comment x` logged in and ran the rest as commands, a commit for
    good from a show. Neither is typed with a control character in it, the
    channel is closed, and the refusal quotes neither. A Tab is text in a
    password; a console already at its prompt is asked for neither."""
    first = "\r\nR1 (ttyp0)\r\n\r\nlogin: "
    for user, passwd, what in (("lab\rconfigure exclusive", "secret", "the username has a carriage return"),
                               ("lab", "pw\rcommit comment x", "the password has a carriage return"),
                               ("lab\x03", "secret", "the username has a control character '\\x03'"),
                               ("lab\t", "secret", "the username has a Tab"),
                               ("lab", "pw\x15commit", "the password has a control character '\\x15'"),
                               ("lab", "pw\x9bx", "the password has a control character '\\x9b'")):
        ch = ScriptChannel(first, junos_device(lab="Password:"), echo=False)
        with pytest.raises(ValueError) as refused:
            Cli(ch, dialects.junos.DIALECT, 5).login(user, passwd, dialogue=True)
        assert str(refused.value) == f"{what}, which a login prompt takes as a key, not as text; it was not sent"
        assert ch.typed == [] and ch.closed
    ch = ScriptChannel("\r\nPassword: ", junos_device(), echo=False)
    with pytest.raises(ValueError, match="^the password has a line break, which a login prompt takes as a key"):
        Cli(ch, dialects.junos.DIALECT, 5).login("lab", "pw\ncommit", dialogue=True)
    assert ch.typed == []
    ch = ScriptChannel(first, junos_device(lab="Password:", **{"pw\tx": "\r\n" + OP}), echo=False)
    Cli(ch, dialects.junos.DIALECT, 5).login("lab", "pw\tx", dialogue=True)
    assert ch.typed == ["lab", "pw\tx"]
    ch = ScriptChannel("\r\n" + OP, junos_device())
    Cli(ch, dialects.junos.DIALECT, 5).login("lab\r", "pw\n", dialogue=True)
    assert ch.typed == []


def test_a_rejected_login_is_not_applied_and_quotes_the_device():
    ch = ScriptChannel("\r\nlogin: ", {"lab": "Password:", "<else>": "\r\nLogin incorrect\r\nlogin: "}, echo=False)
    with pytest.raises(NotAppliedError, match="login failed: Login incorrect"):
        Cli(ch, dialects.junos.DIALECT, 2).login("lab", "wrong", dialogue=True)
    assert ch.closed


def test_a_silent_device_gets_one_enter_then_is_a_failed_login():
    ch = ScriptChannel("", {"": "\r\n" + OP})
    s = Cli(ch, dialects.junos.DIALECT, 1)
    s.login("lab", "secret")                     # the Enter woke it
    assert ch.typed == [""]
    ch = ScriptChannel("", {"": ""})
    with pytest.raises(NotAppliedError, match="login failed: no prompt within 1s"):
        Cli(ch, dialects.junos.DIALECT, 1).login("lab", "secret")


def test_the_password_never_appears_in_a_timeout_message():
    ch = ScriptChannel("\r\nlogin: ", {"lab": "Password:", "s3cret": "s3cret\r\n"})   # echoes it, no prompt
    with pytest.raises(NotAppliedError) as e:
        Cli(ch, dialects.junos.DIALECT, 1).login("lab", "s3cret", dialogue=True)
    assert "s3cret" not in str(e.value) and "***" in str(e.value)


def test_without_the_dialogue_a_banner_that_asks_for_a_password_gets_nothing_typed():
    """#141: login() answered `login:` and `Password:` on every channel,
    and the ssh and openssh shells called it with the SSH credentials: a
    shell banner ending in `Password: `, the prompt in a later read, got
    the password typed into the device CLI, and its echo came back as the
    next command's reply. Without the dialogue, as the SSH shells log in
    now, the engine reads to the prompt and types nothing, whatever the
    banner ends with; telnet's dialogue answers a `Password: ` the device
    waits at."""
    asks = "\r\n--- JUNOS 23.4R2.13\r\nAsk the NOC for the Password: "
    for credentials in (("lab", "secret"), ()):
        ch = ScriptChannel(asks + later(0.5) + "\r\n" + OP, junos_device())
        s = Cli(ch, dialects.junos.DIALECT, 5)
        s.login(*credentials)
        assert ch.typed == [] and s.prompt_re.search("lab@R1> ")
        assert s.run("show version", 5).strip() == "Hostname: R1\nModel: mx204"
    ch = ScriptChannel(asks, junos_device(secret="\r\n" + OP), echo=False)
    Cli(ch, dialects.junos.DIALECT, 5).login("lab", "secret", dialogue=True)
    assert ch.typed == ["secret"]


IOS_LINES = {"configure terminal": "\r\nEnter configuration commands, one per line.  End with CNTL/Z.\r\nR1(config)#",
             "interface": "\r\nR1(config-if)#",
             "ip": "\r\n               ^\r\n% Invalid input detected at '^' marker.\r\nR1(config-if)#",
             "end": "\r\nR1#"}


def test_a_banner_line_shaped_like_a_prompt_does_not_end_the_login():
    """#141: login() took the dialect's prompt at the end of a read, a line
    break after it or not, and waited no longer. A banner whose last line
    ends in a word and `>` (`... report misuse to NOC-DESK>`), the real
    prompt in a later read, ended the login on the banner: the prompt
    learned was the wrong one and every reply after it the one before, so
    the `% Invalid input` for a refused line was read as the reply to `end`
    and the edit said APPLIED. A prompt is the last line with nothing after
    it, however long the device pauses once its line break has come (half
    a second here, past SETTLE), and a login waits SETTLE after one for the
    device to say more: the edit fails on its refused line, every reply
    read by the command it answers. Telnet's dialogue reads past a
    `Password: ` in a banner the same way."""
    replies = {said: reply + PAUSE for said, reply in IOS_LINES.items()}
    for banner in ("\r\nAuthorized users only - report misuse to NOC-DESK>\r\n" + later(0.5) + "\r\nR1>",
                   "\r\nAuthorized users only - report misuse to NOC-DESK>" + PAUSE + "\r\n\r\nR1>",
                   "\r\nAuthorized users only. Report misuse to:\r\nNOC-DESK>" + PAUSE + "\r\n\r\nR1>"):
        ch = ScriptChannel(banner + PAUSE, replies)
        s = Cli(ch, dialects.ios.DIALECT, 5)
        s.login()
        assert s.prompt_re.search("R1(config-if)#") and not s.prompt_re.search("NOC-DESK>")
        with pytest.raises(RuntimeError, match=r"^'ip addres 10\.0\.0\.1 255\.255\.255\.0': % Invalid input detected"):
            s.edit_lines("interface Gi0/1\nip addres 10.0.0.1 255.255.255.0\n")
        assert ch.typed == ["configure terminal", "interface Gi0/1", "ip addres 10.0.0.1 255.255.255.0", "end"]
        assert ch.unread() == ""
    ch = ScriptChannel("\r\nAsk the NOC for the Password: " + PAUSE + "\r\nR1>" + PAUSE, replies)
    s = Cli(ch, dialects.ios.DIALECT, 5)
    s.login("u", "pw", dialogue=True)
    assert ch.typed == [] and s.prompt_re.search("R1#")


def test_on_a_channel_that_echoes_the_first_reply_is_read_through_its_echo():
    """#141 review: a login that ended on a banner line shaped like a
    prompt, the device pausing longer than SETTLE before its line break,
    left the rest of the banner (blank lines, or more of it, and the real
    prompt) to be read as the first command's reply, and with a device
    slow to answer every reply after it was the one before: the `% Invalid
    input` for a refused line was the reply to `end`, and the edit said
    APPLIED. A pty echoes each line typed, and the ssh and openssh shells
    say so: the first reply is read until the echo of its command and then
    its prompt, what came before the echo is not part of it, and each reply
    after it is the command's own. The login could not name the device's
    prompt, which is learned from the first reply."""
    banner = "\r\nAuthorized users only - report misuse to NOC-DESK>" + later(0.3)
    for tail in ("\r\n\r\nR1>", "\r\nEdits: always enter with configure terminal\r\n\r\nR1>",
                 "\r\nChange window 22:00-02:00 only\r\n\r\nR1>"):
        ch = ScriptChannel(banner + tail, IOS_LINES, lag=0.2)
        s = Cli(ch, dialects.ios.DIALECT, 5, echoes=True)
        s.login()
        with pytest.raises(RuntimeError, match=r"^'ip addres 10\.0\.0\.1 255\.255\.255\.0': % Invalid input detected"):
            s.edit_lines("interface Gi0/1\nip addres 10.0.0.1 255.255.255.0\n")
        assert ch.typed == ["configure terminal", "interface Gi0/1", "ip addres 10.0.0.1 255.255.255.0", "end"]
        assert ch.unread() == ""
    s = Cli(ScriptChannel(banner + tail, IOS_LINES, lag=0.2), dialects.ios.DIALECT, 5, echoes=True)
    s.login()
    assert s.prompt_re.search("uplink to BackupR1#")         # no prompt name in the banner line
    assert s.run("configure terminal", 5).strip() == "Enter configuration commands, one per line.  End with CNTL/Z."
    assert s.prompt_re.search("R1(config-if)#") and not s.prompt_re.search("uplink to BackupR1#")


def test_a_junos_banner_line_ending_in_an_address_is_not_the_prompt():
    """#141 review: Junos's prompt name was not anchored at the line start,
    so a banner line that only ends in `user@host>` (`Contact NOC
    <noc@example.net>`), the device pausing before its line break, was
    learned as the prompt: the real one never matched, and the edit failed
    after its timeout. The prompt name starts the line; the login names
    none here, and the prompt is learned from the first reply."""
    banner = "\r\nUnauthorized access prohibited. Contact NOC <noc@example.net>" + later(0.5) + "\r\n\r\n" + OP
    ch = ScriptChannel(banner, junos_device())
    s = Cli(ch, dialects.junos.DIALECT, 5, echoes=True)
    s.login()
    result = s.edit_candidate("set system host-name test\n", dry_run=True)
    assert result.status == R.DRY_RUN and "host-name test" in result.diff
    assert s.prompt_re.search("lab@R1# ") and not s.prompt_re.search("Contact NOC <noc@example.net>")


def test_the_initial_bytes_from_negotiation_count_as_the_banner():
    ch = ScriptChannel("", junos_device())
    s = Cli(ch, dialects.junos.DIALECT, 5, initial="\r\n" + OP)
    s.login("lab", "secret")
    assert ch.typed == []


# --- run ----------------------------------------------------------------------------

def test_run_strips_the_echo_and_the_prompt():
    s, ch = junos_session()
    assert s.run("show version", 5).strip() == "Hostname: R1\nModel: mx204"
    assert ch.typed == ["show version"]


def test_run_times_out_and_notices_a_hangup_rather_than_return_a_partial_reply():
    s, ch = junos_session(hang_on="show")
    with pytest.raises(TimeoutError, match="no prompt within 1s"):
        s.run("show version", 1)
    s, ch = junos_session(close_on="show")
    with pytest.raises(ConnectionError, match="closed by the device"):
        s.run("show version", 1)


def test_a_reply_line_that_is_the_prompt_does_not_end_the_reply():
    """#141: a read whose last line was the learned prompt was the reply, so
    a reply line that is the prompt itself (`Router>`), with the rest of the
    reply in the device's next write, ended it there: `show prompt` gave
    `line one`, and the next command got the rest as its own reply. A reply
    with output is read on until the device has said nothing more for
    SETTLE after its prompt, and must still end with one: each command gets
    its own reply, every word of it."""
    for prompt_line in ("line one\r\nRouter>" + PAUSE + "\r\nline three",
                        # its line break come, the prompt line is the reply's however long the pause
                        "line one\r\nRouter>\r\n" + later(0.5) + "line three",
                        # what comes during the settle is no prompt, and the read goes on to one
                        "line one\r\nRouter>" + later(0.05) + "\r\nline three" + later(0.3)):
        replies = {"show prompt": prompt_line + "\r\n\r\nRouter>" + PAUSE,
                   "show version": "Cisco IOS Software\r\n\r\nRouter>" + PAUSE}
        ch = ScriptChannel("\r\nRouter>" + PAUSE, replies)
        s = Cli(ch, dialects.ios.DIALECT, 5)
        s.login()
        assert s.run("show prompt", 5) == "line one\nRouter>\nline three\n"
        assert s.run("show version", 5) == "Cisco IOS Software\n"
        assert ch.typed == ["show prompt", "show version"] and ch.unread() == ""


def test_the_wait_after_a_prompt_never_runs_past_the_command_timeout():
    """#141: a reply with output is read on while the device goes on after
    its prompt, each new prompt waited on again. A device that never stops
    talking, every write of it ending in the prompt, is read no longer than
    the command timeout: what came by then, ending in the prompt, is the
    reply."""
    stream = "".join(f"x{n}\r\nRouter>" + later(0.05) + "\r\n" for n in range(60))
    ch = ScriptChannel("\r\nRouter>", {"show stream": stream})
    s = Cli(ch, dialects.ios.DIALECT, 5)
    s.login()
    started = time.monotonic()
    out = s.run("show stream", 1)
    assert time.monotonic() - started < 1.5
    assert out.startswith("x0\nRouter>\nx1\nRouter>\nx2\n") and not out.endswith("Router>")


def test_a_line_that_only_ends_in_the_prompt_never_ends_a_read():
    """#141: the learned prompt was looked for anywhere in the last line,
    so `uplink to BackupRouter>` was `Router>` to it: a reply line ending so,
    at a read boundary, ended the read, and the rest of the reply was the
    next command's. The learned prompt is the whole line from its start;
    such a line never ends a read, however long the device pauses after it,
    and a reply that stops there is no reply."""
    replies = {"show cdp": "line one\r\nuplink to BackupRouter>" + PAUSE + "\r\nline three\r\n\r\nRouter>",
               "show uplinks": "line one\r\nuplink to BackupRouter>"}
    ch = ScriptChannel("\r\nRouter>", replies)
    s = Cli(ch, dialects.ios.DIALECT, 5)
    s.login()
    assert not s.prompt_re.search("uplink to BackupRouter>") and s.prompt_re.search("Router(config-if)#")
    assert s.run("show cdp", 5) == "line one\nuplink to BackupRouter>\nline three\n"
    with pytest.raises(TimeoutError, match="^no prompt within 1s; last line: 'uplink to BackupRouter>'$"):
        s.run("show uplinks", 1)


# Above the [edit] banner while a commit confirmed waits.
TIMER = "# commit confirmed will be rolled back in 4 minutes"


@pytest.mark.parametrize("banner", ["[edit]", "{master}[edit]", TIMER + "\r\n[edit]"])
def test_a_line_of_an_edit_is_not_waited_on(banner):
    """#141: a reply with output of its own is read on for SETTLE after its
    prompt. One that is only the echo, the context banner and the prompt,
    each set line of an edit (`{master}[edit]` on a router with two routing
    engines, the note of a pending commit confirmed above `[edit]`), is not
    waited on at all, so a 1000-line edit costs what it did: a few ms a
    line at most. The channel's reads block as a socket's do, so a wait
    would cost its time; one after a set line ends the test."""
    cfg = f"\r\n\r\n{banner}\r\nlab@R1# "
    stamps = []

    def set_line(line):
        assert not (ch.waits and (ch.waits[-1] or "").startswith("set ")), "a set line's reply was waited on"
        stamps.append(time.monotonic())
        return cfg
    ch = ScriptChannel("\r\n" + OP, junos_device(**{
        "configure": "\r\nEntering configuration mode" + cfg, "set": set_line,
        "show | compare": "\r\n[edit system]\r\n+  host-name test;" + cfg, "rollback": "\r\nload complete" + cfg}),
        blocking=True)
    s = Cli(ch, dialects.junos.DIALECT, 5)
    s.login()
    payload = "".join(f"set interfaces ge-0/0/{n} description x{n}\n" for n in range(1000))
    r = s.edit_candidate(payload, dry_run=True)
    assert r.status == R.DRY_RUN and r.diff == "[edit system]\n+  host-name test;"
    assert ch.waits == [None, "configure exclusive", "show | compare", "rollback 0", "exit"]
    assert len(stamps) == 1000 and (stamps[-1] - stamps[0]) / 999 < 0.003


def test_a_long_line_junos_scrolls_on_a_narrow_pty_is_not_waited_on():
    """#141 live check: on `junos@openssh` (an 80-column pty) a 200-line dry
    run took 34 s instead of 5. Junos draws a set line longer than the pty
    as it is typed, then scrolls it: its start, a carriage return, the
    prompt and `...` with the line's end, spaces and backspaces over them.
    That echo, several lines to splitlines(), was taken for output and each
    line of the edit waited SETTLE. It is the echo; a refusal after it
    still fails the edit."""
    def scrolled(line):
        if len(line) <= 50:
            return line
        return line[:50] + "\rlab@R1# ..." + line[-30:-2] + " " * 22 + "\b" * 22 + line[-2:] + " "

    def line_of_an_edit(line):
        assert not (ch.waits and (ch.waits[-1] or "").startswith("set ")), "a set line's reply was waited on"
        stamps.append(time.monotonic())
        return ("\r\nerror: invalid prefix" if "bogus" in line else "") + cfg

    stamps, cfg = [], "\r\n\r\n[edit]\r\nlab@R1# "
    junos = junos_device(**{"configure": "\r\nEntering configuration mode" + cfg, "set": line_of_an_edit,
                            "show | compare": "\r\n[edit policy-options]\r\n+  prefix-list big { ... }" + cfg,
                            "rollback": "\r\nload complete" + cfg})
    ch = ScriptChannel("\r\n" + OP, junos, blocking=True, echo=scrolled)
    s = Cli(ch, dialects.junos.DIALECT, 5, echoes=True)
    s.login()
    payload = "".join(f"set policy-options prefix-list lab141-big 192.0.2.{n}/32\n" for n in range(1, 201))
    r = s.edit_candidate(payload, dry_run=True)
    assert r.status == R.DRY_RUN and ch.waits == [None, "configure exclusive", "show | compare", "rollback 0", "exit"]
    assert len(stamps) == 200 and (stamps[-1] - stamps[0]) / 199 < 0.003
    ch = ScriptChannel("\r\n" + OP, junos, echo=scrolled)
    s = Cli(ch, dialects.junos.DIALECT, 5, echoes=True)
    s.login()
    with pytest.raises(RuntimeError, match=r"^'set policy-options prefix-list lab141-big bogus/32': error: invalid prefix$"):
        s.edit_candidate("set policy-options prefix-list lab141-big 192.0.2.1/32\n"
                         "set policy-options prefix-list lab141-big bogus/32\n", dry_run=True)


def test_a_line_whose_echo_the_cli_redraws_is_not_waited_on():
    """#141 review: a reply that is only the echo and the prompt is not
    waited on, and the echo was known only as the line typed. A Junos CLI
    completes a keyword as it is typed (`set int ge-0/0/0 desc x0` comes
    back `set interfaces ge-0/0/0 description x0`), and an IOS-shaped CLI
    narrower than a long line scrolls it (a `$`, then its end): that echo
    was taken for output, and each such line of an edit waited SETTLE, 150 s
    more for 1000 lines. On a channel that echoes, a reply whose one line
    of text is not the line typed is its echo as the CLI drew it; a reply
    with more than that is output, and a refusal still fails the edit. A
    telnet device need not echo: there a reply of one line is that line."""
    full = {"int": "interfaces", "desc": "description"}

    def line_of_an_edit(line):
        assert not (ch.waits and (ch.waits[-1] or "").startswith(("set ", "snmp"))), "a line's reply was waited on"
        stamps.append(time.monotonic())
        return ("\r\n" + " " * 20 + "^\r\nsyntax error." if "bogus" in line else "") + cfg

    stamps, cfg = [], "\r\n\r\n[edit]\r\nlab@R1# "
    junos = junos_device(**{"configure": "\r\nEntering configuration mode" + cfg, "set": line_of_an_edit,
                            "show | compare": "\r\n[edit system]\r\n+  host-name test;" + cfg,
                            "rollback": "\r\nload complete" + cfg})
    ch = ScriptChannel("\r\n" + OP, junos, blocking=True,
                       echo=lambda line: " ".join(full.get(word, word) for word in line.split(" ")))
    s = Cli(ch, dialects.junos.DIALECT, 5, echoes=True)
    s.login()
    r = s.edit_candidate("".join(f"set int ge-0/0/{n} desc x{n}\n" for n in range(1000)), dry_run=True)
    assert r.status == R.DRY_RUN and ch.waits == [None, "configure exclusive", "show | compare", "rollback 0", "exit"]
    assert len(stamps) == 1000 and (stamps[-1] - stamps[0]) / 999 < 0.003
    ch = ScriptChannel("\r\n" + OP, junos, echo=lambda line: " ".join(full.get(word, word) for word in line.split(" ")))
    s = Cli(ch, dialects.junos.DIALECT, 5, echoes=True)
    s.login()
    with pytest.raises(RuntimeError, match=r"^'set int ge-0/0/1 bogus-knob 1': syntax error\.$"):
        s.edit_candidate("set int ge-0/0/1 desc y\nset int ge-0/0/1 bogus-knob 1\n", dry_run=True)

    stamps, cfg = [], "\r\nR1(config)#"
    ios = {"configure terminal": "\r\nEnter configuration commands, one per line.  End with CNTL/Z." + cfg,
           "snmp-server": line_of_an_edit, "end": "\r\nR1#"}
    ch = ScriptChannel("\r\nR1#", ios, blocking=True, echo=lambda line: line if len(line) < 60 else "$" + line[-58:])
    s = Cli(ch, dialects.ios.DIALECT, 5, echoes=True)
    s.login()
    lines = "".join(f"snmp-server location building {n}, floor 2, rack 17, managed by the noc desk\n"
                    for n in range(1000))
    assert s.edit_lines(lines) == "(config applied)"
    assert ch.waits == [None, "configure terminal"] and len(stamps) == 1000
    ch = ScriptChannel("\r\nR1#", {"show clock": "\r\n*10:00:00.000 UTC Wed Oct 28 2026\r\nR1#"}, echo=False)
    s = Cli(ch, dialects.ios.DIALECT, 5)
    s.login()
    assert s.run("show clock", 5).strip() == "*10:00:00.000 UTC Wed Oct 28 2026"


def test_the_note_of_a_pending_commit_confirmed_is_the_prompts_not_the_replys():
    """#141 review: while a commit confirmed waits, Junos says so above the
    `[edit]` of every configuration-mode prompt. The engine took one line
    there for the prompt's, so the note was the reply's own: an empty `show
    | compare` read as a diff, and an edit that changed nothing typed
    `commit`, which confirms the pending timer; a preview made at 4 minutes
    was another diff at 3. Every such line at the end of a reply is the
    prompt's: nothing to commit is NO CHANGES with no commit typed, and the
    diff is the same whatever the minutes."""
    def cfg(minutes):
        return f"\r\n\r\n# commit confirmed will be rolled back in {minutes} minutes\r\n[edit]\r\n" + OP.replace(">", "#")

    def device(minutes, diff):
        return {"configure": "\r\nEntering configuration mode" + cfg(minutes), "set": cfg(minutes),
                "show | compare": diff + cfg(minutes), "rollback": "\r\nload complete" + cfg(minutes),
                "commit": "\r\ncommit complete" + cfg(minutes)}
    s, ch = junos_session(**device(4, ""))
    r = s.edit_candidate("set system host-name R1\n", dry_run=False, confirmed_minutes=5)
    assert r.status == R.NO_CHANGES and not r.pending
    assert ch.typed == ["configure exclusive", "set system host-name R1", "show | compare", "rollback 0", "exit"]
    diff = "\r\n[edit system]\r\n+  host-name test;"
    s, ch = junos_session(**device(4, diff))
    preview = s.edit_candidate("set system host-name test\n", dry_run=True).diff
    assert preview == "[edit system]\n+  host-name test;"
    s, ch = junos_session(**device(3, diff))
    r = s.edit_candidate("set system host-name test\n", dry_run=False, expected_diff=preview)
    assert r.status == R.COMMITTED and r.diff == preview and ch.typed[-2:] == ["commit", "exit"]


def test_paging_is_answered_and_the_marker_removed():
    s, ch = junos_session(**{"show version": "\r\npart one\r\n---(more)---", "<more>": "\r\npart two\r\n" + OP})
    out = s.run("show version", 5)
    assert "part one" in out and "part two" in out and "more" not in out


def test_ansi_sequences_are_stripped():
    assert strip_ansi("\x1b[32mgreen\x1b[0m") == "green"
    s, ch = junos_session(**{"show version": "\r\n\x1b[1mBold\x1b[0m line\r\n" + OP})
    assert s.run("show version", 5).strip() == "Bold line"


# --- edits ----------------------------------------------------------------------------

def test_a_candidate_edit_commits_what_the_diff_showed():
    s, ch = junos_session()
    r = s.edit_candidate("set system host-name test\n", dry_run=False)
    assert isinstance(r, R.EditResult) and r.status == R.COMMITTED
    assert r.diff == "[edit system]\n+  host-name test;"        # the [edit] banner is the prompt's, not the diff's
    assert ch.typed == ["configure exclusive", "set system host-name test", "show | compare", "commit", "exit"]


def test_a_dry_run_discards_the_candidate_and_a_timer_goes_on_the_wire():
    s, ch = junos_session()
    r = s.edit_candidate("set system host-name test\n", dry_run=True)
    assert r.status == R.DRY_RUN and ch.typed[-2:] == ["rollback 0", "exit"] and "commit" not in ch.typed
    s, ch = junos_session()
    r = s.edit_candidate("set system host-name test\n", dry_run=False, confirmed_minutes=5)
    assert r.status == R.CONFIRMED and r.minutes == 5 and "commit confirmed 5" in ch.typed


def test_no_diff_is_no_changes_and_a_changed_diff_commits_nothing():
    s, ch = junos_session(**{"show | compare": CFG})
    assert s.edit_candidate("set system host-name test\n", dry_run=False).status == R.NO_CHANGES
    s, ch = junos_session()
    with pytest.raises(RuntimeError, match="diff changed since preview; nothing committed"):
        s.edit_candidate("set system host-name test\n", dry_run=False, expected_diff="+  host-name other;")
    assert "commit" not in ch.typed and ch.typed[-2:] == ["rollback 0", "exit"]


def test_an_empty_compare_types_no_commit():
    """#139: with nothing in `show | compare` the engine typed `commit`, or
    `commit confirmed 5`, and said NO CHANGES: a timer armed that the CLI's
    reminder never mentions, and on Junos an empty commit also confirms
    another user's pending commit confirmed. Nothing to commit is NO
    CHANGES before any commit is typed, the candidate discarded, as over
    NETCONF; a --show-diff preview that showed nothing is the same."""
    for kw in ({}, {"confirmed_minutes": 5}, {"expected_diff": ""}):
        s, ch = junos_session(**{"show | compare": CFG})
        r = s.edit_candidate("set system host-name test\n", dry_run=False, **kw)
        assert r.status == R.NO_CHANGES and not r.pending
        assert ch.typed == ["configure exclusive", "set system host-name test", "show | compare", "rollback 0", "exit"]


def test_a_refused_lock_sends_nothing_else_and_a_syntax_error_rolls_back():
    s, ch = junos_session(configure="\r\nerror: configuration database locked by: other\r\n" + OP)
    with pytest.raises(NotAppliedError, match="Failed to lock config"):
        s.edit_candidate("set system host-name test\n", dry_run=False)
    assert ch.typed == ["configure exclusive"]
    s, ch = junos_session(**{"set bogus": "\r\nsyntax error, expecting <command>." + CFG})
    with pytest.raises(RuntimeError, match="'set bogus': syntax error"):
        s.edit_candidate("set bogus\n", dry_run=False)
    assert ch.typed[-2:] == ["rollback 0", "exit"]


def test_a_cli_that_checks_a_line_as_it_is_typed_is_read_past_its_redraw():
    """cRPD on a pty refuses a bad word when the space after it is typed, prints
    the prompt and the line again (with backspaces), then refuses the Enter: two
    complaints and a prompt in the middle of one reply. The error is one line,
    and the prompt in the middle does not end the read early even when the
    device pauses right after it."""
    redraw = ("set interfaces lo0 bogus-knob\r\n" + " " * 30 + "^\r\nsyntax error.\r\n\r\n"
              "lab@R1# set interfaces lo0 bogus-knob   \x08\x08\x081\r\n" + " " * 30 + "^\r\nsyntax error." + CFG)
    ch = ScriptChannel("\r\n" + OP, junos_device(**{"set interfaces lo0 bogus-knob 1": redraw}),
                       echo=False, split_at="\r\n\r\nlab@R1# ")
    s = Cli(ch, dialects.junos.DIALECT, 5)
    s.login("lab", "secret")
    with pytest.raises(RuntimeError, match=r"^'set interfaces lo0 bogus-knob 1': syntax error\.$"):
        s.edit_candidate("set interfaces lo0 bogus-knob 1\n", dry_run=False)
    assert ch.typed == ["configure exclusive", "set interfaces lo0 bogus-knob 1", "show | compare", "rollback 0", "exit"]
    assert not ch.queue                       # every reply was read by the command it answered


def test_the_complaint_is_the_devices_refusal_line_not_the_caret_art():
    ios = dialects.ios.DIALECT
    assert complaint("\n" + " " * 12 + "^\n% Invalid input detected at '^' marker.\n", ios) == \
        "% Invalid input detected at '^' marker."
    assert complaint("Translating \"bogus\"\n% Unknown command\n", ios) == "% Unknown command"
    assert complaint("\n   ^\nsomething the dialect does not know\n", ios) == "something the dialect does not know"
    assert complaint("warning: statement ignored\n", dialects.junos.DIALECT) == "warning: statement ignored"


def test_a_refused_commit_is_discarded_and_an_unanswered_one_is_outcome_unknown():
    s, ch = junos_session(commit="\r\nerror: configuration check-out failed" + CFG)
    with pytest.raises(RuntimeError, match="Commit failed: error: configuration check-out failed"):
        s.edit_candidate("set system host-name test\n", dry_run=False)
    assert ch.typed[-2:] == ["rollback 0", "exit"]
    s, ch = junos_session(close_on="commit")
    with pytest.raises(AmbiguousCommitError, match="commit outcome unknown"):
        s.edit_candidate("set system host-name test\n", dry_run=False)


def test_a_commit_line_in_a_payload_is_refused_before_anything_is_typed():
    with pytest.raises(ValueError, match="'commit' is not configuration"):
        refuse_commit_lines("set a b\ncommit confirmed 5\n")
    refuse_commit_lines("set a b\n")


def test_a_commit_line_is_its_first_word_whatever_ends_it():
    """#139: the rail split a line on spaces alone, so `commit;`, which the
    set-syntax guard itself counts as a commit, and `commit` with a Tab
    after it went past it, and in the library's edit() and run_for_target
    it is the only rail. The word inside a set line is still configuration."""
    for payload in ("set a b\ncommit;\n", "commit;", "set a b\ncommit\tcomment x\n", "commit;; and-quit\n"):
        with pytest.raises(ValueError, match="'commit' is not configuration"):
            refuse_commit_lines(payload)
    refuse_commit_lines("set system commit synchronize\nset a commit;\n")
    s, ch = junos_session()
    with pytest.raises(ValueError, match="'commit' is not configuration"):
        s.edit_candidate("set system host-name x\ncommit;\n", dry_run=True)
    assert ch.typed == []


def test_an_abbreviated_commit_is_a_commit_too():
    """#139 review: the rail took the word `commit` whole, and a Junos CLI
    completes a unique prefix of a command: `com`, `comm` and `commi` are
    `commit` in configuration mode (`co` is `copy` as well). For a library
    caller the rail is the only one. A shortening is refused as the word
    is, with a closing ';' or more words after it, before anything is
    typed; a word that only starts like one is configuration's business."""
    for payload in ("com\n", "set a b\ncomm\n", "commi;\n", "set a b\ncom confirmed 1\n", "com\tcheck\n"):
        with pytest.raises(ValueError, match="is 'commit' to a Junos CLI, and 'commit' is not configuration"):
            refuse_commit_lines(payload)
    refuse_commit_lines("co\nset a commit\ncopy a to b\ncommitted\nCOM\n")
    s, ch = junos_session()
    with pytest.raises(ValueError, match="^'com' is 'commit' to a Junos CLI"):
        s.edit_candidate("set system host-name x\ncom\n", dry_run=True)
    assert ch.typed == []


# What the Junos line editor acts on as it arrives: ^C drops the line typed so
# far, ^U kills it, DEL rubs out a character. The rest of the line then ran as
# a line of its own (#139). An ESC or a C1 CSI starts a key sequence, and a
# NUL is not text.
KEYS = ["set system host-name x\x03commit comment y\n", "set a\x15commit\n", "set " + "\x7f" * 4 + "commit\n",
        "set system\thost-name x\n", "set a\x1b[2Kcommit\n", "set a\x9b2Kcommit\n", "set a\x00commit\n"]


def test_a_line_with_a_control_character_or_a_tab_is_never_typed():
    """#139: `set system host-name x`, ^C, `commit comment y` in a payload
    committed for good with no timer, under a dry run too, and h-ssh said
    DRY-RUN. The engine types no control character and no Tab (a CLI
    completes the word on it): an edit is refused before configure mode, a
    command before it is sent."""
    for payload in KEYS:
        s, ch = junos_session()
        with pytest.raises(ValueError, match="which a CLI takes as a key, not as text; nothing was sent to the device$"):
            s.edit_candidate(payload, dry_run=True)
        assert ch.typed == []
    replies = {"configure terminal": "\r\nRouter(config)#", "end": "\r\nRouter#", "<else>": "\r\nRouter(config)#"}
    ch = ScriptChannel("\r\nRouter#", replies)
    s = Cli(ch, dialects.ios.DIALECT, 5)
    s.login("u", "p")
    with pytest.raises(ValueError, match=r"^'interface Gi0/1\\x03reload' has a control character '\\x03'"):
        s.edit_lines("hostname x\ninterface Gi0/1\x03reload\n")
    assert ch.typed == []
    s, ch = junos_session()
    with pytest.raises(ValueError, match=r"^'set a\\x03commit' has a control character '\\x03', which a CLI takes "
                                         r"as a key, not as text; it was not sent$"):
        s.run("set a\x03commit", 5)
    with pytest.raises(ValueError, match="has a Tab"):
        s.run("show\tversion", 5)
    assert ch.typed == []


def test_a_string_that_is_not_text_is_never_typed():
    """#139: the engine encoded what it typed with errors='replace', so a
    byte that is not UTF-8 (a lone surrogate, from an argv or a JSON \\udcXX
    escape) went out as '?', which a Junos CLI takes as a request for help.
    It is refused before configure mode, and nothing is ever replaced."""
    s, ch = junos_session()
    with pytest.raises(ValueError, match="a byte that is not UTF-8"):
        s.edit_candidate("set system host-name a\udcffb\n", dry_run=True)
    with pytest.raises(ValueError, match="a byte that is not UTF-8"):
        s.run("show \udcff", 5)
    with pytest.raises(UnicodeEncodeError):
        s._send("show \udcff\n")
    assert ch.typed == []


def test_a_confirm_comment_is_one_line_of_text_without_a_double_quote():
    """#139: the comment went on the commit line as it was given: a line
    break ran `rollback 1` and a second commit, and the confirm said
    confirmed-ok; a double quote ends the quoted comment."""
    for comment, what in (('x"\nrollback 1\ncommit', "a line break"), ('x" confirmed 1', "a double quote"),
                          ("x\ty", "a Tab"), ("x\x03", "a control character")):
        s, ch = junos_session()
        with pytest.raises(ValueError, match=f"the comment .* has {what}.*nothing was sent to the device$"):
            s.confirm(5, comment=comment)
        assert ch.typed == []
    s, ch = junos_session()
    assert s.confirm(5, comment="change 42: lo0") == "COMMIT CONFIRMED OK"
    assert 'commit comment "change 42: lo0"' in ch.typed


def test_lines_edit_applies_each_line_in_config_mode():
    replies = {"configure terminal": "\r\nRouter(config)#", "end": "\r\nRouter#", "<else>": "\r\nRouter(config)#"}
    ch = ScriptChannel("\r\nRouter#", replies)
    s = Cli(ch, dialects.ios.DIALECT, 5)
    s.login("u", "p")
    assert s.edit_lines("hostname x\n! comment\ninterface Gi0/1\n") == "(config applied)"
    assert ch.typed == ["configure terminal", "hostname x", "interface Gi0/1", "end"]
    replies["bogus"] = "\r\n% Invalid input detected at '^' marker.\r\nRouter(config)#"
    ch = ScriptChannel("\r\nRouter#", replies)
    s = Cli(ch, dialects.ios.DIALECT, 5)
    s.login("u", "p")
    with pytest.raises(RuntimeError, match="'bogus': % Invalid input"):
        s.edit_lines("bogus\n")
    assert ch.typed[-1] == "end"


# An IOS device with no Gi0/9: a line it refuses leaves it in the mode it was in.
NO_GI09 = {"configure terminal": "\r\nEnter configuration commands, one per line.  End with CNTL/Z.\r\nR1(config)#",
           "interface Gi0/1": "\r\nR1(config-if)#",
           "interface Gi0/9": "\r\n" + " " * 17 + "^\r\n% Invalid input detected at '^' marker.\r\n\r\nR1(config-if)#",
           "end": "\r\nR1#", "<else>": "\r\nR1(config-if)#"}


def test_a_lines_edit_stops_at_the_first_refused_line():
    """#142: a lines edit typed every line, refused or not, each in the mode
    the device was then in. With `interface Gi0/9` refused, the device
    still in Gi0/1's interface mode, the `shutdown` after it shut Gi0/1,
    and the failure named only the refusal. The edit stops at the first
    refused line, types `end` and fails, naming the line and the device's
    complaint, the lines applied before it and the lines not sent."""
    refused = "'interface Gi0/9': % Invalid input detected at '^' marker."
    for payload, typed, said in (
            ("interface Gi0/1\n description uplink-ok\ninterface Gi0/9\n shutdown\n",
             ["interface Gi0/1", "description uplink-ok", "interface Gi0/9"],
             "applied before it: 'interface Gi0/1', 'description uplink-ok'; not sent: 'shutdown'"),
            ("interface Gi0/9\n shutdown\n no ip address\n", ["interface Gi0/9"],
             "applied before it: none; not sent: 'shutdown', 'no ip address'"),
            ("interface Gi0/1\n! the last line\ninterface Gi0/9\n", ["interface Gi0/1", "interface Gi0/9"],
             "applied before it: 'interface Gi0/1'; not sent: none")):
        ch = ScriptChannel("\r\nR1#", NO_GI09)
        s = Cli(ch, dialects.ios.DIALECT, 5)
        s.login()
        with pytest.raises(RuntimeError) as failed:
            s.edit_lines(payload)
        assert str(failed.value) == f"{refused}; {said}"
        assert ch.typed == ["configure terminal", *typed, "end"] and ch.unread() == ""


# --- confirm ----------------------------------------------------------------------------

def test_confirm_is_one_bare_commit_in_exclusive_mode():
    s, ch = junos_session()
    assert s.confirm(5) == "COMMIT CONFIRMED OK"
    assert ch.typed == ["show system commit", "configure exclusive", "commit", "exit"]
    s, ch = junos_session()
    s.confirm(5, comment="done")
    assert 'commit comment "done"' in ch.typed


def test_nothing_pending_means_nothing_sent():
    s, ch = junos_session(**{"show system commit": CLEAN + OP})
    with pytest.raises(NothingToConfirmError, match="nothing to confirm"):
        s.confirm(5)
    assert ch.typed == ["show system commit"]
    assert pending_in(PENDING, dialects.junos.DIALECT) and not pending_in(CLEAN, dialects.junos.DIALECT)


# --- policy ----------------------------------------------------------------------------

def test_a_lines_dialect_refuses_what_only_a_candidate_can_do():
    for kw in ({"dry_run": True}, {"commit_confirmed": 5}, {"expected_diff": "+ x"}):
        with pytest.raises(ValueError, match="not supported by ios@ssh; nothing was sent"):
            edit_policy(dialects.ios.DIALECT, "ios@ssh", kw.get("dry_run", False), kw.get("commit_confirmed"),
                        kw.get("expected_diff"))
    edit_policy(dialects.junos.DIALECT, "junos@ssh", True, 5, "+ x")
    with pytest.raises(ValueError):
        edit_policy(dialects.junos.DIALECT, "junos@ssh", False, 0, None)   # a timer it cannot arm
