"""#83: the CLI engine, hssh.transports.cli, types at any channel in a
dialect's shape. Here the channel is a script in memory: the telnet tests
drive the same engine over a real socket, the paramiko tests over a fake
shell channel."""
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


class ScriptChannel:
    """A device played from a dict: what it says first, then a reply per
    command (a callable gets the line). Typed lines are echoed as a tty does.
    `hang_on` names a command left unanswered, `close_on` one answered by
    hanging up. `split_at` makes the first read that holds that text end
    right after it, as a device pausing there would."""

    def __init__(self, first, replies, echo=True, hang_on=None, close_on=None, split_at=None):
        self.queue = bytearray(first.encode())
        self.split_at = split_at
        self.replies = replies
        self.echo = echo
        self.hang_on = hang_on
        self.close_on = close_on
        self.typed = []
        self.closed = False
        self.eof = False

    def recv(self, n, timeout):
        if self.split_at and self.split_at.encode() in self.queue:
            n = min(n, self.queue.index(self.split_at.encode()) + len(self.split_at))
            self.split_at = None
        if self.queue:
            data = bytes(self.queue[:n])
            del self.queue[:n]
            return data
        if self.eof:
            return b""
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
        if self.echo:
            self.queue += (line + "\r\n").encode()
        reply = self.replies.get(line, self.replies.get(word, self.replies.get("<else>", "")))
        self.queue += (reply(line) if callable(reply) else reply).encode()

    def close(self):
        self.closed = True


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
    s.login("lab", "secret")
    assert ch.typed == ["lab", "secret"]
    assert s.prompt_re.pattern.startswith("lab@R1") and s.prompt_re.search("lab@R1# ")
    assert not s.prompt_re.search("other@R1> ") and not s.prompt_re.search("description noc@example.com>")


def test_a_username_or_password_the_prompt_would_take_as_keys_is_never_typed():
    """#139 review: the login dialogue typed the username and the password
    as they were. A password of `pw`, CR, `configure exclusive`, CR, ...,
    `commit comment x` logged in and ran the rest as commands, a commit for
    good from a show. Neither is typed with a control character in it, the
    channel is closed, and the refusal quotes neither. A Tab is text in a
    password; a shell already at its prompt (SSH, which took the pair for
    its own login) is asked for neither."""
    first = "\r\nR1 (ttyp0)\r\n\r\nlogin: "
    for user, passwd, what in (("lab\rconfigure exclusive", "secret", "the username has a carriage return"),
                               ("lab", "pw\rcommit comment x", "the password has a carriage return"),
                               ("lab\x03", "secret", "the username has a control character '\\x03'"),
                               ("lab\t", "secret", "the username has a Tab"),
                               ("lab", "pw\x15commit", "the password has a control character '\\x15'"),
                               ("lab", "pw\x9bx", "the password has a control character '\\x9b'")):
        ch = ScriptChannel(first, junos_device(lab="Password:"), echo=False)
        with pytest.raises(ValueError) as refused:
            Cli(ch, dialects.junos.DIALECT, 5).login(user, passwd)
        assert str(refused.value) == f"{what}, which a login prompt takes as a key, not as text; it was not sent"
        assert ch.typed == [] and ch.closed
    ch = ScriptChannel("\r\nPassword: ", junos_device(), echo=False)
    with pytest.raises(ValueError, match="^the password has a line break, which a login prompt takes as a key"):
        Cli(ch, dialects.junos.DIALECT, 5).login("lab", "pw\ncommit")
    assert ch.typed == []
    ch = ScriptChannel(first, junos_device(lab="Password:", **{"pw\tx": "\r\n" + OP}), echo=False)
    Cli(ch, dialects.junos.DIALECT, 5).login("lab", "pw\tx")
    assert ch.typed == ["lab", "pw\tx"]
    ch = ScriptChannel("\r\n" + OP, junos_device())
    Cli(ch, dialects.junos.DIALECT, 5).login("lab\r", "pw\n")
    assert ch.typed == []


def test_a_rejected_login_is_not_applied_and_quotes_the_device():
    ch = ScriptChannel("\r\nlogin: ", {"lab": "Password:", "<else>": "\r\nLogin incorrect\r\nlogin: "}, echo=False)
    with pytest.raises(NotAppliedError, match="login failed: Login incorrect"):
        Cli(ch, dialects.junos.DIALECT, 2).login("lab", "wrong")
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
        Cli(ch, dialects.junos.DIALECT, 1).login("lab", "s3cret")
    assert "s3cret" not in str(e.value) and "***" in str(e.value)


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
