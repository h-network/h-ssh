"""Where the password comes from after the --password flag went: HSSH_PASSWORD
for a pipeline, the prompt by hand, keys or an agent with neither; and what
the prompts do on Ctrl-D and an empty variable."""

import asyncio
import os
import sys
import types

import pytest

from hssh import cli, drivers


def run(monkeypatch, capsys, argv, tty=False, env=None, getpass_answer=None, stdin_lines=None):
    seen = {}

    def show(host, user, passwd, cmd, *a, **kw):
        seen.update(user=user, passwd=passwd)
        return "ok"

    monkeypatch.setitem(drivers.MODULES, "junos@netconf", types.SimpleNamespace(AVAILABLE=True, show=show))
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    for k, v in (env or {}).items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(cli, "_tty", lambda stream: tty)
    if getpass_answer is not None:
        monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": getpass_answer() if callable(getpass_answer) else getpass_answer)
    if stdin_lines is not None:
        import io
        monkeypatch.setattr(sys, "stdin", io.StringIO("".join(ln + "\n" for ln in stdin_lines)))
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, *argv, "--target", "R1:10.0.0.1:junos",
                                      "-sC", "show version"])
    try:
        rc = asyncio.run(cli.main())
    except SystemExit as e:
        rc = e.code
    out, err = capsys.readouterr()
    return rc, out, err, seen


def test_the_flag_is_gone_and_the_help_says_where_the_password_comes_from(monkeypatch, capsys):
    rc, out, err, seen = run(monkeypatch, capsys, ["--user", "u", "--password", "x"])
    assert rc == 2 and "unrecognized arguments: --password" in err and seen == {}
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--help"])
    with pytest.raises(SystemExit) as e:
        asyncio.run(cli.main())
    out, err = capsys.readouterr()
    assert e.value.code == 0
    assert "HSSH_PASSWORD" in out and "no --password flag" in out and "config file never" in out


def test_a_pipeline_takes_hssh_password_and_never_prompts(monkeypatch, capsys):
    def never():
        raise AssertionError("prompted in a pipeline")
    rc, out, err, seen = run(monkeypatch, capsys, ["--user", "u"], tty=False, env={"HSSH_PASSWORD": "s3"}, getpass_answer=never)
    assert rc == 0 and seen == {"user": "u", "passwd": "s3"}


def test_a_pipeline_without_the_variable_goes_to_keys_without_a_prompt(monkeypatch, capsys):
    def never():
        raise AssertionError("prompted in a pipeline")
    rc, out, err, seen = run(monkeypatch, capsys, ["--user", "u"], tty=False, getpass_answer=never)
    assert rc == 0 and seen["passwd"] is None


def test_an_empty_variable_refuses_a_pipeline_run(monkeypatch, capsys):
    rc, out, err, seen = run(monkeypatch, capsys, ["--user", "u"], tty=False, env={"HSSH_PASSWORD": ""})
    assert rc == 2 and "HSSH_PASSWORD is set but empty" in err and seen == {}


def test_by_hand_the_prompt_asks_and_enter_skips_to_keys(monkeypatch, capsys):
    rc, out, err, seen = run(monkeypatch, capsys, ["--user", "u"], tty=True, getpass_answer="typed")
    assert rc == 0 and seen["passwd"] == "typed"
    rc, out, err, seen = run(monkeypatch, capsys, ["--user", "u"], tty=True, getpass_answer="")
    assert rc == 0 and seen["passwd"] is None
    # an empty variable by hand is the same as none: the prompt asks
    rc, out, err, seen = run(monkeypatch, capsys, ["--user", "u"], tty=True, env={"HSSH_PASSWORD": ""}, getpass_answer="typed")
    assert rc == 0 and seen["passwd"] == "typed"


def test_the_variable_set_by_hand_means_no_prompt(monkeypatch, capsys):
    def never():
        raise AssertionError("prompted although HSSH_PASSWORD is set")
    rc, out, err, seen = run(monkeypatch, capsys, ["--user", "u"], tty=True, env={"HSSH_PASSWORD": "s3"}, getpass_answer=never)
    assert rc == 0 and seen["passwd"] == "s3"


def test_ctrl_d_at_the_password_prompt_is_one_line_and_exit_2(monkeypatch, capsys):
    def eof():
        raise EOFError
    rc, out, err, seen = run(monkeypatch, capsys, ["--user", "u"], tty=True, getpass_answer=eof)
    assert rc == 2 and "no password given at the prompt" in err and "Traceback" not in err and seen == {}


def test_no_user_means_the_name_you_are_logged_in_as(monkeypatch, capsys):
    """Like ssh: no --user, no HSSH_USER, no `user` in the config file, and no
    question either; the system username is taken, on a terminal or not."""
    import getpass
    me = getpass.getuser()
    rc, out, err, seen = run(monkeypatch, capsys, [], tty=True, env={"HSSH_PASSWORD": "s3"}, stdin_lines=[])
    assert rc == 0 and seen == {"user": me, "passwd": "s3"} and "Username" not in err + out
    rc, out, err, seen = run(monkeypatch, capsys, [], tty=False, env={"HSSH_PASSWORD": "s3"})
    assert rc == 0 and seen["user"] == me
    rc, out, err, seen = run(monkeypatch, capsys, [], tty=False, env={"HSSH_PASSWORD": "s3", "HSSH_USER": "eve"})
    assert rc == 0 and seen["user"] == "eve"                      # the variable still wins over the system name


def test_a_prompt_gives_ctrl_c_back_to_python(monkeypatch):
    """asyncio's SIGINT handler only cancels the task while getpass keeps
    blocking; during a prompt the default handler is in place, and the
    previous one is put back afterwards."""
    import signal
    marker = lambda *a: None   # noqa: E731
    previous = signal.signal(signal.SIGINT, marker)
    try:
        seen = {}
        monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": seen.setdefault("handler", signal.getsignal(signal.SIGINT)) and "x")
        assert cli._ask("Password: ", secret=True) == "x"
        assert seen["handler"] is signal.default_int_handler
        assert signal.getsignal(signal.SIGINT) is marker
    finally:
        signal.signal(signal.SIGINT, previous)
