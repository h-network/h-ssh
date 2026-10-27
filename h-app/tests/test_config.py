"""~/.h-ssh/config defaults."""
import asyncio
import json
import os
import re
import sys
import types
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hssh.core import load_config, get_config_path


def write(tmp_path, text):
    p = tmp_path / "config"
    p.write_text(text)
    return str(p)


def test_missing_file_is_not_an_error(tmp_path):
    assert load_config(str(tmp_path / "absent")) == {}


def test_reads_a_key(tmp_path):
    assert load_config(write(tmp_path, "user = EF\n"))["user"] == "EF"


def test_whitespace_is_optional(tmp_path):
    assert load_config(write(tmp_path, "user=EF"))["user"] == "EF"


def test_comments_are_ignored(tmp_path):
    cfg = load_config(write(tmp_path, "# a comment\nuser = EF  # trailing\n\n"))
    assert cfg == {"user": "EF"}


def test_quotes_are_stripped(tmp_path):
    assert load_config(write(tmp_path, 'user = "EF"'))["user"] == "EF"
    assert load_config(write(tmp_path, "user = 'EF'"))["user"] == "EF"


def test_keys_are_normalised(tmp_path):
    cfg = load_config(write(tmp_path, "USER = EF\nsession-timeout = 45\n"))
    assert cfg["user"] == "EF"
    assert cfg["session_timeout"] == "45"


def test_values_keep_their_case_and_inner_spacing(tmp_path):
    assert load_config(write(tmp_path, "user = Ef-Ops"))["user"] == "Ef-Ops"


def test_lines_without_a_separator_are_named(tmp_path):
    """A line that is not `key = value` is a typo, not a comment (#62)."""
    with pytest.raises(ValueError, match="line 1: expected 'key = value'"):
        load_config(write(tmp_path, "nonsense\nuser = EF\n"))


def test_empty_values_are_skipped(tmp_path):
    assert load_config(write(tmp_path, "user =\n")) == {}


def test_value_may_contain_equals(tmp_path):
    assert load_config(write(tmp_path, "user = a=b"))["user"] == "a=b"


def test_default_path_sits_beside_devices_csv():
    assert get_config_path().name == "config"
    assert get_config_path().parent.name == ".h-ssh"


def test_a_password_in_the_config_file_is_refused_not_read(tmp_path, monkeypatch):
    """A config file is world-readable often enough that secrets must not live
    there: a credential line is refused with exit 2 naming it (as a run file
    does), never read and never quietly ignored on the way to key auth."""
    import subprocess
    from hssh.core import load_config
    for key in ("password", "passwd", "secret", "token", "pass"):
        cfg = write(tmp_path, f"user = EF\n{key} = hunter2\n")
        with pytest.raises(ValueError, match=f"line 2: '{key}' is not allowed, a config file never carries a credential"):
            load_config(cfg)
    cfg = write(tmp_path, "user = EF\npassword = hunter2\n")
    hssh = os.path.join(os.path.dirname(__file__), "..", "h-ssh.py")
    proc = subprocess.run(
        [sys.executable, hssh, "--target", "x:127.0.0.1:openssh", "--config", cfg,
         "-sC", "show version", "--raw", "--session-timeout", "2"],
        capture_output=True, text=True, timeout=60,
        stdin=subprocess.DEVNULL)
    assert proc.returncode == 2
    assert "'password' is not allowed" in proc.stderr and "HSSH_PASSWORD or the prompt" in proc.stderr
    assert "hunter2" not in proc.stdout + proc.stderr


def test_config_fills_unset_options():
    from hssh.cli import apply_config_defaults

    class Args:
        workers = None
        session_timeout = None
        command_timeout = None
        retries = None
        transport = None

    args = Args()
    apply_config_defaults(args, {"workers": "16", "session_timeout": "5"})
    assert args.workers == 16
    assert args.session_timeout == 5


def test_flags_beat_the_config_file():
    from hssh.cli import apply_config_defaults

    class Args:
        workers = 4
        session_timeout = None
        command_timeout = None
        retries = None
        transport = None

    args = Args()
    apply_config_defaults(args, {"workers": "16"})
    assert args.workers == 4, "a value given on the command line must win"


def test_built_in_defaults_apply_with_no_config():
    from hssh.cli import apply_config_defaults, CONFIG_DEFAULTS

    class Args:
        workers = None
        session_timeout = None
        command_timeout = None
        retries = None
        transport = None

    args = Args()
    apply_config_defaults(args, {})
    for key, expected in CONFIG_DEFAULTS.items():
        assert getattr(args, key) == expected


def test_unparsable_or_out_of_range_config_values_name_their_key():
    """A config file is held to what the flag would accept (#39): no silent
    fallback to the default, the error names the key."""
    from hssh.cli import apply_config_defaults

    class Args:
        workers = None
        session_timeout = None
        command_timeout = None
        retries = None
        transport = None

    cases = [({"workers": "lots"}, "workers = 'lots' is not a number"),
             ({"workers": "0"}, "workers = 0 is below 1"),
             ({"session_timeout": "-3"}, "session_timeout = -3 is below 1"),
             ({"transport": "../../etc"}, "transport = '../../etc' is not one of")]
    for cfg, text in cases:
        with pytest.raises(ValueError, match=re.escape(text)):
            apply_config_defaults(Args(), cfg)
    args = Args()
    apply_config_defaults(args, {"workers": "16", "transport": "Junos"})
    assert args.workers == 16 and args.transport == "junos" and args.retries == 2


def test_bad_config_file_value_is_a_usage_error(monkeypatch, tmp_path):
    cfg = write(tmp_path, "transport = telnet-magic\n")
    rc, seen = run_main(monkeypatch, "-sC", "show version", "--target", "R1:192.0.2.1", config=cfg)
    assert rc == 2 and seen == []


def test_retries_zero_from_config_is_honoured():
    """0 is a meaningful value and must not be mistaken for unset."""
    from hssh.cli import apply_config_defaults

    class Args:
        workers = None
        session_timeout = None
        command_timeout = None
        retries = None
        transport = None

    args = Args()
    apply_config_defaults(args, {"retries": "0"})
    assert args.retries == 0


# --- the transport default reaches the targets --------------------------------

def run_main(monkeypatch, *argv, config=os.devnull):
    """h-ssh main() in this process, with the runner and the pre-flight check
    replaced so nothing is contacted. Returns (rc, [(name, vendor, transport)])
    as the runner was handed the targets."""
    from hssh import cli, drivers

    seen = []

    async def fake_run(t, transport, mode, show_cmd, edit_cmd, **kw):
        seen.append((t.name, t.vendor, transport))
        return t.name, True, f"DEVICE: {t.name}\nHOST:   {t.host}\nMODE:   {mode}\nVENDOR: {t.vendor}\n\nok\n", 1

    async def reachable(target, timeout=2):
        return target.name, True, "reachable"

    monkeypatch.setattr(cli, "run_for_target_async", fake_run)
    monkeypatch.setattr(cli, "check_reachability", reachable)
    for name in ("junos@netconf", "none@openssh"):
        monkeypatch.setitem(drivers.MODULES, name, types.SimpleNamespace(AVAILABLE=True))
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", config, "--user", "u", *argv])
    rc = asyncio.run(cli.main())
    return rc, sorted(seen)


def test_transport_flag_is_the_vendor_of_an_undeclared_inline_target(monkeypatch):
    rc, seen = run_main(monkeypatch, "--transport", "junos", "-sC", "show version",
                        "--target", "R1:192.0.2.1")
    assert rc == 0 and seen == [("R1", "junos", "junos")]


def test_transport_flag_is_the_vendor_of_undeclared_inventory_rows(monkeypatch, tmp_path):
    inv = tmp_path / "devices.csv"
    inv.write_text("name,ip\nR1,192.0.2.1\n")
    rc, seen = run_main(monkeypatch, "--transport", "junos", "-sC", "show version",
                        "--devices", str(inv))
    assert rc == 0 and seen == [("R1", "junos", "junos")]


def test_transport_flag_is_the_vendor_of_undeclared_job_targets(monkeypatch, tmp_path):
    job = tmp_path / "job.json"
    job.write_text(json.dumps([{"target": "R1:192.0.2.1", "show": "show version"}]))
    rc, seen = run_main(monkeypatch, "--transport", "junos", "--job", str(job))
    assert rc == 0 and seen == [("R1", "junos", "junos")]


@pytest.mark.parametrize("transport", ["junos", "openssh", "Junos "])
def test_config_transport_is_the_vendor_of_an_undeclared_target(monkeypatch, tmp_path, transport):
    """The README's 'transport = openssh' example has to do what it says;
    the value is matched the way a target's vendor is, lowercase."""
    cfg = write(tmp_path, f"transport = {transport}\n")
    rc, seen = run_main(monkeypatch, "-sC", "show version", "--target", "R1:192.0.2.1", config=cfg)
    assert rc == 0 and seen == [("R1", transport.strip().lower(), transport.strip().lower())]


def test_a_declared_vendor_beats_the_transport_default(monkeypatch, tmp_path):
    """Flag beats config file, and a vendor on the target beats both."""
    cfg = write(tmp_path, "transport = openssh\n")
    rc, seen = run_main(monkeypatch, "--transport", "junos", "-sC", "show version",
                        "--target", "R1:192.0.2.1:telnet", "--target", "R2:192.0.2.2", config=cfg)
    assert rc == 0 and seen == [("R1", "telnet", "telnet"), ("R2", "junos", "junos")]


# --- #126: --connect-timeout, `connect-timeout` in the config file, 3 by default ---------

def connect_timeouts(monkeypatch, *argv, config=os.devnull):
    """(rc, [(session_timeout, connect_timeout)]) as the driver got them for
    one show through main(); nothing is contacted."""
    from hssh import cli, drivers
    got = []

    def show(host, user, passwd, cmd, st, ct, port=None, vendor_hint=None, connect_timeout=None):
        got.append((st, connect_timeout))
        return "ok"
    monkeypatch.setitem(drivers.MODULES, "none@ssh", types.SimpleNamespace(AVAILABLE=True, show=show))
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", config, "--user", "u", "-sC", "show version",
                                      "R1:192.0.2.1:ssh", *argv])
    rc = asyncio.run(cli.main())
    return rc, got


def test_the_connect_timeout_is_a_flag_and_a_config_key_and_3_by_default(monkeypatch, tmp_path):
    assert connect_timeouts(monkeypatch) == (0, [(30, 3)])
    cfg = write(tmp_path, "connect-timeout = 5\nsession_timeout = 20\n")
    assert connect_timeouts(monkeypatch, config=cfg) == (0, [(20, 5)])
    assert connect_timeouts(monkeypatch, "--connect-timeout", "2", config=cfg) == (0, [(20, 2)])    # the flag wins
    from hssh.cli import apply_config_defaults
    for value, text in (("0", "connect_timeout = 0 is below 1"), ("86401", "connect_timeout = 86401 is above 86400"),
                        ("soon", "connect_timeout = 'soon' is not a number")):
        args = types.SimpleNamespace(workers=None, session_timeout=None, connect_timeout=None,
                                     command_timeout=None, retries=None, transport=None)
        with pytest.raises(ValueError, match=re.escape(text)):
            apply_config_defaults(args, {"connect_timeout": value})


def test_the_help_shows_the_connect_timeout(monkeypatch, capsys):
    from hssh import cli
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--help"])
    with pytest.raises(SystemExit) as e:
        asyncio.run(cli.main())
    out = " ".join(capsys.readouterr().out.split())
    assert e.value.code == 0 and "--connect-timeout SECONDS" in out
    assert ("how long the TCP connect and the SSH banner may take, per attempt and never more than "
            "--session-timeout" in out and "(default: 3)" in out)
