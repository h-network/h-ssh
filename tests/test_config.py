"""~/.h-ssh/config defaults."""
import os
import sys
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


def test_lines_without_a_separator_are_skipped(tmp_path):
    assert load_config(write(tmp_path, "nonsense\nuser = EF\n")) == {"user": "EF"}


def test_empty_values_are_skipped(tmp_path):
    assert load_config(write(tmp_path, "user =\n")) == {}


def test_value_may_contain_equals(tmp_path):
    assert load_config(write(tmp_path, "user = a=b"))["user"] == "a=b"


def test_default_path_sits_beside_devices_csv():
    assert get_config_path().name == "config"
    assert get_config_path().parent.name == ".h-ssh"


def test_password_is_not_read_from_config(tmp_path, monkeypatch):
    """A config file is world-readable often enough that secrets must not live there."""
    import subprocess
    cfg = write(tmp_path, "user = EF\npassword = hunter2\n")
    hssh = os.path.join(os.path.dirname(__file__), "..", "h-ssh.py")
    proc = subprocess.run(
        [sys.executable, hssh, "--target", "x:127.0.0.1:openssh", "--config", cfg,
         "-sC", "show version", "--raw", "--session-timeout", "2"],
        capture_output=True, text=True, timeout=60,
        stdin=subprocess.DEVNULL)
    # It must not have authenticated with a config-supplied password; the run
    # fails on connection, never on a password read out of the file.
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


def test_unparsable_numbers_fall_back_to_the_default():
    from hssh.cli import apply_config_defaults

    class Args:
        workers = None
        session_timeout = None
        command_timeout = None
        retries = None
        transport = None

    args = Args()
    apply_config_defaults(args, {"workers": "lots"})
    assert args.workers == 8


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
