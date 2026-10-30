"""Configuration precedence: a typed flag, then the run file, then ~/.h-ssh/config, then the orchestrator's default."""

import pytest

from hssh.frontends import cli
from hssh.orchestrator import DEFAULT_TIMEOUTS, DEFAULT_WORKERS

R1 = "R1:10.0.0.1:junos"
BASE = ["-sC", "show version", "--transport", "netconf"]


@pytest.fixture
def files(tmp_path):
    run = tmp_path / "run.yaml"
    run.write_text("workers: 3\nsession-timeout: 7\nprobe: false\n")
    config = tmp_path / "config"
    config.write_text("workers = 5\nsession_timeout = 11\nprobe = no\nuser = cfg\n")
    return str(run), str(config)


def test_the_orchestrators_defaults_apply_when_nothing_is_set(cli_run):
    _, specs, _, _ = cli_run(R1, *BASE)
    spec = specs[0]
    assert spec.workers == DEFAULT_WORKERS and spec.timeouts == DEFAULT_TIMEOUTS and spec.probe is cli.DEFAULT_PROBE
    assert spec.host_key_policy == cli.DEFAULT_HOST_KEY_POLICY and spec.policy == cli.DEFAULT_POLICY


def test_the_config_file_fills_what_is_not_typed(cli_run, files):
    _, config = files
    _, specs, _, _ = cli_run(R1, *BASE, "--config", config)
    assert (specs[0].workers, specs[0].timeouts.setup, specs[0].probe) == (5, 11, False)


def test_the_run_file_wins_over_the_config_file(cli_run, files):
    run, config = files
    _, specs, _, _ = cli_run(R1, *BASE, "--run", run, "--config", config)
    assert (specs[0].workers, specs[0].timeouts.setup, specs[0].probe) == (3, 7, False)


def test_a_typed_flag_wins_over_both(cli_run, files):
    run, config = files
    _, specs, _, _ = cli_run(R1, *BASE, "--run", run, "--config", config, "--workers", "2", "--probe")
    assert (specs[0].workers, specs[0].probe) == (2, True)


def test_a_flag_typed_with_the_defaults_value_still_wins(cli_run, files):
    run, _ = files
    _, specs, _, _ = cli_run(R1, *BASE, "--run", run, "--workers", str(DEFAULT_WORKERS))
    assert specs[0].workers == DEFAULT_WORKERS


def test_the_user_comes_from_the_flag_then_the_config_then_the_login_name(cli_run, files, monkeypatch):
    _, config = files
    _, specs, _, _ = cli_run(R1, *BASE, "--config", config, "--user", "flag")
    assert specs[0].credentials.username == "flag"
    _, specs, _, _ = cli_run(R1, *BASE, "--config", config)
    assert specs[0].credentials.username == "cfg"
    monkeypatch.setattr(cli, "default_username", lambda: "login")
    _, specs, _, _ = cli_run(R1, *BASE)
    assert specs[0].credentials.username == "login"


def test_hssh_user_beats_the_login_name(cli_run, monkeypatch):
    monkeypatch.setenv("HSSH_USER", "env")
    _, specs, _, _ = cli_run(R1, *BASE)
    assert specs[0].credentials.username == "env"


@pytest.mark.xfail(strict=True, reason="config 'user' is filled into args.user before HSSH_USER is read, so the file beats the variable")
def test_hssh_user_beats_the_config_file(cli_run, files, monkeypatch):
    _, config = files
    monkeypatch.setenv("HSSH_USER", "env")
    _, specs, _, _ = cli_run(R1, *BASE, "--config", config)
    assert specs[0].credentials.username == "env"


def test_the_password_is_hssh_password_and_never_prompted_off_a_terminal(cli_run, monkeypatch):
    _, specs, _, _ = cli_run(R1, *BASE)
    assert specs[0].credentials.password == "x"
    monkeypatch.delenv("HSSH_PASSWORD")
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: pytest.fail("prompted without a terminal"))
    _, specs, _, _ = cli_run(R1, *BASE)
    assert specs[0].credentials.password is None


def test_config_syntax(tmp_path):
    config = tmp_path / "config"
    config.write_text("﻿# comment\nWorkers = 4   # trailing\nRetry-Pause = '2'\nstore = \"/tmp/x.db\"\n\n")
    assert cli.load_config(str(config)) == {"workers": "4", "retry_pause": "2", "store": "/tmp/x.db"}


def test_a_missing_config_file_is_empty(tmp_path):
    assert cli.load_config(str(tmp_path / "none")) == {}


def test_a_config_line_without_a_separator_names_the_line(tmp_path):
    config = tmp_path / "config"
    config.write_text("workers = 4\njust words\n")
    with pytest.raises(ValueError, match="line 2: expected 'key = value'"):
        cli.load_config(str(config))


@pytest.mark.parametrize("key", ["password", "passwd", "secret", "token", "pass"])
def test_a_credential_in_the_config_file_is_refused(tmp_path, key):
    config = tmp_path / "config"
    config.write_text(f"{key} = hunter2\n")
    with pytest.raises(ValueError, match="never carries a credential"):
        cli.load_config(str(config))


def test_a_bad_config_value_is_a_usage_error(cli_run, tmp_path):
    config = tmp_path / "config"
    config.write_text("workers = many\n")
    rc, specs, _, err = cli_run(R1, *BASE, "--config", str(config))
    assert rc == 2 and specs == [] and err.startswith("ERROR: ")
