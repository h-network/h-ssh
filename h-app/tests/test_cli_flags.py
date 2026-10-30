"""Flags and the refusals that come before the password, each one line and exit 2, with no run started."""

import pytest

from hssh.frontends import cli

R1 = "R1:10.0.0.1:junos"
NETCONF = ("--transport", "netconf")


def refused(cli_run, *argv):
    rc, specs, _, err = cli_run(*argv, *NETCONF)
    assert rc == 2 and specs == []
    assert err.startswith("ERROR: ")
    return err


def test_no_mode_is_refused(cli_run):
    assert "exactly one of" in refused(cli_run, R1)


def test_two_modes_are_refused(cli_run):
    assert "exactly one of" in refused(cli_run, R1, "-sC", "show version", "--confirm")


@pytest.mark.parametrize("argv, mode", [
    (["-sC", "show version"], "show"),
    (["-sC", "show version", "--format", "json"], "structured"),
    (["-sC", "show version", "--format", "text"], "show"),
    (["-eC", "set x"], "edit"),
    (["--confirm"], "confirm"),
    (["--commit-status"], "commit_status"),
])
def test_each_mode_builds_its_spec(cli_run, argv, mode):
    rc, specs, _, _ = cli_run(R1, *argv, *NETCONF)
    assert rc == 0 and specs[0].mode == mode


def test_format_is_carried_only_in_structured_mode(cli_run):
    _, specs, _, _ = cli_run(R1, "-sC", "show version", "--format", "xml", *NETCONF)
    assert specs[0].format == "xml" and specs[0].commands == ("show version",)
    _, specs, _, _ = cli_run(R1, "-sC", "show version", *NETCONF)
    assert specs[0].format is None


def test_a_batch_file_is_the_commands_in_order(cli_run, tmp_path):
    batch = tmp_path / "b.txt"
    batch.write_text("# reads\nshow version\n\nshow route summary # trailing\n")
    _, specs, _, _ = cli_run(R1, "--batch", str(batch), *NETCONF)
    assert specs[0].mode == "batch" and specs[0].commands == ("show version", "show route summary")


def test_skip_unreachable_needs_an_edit(cli_run):
    assert "--skip-unreachable goes with an edit" in refused(cli_run, R1, "-sC", "show version", "--skip-unreachable")


def test_skip_unreachable_rides_an_edit(cli_run):
    _, specs, _, _ = cli_run(R1, "-eC", "set x", "--skip-unreachable", *NETCONF)
    assert specs[0].skip_unreachable is True


def test_every_refuses_an_edit(cli_run):
    assert "--every repeats reads" in refused(cli_run, R1, "-eC", "set x", "--every", "5")


def test_an_unknown_choice_is_one_line_and_exit_2(cli_run, capsys):
    with pytest.raises(SystemExit) as stop:
        cli.main([R1, "-sC", "x", "--transport", "carrier-pigeon"])
    assert str(stop.value).startswith("ERROR: argument --transport")


def test_yes_applies_and_without_it_an_edit_is_a_dry_run(cli_run):
    _, specs, _, _ = cli_run(R1, "-eC", "set x", *NETCONF)
    assert specs[0].edit.apply is False
    _, specs, _, _ = cli_run(R1, "-eC", "set x", "-y", *NETCONF)
    assert specs[0].edit.apply is True


def test_commit_confirmed_alone_takes_the_default_minutes(cli_run):
    _, specs, _, _ = cli_run(R1, "-eC", "set x", "--commit-confirmed", *NETCONF)
    assert specs[0].edit.confirmed_minutes == cli.DEFAULT_CONFIRMED_MINUTES
    _, specs, _, _ = cli_run(R1, "-eC", "set x", "--commit-confirmed", "3", *NETCONF)
    assert specs[0].edit.confirmed_minutes == 3


def test_the_safety_gate_is_off_without_a_safety_file(cli_run, tmp_path):
    _, specs, _, _ = cli_run(R1, "-sC", "x", *NETCONF)
    assert specs[0].safety is None
    _, specs, _, _ = cli_run(R1, "-sC", "x", "--safety-file", str(tmp_path / "s.json"), "--cooldown", "9", *NETCONF)
    assert (specs[0].safety.cooldown_seconds, specs[0].safety.rate_limit) == (9, cli.DEFAULT_SAFETY.rate_limit)


def test_recording_carries_the_store_and_argv(cli_run):
    argv = [R1, "-sC", "x", *NETCONF]
    _, specs, _, _ = cli_run(*argv)
    assert specs[0].recording.store_path == cli.DEFAULT_STORE and specs[0].recording.argv == tuple(argv)
    _, specs, _, _ = cli_run(*argv, "--no-store", "--store", "ignored.db")
    assert specs[0].recording.store_path is None


def test_list_profiles_runs_nothing(cli_run, monkeypatch, tmp_path):
    monkeypatch.setattr(cli.profiles, "user_dir", lambda: tmp_path)
    monkeypatch.setattr(cli.profiles, "SHIPPED_DIR", tmp_path / "none")
    rc, specs, out, _ = cli_run("--list-profiles")
    assert rc == 0 and specs == [] and out.startswith("no profiles")


def test_library_loggers_are_quiet_unless_verbose(cli_run):
    import logging

    cli_run(R1, "-sC", "x", *NETCONF)
    assert logging.getLogger("paramiko").level == logging.CRITICAL
    for name in cli.LIBRARY_LOGGERS:
        logging.getLogger(name).setLevel(logging.NOTSET)
    cli_run(R1, "-sC", "x", "-v", *NETCONF)
    assert logging.getLogger("paramiko").level == logging.NOTSET
