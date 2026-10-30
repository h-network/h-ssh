"""The checks an edit must pass before the password is asked: the comment, the timer, the run-file timer rule, the payload."""

import pytest

R1 = "R1:10.0.0.1:junos"
NETCONF = ("--transport", "netconf")


def refused(cli_run, *argv):
    rc, specs, _, err = cli_run(*argv, *NETCONF)
    assert rc == 2 and specs == []
    return err


@pytest.mark.parametrize("minutes", ["0", "70000", "-1"])
def test_the_timer_is_checked_before_the_password(cli_run, minutes):
    assert "commit-confirmed minutes must be a whole number from 1 to 65535" in refused(cli_run, R1, "-eC", "set x", "--commit-confirmed", minutes)


def test_a_comment_of_blanks_is_refused(cli_run):
    assert "comment is empty" in refused(cli_run, R1, "-eC", "set x", "--comment", "   ")


def test_a_comment_with_a_control_character_is_refused(cli_run):
    assert "control character" in refused(cli_run, R1, "-eC", "set x", "--comment", "two\nlines")


def test_a_comment_over_512_bytes_is_refused(cli_run):
    assert "over 512 bytes" in refused(cli_run, R1, "-eC", "set x", "--comment", "x" * 513)


def test_a_plain_comment_rides_the_spec(cli_run):
    rc, specs, _, _ = cli_run(R1, "-eC", "set x", "--comment", "ticket 42 (Bob's)", *NETCONF)
    assert rc == 0 and specs[0].edit.comment == "ticket 42 (Bob's)"


def test_a_run_file_that_applies_without_a_timer_is_refused(cli_run, tmp_path):
    run = tmp_path / "run.yaml"
    run.write_text("edit: set x\nyes: true\n")
    assert "applies changes without a rollback timer" in refused(cli_run, R1, "--run", str(run))


def test_a_run_file_that_applies_with_a_timer_runs(cli_run, tmp_path):
    run = tmp_path / "run.yaml"
    run.write_text("edit: set x\nyes: true\ncommit-confirmed: 5\n")
    rc, specs, _, _ = cli_run(R1, "--run", str(run), *NETCONF)
    assert rc == 0 and (specs[0].edit.apply, specs[0].edit.confirmed_minutes) == (True, 5)


def test_a_run_files_dry_run_needs_no_timer(cli_run, tmp_path):
    run = tmp_path / "run.yaml"
    run.write_text("edit: set x\n")
    rc, specs, _, _ = cli_run(R1, "--run", str(run), *NETCONF)
    assert rc == 0 and specs[0].edit.apply is False


def test_the_timer_may_come_from_the_flag_beside_the_file(cli_run, tmp_path):
    run = tmp_path / "run.yaml"
    run.write_text("edit: set x\nyes: true\n")
    rc, specs, _, _ = cli_run(R1, "--run", str(run), "--commit-confirmed", "7", *NETCONF)
    assert rc == 0 and specs[0].edit.confirmed_minutes == 7


def test_yes_typed_beside_a_timerless_file_is_refused_too(cli_run, tmp_path):
    run = tmp_path / "run.yaml"
    run.write_text("edit: set x\n")
    assert "without a rollback timer" in refused(cli_run, R1, "--run", str(run), "-y")


def test_an_edit_without_a_run_file_needs_no_timer(cli_run):
    rc, specs, _, _ = cli_run(R1, "-eC", "set x", "-y", *NETCONF)
    assert rc == 0 and specs[0].edit.confirmed_minutes is None


def test_an_eC_payload_keeps_an_inline_hash_and_drops_comment_lines(cli_run):
    _, specs, _, _ = cli_run(R1, "-eC", "set x # keep\n# drop\n\nset y", *NETCONF)
    assert dict(specs[0].payloads) == {"R1": ("set x # keep", "set y")}


def test_a_payload_the_dialect_refuses_names_the_source(cli_run):
    assert "-eC: line 2: commit is not permitted" in refused(cli_run, R1, "-eC", "set x\ncommit")


def test_an_eC_payload_of_comments_only_is_refused(cli_run):
    assert "nothing but blank lines and comments" in refused(cli_run, R1, "-eC", "# nothing\n")


def test_an_eB_control_character_names_the_file_and_the_line(cli_run, tmp_path):
    payload = tmp_path / "all.set"
    payload.write_bytes(b"set x\nset y\x00\n")
    err = refused(cli_run, R1, "-eB", str(payload))
    assert f"-eB {payload}: line 2 has a NUL" in err
