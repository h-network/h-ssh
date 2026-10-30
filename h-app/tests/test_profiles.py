"""Profiles: a batch file known by name, yours before the shipped ones."""

import pytest

from hssh.frontends import cli, profiles


@pytest.fixture
def dirs(tmp_path, monkeypatch):
    yours, shipped = tmp_path / "yours", tmp_path / "shipped"
    yours.mkdir()
    shipped.mkdir()
    (shipped / "health.txt").write_text("# Junos health\nshow version\nshow chassis alarms\n")
    (shipped / "snapshot.txt").write_text("show configuration\n")
    monkeypatch.setattr(profiles, "user_dir", lambda: yours)
    monkeypatch.setattr(profiles, "SHIPPED_DIR", shipped)
    return yours, shipped


def test_a_shipped_name_resolves(dirs):
    _, shipped = dirs
    assert profiles.profile_path("health") == shipped / "health.txt"


def test_yours_wins_over_a_shipped_one_of_the_same_name(dirs):
    yours, _ = dirs
    (yours / "health.txt").write_text("show version\n")
    assert profiles.profile_path("health") == yours / "health.txt"


def test_a_name_with_a_slash_is_a_path(dirs, tmp_path):
    own = tmp_path / "mine.txt"
    own.write_text("show x\n")
    assert profiles.profile_path(str(own)) == own
    with pytest.raises(ValueError, match="no such file"):
        profiles.profile_path(str(tmp_path / "gone.txt"))


def test_an_unknown_name_says_where_it_looked(dirs):
    yours, _ = dirs
    with pytest.raises(ValueError, match=f"no profile 'nope': not in {yours} and not shipped"):
        profiles.profile_path("nope")


def test_read_commands_drops_blank_lines_and_comments(tmp_path):
    batch = tmp_path / "b.txt"
    batch.write_text("﻿# header\nshow version  \n\nshow route # trailing\n")
    assert profiles.read_commands(batch) == ["show version", "show route"]


def test_describe_counts_the_commands_and_takes_the_first_comment(dirs):
    _, shipped = dirs
    assert profiles.describe(shipped / "health.txt") == (2, "Junos health")
    assert profiles.describe(shipped / "snapshot.txt") == (1, "show configuration")


def test_listing_puts_yours_first_and_lists_a_shared_name_once(dirs):
    yours, _ = dirs
    (yours / "health.txt").write_text("show version\n")
    (yours / "mine").write_text("show x\nshow y\n")
    assert profiles.listing() == [("health", "yours", 1, "show version"), ("mine", "yours", 2, "show x"),
                                  ("snapshot", "shipped", 1, "show configuration")]


def test_listing_lines_group_by_origin(dirs):
    lines = profiles.listing_lines()
    assert lines[0].startswith("shipped (") and lines[1].strip().startswith("health") and "2 commands" in lines[1]


def test_no_profiles_says_where_to_put_one(dirs):
    yours, shipped = dirs
    for path in shipped.iterdir():
        path.unlink()
    assert profiles.listing_lines() == [f"no profiles: put a batch file in {yours}/NAME.txt"]


def test_a_profile_runs_as_the_batch_it_is(cli_run, dirs):
    rc, specs, _, _ = cli_run("R1:10.0.0.1:junos", "--profile", "health", "--transport", "netconf")
    assert rc == 0 and specs[0].mode == "batch" and specs[0].commands == ("show version", "show chassis alarms")


def test_an_unknown_profile_is_refused_before_anything_runs(cli_run, dirs):
    rc, specs, _, err = cli_run("R1:10.0.0.1:junos", "--profile", "nope", "--transport", "netconf")
    assert rc == 2 and specs == [] and "no profile 'nope'" in err


def test_list_profiles_prints_the_listing(cli_run, dirs):
    rc, _, out, _ = cli_run("--list-profiles")
    assert rc == 0 and out.splitlines() == profiles.listing_lines()


def test_the_cli_reads_the_profile_through_profiles(cli_run, dirs, monkeypatch):
    seen = []
    monkeypatch.setattr(cli.profiles, "read_commands", lambda path: seen.append(path) or ["show a"])
    cli_run("R1:10.0.0.1:junos", "--profile", "snapshot", "--transport", "netconf")
    assert seen == [dirs[1] / "snapshot.txt"]
