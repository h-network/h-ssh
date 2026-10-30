"""-eD: one <NAME>.set per target, read before the password; -eC/-eB payloads follow each target's dialect."""

import re

import pytest

from hssh.drivers import Driver, Registry
from hssh.frontends import cli, fleet
from hssh.model import RunReport


class HashDialect:
    """A dialect that refuses nothing, so a test sees the stripping alone."""

    comment_prefixes = ("#",)

    def check_edit(self, lines):
        return None


class BangDialect(HashDialect):
    """Comment lines start with '!' as well, to tell per-target stripping from a shared rule."""

    comment_prefixes = ("#", "!")


class NoComm:
    capabilities = frozenset({"edit"})
    default_port = 22
    banner = None

    def __init__(self, dialect):
        self.dialect = dialect


@pytest.fixture
def two_drivers(monkeypatch):
    def registry():
        return Registry([Driver("hash@ssh", HashDialect(), NoComm(HashDialect())), Driver("bang@ssh", BangDialect(), NoComm(BangDialect()))])

    monkeypatch.setattr(cli, "Registry", registry)


@pytest.fixture
def run_cli(monkeypatch, capsys):
    monkeypatch.setenv("HSSH_PASSWORD", "x")
    seen = []

    def runner(spec):
        seen.append(spec)
        return RunReport(1, spec.mode, "2026-10-30T10:00:00+00:00", "2026-10-30T10:00:01+00:00", [], 0, 0, 0)

    def run(*argv):
        rc = cli.main(["--transport", "netconf", "--vendor", "junos", "--raw", *argv], runner=runner)
        return rc, seen[-1] if rc == 0 else None, capsys.readouterr().err.strip()

    return run


@pytest.fixture
def set_dir(tmp_path):
    tmp_path = tmp_path / "sets"
    tmp_path.mkdir()
    (tmp_path / "R1.set").write_text("# header\nset system host-name R1 # inline kept\n\nset x\n")
    (tmp_path / "R2.set").write_bytes("﻿set y\n".encode("utf-8"))
    return tmp_path


def test_each_target_gets_its_own_set_file(run_cli, set_dir):
    rc, spec, _ = run_cli("R1:10.0.0.1", "R2:10.0.0.2", "-eD", str(set_dir))
    assert rc == 0
    assert dict(spec.payloads) == {"R1": ("set system host-name R1 # inline kept", "set x"), "R2": ("set y",)}
    assert spec.config_lines == ()


def test_a_missing_set_file_ends_the_run_naming_the_device(run_cli, set_dir):
    rc, _, err = run_cli("R1:10.0.0.1", "R3:10.0.0.3", "-eD", str(set_dir))
    assert rc == 2
    assert "no <NAME>.set for 1 of 2 device(s): R3" in err and "--allow-missing" in err


def test_allow_missing_skips_the_device_and_says_so(run_cli, set_dir):
    rc, spec, err = run_cli("R1:10.0.0.1", "R3:10.0.0.3", "-eD", str(set_dir), "--allow-missing")
    assert rc == 0
    assert set(spec.payloads) == {"R1"} and [t.name for t in spec.targets] == ["R1", "R3"]
    assert "Skipping 1 device(s) without a set file: R3" in err


def test_allow_missing_with_no_set_file_at_all_is_nothing_to_do(run_cli, tmp_path):
    rc, _, err = run_cli("R9:10.0.0.9", "-eD", str(tmp_path), "--allow-missing")
    assert rc == 2 and "no device has a set file" in err


def test_allow_missing_needs_edit_dir(run_cli):
    rc, _, err = run_cli("R1:10.0.0.1", "-eC", "set x", "--allow-missing")
    assert rc == 2 and "--allow-missing goes with -eD" in err


def test_edit_dir_goes_alone(run_cli, set_dir):
    rc, _, err = run_cli("R1:10.0.0.1", "-eD", str(set_dir), "-eC", "set x")
    assert rc == 2 and "-eD goes alone" in err


def test_a_name_that_could_leave_the_directory_is_refused(run_cli, set_dir):
    rc, _, err = run_cli("--target", "../x:10.0.0.1", "-eD", str(set_dir))
    assert rc == 2 and "invalid device name '../x'" in err


def test_a_set_file_of_only_comments_is_refused_naming_the_file(run_cli, set_dir):
    (set_dir / "R1.set").write_text("# nothing\n\n# here\n")
    rc, _, err = run_cli("R1:10.0.0.1", "R2:10.0.0.2", "-eD", str(set_dir))
    assert rc == 2 and "nothing but blank lines and comments in" in err and "R1.set" in err and "R2.set" not in err


def test_a_control_character_is_refused_naming_the_file_and_the_line(run_cli, set_dir):
    (set_dir / "R1.set").write_text("set x\nset y\x1b[2J\n")
    rc, _, err = run_cli("R1:10.0.0.1", "-eD", str(set_dir))
    assert rc == 2 and re.search(r"R1\.set: line 2 has an ESC", err)


def test_comment_prefixes_follow_each_targets_dialect(run_cli, two_drivers, set_dir):
    (set_dir / "H1.set").write_text("! hash keeps this\nset x\n")
    (set_dir / "B1.set").write_text("! bang drops this\nset x\n")
    rc, spec, _ = run_cli("H1:10.0.0.1:hash", "--target", "B1:10.0.0.2:bang", "--transport", "ssh", "-eD", str(set_dir))
    assert rc == 0
    assert dict(spec.payloads) == {"H1": ("! hash keeps this", "set x"), "B1": ("set x",)}


def test_a_dialect_refusal_names_the_file(run_cli, set_dir):
    (set_dir / "R1.set").write_text("set x\ncommit\n")
    rc, _, err = run_cli("R1:10.0.0.1", "-eD", str(set_dir))
    assert rc == 2 and "R1.set: line 2: commit is not permitted" in err


def test_an_unknown_driver_is_refused_before_the_password(run_cli, set_dir):
    rc, _, err = run_cli("R1:10.0.0.1:nosuch", "-eD", str(set_dir))
    assert rc == 2 and "unknown driver 'nosuch@netconf'" in err


def test_eC_and_eB_payloads_are_per_target_too(run_cli, tmp_path):
    (tmp_path / "all.set").write_text("# c\nset shared\n")
    rc, spec, _ = run_cli("R1:10.0.0.1", "R2:10.0.0.2", "-eB", str(tmp_path / "all.set"))
    assert rc == 0 and dict(spec.payloads) == {"R1": ("set shared",), "R2": ("set shared",)}


def test_run_file_keys_edit_dir_and_allow_missing(run_cli, set_dir, tmp_path):
    run = tmp_path / "run.yaml"
    run.write_text("edit-dir: sets\nallow-missing: true\n")
    rc, spec, err = run_cli("R1:10.0.0.1", "R3:10.0.0.3", "--run", str(run))
    assert rc == 0 and set(spec.payloads) == {"R1"} and "Skipping 1 device(s)" in err


def test_every_does_not_run_edits(run_cli):
    rc, _, err = run_cli("R1:10.0.0.1", "-eC", "set x", "--every", "5")
    assert rc == 2 and "--every repeats reads" in err


def test_fleet_edit_takes_payloads_per_target():
    seen = []
    runner = lambda spec: (seen.append(spec), RunReport(1, "edit", "a", "b", [], 0, 0, 0))[1]  # noqa: E731
    f = fleet.Fleet(["R1:10.0.0.1:junos", "R2:10.0.0.2:junos"], transport="netconf", user="u", runner=runner)
    f.edit(payloads={"R1": ["set a"]})
    assert dict(seen[-1].payloads) == {"R1": ("set a",)} and seen[-1].config_lines == ()
    f.edit(lines=["set b"])
    assert dict(seen[-1].payloads) == {} and seen[-1].config_lines == ("set b",)
    with pytest.raises(ValueError):
        f.edit()
