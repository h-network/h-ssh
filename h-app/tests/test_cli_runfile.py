"""A run file's devices are used unless a target or --devices is typed; the spelling of --run does not matter."""

import pytest

from hssh.frontends import cli
from hssh.model import RunReport


def run_cli(argv, monkeypatch):
    monkeypatch.setenv("HSSH_PASSWORD", "x")
    seen = []

    def runner(spec):
        seen.append(spec)
        return RunReport(1, spec.mode, "2026-10-30T10:00:00+00:00", "2026-10-30T10:00:01+00:00", [], 0, 0, 0)

    assert cli.main(argv, runner=runner) == 0
    return seen[0]


@pytest.fixture
def run_file(tmp_path):
    path = tmp_path / "run.yaml"
    path.write_text("devices:\n  - R1:10.0.0.1:junos\nshow: show version\ntransport: netconf\n")
    return str(path)


@pytest.mark.parametrize("spelling", [lambda f: ["--run", f], lambda f: [f"--run={f}"]])
def test_the_run_files_devices_are_used(run_file, spelling, monkeypatch):
    spec = run_cli(spelling(run_file) + ["--raw"], monkeypatch)
    assert [t.name for t in spec.targets] == ["R1"]


def test_a_typed_target_replaces_the_run_files_devices(run_file, monkeypatch):
    spec = run_cli(["R9", "--run", run_file, "--raw"], monkeypatch)
    assert [t.name for t in spec.targets] == ["R9"]


def test_typed_dests_counts_only_what_was_typed():
    parser = cli.build_parser()
    assert "hosts" not in cli.typed_dests(parser, ["--run", "f.yaml", "--user", "admin"])
    assert cli.typed_dests(parser, ["R1", "--run", "f.yaml"]) >= {"hosts", "run"}
    assert "raw" in cli.typed_dests(parser, ["--raw"])
