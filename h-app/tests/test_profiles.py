"""--profile NAME: a batch file by name, yours in ~/.h-ssh/profiles before the
shipped ones; --list-profiles shows both; a profile is run exactly like --batch."""

import asyncio
import os
import sys
import types

import pytest

from hssh import cli, drivers, profiles


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def test_a_name_resolves_to_yours_first_then_the_shipped_one(home):
    shipped = profiles.profile_path("junos-health")
    assert shipped == profiles.SHIPPED_DIR / "junos-health.txt" and shipped.is_file()
    assert profiles.describe(shipped)[0] == 8 and profiles.describe(shipped)[1].startswith("Junos health")
    mine = home / ".h-ssh" / "profiles"
    mine.mkdir(parents=True)
    (mine / "junos-health.txt").write_text("# my own\nshow version\n")
    assert profiles.profile_path("junos-health") == mine / "junos-health.txt"       # yours wins
    (mine / "core").write_text("show bgp summary\nshow ospf neighbor\n")
    assert profiles.profile_path("core") == mine / "core"                           # with or without .txt
    with pytest.raises(ValueError) as e:
        profiles.profile_path("nope")
    assert "no profile 'nope'" in str(e.value) and "junos-snapshot" in str(e.value) and str(mine) in str(e.value)
    assert profiles.profile_path(str(mine / "core")) == mine / "core"              # a path is a path
    rows = profiles.listing()
    assert [(n, o) for n, o, _, _ in rows] == [("core", "yours"), ("junos-health", "yours"), ("junos-snapshot", "shipped")]
    assert [c for _, _, c, _ in rows] == [2, 1, 10]


def run(monkeypatch, capsys, argv, fake=None):
    seen = []

    def show_batch(host, user, passwd, cmds, *a, **kw):
        seen.append((host, list(cmds)))
        return [{"command": c, "ok": True, "output": f"{c} on {host}"} for c in cmds]

    fake = fake or types.SimpleNamespace(AVAILABLE=True, show_batch=show_batch)
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", fake)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_USER", "HSSH_STORE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "--no-store", *argv])
    try:
        rc = asyncio.run(cli.main())
    except SystemExit as e:
        rc = e.code
    out, err = capsys.readouterr()
    return rc, out, err, seen


def test_a_profile_runs_as_the_batch_it_is(monkeypatch, capsys):
    rc, out, err, seen = run(monkeypatch, capsys, ["--profile", "junos-health", "R1:10.0.0.1:junos", "R2:10.0.0.2:junos"])
    assert rc == 0, err
    assert sorted(h for h, _ in seen) == ["10.0.0.1", "10.0.0.2"]
    assert all(cmds[0] == "show version" and len(cmds) == 8 for _, cmds in seen)
    assert "Batch: 8 commands from" in out and "junos-health.txt" in out


def test_your_own_profile_and_the_errors(home, monkeypatch, capsys):
    mine = home / ".h-ssh" / "profiles"
    mine.mkdir(parents=True)
    (mine / "core.txt").write_text("# core routers\nshow bgp summary\n# a comment\nshow ospf neighbor\n")
    rc, out, err, seen = run(monkeypatch, capsys, ["--profile", "core", "R1:10.0.0.1:junos"])
    assert rc == 0 and seen == [("10.0.0.1", ["show bgp summary", "show ospf neighbor"])]
    rc, out, err, seen = run(monkeypatch, capsys, ["--profile", "nope", "R1:10.0.0.1:junos"])
    assert rc == 2 and "ERROR: no profile 'nope'" in err and seen == []
    rc, out, err, seen = run(monkeypatch, capsys, ["--profile", "core", "--batch", str(mine / "core.txt"), "R1:10.0.0.1:junos"])
    assert rc == 2 and "--profile and --batch both name the commands" in err and seen == []


def test_list_profiles_shows_yours_and_the_shipped_ones(home, monkeypatch, capsys):
    mine = home / ".h-ssh" / "profiles"
    mine.mkdir(parents=True)
    (mine / "core.txt").write_text("# core routers\nshow bgp summary\n")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--list-profiles"])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    assert rc == 0
    assert out.index("yours (") < out.index("core ") < out.index("shipped (") < out.index("junos-health")
    assert "  8 commands  Junos health" in out and " 10 commands  Junos snapshot" in out and "1 commands  core routers" in out
