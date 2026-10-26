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


def test_a_profile_that_is_not_utf8_is_said_so_and_still_listed(home, monkeypatch, capsys):
    """#110: a Latin-1 accent in a comment was a UnicodeDecodeError traceback
    on --profile and --batch, and on --list-profiles through describe(); on
    `--profile nope` the codec error came out instead of the "no profile" line."""
    mine = home / ".h-ssh" / "profiles"
    mine.mkdir(parents=True)
    latin = mine / "latin.txt"
    latin.write_bytes("# caf\xe9 routers\nshow version\n".encode("latin-1"))
    (mine / "core.txt").write_text("# core routers\nshow bgp summary\n")
    rc, out, err, seen = run(monkeypatch, capsys, ["--profile", "latin", "R1:10.0.0.1:junos"])
    assert rc == 2 and seen == [] and "Traceback" not in err
    assert f"ERROR reading profile 'latin' ({latin}): not UTF-8 text" in err
    rc, out, err, seen = run(monkeypatch, capsys, ["--batch", str(latin), "R1:10.0.0.1:junos"])
    assert rc == 2 and seen == [] and f"ERROR reading batch file '{latin}': not UTF-8 text" in err
    rc, out, err, seen = run(monkeypatch, capsys, ["--profile", "nope", "R1:10.0.0.1:junos"])
    assert rc == 2 and seen == [] and "ERROR: no profile 'nope'" in err and "codec" not in err
    assert profiles.describe(latin) == (None, "not UTF-8 text")
    assert [(n, c) for n, _, c, _ in profiles.listing()][:2] == [("core", 1), ("latin", None)]
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--list-profiles"])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    assert rc == 0 and "  1 commands  core routers" in out and "  unreadable  not UTF-8 text" in out
    assert out.index("core ") < out.index("latin ") < out.index("shipped (")


def test_a_profile_without_read_permission_is_said_so_and_still_listed(home, monkeypatch, capsys):
    """The same for a file the user may not read: a PermissionError traceback before."""
    mine = home / ".h-ssh" / "profiles"
    mine.mkdir(parents=True)
    locked = mine / "locked.txt"
    locked.write_text("# locked\nshow version\n")
    locked.chmod(0)
    if os.access(locked, os.R_OK):
        locked.chmod(0o600)
        pytest.skip("a mode-000 file is readable here (root)")
    try:
        rc, out, err, seen = run(monkeypatch, capsys, ["--profile", "locked", "R1:10.0.0.1:junos"])
        assert rc == 2 and seen == [] and "Traceback" not in err
        assert f"ERROR reading profile 'locked' ({locked}): Permission denied" in err
        rc, out, err, seen = run(monkeypatch, capsys, ["--batch", str(locked), "R1:10.0.0.1:junos"])
        assert rc == 2 and seen == [] and f"ERROR reading batch file '{locked}': Permission denied" in err
        rc, out, err, seen = run(monkeypatch, capsys, ["--profile", "nope", "R1:10.0.0.1:junos"])
        assert rc == 2 and "ERROR: no profile 'nope'" in err and "locked" in err
        monkeypatch.setattr(sys, "argv", ["h-ssh", "--list-profiles"])
        rc = asyncio.run(cli.main())
        out, err = capsys.readouterr()
        assert rc == 0 and "  unreadable  Permission denied" in out and "locked" in out
    finally:
        locked.chmod(0o600)


def test_a_profile_or_batch_behind_a_directory_that_may_not_be_read_is_said_so(home, monkeypatch, capsys):
    """The same behind a directory that may not be searched or read, where
    the check that the file is there raised before it was ever opened."""
    shut = home / "shut"
    shut.mkdir()
    batch = shut / "cmds.txt"
    batch.write_text("show version\n")
    mine = home / ".h-ssh" / "profiles"
    mine.mkdir(parents=True)
    (mine / "core.txt").write_text("show version\n")
    shut.chmod(0)
    mine.chmod(0)
    try:
        if os.access(shut, os.X_OK):
            pytest.skip("a mode-000 directory is searchable here (root)")
        rc, out, err, seen = run(monkeypatch, capsys, ["--batch", str(batch), "R1:10.0.0.1:junos"])
        assert rc == 2 and seen == [] and f"ERROR reading batch file '{batch}': Permission denied" in err
        rc, out, err, seen = run(monkeypatch, capsys, ["--profile", str(batch), "R1:10.0.0.1:junos"])
        assert rc == 2 and seen == [] and f"ERROR reading profile '{batch}' ({batch}): Permission denied" in err
        rc, out, err, seen = run(monkeypatch, capsys, ["--profile", "core", "R1:10.0.0.1:junos"])
        assert rc == 2 and seen == [] and f"ERROR reading profile 'core' ({mine / 'core.txt'}): Permission denied" in err
        monkeypatch.setattr(sys, "argv", ["h-ssh", "--list-profiles"])
        rc = asyncio.run(cli.main())
        out, err = capsys.readouterr()
        assert rc == 2 and f"ERROR reading {mine}: Permission denied" in err
    finally:
        shut.chmod(0o700)
        mine.chmod(0o700)


def test_a_profile_under_format_is_reads_only(home, monkeypatch, capsys):
    """#110: `-sC "request system reboot" --format json` was refused before any
    I/O; a profile with such a line went whole to rpc_batch, on every router."""
    calls = []

    def rpc_batch(host, user, passwd, cmds, *a, **kw):
        calls.append((host, list(cmds)))
        return [{"command": c, "ok": True, "output": {}} for c in cmds]

    # a module is believed on the functions it has: rpc() is what says "--format works here"
    fake = types.SimpleNamespace(AVAILABLE=True, rpc_batch=rpc_batch, rpc=lambda *a, **kw: {})
    mine = home / ".h-ssh" / "profiles"
    mine.mkdir(parents=True)
    (mine / "reboot.txt").write_text("# a read, then not\nshow version\nrequest system reboot\n")
    (mine / "reads.txt").write_text("show version\nshow route summary\n")
    for fmt in ("json", "xml"):
        rc, out, err, _ = run(monkeypatch, capsys, ["--profile", "reboot", "--format", fmt, "R1:10.0.0.1:junos"], fake=fake)
        assert rc == 2 and calls == [], err
        assert f"ERROR: --format {fmt} runs reads only (show …, get-*); 'request system reboot' would act on " \
               "the device with no confirmation. Nothing was sent." in err
    rc, out, err, _ = run(monkeypatch, capsys, ["--profile", "reads", "--format", "json", "R1:10.0.0.1:junos"], fake=fake)
    assert rc == 0 and calls == [("10.0.0.1", ["show version", "show route summary"])], err
