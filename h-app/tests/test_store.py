"""The result store (--store, h-ssh-store): every command's reply in one
SQLite file, byte for byte, read back by run, device and command."""

import asyncio
import json
import os
import sqlite3
import stat
import sys
import types

import pytest

from hssh import cli, drivers
from hssh import store as store_module
from hssh.store import Store, StoreError, main as store_main, new_run_id

SHOW = {"device": "r1", "host": "10.0.0.1", "vendor": "junos@ssh", "ok": True, "duration_ms": 120,
        "command": "show version", "output": "Hostname: r1\nJunos: 23.2\nencrypted-password \"$9$abcDEF\"\n"}
FAILED = {"device": "r2", "host": "10.0.0.2", "vendor": "junos@ssh", "ok": False, "duration_ms": 5000,
          "error": "ERROR: connect timed out"}
BATCH = {"device": "r1", "host": "10.0.0.1", "vendor": "junos@netconf", "ok": False, "duration_ms": 300,
         "commands": [{"command": "show version", "ok": True, "output": "Hostname: r1\nJunos: 23.3\n"},
                      {"command": "show system uptime", "ok": False, "error": "refused by the device: error: no"}]}
COMMITS = {"device": "r1", "host": "10.0.0.1", "vendor": "junos@netconf", "ok": True, "duration_ms": 50,
           "commits": [{"seq": 0, "user": "lab", "comment": None}]}


def filled(path):
    """Three runs: a show with one failure, a batch, a commit history."""
    s = Store(str(path))
    r1 = s.begin_run("show", ["--devices", "core.csv", "-sC", "version"], "lab", 2, "1.0.0", command="version")
    s.add_entry(r1, SHOW, "show version")
    s.add_entry(r1, FAILED, "show version")
    s.finish_run(r1, 1, 1, 0)
    r2 = s.begin_run("show-batch", ["--batch", "c.txt"], "lab", 1, "1.0.0", command="show version\nshow system uptime")
    s.add_entry(r2, BATCH, "")
    s.finish_run(r2, 0, 1, 0)
    r3 = s.begin_run("commit-status", ["--commit-status"], "lab", 1, "1.0.0", command="commit-status")
    s.add_entry(r3, COMMITS, "show system commit")
    s.finish_run(r3, 1, 0, 0)
    s.close()
    return r1, r2, r3


def rows(path, sql, *params):
    c = sqlite3.connect(str(path))
    c.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in c.execute(sql, params).fetchall()]
    finally:
        c.close()


# --- the writer ------------------------------------------------------------------

def test_the_store_is_a_private_file_with_the_two_tables(tmp_path):
    path = tmp_path / "deep" / "runs.db"
    Store(str(path)).close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    names = {r["name"] for r in rows(path, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"runs", "results"} <= names


def test_a_symlink_in_place_of_the_store_is_refused(tmp_path):
    target = tmp_path / "elsewhere.db"
    target.write_text("")
    link = tmp_path / "runs.db"
    link.symlink_to(target)
    with pytest.raises(StoreError):
        Store(str(link))


def test_run_ids_sort_by_time_and_differ_within_a_second():
    ids = {new_run_id() for _ in range(20)}
    assert len(ids) == 20
    assert all(len(i) == len("20261024-173055-6dc0") for i in ids)


def test_one_row_per_command_kept_as_it_came(tmp_path):
    path = tmp_path / "runs.db"
    r1, r2, r3 = filled(path)
    runs = rows(path, "SELECT * FROM runs ORDER BY rowid")
    assert [r["mode"] for r in runs] == ["show", "show-batch", "commit-status"]
    assert runs[0]["argv"] == "--devices core.csv -sC version"     # as typed: a snapshot is not edited
    assert (runs[0]["targets"], runs[0]["ok"], runs[0]["failed"], runs[0]["skipped"]) == (2, 1, 1, 0)
    assert runs[0]["finished"] and runs[0]["command"] == "version"
    show = rows(path, "SELECT * FROM results WHERE run_id = ? ORDER BY device, seq", r1)
    assert [(r["device"], r["seq"], r["ok"]) for r in show] == [("r1", 0, 1), ("r2", 0, 0)]
    assert show[0]["command"] == "show version" and show[0]["format"] == "text"
    assert show[0]["output"] == SHOW["output"]                       # the hash stays: a restore needs it
    assert show[1]["output"] is None and show[1]["error"] == "ERROR: connect timed out"
    batch = rows(path, "SELECT * FROM results WHERE run_id = ? ORDER BY seq", r2)
    assert [(r["seq"], r["command"], r["ok"]) for r in batch] == \
        [(0, "show version", 1), (1, "show system uptime", 0)]
    assert batch[0]["duration_ms"] == 300 and batch[1]["duration_ms"] is None
    assert batch[1]["error"].startswith("refused by the device")
    commits = rows(path, "SELECT * FROM results WHERE run_id = ?", r3)
    assert commits[0]["format"] == "json" and json.loads(commits[0]["output"])[0]["user"] == "lab"
    assert commits[0]["command"] == "show system commit"


def test_a_json_reply_is_stored_as_json(tmp_path):
    path = tmp_path / "runs.db"
    s = Store(str(path))
    run = s.begin_run("show", ["-sC", "show version"], "lab", 1, "1.0.0")
    s.add_entry(run, {**SHOW, "device": "r9", "output": {"software-information": [{"host-name": [{"data": "r9"}]}]}},
                "show version", fmt="json")
    s.close()
    got = rows(path, "SELECT * FROM results")[0]
    assert got["format"] == "json" and json.loads(got["output"])["software-information"]


def test_a_second_result_for_the_same_command_replaces_the_first(tmp_path):
    path = tmp_path / "runs.db"
    s = Store(str(path))
    run = s.begin_run("show", [], "lab", 1, "1.0.0")
    s.add_entry(run, FAILED, "show version")
    s.add_entry(run, {**FAILED, "ok": True, "error": None, "output": "fine"}, "show version")
    s.close()
    got = rows(path, "SELECT * FROM results")
    assert len(got) == 1 and got[0]["ok"] == 1 and got[0]["output"] == "fine"


def test_a_run_is_found_by_its_id_or_a_unique_prefix_or_as_the_last(tmp_path):
    path = tmp_path / "runs.db"
    r1, r2, r3 = filled(path)
    s = Store(str(path), readonly=True)
    assert s.resolve_run(None) == r3
    assert s.resolve_run(r1) == r1
    assert s.resolve_run(r2[:-1]) == r2
    with pytest.raises(StoreError, match="matches 3 runs|matches 2 runs"):
        s.resolve_run(r1[:8])
    with pytest.raises(StoreError, match="no run"):
        s.resolve_run("nope")
    with pytest.raises(StoreError, match="no result for"):
        s.output(r1, "r9")
    s.close()
    with pytest.raises(StoreError, match="no store at"):
        Store(str(tmp_path / "missing.db"), readonly=True)


# --- the reader --------------------------------------------------------------------

def reader(capsys, path, *argv):
    rc = store_main(["--store", str(path), *argv])
    out, err = capsys.readouterr()
    return rc, out, err


def test_runs_failed_and_output(tmp_path, capsys):
    path = tmp_path / "runs.db"
    r1, r2, r3 = filled(path)
    rc, out, _ = reader(capsys, path, "runs")
    lines = out.splitlines()
    assert rc == 0 and lines[0].startswith("run ") and [ln.split()[0] for ln in lines[1:]] == [r3, r2, r1]
    assert "2/1/1" in lines[3] and "commit-status" in lines[1]
    rc, out, _ = reader(capsys, path, "failed", r1)
    assert rc == 1 and f"run {r1}: 1 failed" in out and "r2" in out and "connect timed out" in out
    rc, out, _ = reader(capsys, path, "failed", r3)
    assert rc == 0 and "0 failed" in out
    rc, out, err = reader(capsys, path, "output", "r1", r1)
    assert rc == 0 and out == SHOW["output"]
    rc, out, err = reader(capsys, path, "output", "r2", r1)
    assert rc == 1 and out == "" and "connect timed out" in err
    rc, out, _ = reader(capsys, path, "output", "r1", r2, "--seq", "1")
    assert rc == 1
    rc, out, _ = reader(capsys, path, "output", "r1")          # the last run
    assert rc == 0 and json.loads(out)[0]["user"] == "lab"


def test_grep_field_diff_history_slowest(tmp_path, capsys):
    path = tmp_path / "runs.db"
    r1, r2, r3 = filled(path)
    rc, out, _ = reader(capsys, path, "grep", "junos:", "-i")
    assert rc == 0 and sorted(ln.split()[0] for ln in out.splitlines()) == sorted([r1, r2])
    assert "Junos: 23.2" in out and "Junos: 23.3" in out
    rc, out, _ = reader(capsys, path, "grep", "nothing-like-this")
    assert rc == 1 and out == ""
    rc, _, err = reader(capsys, path, "grep", "(")
    assert rc == 2 and "bad pattern" in err
    rc, out, _ = reader(capsys, path, "field", "0.user", "--run", r3)
    assert rc == 0 and out.strip().endswith("0.user = lab")
    rc, out, _ = reader(capsys, path, "field", "0.nothing")
    assert rc == 1
    rc, out, _ = reader(capsys, path, "diff", "r1", r1, r2)
    assert rc == 1 and "-Junos: 23.2" in out and "+Junos: 23.3" in out and out.startswith("--- r1 ")
    rc, out, _ = reader(capsys, path, "diff", "r1", r1, r1)
    assert rc == 0 and out == ""
    rc, out, _ = reader(capsys, path, "history", "r1")
    lines = out.splitlines()
    assert rc == 0 and len(lines) == 1 + 4 and "FAIL" in out and lines[1].split()[1] == r3
    rc, out, _ = reader(capsys, path, "history", "r1", "--command", "show version")
    assert rc == 0 and len(out.splitlines()) == 1 + 2
    rc, out, _ = reader(capsys, path, "slowest", "--last", "2")
    lines = out.splitlines()
    assert rc == 0 and lines[1].split()[:2] == ["5000", "r2"] and len(lines) == 3


def test_export_csv_and_jsonl(tmp_path, capsys):
    """The rows as they are: CSV with a header (the batch's two commands are two
    rows, a failure keeps its error), JSON Lines with the same keys, --all for
    the whole store, --out to a file, filters, exit 1 when nothing matches."""
    import csv
    r1, r2, r3 = filled(tmp_path / "s.db")
    rc, out, err = reader(capsys, tmp_path / "s.db", "export", r1)
    assert rc == 0
    rows = list(csv.DictReader(out.splitlines()))
    assert [r["device"] for r in rows] == ["r1", "r2"] and rows[0]["output"].startswith("Hostname: r1")
    assert rows[1]["ok"] == "0" and rows[1]["error"] == "ERROR: connect timed out"
    assert list(rows[0]) == list(store_module.EXPORT_FIELDS)
    rc, out, err = reader(capsys, tmp_path / "s.db", "export", "--all", "--format", "jsonl")
    lines = [json.loads(ln) for ln in out.splitlines()]
    assert rc == 0 and len(lines) == 5 and {ln["run_id"] for ln in lines} == {r1, r2, r3}
    assert [ln["seq"] for ln in lines if ln["run_id"] == r2] == [0, 1]           # the batch: one row per command
    target = tmp_path / "rows.csv"
    rc, out, err = reader(capsys, tmp_path / "s.db", "export", "--all", "--device", "r1", "--out", str(target))
    assert rc == 0 and out == "" and "4 rows written to" in err
    assert len(list(csv.DictReader(target.read_text().splitlines()))) == 4     # r1: a show, two batch rows, a history
    rc, out, err = reader(capsys, tmp_path / "s.db", "export", "--all", "--device", "nobody")
    assert rc == 1 and out.strip() == ",".join(store_module.EXPORT_FIELDS)     # a header and nothing else


def test_the_reader_looks_where_the_run_wrote(tmp_path, capsys, monkeypatch):
    """--store, else HSSH_STORE, else the config file's `store`, else h-ssh.db here."""
    from hssh import core
    monkeypatch.delenv("HSSH_STORE", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(core, "get_config_path", lambda: tmp_path / "no-config")
    rc = store_main(["runs"])
    assert rc == 2 and "no store at h-ssh.db: no run has been kept here" in capsys.readouterr()[1]
    rc = store_main(["--store", str(tmp_path / "none.db"), "runs"])
    assert rc == 2 and "no store at" in capsys.readouterr()[1]
    filled(tmp_path / "h-ssh.db")
    assert store_main(["runs"]) == 0                       # the default: h-ssh.db in the current directory
    capsys.readouterr()
    filled(tmp_path / "from-config.db")
    (tmp_path / "config").write_text(f"store = {tmp_path / 'from-config.db'}\n")
    monkeypatch.setattr(core, "get_config_path", lambda: tmp_path / "config")
    assert store_main(["runs"]) == 0 and "from-config" not in capsys.readouterr()[0]   # read, no error
    monkeypatch.setenv("HSSH_STORE", str(tmp_path / "missing.db"))
    assert store_main(["runs"]) == 2                       # the variable beats the config file


# --- through the CLI ----------------------------------------------------------------

def run_cli(monkeypatch, capsys, argv, fake=None):
    fake = fake or types.SimpleNamespace(
        AVAILABLE=True,
        show=lambda host, user, passwd, cmd, *a, **kw: f"Hostname: {host}\nroot-authentication encrypted-password \"$9$zz\"\n",
        show_batch=lambda host, user, passwd, cmds, *a, **kw: [
            {"command": c, "ok": c != "show nothing", **({"output": f"{c} on {host}"} if c != "show nothing"
                                                          else {"error": "'show nothing' was refused by the device: error: syntax error"})}
            for c in cmds],
        edit=lambda *a, **kw: "COMMIT OK\n")
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", fake)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD", "HSSH_USER", "HSSH_STORE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", *argv])
    try:
        rc = asyncio.run(cli.main())
    except SystemExit as e:
        rc = e.code
    out, err = capsys.readouterr()
    return rc, out, err


def test_a_show_run_lands_in_the_store_with_its_run_row(tmp_path, monkeypatch, capsys):
    path = tmp_path / "runs.db"
    rc, out, err = run_cli(monkeypatch, capsys, ["--store", str(path), "--target", "R1:10.0.0.1:junos",
                                                 "--target", "R2:10.0.0.2:junos", "-sC", "show version"])
    assert rc == 0, err
    runs = rows(path, "SELECT * FROM runs")
    assert len(runs) == 1
    run = runs[0]
    assert run["mode"] == "show" and run["user"] == "u" and run["command"] == "show version"
    assert (run["targets"], run["ok"], run["failed"], run["skipped"], run["interrupted"]) == (2, 2, 0, 0, 0)
    assert run["finished"] is not None and run["version"] == cli.__version__
    assert run["argv"].startswith("--config ") and "--store" in run["argv"]
    got = {r["device"]: r for r in rows(path, "SELECT * FROM results")}
    assert set(got) == {"R1", "R2"}
    assert got["R1"]["command"] == "show version" and got["R1"]["vendor"] == "junos" and got["R1"]["host"] == "10.0.0.1"
    assert got["R1"]["output"] == "Hostname: 10.0.0.1\nroot-authentication encrypted-password \"$9$zz\""
    assert got["R1"]["ok"] == 1 and got["R1"]["format"] == "text" and got["R1"]["duration_ms"] is not None
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_a_batch_is_one_row_per_command_and_a_failure_is_the_devices_line(tmp_path, monkeypatch, capsys):
    path = tmp_path / "runs.db"
    cmds = tmp_path / "cmds.txt"
    cmds.write_text("show version\nshow nothing\nshow route\n")
    rc, out, err = run_cli(monkeypatch, capsys, ["--store", str(path), "--target", "R1:10.0.0.1:junos",
                                                 "--batch", str(cmds)])
    assert rc == 1, err
    got = rows(path, "SELECT * FROM results ORDER BY seq")
    assert [(r["seq"], r["command"], r["ok"]) for r in got] == \
        [(0, "show version", 1), (1, "show nothing", 0), (2, "show route", 1)]
    assert got[1]["error"].startswith("'show nothing' was refused by the device")
    assert got[2]["output"] == "show route on 10.0.0.1"
    run = rows(path, "SELECT * FROM runs")[0]
    assert run["mode"] == "show-batch" and run["command"] == "show version\nshow nothing\nshow route"
    assert (run["ok"], run["failed"]) == (0, 1)
    # the reader sees what the CLI stored
    rc = store_main(["--store", str(path), "failed"])
    assert rc == 1 and "show nothing" in capsys.readouterr()[0]


def test_the_store_env_var_names_the_file(tmp_path, monkeypatch, capsys):
    path = tmp_path / "runs.db"
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", types.SimpleNamespace(
        AVAILABLE=True, show=lambda *a, **kw: "encrypted-password \"$9$keep\"\n"))
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_STORE", str(path))
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u",
                                      "--target", "R1:10.0.0.1:junos", "-sC", "show version"])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    assert rc == 0, err
    assert rows(path, "SELECT output FROM results")[0]["output"] == "encrypted-password \"$9$keep\""


def test_an_unwritable_store_refuses_to_start(tmp_path, monkeypatch, capsys):
    blocker = tmp_path / "file"
    blocker.write_text("")
    calls = []
    fake = types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: calls.append(1) or "ok")
    rc, out, err = run_cli(monkeypatch, capsys, ["--store", str(blocker / "runs.db"), "--target", "R1:10.0.0.1:junos",
                                                 "-sC", "show version"], fake=fake)
    assert rc == 2 and "every run is kept" in err and "--no-store" in err and "refusing to start" in err
    assert calls == []


def test_every_run_is_kept_in_h_ssh_db_in_the_current_directory(tmp_path, monkeypatch, capsys):
    """No flag, no variable, no config: the store is ./h-ssh.db, and the
    evidence sits with the job."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HSSH_STORE", raising=False)
    rc, out, err = run_cli(monkeypatch, capsys, ["--target", "R1:10.0.0.1:junos", "-sC", "show version"])
    assert rc == 0, err
    assert (tmp_path / "h-ssh.db").is_file() and stat.S_IMODE((tmp_path / "h-ssh.db").stat().st_mode) == 0o600
    got = rows(tmp_path / "h-ssh.db", "SELECT device, command, ok FROM results")
    assert got == [{"device": "R1", "command": "show version", "ok": 1}]
    # the reader finds it the same way
    assert store_main(["runs"]) == 0 and "show version" in capsys.readouterr()[0]


def test_the_config_file_can_name_the_store(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HSSH_STORE", raising=False)
    cfg = tmp_path / "config"
    cfg.write_text(f"store = {tmp_path / 'kept' / 'fleet.db'}\n")
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: "ok"))
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", str(cfg), "--user", "u", "--target", "R1:10.0.0.1:junos",
                                      "-sC", "show version"])
    assert asyncio.run(cli.main()) == 0
    assert (tmp_path / "kept" / "fleet.db").is_file() and not (tmp_path / "h-ssh.db").exists()
    # the variable beats the file, the flag beats both
    monkeypatch.setenv("HSSH_STORE", str(tmp_path / "env.db"))
    assert asyncio.run(cli.main()) == 0 and (tmp_path / "env.db").is_file()
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", str(cfg), "--user", "u", "--store", str(tmp_path / "flag.db"),
                                      "--target", "R1:10.0.0.1:junos", "-sC", "show version"])
    assert asyncio.run(cli.main()) == 0 and (tmp_path / "flag.db").is_file()
    assert len(rows(tmp_path / "env.db", "SELECT * FROM runs")) == 1


def test_no_store_keeps_nothing_and_contradicts_store(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HSSH_STORE", raising=False)
    rc, out, err = run_cli(monkeypatch, capsys, ["--no-store", "--target", "R1:10.0.0.1:junos", "-sC", "show version"])
    assert rc == 0, err
    assert not (tmp_path / "h-ssh.db").exists() and "R1" in out
    rc, out, err = run_cli(monkeypatch, capsys, ["--no-store", "--store", str(tmp_path / "x.db"), "--target", "R1:10.0.0.1:junos",
                                                 "-sC", "show version"])
    assert rc == 2 and "contradict" in err and not (tmp_path / "x.db").exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes anywhere")
def test_a_directory_you_cannot_write_in_is_no_run(tmp_path, monkeypatch, capsys):
    """The user's rule: not being able to store is a no-go for the run."""
    ro = tmp_path / "ro"
    ro.mkdir(mode=0o500)
    monkeypatch.chdir(ro)
    monkeypatch.delenv("HSSH_STORE", raising=False)
    calls = []
    fake = types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: calls.append(1) or "ok")
    rc, out, err = run_cli(monkeypatch, capsys, ["--target", "R1:10.0.0.1:junos", "-sC", "show version"], fake=fake)
    assert rc == 2 and "h-ssh.db" in err and "every run is kept" in err and calls == []
    rc, out, err = run_cli(monkeypatch, capsys, ["--no-store", "--target", "R1:10.0.0.1:junos", "-sC", "show version"], fake=fake)
    assert rc == 0 and calls == [1]


def test_a_dry_run_edit_stores_the_payload_and_the_verdict(tmp_path, monkeypatch, capsys):
    path = tmp_path / "runs.db"
    fake = types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: "",
                                 edit=lambda *a, **kw: "DRY-RUN\n\nDIFF:\n[edit system]\n+  host-name x;\n")
    rc, out, err = run_cli(monkeypatch, capsys, ["--store", str(path), "--target", "R1:10.0.0.1:junos", "-y",
                                                 "--dry-run", "-eC", "set system host-name x"], fake=fake)
    assert rc == 0, err
    got = rows(path, "SELECT * FROM results")[0]
    assert got["command"] == "set system host-name x" and got["ok"] == 1
    assert "+  host-name x;" in got["output"]
    run = rows(path, "SELECT * FROM runs")[0]
    assert run["mode"] == "edit-cmd" and run["command"] == "set system host-name x" and "--dry-run" in run["argv"]
