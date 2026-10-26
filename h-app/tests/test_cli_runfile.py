"""Run files (#60): `h-ssh --run FILE` describes a whole fleet run in YAML or
JSON. Every key is a flag name; a flag typed on the command line wins; the
file never carries a credential; relative paths resolve against the file;
an edit from a file must arm a commit-confirmed timer or be a dry run."""
import asyncio
import json
import os
import sys
import types
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hssh import cli, drivers, runfile


async def _reachable(target, timeout=2):
    return (target.name, True, "reachable")


class Driver:
    """A junos driver that records what the CLI asked of it."""
    AVAILABLE = True

    def __init__(self):
        self.shows, self.batches, self.edits = [], [], []

    def show(self, host, user, passwd, cmd, st, ct, port=None, vendor_hint=None):
        self.shows.append((host, cmd, port))
        return f"{host} says {cmd}"

    def show_batch(self, host, user, passwd, cmds, st, ct, port=None, vendor_hint=None):
        self.batches.append((host, list(cmds)))
        return [{"command": c, "ok": True, "output": f"{host} says {c}"} for c in cmds]

    def edit(self, host, user, passwd, payload, st, ct, commit_confirmed=None, port=None,
             dry_run=False, comment=None, expected_diff=None, vendor_hint=None):
        self.edits.append((host, payload.strip(), commit_confirmed, dry_run))
        return "COMMIT OK\n" if not dry_run else "DRY-RUN\n"


def run(monkeypatch, capsys, tmp_path, argv, driver=None):
    """cli.main() in-process against the fake driver; nothing is contacted."""
    drv = driver or Driver()
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", drv)
    monkeypatch.setattr(cli, "check_reachability", _reachable)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["./h-app/h-ssh.py", "--config", os.devnull, *argv])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    return rc, out, err, drv


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


# --- reads -------------------------------------------------------------------

def test_yaml_run_file_runs_a_show_on_inline_devices(monkeypatch, capsys, tmp_path):
    f = write(tmp_path, "run.yaml", """
devices:
  - R1:10.0.0.1:junos
  - {name: R2, host: 10.0.0.2, vendor: junos, port: 2830}
user: h-lab
show: show version
workers: 3
json: true
""")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
    assert rc == 0, err
    assert sorted(drv.shows) == [("10.0.0.1", "show version", None), ("10.0.0.2", "show version", 2830)]
    data = json.loads(out)
    assert {d["device"] for d in data} == {"R1", "R2"} and all(d["ok"] for d in data)


def test_json_run_file_needs_no_yaml(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(runfile, "yaml", None)
    f = write(tmp_path, "run.json", json.dumps({"devices": ["R1:10.0.0.1:junos"], "user": "u",
                                                "show": "show version", "json": True}))
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
    assert rc == 0, err
    assert drv.shows == [("10.0.0.1", "show version", None)]


def test_yaml_without_pyyaml_is_a_clear_error(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(runfile, "yaml", None)
    f = write(tmp_path, "run.yaml", "devices: [R1:10.0.0.1:junos]\nuser: u\nshow: show version\n")
    rc, out, err, _ = run(monkeypatch, capsys, tmp_path, ["--run", f])
    assert rc == 2
    assert "PyYAML is not installed" in err and "JSON" in err


def test_commands_list_is_an_inline_batch(monkeypatch, capsys, tmp_path):
    f = write(tmp_path, "run.yaml", """
devices: [R1:10.0.0.1:junos]
user: u
commands:
  - show version
  - show route summary
""")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
    assert rc == 0, err
    assert drv.batches == [("10.0.0.1", ["show version", "show route summary"])]
    assert "Batch: 2 commands from the run file" in out
    assert "Run file:" in out and "read on 1 device(s)" in out


def test_relative_paths_resolve_against_the_run_file(monkeypatch, capsys, tmp_path):
    sub = tmp_path / "runs"
    sub.mkdir()
    (sub / "ax.csv").write_text("R1,10.0.0.1,junos\n")
    (sub / "cmds.txt").write_text("show version\n")
    f = write(sub, "run.yaml", "devices: ax.csv\nbatch: cmds.txt\nuser: u\nlog: out/run.jsonl\n")
    monkeypatch.chdir(tmp_path)          # cwd is not the file's directory
    (sub / "out").mkdir()
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
    assert rc == 0, err
    assert drv.batches == [("10.0.0.1", ["show version"])]
    assert (sub / "out" / "run.jsonl").is_file()


def test_a_flag_on_the_command_line_wins_over_the_file(monkeypatch, capsys, tmp_path):
    f = write(tmp_path, "run.yaml", "devices: [R1:10.0.0.1:junos]\nuser: u\nshow: show version\nworkers: 64\n")
    rc, out, err, _ = run(monkeypatch, capsys, tmp_path, ["--run", f, "--workers", "3"])
    assert rc == 0, err
    assert "Workers: 3" in out


def test_file_values_pass_the_config_validation(monkeypatch, capsys, tmp_path):
    for body, needle in (
        ("workers: 0", "'workers' must be at least 1"),
        ("transport: carrier-pigeon", "'transport' must be one of"),
        ("format: csv", "'format' must be one of"),
        ("workers: eight", "'workers' must be a number"),
        ("workers: true", "'workers' must be a number, not a boolean"),
        ("commit_confirmed: 0", "'commit_confirmed' takes 1..65535"),
        ("rollback: 50", "'rollback' takes a number from 0 to 49"),
    ):
        f = write(tmp_path, "run.yaml", f"devices: [R1:10.0.0.1:junos]\nuser: u\nshow: show version\n{body}\n")
        rc, out, err, _ = run(monkeypatch, capsys, tmp_path, ["--run", f])
        assert rc == 2 and needle in err, (body, err)


def test_unknown_key_names_the_key(monkeypatch, capsys, tmp_path):
    f = write(tmp_path, "run.yaml", "devices: [R1:10.0.0.1:junos]\nuser: u\nshow: show version\nworkerz: 4\n")
    rc, out, err, _ = run(monkeypatch, capsys, tmp_path, ["--run", f])
    assert rc == 2 and "unknown option 'workerz'" in err


def test_a_credential_in_the_file_is_refused(monkeypatch, capsys, tmp_path):
    for key in ("password", "passwd", "secret", "token"):
        f = write(tmp_path, "run.yaml", f"devices: [R1:10.0.0.1:junos]\nuser: u\nshow: show version\n{key}: hunter2\n")
        rc, out, err, _ = run(monkeypatch, capsys, tmp_path, ["--run", f])
        assert rc == 2 and "never carries a credential" in err and "hunter2" not in err, key


def test_a_file_that_is_not_a_mapping_is_refused(monkeypatch, capsys, tmp_path):
    f = write(tmp_path, "run.yaml", "- show version\n- show route\n")
    rc, out, err, _ = run(monkeypatch, capsys, tmp_path, ["--run", f])
    assert rc == 2 and "must be a mapping" in err


def test_hyphenated_keys_are_the_flag_names(monkeypatch, capsys, tmp_path):
    f = write(tmp_path, "run.yaml", "devices: [R1:10.0.0.1:junos]\nuser: u\nshow: show version\n"
                                    "session-timeout: 7\ncommand-timeout: 9\n")
    rc, out, err, _ = run(monkeypatch, capsys, tmp_path, ["--run", f, "-v"])
    assert rc == 0, err


def test_two_command_lists_are_refused(monkeypatch, capsys, tmp_path):
    cmds = write(tmp_path, "cmds.txt", "show version\n")
    f = write(tmp_path, "run.yaml", f"devices: [R1:10.0.0.1:junos]\nuser: u\ncommands: [show version]\n")
    rc, out, err, _ = run(monkeypatch, capsys, tmp_path, ["--run", f, "--batch", cmds])
    assert rc == 2 and "two command lists" in err


def test_bad_device_entries_are_named(monkeypatch, capsys, tmp_path):
    for body, needle in (
        ("devices: []", "'devices' list is empty"),
        ("devices: [{host: 10.0.0.1}]", "devices[0] needs a 'name' string"),
        ("devices: [{name: R1, host: 10.0.0.1, colour: red}]", "unknown field(s) colour"),
        ("devices: [{name: R1, host: 10.0.0.1, port: x}]", "'port' must be a number"),
        ("devices: [42]", "devices[0] must be a 'name:host:vendor' string or a mapping"),
    ):
        f = write(tmp_path, "run.yaml", f"{body}\nuser: u\nshow: show version\n")
        rc, out, err, _ = run(monkeypatch, capsys, tmp_path, ["--run", f])
        assert rc == 2 and needle in err, (body, err)


# --- edits -------------------------------------------------------------------

def test_an_edit_from_a_file_needs_a_timer(monkeypatch, capsys, tmp_path):
    f = write(tmp_path, "run.yaml", "devices: [R1:10.0.0.1:junos]\nuser: u\nedit: set system host-name R1\nyes: true\n")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
    assert rc == 2 and "without a rollback timer" in err and "commit_confirmed" in err
    assert drv.edits == []


def test_the_timer_may_come_from_the_file_or_the_flag(monkeypatch, capsys, tmp_path):
    f = write(tmp_path, "run.yaml", "devices: [R1:10.0.0.1:junos]\nuser: u\nedit: set system host-name R1\n"
                                    "yes: true\ncommit_confirmed: 5\n")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
    assert rc == 0, err
    assert drv.edits == [("10.0.0.1", "set system host-name R1", 5, False)]
    assert "edit on 1 device(s), commit confirmed 5 min" in out

    f = write(tmp_path, "run2.yaml", "devices: [R1:10.0.0.1:junos]\nuser: u\nedit: set system host-name R1\nyes: true\n")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f, "--commit-confirmed", "3"])
    assert rc == 0, err
    assert drv.edits[0][2] == 3


def test_a_dry_run_needs_no_timer(monkeypatch, capsys, tmp_path):
    f = write(tmp_path, "run.yaml", "devices: [R1:10.0.0.1:junos]\nuser: u\nedit: set system host-name R1\n"
                                    "dry_run: true\nassume_yes: true\n")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
    assert rc == 0, err
    assert drv.edits == [("10.0.0.1", "set system host-name R1", None, True)]
    assert "edit on 1 device(s), dry run" in out


def test_a_confirm_from_a_file_needs_no_timer(monkeypatch, capsys, tmp_path):
    f = write(tmp_path, "run.yaml", "devices: [R1:10.0.0.1:junos]\nuser: u\nedit: commit\nyes: true\n")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
    assert rc == 0, err
    assert drv.edits and drv.edits[0][1] == "commit" and drv.edits[0][2] is None


def test_the_edit_confirmation_prompt_still_applies(monkeypatch, capsys, tmp_path):
    """No `yes:` and no TTY: the run is refused before anything is sent, as
    without a file."""
    f = write(tmp_path, "run.yaml", "devices: [R1:10.0.0.1:junos]\nuser: u\nedit: set system host-name R1\n"
                                    "commit_confirmed: 5\n")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
    assert rc == 2 and "requires confirmation" in err
    assert drv.edits == []


def test_jobs_list_runs_in_job_mode(monkeypatch, capsys, tmp_path):
    f = write(tmp_path, "run.yaml", """
user: u
yes: true
commit_confirmed: 2
jobs:
  - {target: "R1:10.0.0.1:junos", show: show version}
  - {target: "R2:10.0.0.2:junos", edit: set system host-name R2, port: 2830}
""")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
    assert rc == 0, err
    assert drv.shows == [("10.0.0.1", "show version", None)]
    assert drv.edits == [("10.0.0.2", "set system host-name R2", 2, False)]


def test_a_job_edit_from_a_file_needs_a_timer(monkeypatch, capsys, tmp_path):
    f = write(tmp_path, "run.yaml", 'user: u\nyes: true\njobs:\n  - {target: "R2:10.0.0.2:junos", edit: set system host-name R2}\n')
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
    assert rc == 2 and "without a rollback timer" in err
    assert drv.edits == []


def test_jobs_and_job_flag_are_two_lists(monkeypatch, capsys, tmp_path):
    job = write(tmp_path, "job.json", json.dumps([{"target": "R1:10.0.0.1:junos", "show": "show version"}]))
    f = write(tmp_path, "run.yaml", 'user: u\njobs:\n  - {target: "R1:10.0.0.1:junos", show: show version}\n')
    rc, out, err, _ = run(monkeypatch, capsys, tmp_path, ["--run", f, "--job", job])
    assert rc == 2 and "two job lists" in err


def test_the_password_still_comes_from_the_prompt_or_the_environment(monkeypatch, capsys, tmp_path):
    """With no HSSH_PASSWORD and no terminal, a run file runs key-auth style
    with no password; nothing in the file can change that. There is no third
    source: --password is not a flag, so argparse refuses it before anything
    is read or sent."""
    f = write(tmp_path, "run.yaml", "devices: [R1:10.0.0.1:junos]\nuser: u\nshow: show version\njson: true\n")
    seen = {}

    class Drv(Driver):
        def show(self, host, user, passwd, cmd, st, ct, port=None, vendor_hint=None):
            seen["passwd"] = passwd
            return "ok"
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", Drv())
    monkeypatch.setattr(cli, "check_reachability", _reachable)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(sys, "argv", ["./h-app/h-ssh.py", "--config", os.devnull, "--run", f])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    assert rc == 0, err
    assert seen["passwd"] is None

    seen.clear()
    monkeypatch.setattr(sys, "argv", ["./h-app/h-ssh.py", "--config", os.devnull, "--run", f,
                                      "--password", "hunter2"])
    with pytest.raises(SystemExit) as exc:
        asyncio.run(cli.main())
    err = capsys.readouterr().err
    assert exc.value.code == 2 and "unrecognized arguments: --password" in err
    assert seen == {}


# --- the run file meets #62's ceilings and port checks, and #64's --allow-missing ----

def test_run_file_values_are_held_to_the_flags_ceilings(tmp_path):
    from hssh.runfile import validate_run
    from hssh.cli import CONFIG_FLOORS, CONFIG_CEILINGS, TRANSPORT_CHOICES
    with pytest.raises(ValueError, match="'workers' must be at most 256, not 300"):
        validate_run({"workers": 300}, str(tmp_path / "r.yaml"), TRANSPORT_CHOICES, CONFIG_FLOORS, CONFIG_CEILINGS)
    with pytest.raises(ValueError, match="'session_timeout' must be at most 86400"):
        validate_run({"session_timeout": 10 ** 6}, str(tmp_path / "r.yaml"), TRANSPORT_CHOICES, CONFIG_FLOORS, CONFIG_CEILINGS)
    assert validate_run({"workers": 256}, str(tmp_path / "r.yaml"), TRANSPORT_CHOICES, CONFIG_FLOORS, CONFIG_CEILINGS)["workers"] == 256


def test_a_device_port_in_a_run_file_is_checked_like_everywhere_else(tmp_path):
    from hssh.runfile import target_spec
    assert target_spec({"name": "R1", "host": "10.0.0.1", "port": 22}, "r.yaml", 0) == "R1:10.0.0.1:22"
    with pytest.raises(ValueError, match=r"devices\[0\]: port 70000 is outside 1..65535"):
        target_spec({"name": "R1", "host": "10.0.0.1", "port": 70000}, "r.yaml", 0)
    with pytest.raises(ValueError, match=r"devices\[0\]: 'port' must be a number, not 'x'"):
        target_spec({"name": "R1", "host": "10.0.0.1", "port": "x"}, "r.yaml", 0)


def test_allow_missing_is_a_run_file_key(tmp_path, monkeypatch, capsys):
    from hssh.runfile import RUN_KEYS
    assert RUN_KEYS["allow_missing"] == ("allow_missing", bool)


def test_a_verbose_batch_still_shows_the_command_echo_and_a_tuple_runner_still_works(monkeypatch, capsys, tmp_path):
    """#82 review: the JSON entry strips the '$ cmd' echo for display on a copy,
    so -v and --raw keep printing what the device said; and a stand-in runner
    that returns the bare 4-tuple is still accepted, on the failure path too."""
    import json as _json
    from hssh import runner as _runner

    class Batch(Driver):
        def show_batch(self, host, user, passwd, cmds, st, ct, port=None, vendor_hint=None):
            return [{"command": c, "ok": True, "output": f"$ {c}\nHostname: R1"} for c in cmds]
    b = write(tmp_path, "b.txt", "show version\n")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--user", "u", "--target", "R1:10.0.0.1:junos",
                                                              "--batch", b, "-v"], driver=Batch())
    assert rc == 0, err
    assert "$ show version\nHostname: R1" in out
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--user", "u", "--target", "R1:10.0.0.1:junos",
                                                              "--batch", b, "--json"], driver=Batch())
    assert _json.loads(out)[0]["commands"][0]["output"] == "Hostname: R1"

    async def bare_tuple(**kw):
        return ("R1", False, "DEVICE: R1\n\nERROR: no luck\n", 3)
    monkeypatch.setattr(cli, "run_for_target_async", bare_tuple)
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--user", "u", "--target", "R1:10.0.0.1:junos", "-sC", "show version"])
    assert rc == 1 and "ERROR: no luck" in out


def test_a_command_of_the_run_file_is_one_line_of_text(monkeypatch, capsys, tmp_path):
    """#110: YAML can fold two lines into one string; that string is not a command."""
    f = write(tmp_path, "run.yaml", "devices: [R1:10.0.0.1:junos]\nuser: u\ncommands:\n  - show version\n  - \"show route\\nrequest system reboot\"\n")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
    assert rc == 2 and drv.batches == []
    assert f"ERROR: run file '{f}' commands: a line break in 'show route\\nrequest system reboot'; a command is one line of text." in err
