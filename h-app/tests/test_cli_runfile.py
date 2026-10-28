"""Run files (#60): `h-ssh --run FILE` describes a whole fleet run in YAML or
JSON. Every key is a flag name; a flag typed on the command line wins; the
file never carries a credential; relative paths resolve against the file;
an edit from a file must arm a commit-confirmed timer or be a dry run."""
import argparse
import asyncio
import json
import os
import sys
import types
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hssh import cli, drivers, runfile


class Driver:
    """A junos driver that records what the CLI asked of it."""
    AVAILABLE = True

    def __init__(self):
        self.shows, self.batches, self.edits, self.comments = [], [], [], []

    def show(self, host, user, passwd, cmd, st, ct, port=None, vendor_hint=None):
        self.shows.append((host, cmd, port))
        return f"{host} says {cmd}"

    def show_batch(self, host, user, passwd, cmds, st, ct, port=None, vendor_hint=None):
        self.batches.append((host, list(cmds)))
        return [{"command": c, "ok": True, "output": f"{host} says {c}"} for c in cmds]

    def edit(self, host, user, passwd, payload, st, ct, commit_confirmed=None, port=None,
             dry_run=False, comment=None, expected_diff=None, vendor_hint=None):
        self.edits.append((host, payload.strip(), commit_confirmed, dry_run))
        self.comments.append(comment)
        return "COMMIT OK\n" if not dry_run else "DRY-RUN\n"


def run(monkeypatch, capsys, tmp_path, argv, driver=None, env=None, watch=False):
    """cli.main() in-process against the fake driver; nothing is contacted.
    With `watch`, as the console script runs it: every tick of an --every,
    with no pause between them."""
    drv = driver or Driver()
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", drv)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    for var, value in (env or {}).items():
        monkeypatch.setenv(var, value)
    monkeypatch.setattr(sys, "argv", ["./h-app/h-ssh.py", "--config", os.devnull, *argv])
    if watch:
        monkeypatch.setattr(cli, "_watch_sleep", lambda seconds: None)
        with pytest.raises(SystemExit) as e:
            cli.main_sync()
        rc = e.value.code
    else:
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


def test_a_job_file_typed_beside_the_run_file_needs_a_timer_too(monkeypatch, capsys, tmp_path):
    """#134: the rule looked at the file's own `jobs` and at -eC, -eD, -eB
    and --rollback typed beside --run, not at a --job file typed there:
    its edit entries committed with no timer, exit 0. They are held to it
    as the file's jobs are; a timer or a dry run lets them run, and a job
    that only reads, or only confirms, needs neither."""
    f = write(tmp_path, "run.yaml", "user: u\nworkers: 2\n")
    edit_job = write(tmp_path, "edit.json", json.dumps([
        {"target": "R1:10.0.0.1:junos", "show": "show version"},
        {"target": "R2:10.0.0.2:junos", "edit": "set system host-name R2"}]))
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f, "--job", edit_job, "-y"])
    assert rc == 2 and "without a rollback timer" in err and "commit_confirmed" in err
    assert drv.edits == [] and drv.shows == []
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f, "--job", edit_job, "-y", "--commit-confirmed", "5"])
    assert rc == 0, err
    assert drv.edits == [("10.0.0.2", "set system host-name R2", 5, False)]
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f, "--job", edit_job, "-y", "--dry-run"])
    assert rc == 0, err
    assert drv.edits == [("10.0.0.2", "set system host-name R2", None, True)]
    reads = write(tmp_path, "reads.json", json.dumps([{"target": "R1:10.0.0.1:junos", "show": "show version"}]))
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f, "--job", reads])
    assert rc == 0, err
    assert drv.shows == [("10.0.0.1", "show version", None)]
    confirm = write(tmp_path, "confirm.json", json.dumps([{"target": "R1:10.0.0.1:junos", "edit": "commit"}]))
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f, "--job", confirm, "-y"])
    assert rc == 0, err
    assert drv.edits == [("10.0.0.1", "commit", None, False)]


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


def test_the_show_of_a_run_file_is_stripped_and_its_errors_name_the_file(monkeypatch, capsys, tmp_path):
    """#110 review: a YAML block (`show: |`) ends its value with a line break,
    which ran before #110 and was then refused as "-sC has a line break", a
    flag nobody typed. The show is stripped like `commands`; what is still
    wrong is said as the file's key."""
    f = write(tmp_path, "run.yaml", "devices: [R1:10.0.0.1:junos]\nuser: u\nshow: |\n  show version\n")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
    assert rc == 0 and drv.shows == [("10.0.0.1", "show version", None)], err
    for body, text in (("show: \"show version\\nrequest system reboot\"",
                        "'show' has a line break ('show version\\nrequest system reboot'); a command is one line of text"),
                       ("show: \"  \"", "'show' is empty"),
                       ("edit: \"set system host-name x\\e\"\ndry_run: true",
                        "'edit' has an ESC ('set system host-name x\\x1b'); a payload is plain text")):
        f = write(tmp_path, "run.yaml", f"devices: [R1:10.0.0.1:junos]\nuser: u\n{body}\n")
        rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
        assert rc == 2 and drv.shows == drv.edits == [], err
        assert f"ERROR: run file '{f}': {text}" in err and "-sC" not in err and "-eC" not in err


def test_connect_timeout_is_a_run_file_key(monkeypatch, capsys, tmp_path):
    """#126: `connect-timeout` reaches the run, a flag on the command line
    wins, and it is held to the flag's range."""
    class Timed(Driver):
        def __init__(self):
            super().__init__()
            self.connects = []

        def show(self, host, user, passwd, cmd, st, ct, port=None, vendor_hint=None, connect_timeout=None):
            self.connects.append(connect_timeout)
            return super().show(host, user, passwd, cmd, st, ct, port=port, vendor_hint=vendor_hint)
    f = write(tmp_path, "run.yaml", "devices: [R1:10.0.0.1:junos]\nuser: u\nshow: show version\nconnect-timeout: 4\n")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f], driver=Timed())
    assert rc == 0 and drv.connects == [4], err
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f, "--connect-timeout", "2"], driver=Timed())
    assert rc == 0 and drv.connects == [2], err
    f = write(tmp_path, "run.yaml", "devices: [R1:10.0.0.1:junos]\nuser: u\nshow: show version\nconnect_timeout: 0\n")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f], driver=Timed())
    assert rc == 2 and "'connect_timeout' must be at least 1, not 0" in err and drv.connects == []


# --- #140: what the command line gives wins, whatever its value ---------------

def test_typed_dests_holds_what_argv_gives_whatever_its_value():
    """#140: the run file filled every option still at argparse's default,
    so a flag typed with the default's value counted as not typed. The
    second parse sees what argv gives (a default's value, a bare host, a
    flag with no value, one given twice) and puts the defaults back."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--devices", default="devices.csv")
    parser.add_argument("--format", choices=["text", "xml"], default="text")
    parser.add_argument("-y", "--yes", action="store_true")
    parser.add_argument("--target", action="append")
    parser.add_argument("--commit-confirmed", type=int, nargs="?", const=10)
    parser.add_argument("hosts", nargs="*")
    assert cli.typed_dests(parser, []) == set()
    assert cli.typed_dests(parser, ["--format", "text", "--devices", "devices.csv"]) == {"format", "devices"}
    assert cli.typed_dests(parser, ["R1", "-y", "--target", "a:1", "R2", "--target", "b:2", "--commit-confirmed"]) == \
        {"hosts", "yes", "target", "commit_confirmed"}
    assert vars(parser.parse_intermixed_args([])) == {"devices": "devices.csv", "format": "text", "yes": False,
                                                      "target": None, "commit_confirmed": None, "hosts": []}


def test_a_typed_devices_replaces_the_files_inline_list_and_says_so(monkeypatch, capsys, tmp_path):
    """#140: --devices lab.csv beside a run file holding an inline list of
    production routers, an edit, commit-confirmed and yes committed on the
    production routers, with no prompt and no word, and printed a confirm
    command for them: the CLI read only the file's list. A typed --devices
    replaces the file's `devices`, and one line on stderr says so."""
    lab = write(tmp_path, "lab.csv", "lab1,10.0.9.1,junos\n")
    f = write(tmp_path, "run.yaml", "devices: [prod1:10.0.0.1:junos, prod2:10.0.0.2:junos]\nuser: u\n"
                                    "edit: set system location building B\ncommit-confirmed: 5\nyes: true\n")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f, "--devices", lab])
    assert rc == 0, err
    assert drv.edits == [("10.0.9.1", "set system location building B", 5, False)]
    assert f"Run file '{f}': 'devices' is ignored; --devices on the command line wins.\n" in err
    assert f"Inventory: {lab}" in out and f'-eC "commit" --user u --devices {lab}' in out


def test_a_typed_target_replaces_the_files_devices_and_says_so(monkeypatch, capsys, tmp_path):
    """A target typed bare or with --target replaces the file's `devices`, a
    list or a path, with the same line, once for a whole --every watch, not
    once a tick; without one the file's are used and nothing is said."""
    write(tmp_path, "prod.csv", "prod1,10.0.0.1,junos\n")
    for devices in ("prod.csv", "[prod1:10.0.0.1:junos]"):
        f = write(tmp_path, "run.yaml", f"devices: {devices}\nuser: u\nshow: show version\n")
        for given in (["lab1:10.0.9.1:junos"], ["--target", "lab1:10.0.9.1:junos"]):
            rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f, *given])
            assert rc == 0 and drv.shows == [("10.0.9.1", "show version", None)], (devices, given, err)
            assert f"Run file '{f}': 'devices' is ignored; the targets on the command line win.\n" in err
        rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
        assert rc == 0 and drv.shows == [("10.0.0.1", "show version", None)] and "ignored" not in err, devices
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f, "--every", "1", "--times", "3",
                                                            "lab1:10.0.9.1:junos"], watch=True)
    assert rc == 0 and drv.shows == [("10.0.9.1", "show version", None)] * 3, err
    assert err.count("'devices' is ignored") == 1, err


def test_a_flag_typed_with_its_defaults_value_still_wins(monkeypatch, capsys, tmp_path):
    """#140: a flag whose value was argparse's default was taken for one not
    typed: `--format text` lost to `format: xml`, `--devices devices.csv`
    (the default's own spelling) to `devices: prod.csv`, an --audit-log
    equal to $HSSH_AUDIT_LOG to `audit-log:`. Typed is typed; the file still
    wins over the environment, and a typed --profile over the file's batch."""
    class Rpc(Driver):
        def __init__(self):
            super().__init__()
            self.rpcs = []

        def rpc(self, host, user, passwd, cmd, st, ct, port=None, vendor_hint=None, fmt="json"):
            self.rpcs.append((host, cmd, fmt))
            return "<reply/>"
    f = write(tmp_path, "run.yaml", "devices: [R1:10.0.0.1:junos]\nuser: u\nshow: show version\nformat: xml\n")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f], driver=Rpc())
    assert rc == 0 and drv.rpcs == [("10.0.0.1", "show version", "xml")] and drv.shows == [], err
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f, "--format", "text"], driver=Rpc())
    assert rc == 0 and drv.shows == [("10.0.0.1", "show version", None)] and drv.rpcs == [], err

    monkeypatch.setenv("HOME", str(tmp_path))          # no ~/.h-ssh/devices.csv: the default is ./devices.csv
    monkeypatch.chdir(tmp_path)
    write(tmp_path, "devices.csv", "lab1,10.0.9.1,junos\n")
    write(tmp_path, "prod.csv", "prod1,10.0.0.1,junos\n")
    f = write(tmp_path, "run.yaml", "devices: prod.csv\nuser: u\nshow: show version\n")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f, "--devices", "devices.csv"])
    assert rc == 0 and drv.shows == [("10.0.9.1", "show version", None)], err
    assert "'devices' is ignored; --devices on the command line wins." in err

    site, other = tmp_path / "site-audit.jsonl", tmp_path / "other-audit.jsonl"
    f = write(tmp_path, "run.yaml", "devices: [R1:10.0.0.1:junos]\nuser: u\nshow: show version\n"
                                    "audit-log: file-audit.jsonl\n")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f, "--audit-log", str(site)],
                            env={"HSSH_AUDIT_LOG": str(site)})
    assert rc == 0 and site.is_file() and not (tmp_path / "file-audit.jsonl").exists(), err
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f], env={"HSSH_AUDIT_LOG": str(other)})
    assert rc == 0 and (tmp_path / "file-audit.jsonl").is_file() and not other.exists(), err

    mine = write(tmp_path, "mine.txt", "show route summary\n")
    write(tmp_path, "cmds.txt", "show version\n")
    f = write(tmp_path, "run.yaml", "devices: [R1:10.0.0.1:junos]\nuser: u\nbatch: cmds.txt\n")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f, "--profile", mine])
    assert rc == 0 and drv.batches == [("10.0.0.1", ["show route summary"])], err


def test_targets_typed_beside_a_job_are_refused(monkeypatch, capsys, tmp_path):
    """#140: a job's targets are its entries. A target typed beside --job or
    a run file's jobs, bare or --target, or a --devices (the default's own
    spelling too), was ignored without a word: the job ran on every device
    it names, exit 0, and with an edit entry and -y committed on a router
    the operator had left out. Refused before the job is read, nothing
    sent. The file's own `devices` beside its jobs is still not used."""
    job = write(tmp_path, "job.json", json.dumps([
        {"target": "R1:10.0.0.1:junos", "edit": "set system location building A"},
        {"target": "R2:10.0.0.2:junos", "show": "show version"}]))
    lab = write(tmp_path, "lab.csv", "lab1,10.0.9.1,junos\n")
    for given, named in ((["lab1:10.0.9.1:junos"], "a bare host"), (["--target", "lab1:10.0.9.1:junos"], "--target"),
                         (["--devices", lab], "--devices"), (["R9:10.0.0.9:junos", "--devices", lab],
                                                            "a bare host, --devices")):
        rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--job", job, "-y", *given])
        assert rc == 2 and drv.edits == drv.shows == [], (given, err)
        assert f"ERROR: {named} beside --job: a job's targets are its entries.\n" in err
    jobs = "jobs:\n  - {target: R1:10.0.0.1:junos, edit: set system location building A}\n"
    f = write(tmp_path, "run.yaml", f"user: u\ncommit-confirmed: 5\nyes: true\n{jobs}")
    for given, named in ((["--target", "lab1:10.0.9.1:junos"], "--target"), (["--devices", "devices.csv"], "--devices")):
        rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f, *given])
        assert rc == 2 and drv.edits == [], (given, err)
        assert f"ERROR: {named} beside a run file's 'jobs': a job's targets are its entries.\n" in err
    f = write(tmp_path, "run.yaml", f"devices: [lab1:10.0.9.1:junos]\nuser: u\ncommit-confirmed: 5\nyes: true\n{jobs}")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
    assert rc == 0 and drv.edits == [("10.0.0.1", "set system location building A", 5, False)], err


def test_a_run_files_devices_beside_a_typed_job_are_refused(monkeypatch, capsys, tmp_path):
    """#140 review: a run file's `devices` (a list or a path) beside a --job
    typed next to the file was dropped without a word: the job ran on its
    own entries and, with the file's timer and `yes`, committed on prod1
    with no prompt, the confirm hint naming it. Refused as a typed target
    beside a job is, nothing sent; a file without `devices` still lends a
    typed job its options."""
    job = write(tmp_path, "job.json", json.dumps([
        {"target": "prod1:10.0.0.1:junos", "edit": "set system location building A"},
        {"target": "prod2:10.0.0.2:junos", "show": "show version"}]))
    write(tmp_path, "lab.csv", "lab1,10.0.9.1,junos\n")
    options = {"user": "u", "commit-confirmed": 5, "yes": True}
    for devices in (["lab1:10.0.9.1:junos"], "lab.csv"):
        f = write(tmp_path, "run.json", json.dumps({"devices": devices, **options}))
        rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f, "--job", job])
        assert rc == 2 and drv.edits == drv.shows == [] and out == "", (devices, err)
        assert err == f"ERROR: run file '{f}': 'devices' beside --job: a job's targets are its entries.\n", devices
    f = write(tmp_path, "run.json", json.dumps(options))
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f, "--job", job])
    assert rc == 0 and drv.edits == [("10.0.0.1", "set system location building A", 5, False)], err
    assert drv.shows == [("10.0.0.2", "show version", None)]


def test_an_empty_path_user_or_comment_in_the_file_is_refused(monkeypatch, capsys, tmp_path):
    """#140: a run file's empty value was the key left out: `audit_log: ''`
    turned the HSSH_AUDIT_LOG trail off, `user: ''` fell back to HSSH_USER,
    `save_output: ''` saved nothing. Every path, `user` and `comment` that
    is empty is refused naming the key, exit 2, nothing sent."""
    for key in ("devices", "user", "batch", "edit_dir", "edit_broadcast", "comment", "save_output", "log",
                "audit_log", "safety_file"):
        f = write(tmp_path, "run.json", json.dumps({"devices": ["R1:10.0.0.1:junos"], "user": "u",
                                                    "show": "show version", key: ""}))
        rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
        assert rc == 2 and drv.shows == drv.batches == drv.edits == [], (key, err)
        assert f"ERROR: run file '{f}': '{key}' is empty; give it a value or leave the key out\n" in err, key


# --- #146: a commit comment Junos would not log as given --------------------------

def run_argv(monkeypatch, capsys, tmp_path, argv):
    """run(), with a flag argparse refuses read as its exit code and stderr."""
    drv = Driver()
    try:
        return run(monkeypatch, capsys, tmp_path, argv, driver=drv)
    except SystemExit as e:
        out, err = capsys.readouterr()
        return e.code, out, err, drv


RULE = "a commit comment is one line of text, at most 512 bytes"


@pytest.mark.parametrize("comment, said", [
    ("line one\nline two", f"'line one\\nline two' has a line break; {RULE}"),
    ("é" * 257, f"{'é' * 257!r} is 514 bytes; {RULE}"),
    ("   ", f"'   ' has no text; {RULE}"),
    ("cutover \x1b[1m", f"'cutover \\x1b[1m' has an ESC; {RULE}"),
], ids=["line break", "514 bytes", "blanks", "ESC"])
def test_a_comment_junos_would_not_log_as_given_is_refused_before_the_probe(monkeypatch, capsys, tmp_path, probed,
                                                                            comment, said):
    """#146: --comment went to the driver as typed. Junos logged the last
    line of one with a line break alone (guarded_commit() then found no
    commit of its own), and 600 characters, 512 two-byte ones or only
    spaces went through lock, load, diff and commit check on every router
    before the commit failed, each router cooled under --safety-file. Each
    is refused before the probe, exit 2, the driver never asked, as an
    empty one is (#140)."""
    rc, out, err, drv = run_argv(monkeypatch, capsys, tmp_path,
                                 ["-eC", "set system location x", "--comment", comment, "-y", "R1:10.0.0.1:junos"])
    assert rc == 2 and drv.edits == [] and probed == [] and out == "", err
    assert err == f"h-ssh.py: error: argument --comment: {said} (see --help)\n"


def test_a_comment_is_stripped_and_512_bytes_go_through(monkeypatch, capsys, tmp_path):
    for comment, sent in (("A" * 512, "A" * 512), ("  C1 cutover \n", "C1 cutover")):
        rc, out, err, drv = run_argv(monkeypatch, capsys, tmp_path,
                                     ["-eC", "set system location x", "--comment", comment, "-y", "R1:10.0.0.1:junos"])
        assert rc == 0 and drv.comments == [sent], err


def test_a_run_files_comment_is_held_to_the_flags_rule(monkeypatch, capsys, tmp_path, probed):
    """#146: the file's `comment` had no rule of its own: a YAML block
    (`comment: |`) of two lines committed the last one alone. It is said as
    the file's key, exit 2, nothing sent or probed; a block of one line is
    that line, the line break the block ends with not part of it."""
    head = "devices: [R1:10.0.0.1:junos]\nedit: set system location x\ncommit_confirmed: 5\nyes: true\n"
    f = write(tmp_path, "run.yaml", head + "comment: |\n  C1 cutover\n  and the rest\n")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
    assert rc == 2 and drv.edits == [] and probed == [], err
    assert err == (f"ERROR: run file '{f}': 'comment' has a line break ('C1 cutover\\nand the rest\\n'); "
                   f"{RULE}\n")
    for value, said in (("é" * 257, "is 514 bytes"), ("'   '", "has no text")):
        f = write(tmp_path, "run.yaml", head + f"comment: {value}\n")
        rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
        assert rc == 2 and drv.edits == [] and probed == [] and f"'comment' {said} (" in err, err
    f = write(tmp_path, "run.yaml", head + "comment: |\n  C1 cutover\n")
    rc, out, err, drv = run(monkeypatch, capsys, tmp_path, ["--run", f])
    assert rc == 0 and drv.comments == ["C1 cutover"], err
