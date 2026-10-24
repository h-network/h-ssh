"""#62: wrong input is refused with a named reason before anything runs —
numeric flags and config keys out of range, ports, BOM inventories, a
--config that is not a file, --save-output on a file, a closed stdout,
whitespace commands, unknown job keys, lines without '=', wide CSV rows."""
import asyncio
import io
import json
import os
import subprocess
import sys
import types
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hssh import cli, drivers, core
from hssh.core import load_devices_csv, load_config, parse_inline_target, load_jobs, check_port

HSSH = os.path.join(os.path.dirname(__file__), "..", "h-ssh.py")


def run_main(monkeypatch, capsys, argv, config=os.devnull):
    fake = types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: "ok", edit=lambda *a, **kw: "COMMIT OK\n")
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", fake)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", config, "--user", "u", "--password", "p", *argv])
    try:
        rc = asyncio.run(cli.main())
    except SystemExit as e:      # argparse
        rc = e.code
    out, err = capsys.readouterr()
    return rc, out, err


# --- numeric flags: one line, the range, no usage dump -------------------------

@pytest.mark.parametrize("argv, needle", [
    (["--session-timeout", "0"], "--session-timeout takes a number from 1 to 86400, not 0"),
    (["--session-timeout", "-1"], "from 1 to 86400, not -1"),
    (["--session-timeout", "99999999"], "from 1 to 86400, not 99999999"),
    (["--command-timeout", "0"], "--command-timeout takes a number from 1 to 86400"),
    (["--workers", "0"], "--workers takes a number from 1 to 256, not 0"),
    (["--workers", "-5"], "not -5"),
    (["--workers", "100000"], "not 100000"),
    (["--workers", "eight"], "--workers takes a whole number, not 'eight'"),
    (["--retries", "-1"], "--retries takes a number of 0 or more, not -1"),
    (["--rollback", "50"], "--rollback takes a number from 0 to 49, not 50"),
    (["--commit-confirmed", "0"], "1..65535 minutes"),
])
def test_numeric_flags_are_range_checked_in_one_line(argv, needle):
    res = subprocess.run([sys.executable, HSSH, "--target", "R1:10.0.0.1:junos", "-sC", "show version", *argv],
                         capture_output=True, text=True)
    assert res.returncode == 2
    assert needle in res.stderr
    assert "usage:" not in res.stderr and res.stderr.count("\n") == 1, res.stderr


def test_config_values_have_the_same_ceiling(monkeypatch, capsys, tmp_path):
    cfg = tmp_path / "config"
    cfg.write_text("workers = 999\n")
    rc, out, err = run_main(monkeypatch, capsys, ["--target", "R1:10.0.0.1:junos", "-sC", "show version"], config=str(cfg))
    assert rc == 2 and "workers = 999 is above 256" in err


# --- ports everywhere ----------------------------------------------------------

@pytest.mark.parametrize("value, needle", [
    ("0", "port 0 is outside 1..65535"), ("70000", "port 70000 is outside 1..65535"),
    ("abc", "'port' must be a number, not 'abc'"), (True, "not a boolean"), (3.5, "not float"),
])
def test_check_port_names_the_problem(value, needle):
    with pytest.raises(ValueError, match="here: .*" + needle.replace("(", r"\(").replace(")", r"\)").replace("[", r"\[")):
        check_port(value, "here")


def test_csv_ports_are_checked_and_leak_no_int_error(tmp_path):
    f = tmp_path / "d.csv"
    f.write_text("R1,10.0.0.1,junos,x\n")
    with pytest.raises(ValueError) as e:
        load_devices_csv(str(f))
    assert "row 1 (R1)" in str(e.value) and "'port' must be a number, not 'x'" in str(e.value)
    assert "invalid literal" not in str(e.value)
    f.write_text("R1,10.0.0.1,junos,0\n")
    with pytest.raises(ValueError, match="port 0 is outside 1..65535"):
        load_devices_csv(str(f))


@pytest.mark.parametrize("spec", ["R1:10.0.0.1:junos:0", "R1:10.0.0.1:0", "R1:10.0.0.1:70000:junos"])
def test_inline_target_ports_are_checked(spec):
    with pytest.raises(ValueError, match="outside 1..65535"):
        parse_inline_target(spec)


def test_job_ports_and_keys_are_checked(tmp_path):
    job = tmp_path / "job.json"
    job.write_text(json.dumps([{"target": "R1:10.0.0.1:junos", "show": "show version", "port": 0}]))
    with pytest.raises(ValueError, match="Job entry 0: port 0 is outside"):
        load_jobs(str(job))
    job.write_text(json.dumps([{"target": "R1:10.0.0.1:junos", "show": "show version", "colour": "red", "vendor": "junos"}]))
    with pytest.raises(ValueError, match="Job entry 0: unknown key\\(s\\) colour, vendor \\(target, show, edit, port\\)"):
        load_jobs(str(job))


# --- files people actually produce --------------------------------------------

def test_a_bom_inventory_keeps_the_first_name(tmp_path):
    f = tmp_path / "d.csv"
    f.write_bytes("﻿name,ip,vendor\nR1,10.0.0.1,junos\n".encode("utf-8"))
    t = load_devices_csv(str(f))
    assert [x.name for x in t] == ["R1"]
    f.write_bytes("﻿a,10.0.0.1\n".encode("utf-8"))
    assert load_devices_csv(str(f))[0].name == "a"


def test_a_wide_csv_row_is_named(tmp_path):
    f = tmp_path / "d.csv"
    f.write_text("name,ip,vendor,port\nR1,10.0.0.1,junos,830,extra\n")
    with pytest.raises(ValueError, match="row 2: 5 columns; expected name,ip\\[,vendor\\[,port\\]\\]"):
        load_devices_csv(str(f))


def test_a_bom_config_and_batch_file_read_cleanly(tmp_path):
    cfg = tmp_path / "config"
    cfg.write_bytes("﻿user = EF\n".encode("utf-8"))
    assert load_config(str(cfg)) == {"user": "EF"}
    b = tmp_path / "cmds.txt"
    b.write_bytes("﻿show version\n".encode("utf-8"))
    assert core.read_command_file_lines(b) == ["show version"]


def test_config_that_is_a_directory_or_binary_is_refused(monkeypatch, capsys, tmp_path):
    rc, out, err = run_main(monkeypatch, capsys, ["--target", "R1:10.0.0.1:junos", "-sC", "show version"], config=str(tmp_path))
    assert rc == 2 and "is a directory, not a config file" in err
    bad = tmp_path / "bin.cfg"
    bad.write_bytes(b"\xff\xfe\x00garbage")
    rc, out, err = run_main(monkeypatch, capsys, ["--target", "R1:10.0.0.1:junos", "-sC", "show version"], config=str(bad))
    assert rc == 2 and "is not UTF-8 text" in err and "Traceback" not in err


def test_an_explicit_missing_config_is_an_error(monkeypatch, capsys, tmp_path):
    rc, out, err = run_main(monkeypatch, capsys, ["--target", "R1:10.0.0.1:junos", "-sC", "show version"],
                            config=str(tmp_path / "confg"))
    assert rc == 2 and "config file not found" in err and "confg" in err


def test_the_default_config_path_may_be_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "get_config_path", lambda: tmp_path / "absent")
    assert load_config(None) == {}


def test_config_line_without_separator_is_named(tmp_path):
    cfg = tmp_path / "config"
    cfg.write_text("user = EF\nworkers 16\n")
    with pytest.raises(ValueError, match="line 2: expected 'key = value', got 'workers 16'"):
        load_config(str(cfg))


# --- the run's own files and streams ------------------------------------------

def test_save_output_on_an_existing_file_is_refused(monkeypatch, capsys, tmp_path):
    f = tmp_path / "afile"
    f.write_text("x")
    rc, out, err = run_main(monkeypatch, capsys, ["--target", "R1:10.0.0.1:junos", "-sC", "show version", "--save-output", str(f)])
    assert rc == 2 and "exists and is not a directory" in err


def test_a_closed_stdout_is_not_a_terminal_and_not_a_traceback(monkeypatch):
    assert cli._tty(None) is False
    closed = io.StringIO()
    closed.close()
    assert cli._tty(closed) is False
    assert cli._tty(types.SimpleNamespace()) is False


@pytest.mark.parametrize("flag", ["-sC", "-eC"])
def test_a_whitespace_command_is_refused(monkeypatch, capsys, flag):
    rc, out, err = run_main(monkeypatch, capsys, ["--target", "R1:10.0.0.1:junos", flag, "   "])
    assert rc == 2 and f"{flag} is empty" in err


def test_a_target_that_still_says_arista_is_refused_before_any_device(monkeypatch, capsys):
    """#79: eAPI is gone; the old vendor name is not 'unknown', it is retired, and the line says what to use."""
    import asyncio
    from hssh import cli
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "--password", "p",
                                      "--target", "SW1:10.0.0.1:arista", "-sC", "show version"])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    assert rc == 2
    assert "ERROR: vendor 'arista' (eAPI over HTTPS) is no longer supported; EOS devices use the ssh or openssh transport" in err
