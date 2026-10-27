"""Tests for hssh.core module."""

import pytest
import tempfile
from pathlib import Path
from hssh.core import load_devices_csv, Target


def test_load_csv_with_header():
    """Test loading CSV with header row."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("name,ip,vendor\n")
        f.write("CR1,10.0.1.1,junos\n")
        f.write("CR2,10.0.1.2,junos\n")
        f.write("SW1,10.0.2.1,openssh\n")
        f.flush()

        targets = load_devices_csv(f.name)

    Path(f.name).unlink()

    assert len(targets) == 3
    assert targets[0].name == "CR1"
    assert targets[0].host == "10.0.1.1"
    assert targets[0].vendor == "junos"
    assert targets[2].vendor == "openssh"


def test_load_csv_without_header():
    """Test loading CSV without header (backwards compatibility)."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("CR1,10.0.1.1,junos\n")
        f.write("CR2,10.0.1.2,openssh\n")
        f.flush()

        targets = load_devices_csv(f.name)

    Path(f.name).unlink()

    assert len(targets) == 2
    assert targets[0].name == "CR1"
    assert targets[0].host == "10.0.1.1"
    assert targets[0].vendor == "junos"


def test_load_csv_with_comments():
    """Test loading CSV with comments."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("# This is a comment\n")
        f.write("name,ip,vendor\n")
        f.write("CR1,10.0.1.1,junos\n")
        f.write("# Another comment\n")
        f.write("CR2,10.0.1.2,junos  # Inline comment\n")
        f.write("\n")  # Empty line
        f.write("CR3,10.0.1.3,junos\n")
        f.flush()

        targets = load_devices_csv(f.name)

    Path(f.name).unlink()

    assert len(targets) == 3
    assert targets[0].name == "CR1"
    assert targets[1].name == "CR2"
    assert targets[2].name == "CR3"


def test_load_csv_name_only():
    """Test loading CSV with only device names (no commas)."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("router1\n")
        f.write("router2\n")
        f.write("# comment\n")
        f.write("router3\n")
        f.flush()

        targets = load_devices_csv(f.name)

    Path(f.name).unlink()

    assert len(targets) == 3
    assert targets[0].name == "router1"
    assert targets[0].host == "router1"  # host should equal name
    assert targets[1].name == "router2"


def test_load_csv_default_vendor():
    """Vendor defaults to 'ssh' when the inventory doesn't declare one."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("name,ip\n")
        f.write("CR1,10.0.1.1\n")
        f.flush()

        targets = load_devices_csv(f.name)

    Path(f.name).unlink()

    assert len(targets) == 1
    assert targets[0].vendor == "ssh"


def test_load_csv_default_vendor_is_the_callers(tmp_path):
    """The CLI passes --transport as default_vendor; a declared vendor still wins."""
    inv = tmp_path / "devices.csv"
    inv.write_text("name,ip,vendor\nCR1,10.0.1.1\nSW1,10.0.2.1,openssh\n")
    targets = load_devices_csv(str(inv), default_vendor="junos")
    assert [t.vendor for t in targets] == ["junos", "openssh"]


def test_load_csv_name_only_rows_get_the_default_vendor(tmp_path):
    inv = tmp_path / "devices.csv"
    inv.write_text("router1\nrouter2\n")
    targets = load_devices_csv(str(inv), default_vendor="junos")
    assert [t.vendor for t in targets] == ["junos", "junos"]


def test_load_csv_file_not_found():
    """Test that FileNotFoundError is raised for missing file."""
    with pytest.raises(FileNotFoundError):
        load_devices_csv("/nonexistent/path/devices.csv")


def test_load_csv_empty_file():
    """Test loading an empty CSV file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("# Only comments\n")
        f.write("\n")
        f.flush()

        targets = load_devices_csv(f.name)

    Path(f.name).unlink()

    assert len(targets) == 0


def test_target_dataclass():
    """Test Target dataclass creation."""
    target = Target(name="CR1", host="10.0.1.1", vendor="junos")

    assert target.name == "CR1"
    assert target.host == "10.0.1.1"
    assert target.vendor == "junos"

    # Test default vendor
    target2 = Target(name="CR2", host="10.0.1.2")
    assert target2.vendor == "ssh"


def test_resolve_target_port():
    from hssh.core import resolve_target_port

    # Explicit port takes precedence
    assert resolve_target_port(Target(name="R1", host="10.0.1.1", vendor="junos", port=2222)) == 2222
    # Junos defaults to 830
    assert resolve_target_port(Target(name="R1", host="10.0.1.1", vendor="junos")) == 830
    # telnet-arista (EOS over telnet) defaults to 23
    assert resolve_target_port(Target(name="R1", host="10.0.1.1", vendor="telnet-arista")) == 23
    # Telnet defaults to 23
    assert resolve_target_port(Target(name="R1", host="10.0.1.1", vendor="telnet")) == 23
    assert resolve_target_port(Target(name="R1", host="10.0.1.1", vendor="telnet-ios")) == 23
    # SSH defaults to 22
    assert resolve_target_port(Target(name="R1", host="10.0.1.1", vendor="ssh")) == 22


def test_validate_junos_set_syntax():
    from hssh.core import validate_junos_set_syntax

    # Valid set commands with # comments and blank lines
    payload = """
    # Set system hostname
    set system host-name R1
    
    # Interface config
    set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24
    delete interfaces ge-0/0/1
    deactivate interfaces ge-0/0/2
    activate interfaces ge-0/0/3
    annotate interfaces ge-0/0/0 "Uplink"
    protect system
    unprotect system
    """
    valid, err = validate_junos_set_syntax(payload)
    assert valid is True
    assert err == ""

    # Standalone commit is valid when allow_commit is True
    valid, err = validate_junos_set_syntax("commit", allow_commit=True)
    assert valid is True
    assert err == ""

    valid, err = validate_junos_set_syntax("commit;", allow_commit=True)
    assert valid is True
    assert err == ""

    # Uppercase verbs are rejected by guard
    valid, err = validate_junos_set_syntax("SET system host-name R1", allow_commit=True)
    assert valid is False
    assert "invalid Junos set command" in err

    valid, err = validate_junos_set_syntax("COMMIT", allow_commit=True)
    assert valid is False
    assert "invalid Junos set command" in err

    # Standalone commit is rejected when allow_commit is False (-eD/-eB)
    valid, err = validate_junos_set_syntax("commit", allow_commit=False)
    assert valid is False
    assert "not permitted in configuration files" in err

    # Commit cannot be combined with set commands
    valid, err = validate_junos_set_syntax("set system host-name R1\ncommit", allow_commit=True)
    assert valid is False
    assert "cannot be combined" in err

    # Multi-line bypass attempt (line 1 valid set, line 2 invalid command)
    bypass_payload = "set system host-name R1\nreboot"
    valid, err = validate_junos_set_syntax(bypass_payload)
    assert valid is False
    assert "line 2" in err
    assert "reboot" in err

    # Curly brace hierarchy rejection
    curly_payload = "interfaces {\n  ge-0/0/0 {\n    unit 0 {}\n  }\n}"
    valid, err = validate_junos_set_syntax(curly_payload)
    assert valid is False
    assert "line 1" in err

    # Empty payload
    valid, err = validate_junos_set_syntax("  \n# only comments\n  ")
    assert valid is False
    assert "no commands" in err

    # Reject 'commitfoo'
    valid, err = validate_junos_set_syntax("commitfoo")
    assert valid is False
    assert "invalid Junos set command" in err

    # Reject 'commit confirmed' as raw command (must use --commit-confirmed flag)
    valid, err = validate_junos_set_syntax("commit confirmed")
    assert valid is False
    assert "invalid Junos set command" in err

    # Reject C-style and Cisco-style comments (! and /*)
    valid, err = validate_junos_set_syntax("/* comment */\nset system host-name R1")
    assert valid is False
    assert "line 1" in err

    valid, err = validate_junos_set_syntax("! comment\nset system host-name R1")
    assert valid is False
    assert "line 1" in err


def test_read_set_file_for_device(tmp_path):
    """The -eD reader drops blank and full-line '#' lines only; a '#' inside
    a line is part of the value, as it is for -eB and the syntax guard."""
    from hssh.core import read_set_file_for_device

    (tmp_path / "R1.set").write_text(
        "# full-line comment\n"
        "\n"
        "set snmp community ab#12 authorization read-only\n"
        "   # indented comment\n"
        'set interfaces ge-0/0/0 description "uplink #3"\n')
    assert read_set_file_for_device(str(tmp_path), "R1") == (
        "set snmp community ab#12 authorization read-only\n"
        'set interfaces ge-0/0/0 description "uplink #3"\n')

    with pytest.raises(FileNotFoundError):
        read_set_file_for_device(str(tmp_path), "R2")

    (tmp_path / "R3.set").write_text("# only comments\n\n")
    with pytest.raises(ValueError):
        read_set_file_for_device(str(tmp_path), "R3")


def test_command_template_path_resolution(tmp_path, monkeypatch):
    """Template resolution should work even when CWD is outside the repo."""
    from hssh.core import resolve_command

    # Change CWD to an empty temporary directory
    monkeypatch.chdir(tmp_path)

    # Shipped templates should still be found relative to the hssh package
    cmd = resolve_command("bgp", "junos")
    assert "bgp" in cmd


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


def test_target_spec_round_trips_every_target_form():
    """The confirm hint is built from target_spec(); an IPv6 host lost its
    brackets and the hint could not be pasted back (#39)."""
    from hssh.cli import target_spec
    from hssh.core import Target, parse_inline_target
    for t in (Target("R1", "10.0.0.1", "junos"), Target("R1", "10.0.0.1", "junos", 830),
              Target("R1", "2001:db8::1", "junos"), Target("R1", "2001:db8::1", "junos", 830),
              Target("sw", "::1", "telnet-ios", 5001)):
        assert parse_inline_target(target_spec(t)) == t

# --- #41: a device name is a file name --------------------------------------------

@pytest.mark.parametrize("name", ["../outside", "/home/op/x", "a/b", ".", "..", "-oProxyCommand=x", "", ".hidden", "a b"])
def test_a_target_name_that_could_leave_its_directory_is_refused(name):
    """'../x' in an inventory row once chose which local file became the
    pushed config, and where the device's output was written."""
    from hssh.core import parse_inline_target, validate_device_name
    with pytest.raises(ValueError, match="invalid device name"):
        validate_device_name(name)
    with pytest.raises(ValueError, match="invalid device name"):
        Target(name, "10.0.0.1", "junos")
    if ":" not in name:
        with pytest.raises(ValueError, match="invalid device name"):
            parse_inline_target(f"{name}:10.0.0.1:junos")


@pytest.mark.parametrize("name", ["R1", "sw-1.lab", "10.0.0.1", "2001:db8::1", "ax4_ede0004", "C02"])
def test_hostname_shaped_names_are_fine(name):
    assert Target(name, "10.0.0.1", "junos").name == name


def test_inventory_rows_and_job_entries_with_a_bad_name_are_refused(tmp_path):
    from hssh.core import load_devices_csv, load_jobs
    csv_file = tmp_path / "d.csv"
    csv_file.write_text("name,ip,vendor\n../x,10.0.0.1,junos\n")
    with pytest.raises(ValueError, match="invalid device name"):
        load_devices_csv(str(csv_file))
    job = tmp_path / "j.json"
    job.write_text('[{"target": "../x:10.0.0.1:junos", "show": "show version"}]')
    with pytest.raises(ValueError, match="invalid device name"):
        load_jobs(str(job))


def test_set_file_and_save_paths_stay_inside_their_directory(tmp_path):
    """Belt and braces at the join: even a caller that skips Target cannot
    read or write outside the directory."""
    from hssh.core import path_inside, read_set_file_for_device
    (tmp_path / "outside.set").write_text("set x y\n")
    cfg = tmp_path / "configs"; cfg.mkdir()
    with pytest.raises(ValueError):
        read_set_file_for_device(str(cfg), "../outside")
    with pytest.raises(ValueError, match="does not stay inside"):
        path_inside(str(cfg), "../outside.output")
    with pytest.raises(ValueError, match="does not stay inside"):
        path_inside(str(cfg), "/etc/passwd")
    assert path_inside(str(cfg), "R1.output") == cfg / "R1.output"

# --- #79: eAPI is gone; the vendor name gets one clear line --------------------------

def test_the_arista_eapi_vendor_is_retired_with_one_clear_line():
    from hssh import drivers
    assert "arista" not in drivers.names() and "telnet-arista" in drivers.ALIASES
    with pytest.raises(ValueError, match="vendor 'arista' \\(eAPI over HTTPS\\) is no longer supported; EOS devices use the ssh or openssh transport"):
        drivers.get("arista")
    import importlib
    assert importlib.util.find_spec("hssh.transports.arista") is None
