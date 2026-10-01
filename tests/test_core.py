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
        f.write("SW1,10.0.2.1,arista\n")
        f.flush()

        targets = load_devices_csv(f.name)

    Path(f.name).unlink()

    assert len(targets) == 3
    assert targets[0].name == "CR1"
    assert targets[0].host == "10.0.1.1"
    assert targets[0].vendor == "junos"
    assert targets[2].vendor == "arista"


def test_load_csv_without_header():
    """Test loading CSV without header (backwards compatibility)."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("CR1,10.0.1.1,junos\n")
        f.write("CR2,10.0.1.2,arista\n")
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
    # Arista defaults to 443
    assert resolve_target_port(Target(name="R1", host="10.0.1.1", vendor="arista")) == 443
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
    SET interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24
    DELETE interfaces ge-0/0/1
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

    valid, err = validate_junos_set_syntax("COMMIT;", allow_commit=True)
    assert valid is True
    assert err == ""

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
