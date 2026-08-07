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
    """Test that default vendor is 'junos' when not specified."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("name,ip\n")
        f.write("CR1,10.0.1.1\n")
        f.flush()

        targets = load_devices_csv(f.name)

    Path(f.name).unlink()

    assert len(targets) == 1
    assert targets[0].vendor == "junos"


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
    assert target2.vendor == "junos"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
