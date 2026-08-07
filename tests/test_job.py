"""Job file parsing tests."""
import json
import pytest
from hssh.core import load_jobs, JobEntry, parse_inline_target, Target


def test_parse_inline_target_two_parts():
    t = parse_inline_target("R1:10.0.0.1")
    assert t.name == "R1"
    assert t.host == "10.0.0.1"
    assert t.vendor == "junos"
    assert t.port is None


def test_parse_inline_target_with_vendor():
    t = parse_inline_target("SW1:10.0.0.2:arista")
    assert t.name == "SW1"
    assert t.vendor == "arista"


def test_parse_inline_target_with_port():
    t = parse_inline_target("SW1:10.0.0.1:5000:telnet-ios")
    assert t.name == "SW1"
    assert t.host == "10.0.0.1"
    assert t.port == 5000
    assert t.vendor == "telnet-ios"


def test_parse_inline_target_invalid():
    with pytest.raises(ValueError):
        parse_inline_target("invalid")


def test_load_jobs_show(tmp_path):
    job_file = tmp_path / "test.json"
    job_file.write_text(json.dumps([
        {"target": "R1:10.0.0.1:junos", "show": "show bgp summary"},
        {"target": "R2:10.0.0.2:junos", "show": "show version"},
    ]))
    entries = load_jobs(str(job_file))
    assert len(entries) == 2
    assert entries[0].target.name == "R1"
    assert entries[0].mode == "show"
    assert entries[0].command == "show bgp summary"
    assert entries[1].target.name == "R2"
    assert entries[1].command == "show version"


def test_load_jobs_edit(tmp_path):
    job_file = tmp_path / "test.json"
    job_file.write_text(json.dumps([
        {"target": "R1:10.0.0.1:junos", "edit": "set system host-name R1-new"},
    ]))
    entries = load_jobs(str(job_file))
    assert len(entries) == 1
    assert entries[0].mode == "edit-cmd"
    assert entries[0].command == "set system host-name R1-new"


def test_load_jobs_empty_array(tmp_path):
    job_file = tmp_path / "test.json"
    job_file.write_text("[]")
    with pytest.raises(ValueError, match="non-empty"):
        load_jobs(str(job_file))


def test_load_jobs_missing_target(tmp_path):
    job_file = tmp_path / "test.json"
    job_file.write_text(json.dumps([{"show": "test"}]))
    with pytest.raises(ValueError, match="missing 'target'"):
        load_jobs(str(job_file))


def test_load_jobs_missing_operation(tmp_path):
    job_file = tmp_path / "test.json"
    job_file.write_text(json.dumps([{"target": "R1:10.0.0.1"}]))
    with pytest.raises(ValueError, match="show.*edit"):
        load_jobs(str(job_file))


def test_load_jobs_both_operations(tmp_path):
    job_file = tmp_path / "test.json"
    job_file.write_text(json.dumps([{"target": "R1:10.0.0.1", "show": "x", "edit": "y"}]))
    with pytest.raises(ValueError, match="show.*edit"):
        load_jobs(str(job_file))


def test_load_jobs_port_override(tmp_path):
    job_file = tmp_path / "test.json"
    job_file.write_text(json.dumps([
        {"target": "SW1:10.0.0.1:telnet-ios", "show": "show version", "port": 5000},
    ]))
    entries = load_jobs(str(job_file))
    assert entries[0].target.port == 5000
