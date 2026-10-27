"""Job file parsing tests."""
import json
import re
import pytest
from hssh.core import load_jobs, JobEntry, parse_inline_target, Target


def test_parse_inline_target_two_parts():
    t = parse_inline_target("R1:10.0.0.1")
    assert t.name == "R1"
    assert t.host == "10.0.0.1"
    assert t.vendor == "ssh"
    assert t.port is None


def test_parse_inline_target_with_vendor():
    t = parse_inline_target("SW1:10.0.0.2:openssh")
    assert t.name == "SW1"
    assert t.vendor == "openssh"


def test_parse_inline_target_with_port():
    t = parse_inline_target("SW1:10.0.0.1:5000:telnet-ios")
    assert t.name == "SW1"
    assert t.host == "10.0.0.1"
    assert t.port == 5000
    assert t.vendor == "telnet-ios"


def test_parse_inline_target_invalid():
    with pytest.raises(ValueError):
        parse_inline_target("invalid")


def test_parse_inline_target_default_vendor_fills_an_undeclared_spec():
    """The CLI passes --transport here; a spec that names no vendor gets it."""
    t = parse_inline_target("R1:10.0.0.1", default_vendor="junos")
    assert t.vendor == "junos" and t.port is None
    t = parse_inline_target("R1:10.0.0.1:5000", default_vendor="junos")
    assert t.vendor == "junos" and t.port == 5000


def test_parse_inline_target_declared_vendor_beats_the_default():
    for spec in ("R1:10.0.0.1:telnet", "R1:10.0.0.1:5000:telnet", "R1:10.0.0.1:telnet:5000"):
        assert parse_inline_target(spec, default_vendor="junos").vendor == "telnet"


def test_parse_inline_target_ipv6_in_brackets():
    """An IPv6 literal has colons of its own, so it goes in brackets."""
    assert parse_inline_target("R1:[2001:db8::1]:830:junos") == Target("R1", "2001:db8::1", "junos", 830)
    assert parse_inline_target("R1:[2001:db8::1]:junos:830") == Target("R1", "2001:db8::1", "junos", 830)
    assert parse_inline_target("R1:[2001:db8::1]:junos") == Target("R1", "2001:db8::1", "junos")
    assert parse_inline_target("R1:[::1]") == Target("R1", "::1")


def test_parse_inline_target_bare_ipv6_says_to_bracket_it():
    with pytest.raises(ValueError, match="brackets"):
        parse_inline_target("R1:2001:db8::1:junos")


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


def test_load_jobs_default_vendor_fills_undeclared_targets(tmp_path):
    job_file = tmp_path / "test.json"
    job_file.write_text(json.dumps([
        {"target": "R1:10.0.0.1", "show": "show version"},
        {"target": "SW1:10.0.0.2:openssh", "show": "show version"},
    ]))
    entries = load_jobs(str(job_file), default_vendor="junos")
    assert entries[0].target.vendor == "junos"
    assert entries[1].target.vendor == "openssh", "a declared vendor must win"


@pytest.mark.parametrize("entry, text", [
    ({"target": "R1:10.0.0.1:junos", "edit": ["set system host-name X"]}, "'edit' must be a string"),
    ({"target": {"a": 1}, "show": "show version"}, "'target' must be a string"),
    ({"target": "R1:10.0.0.1:junos", "show": "show version", "port": "eight"}, "'port' must be a number"),
    ({"target": "R1:10.0.0.1:junos:notaport", "show": "show version"}, "Job entry 0: Invalid target"),
])
def test_load_jobs_rejects_wrongly_typed_entries_with_the_entry_number(tmp_path, entry, text):
    """Wrongly typed job values ended in AttributeError/TypeError tracebacks (#39)."""
    job_file = tmp_path / "bad.json"
    job_file.write_text(json.dumps([entry]))
    with pytest.raises(ValueError, match=text):
        load_jobs(str(job_file))


def test_a_job_show_is_one_line_of_text_and_an_edit_plain_text(tmp_path):
    """#110: what -sC and -eC refuse, a job entry (a --job file, a run file's
    `jobs`) refuses too: a show with a line break runs both lines, an ESC
    typed into a device's CLI is a key. An edit keeps its line breaks."""
    job_file = tmp_path / "job.json"
    for entry, text in (({"show": "show version\nrequest system reboot"}, "'show' has a line break"),
                        ({"show": "show ver\x00sion"}, "'show' has a NUL"),
                        ({"edit": "set system host-name x\x1b"}, "'edit' has an ESC")):
        job_file.write_text(json.dumps([{"target": "R1:10.0.0.1:junos", "show": "show version"},
                                        {"target": "R2:10.0.0.2:junos", **entry}]))
        with pytest.raises(ValueError, match=re.escape(f"Job entry 1 (R2): {text} (")) as e:
            load_jobs(str(job_file))
        assert str(e.value).endswith("a command is one line of text" if "show" in entry else "a payload is plain text")
    job_file.write_text(json.dumps([{"target": "R1:10.0.0.1:junos", "edit": "set a b\nset c d"}]))
    assert load_jobs(str(job_file))[0].command == "set a b\nset c d"


def test_a_job_show_loses_its_closing_line_break(tmp_path):
    """#110 review: `"show": "show version\\n"` ran before #110 and was then
    refused for its line break; it is stripped, as a run file's commands are.
    What is left of a show of whitespace is nothing, and refused as such."""
    job_file = tmp_path / "job.json"
    job_file.write_text(json.dumps([{"target": "R1:10.0.0.1:junos", "show": " show version\n"}]))
    assert load_jobs(str(job_file))[0].command == "show version"
    job_file.write_text(json.dumps([{"target": "R1:10.0.0.1:junos", "show": " \n"}]))
    with pytest.raises(ValueError, match=re.escape("Job entry 0 (R1): 'show' is empty")):
        load_jobs(str(job_file))
