"""Run files: loading, validation and how they fill the arguments the command line left alone."""

import argparse

import pytest

from hssh.frontends import runfile


def load(tmp_path, text, name="run.yaml"):
    path = tmp_path / name
    path.write_text(text)
    return path, runfile.load_run_file(str(path))


def test_yaml_and_json_load_to_the_same_keys(tmp_path):
    _, from_yaml = load(tmp_path, "workers: 4\nshow: show version\n")
    _, from_json = load(tmp_path, '{"workers": 4, "show": "show version"}', "run.json")
    assert from_yaml == from_json == {"workers": 4, "show": "show version"}


def test_hyphenated_and_cased_keys_are_the_flag_names(tmp_path):
    _, data = load(tmp_path, "Session-Timeout: 5\ncommit-confirmed: 3\n")
    assert data == {"session_timeout": 5, "commit_confirmed": 3}


def test_a_bare_yes_key_is_the_yes_option(tmp_path):
    _, data = load(tmp_path, "yes: true\n")
    assert data == {"yes": True}
    _, data = load(tmp_path, "assume-yes: true\n")
    assert data == {"yes": True}


@pytest.mark.parametrize("key", ["password", "passwd", "secret", "token", "pass"])
def test_a_credential_key_is_refused(tmp_path, key):
    with pytest.raises(ValueError, match="never carries a credential"):
        load(tmp_path, f"{key}: hunter2\n")


def test_an_unknown_key_is_named(tmp_path):
    with pytest.raises(ValueError, match="unknown option 'worker'"):
        load(tmp_path, "worker: 4\n")


def test_a_key_written_two_ways_is_refused(tmp_path):
    with pytest.raises(ValueError, match="given twice"):
        load(tmp_path, "session-timeout: 5\nsession_timeout: 6\n")


def test_a_file_that_is_not_a_mapping_is_refused(tmp_path):
    with pytest.raises(ValueError, match="must be a mapping"):
        load(tmp_path, "- show version\n")


def test_a_missing_file_names_the_path(tmp_path):
    with pytest.raises(ValueError, match="cannot read run file"):
        runfile.load_run_file(str(tmp_path / "none.yaml"))


def test_values_are_type_checked_and_a_boolean_is_not_a_number(tmp_path):
    path, data = load(tmp_path, "workers: true\n")
    with pytest.raises(ValueError, match="'workers' must not be a boolean"):
        runfile.validate_run(data, str(path))
    path, data = load(tmp_path, "workers: four\n")
    with pytest.raises(ValueError, match="'workers' must be a int, not str"):
        runfile.validate_run(data, str(path))


def test_relative_paths_resolve_against_the_file(tmp_path):
    path, data = load(tmp_path, "devices: inv.csv\nbatch: cmds.txt\nedit-dir: sets\naudit-log: /var/log/a.jsonl\n")
    out = runfile.validate_run(data, str(path))
    assert out["devices"] == str(tmp_path / "inv.csv") and out["batch"] == str(tmp_path / "cmds.txt")
    assert out["edit_dir"] == str(tmp_path / "sets") and out["audit_log"] == "/var/log/a.jsonl"


def test_inline_devices_become_target_specs(tmp_path):
    path, data = load(tmp_path, "devices:\n  - R1:10.0.0.1:junos\n  - {name: R2, host: 10.0.0.2, vendor: junos, port: 830}\n")
    assert runfile.validate_run(data, str(path))["devices"] == ["R1:10.0.0.1:junos", "R2:10.0.0.2:junos:830"]


@pytest.mark.parametrize("entry, message", [
    ("  - ''", "devices\\[0\\] is empty"),
    ("  - {host: 10.0.0.1}", "needs a 'name' string"),
    ("  - {name: R1, host: 10.0.0.1, color: red}", "unknown field\\(s\\) color"),
    ("  - 42", "must be a string or a mapping"),
    ("  []", "'devices' list is empty"),
])
def test_bad_device_entries_are_named(tmp_path, entry, message):
    path, data = load(tmp_path, f"devices:\n{entry}\n")
    with pytest.raises(ValueError, match=message):
        runfile.validate_run(data, str(path))


def test_commands_must_be_a_non_empty_list_of_text(tmp_path):
    path, data = load(tmp_path, "commands: [show a, '  show b  ']\n")
    assert runfile.validate_run(data, str(path))["commands"] == ["show a", "show b"]
    path, data = load(tmp_path, "commands: []\n")
    with pytest.raises(ValueError, match="non-empty list of command strings"):
        runfile.validate_run(data, str(path))


def test_apply_run_fills_what_was_not_typed_and_reports_it():
    args = argparse.Namespace(workers=None, show_command=None, target=None, devices=None)
    applied = runfile.apply_run(args, {"workers": 4, "show": "show version", "devices": ["R1:10.0.0.1"]}, typed={"workers"})
    assert args.workers is None and args.show_command == "show version" and args.target == ["R1:10.0.0.1"]
    assert applied == ["show", "devices"]


def test_a_typed_target_or_devices_keeps_the_files_devices_out():
    for typed in ({"hosts"}, {"target"}, {"devices"}):
        args = argparse.Namespace(target=["typed"], devices="typed.csv")
        runfile.apply_run(args, {"devices": "file.csv"}, typed=typed)
        assert (args.target, args.devices) == (["typed"], "typed.csv")


def test_a_devices_path_in_the_file_is_the_inventory():
    args = argparse.Namespace(target=None, devices=None)
    runfile.apply_run(args, {"devices": "/inv/file.csv"}, typed=set())
    assert args.devices == "/inv/file.csv" and args.target is None
