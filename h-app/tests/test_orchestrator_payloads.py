from fakes import T1, T2, FakeNetconf, FaultKind, fault_of, run

from hssh.model import EditSettings, RunSpec


def edit_spec(**kw):
    return RunSpec((T1, T2), "edit", probe=False, edit=EditSettings(apply=False), **kw)


def test_each_target_loads_its_own_payload():
    comm = FakeNetconf()
    run(edit_spec(payloads={"r1": ("set a 1",), "r2": ("set b 2",)}), comm)
    assert comm.loaded == {"r1": ["set a 1"], "r2": ["set b 2"]}


def test_a_target_not_named_gets_the_configuration_lines():
    comm = FakeNetconf()
    run(edit_spec(config_lines=("set shared 1",), payloads={"r1": ("set own 1",)}), comm)
    assert comm.loaded == {"r1": ["set own 1"], "r2": ["set shared 1"]}


def test_without_payloads_every_target_gets_the_configuration_lines():
    comm = FakeNetconf()
    run(edit_spec(config_lines=("set shared 1",)), comm)
    assert comm.loaded == {"r1": ["set shared 1"], "r2": ["set shared 1"]}


def test_a_target_with_no_payload_is_skipped_before_open():
    comm = FakeNetconf()
    report = run(edit_spec(payloads={"r1": ("set a 1",)}), comm)
    assert ("open", "r2") not in comm.calls
    assert (report.ok, report.failed, report.skipped) == (1, 0, 1)
    r2 = report.results[1]
    assert r2.status == "skipped"
    assert r2.operations[0].command == "open"
    assert fault_of(r2.operations[0]).kind is FaultKind.LOCAL
    assert fault_of(r2.operations[0]).detail == "no configuration for this target"


def test_the_dialect_checks_each_targets_own_lines():
    comm = FakeNetconf()
    report = run(edit_spec(payloads={"r1": ("set a 1",), "r2": ("commit",)}), comm)
    assert ("open", "r2") not in comm.calls
    assert report.results[0].status == "ok"
    r2 = report.results[1]
    assert r2.status == "failed"
    assert "commit" in fault_of(r2.operations[0]).detail


def test_line_by_line_loads_are_audited_as_load_for_the_targets_own_lines(tmp_path):
    class NoCandidate(type(FakeNetconf().dialect)):
        has_candidate = False

    import json

    from hssh.model import RecordSettings

    comm = FakeNetconf(NoCandidate())
    audit = tmp_path / "audit.jsonl"
    run(edit_spec(payloads={"r1": ("set a 1", "set a 2"), "r2": ("set b 1",)},
                  recording=RecordSettings(audit_log_path=str(audit))), comm)
    entries = [json.loads(line) for line in audit.read_text().splitlines()]
    by_target = {}
    for entry in entries:
        by_target.setdefault(entry["target"], []).append(entry["action"])
    assert by_target == {"r1": ["load", "load", "diff"], "r2": ["load", "diff"]}
