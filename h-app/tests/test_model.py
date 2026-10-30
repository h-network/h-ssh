import dataclasses
import typing

import pytest

from hssh import model
from hssh.model import (CommitStatus, Credentials, EditSettings, Fault, FaultKind, OperationResult, PolicySettings,
                        RecordSettings, Result, RunReport, RunSpec, SafetySettings, Target, TargetResult, Timeouts)

R1 = Target("R1", "192.0.2.1", "junos", "netconf")
OK = OperationResult("show version", Result("Junos"), "2026-10-30T00:00:00Z", 12)
REPORT_ARGS = (1, "show", "t0", "t1", (TargetResult(R1, "ok", (OK,)),), 1, 0, 0)


@pytest.mark.parametrize("value, attr", [
    (R1, "host"),
    (Credentials("admin"), "password"),
    (Timeouts(3, 30, 20, 60), "setup"),
    (SafetySettings(300, 6), "rate_limit"),
    (RecordSettings(), "store_path"),
    (EditSettings(apply=False), "apply"),
    (PolicySettings(2, 1), "retries"),
    (RunSpec((R1,), "show"), "mode"),
    (Result("x"), "output"),
    (CommitStatus(False, None, ""), "pending"),
    (Fault(FaultKind.LOCAL, "d", False), "kind"),
    (OK, "command"),
    (TargetResult(R1, "ok"), "status"),
    (RunReport(*REPORT_ARGS), "ok"),
])
def test_every_shared_type_is_frozen(value, attr):
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(value, attr, None)


def test_a_target_defaults_to_no_port_and_compares_by_value():
    assert R1.port is None
    assert R1 == Target("R1", "192.0.2.1", "junos", "netconf") and R1 != Target("R1", "192.0.2.1", "junos", "ssh")


def test_credentials_default_to_no_password_and_no_key_so_the_agent_is_used():
    assert (Credentials("admin").password, Credentials("admin").key_file) == (None, None)


def test_timeouts_are_connect_setup_command_commit_in_that_order_with_no_defaults():
    assert dataclasses.astuple(Timeouts(3, 30, 20, 60)) == (3, 30, 20, 60)
    assert [f.name for f in dataclasses.fields(Timeouts)] == ["connect", "setup", "command", "commit"]
    with pytest.raises(TypeError):
        Timeouts(3, 20, 60)


def test_apply_has_no_default_so_an_edit_run_must_say_dry_run_or_not():
    with pytest.raises(TypeError):
        EditSettings()
    assert EditSettings(apply=False).confirmed_minutes is None and EditSettings(apply=False).comment is None


def test_policy_retries_and_pause_have_no_defaults():
    with pytest.raises(TypeError):
        PolicySettings()


def test_safety_file_and_every_record_path_are_optional():
    assert SafetySettings(300, 6).safety_file is None
    assert dataclasses.astuple(RecordSettings()) == (None, None, None, None, None)


def test_a_run_spec_needs_targets_and_mode_and_nothing_else():
    with pytest.raises(TypeError):
        RunSpec((R1,))
    spec = RunSpec((R1,), "show")
    assert (spec.commands, spec.config_lines, spec.format, spec.credentials, spec.timeouts) == ((), (), None, None, None)


def test_a_run_spec_leaves_every_orchestrator_owned_setting_unset():
    spec = RunSpec((R1,), "edit")
    unset = ("workers", "host_key_policy", "probe", "skip_unreachable", "edit", "policy", "safety", "recording")
    assert [getattr(spec, name) for name in unset] == [None] * len(unset)


def test_the_literal_types_name_exactly_the_documented_values():
    assert typing.get_args(model.Mode) == ("show", "batch", "structured", "edit", "confirm", "commit_status")
    assert typing.get_args(model.HostKeyPolicy) == ("accept-new", "strict", "off")
    assert typing.get_args(model.TargetStatus) == ("ok", "failed", "skipped")


def test_a_result_is_output_with_optional_data_and_no_elapsed():
    assert Result("x").data is None
    assert [f.name for f in dataclasses.fields(Result)] == ["output", "data"]


def test_commit_status_carries_pending_minutes_and_the_newest_entry():
    assert dataclasses.astuple(CommitStatus(True, 4, "<entry/>")) == (True, 4, "<entry/>")
    with pytest.raises(TypeError):
        CommitStatus(True)


def test_fault_kinds_are_the_ten_of_section_4_3_in_order():
    assert [k.name for k in FaultKind] == ["UNREACHABLE", "AUTH", "HOST_KEY", "TIMEOUT", "SESSION_LOST", "REFUSED",
                                           "COMMIT_FAILED", "OUTCOME_UNKNOWN", "UNSUPPORTED", "LOCAL"]


def test_a_fault_is_raised_and_caught_with_its_kind_detail_and_reached_device():
    try:
        raise Fault(FaultKind.REFUSED, "syntax error", True)
    except Fault as f:
        assert (f.kind, f.detail, f.reached_device) == (FaultKind.REFUSED, "syntax error", True)
        assert f.__traceback__ is not None


def test_a_fault_needs_reached_device_said_explicitly():
    with pytest.raises(TypeError):
        Fault(FaultKind.TIMEOUT, "no reply")


def test_faults_compare_by_value():
    assert Fault(FaultKind.AUTH, "x", True) == Fault(FaultKind.AUTH, "x", True)
    assert Fault(FaultKind.AUTH, "x", True) != Fault(FaultKind.AUTH, "x", False)


def test_an_operation_result_holds_the_command_outcome_start_and_elapsed_milliseconds():
    assert [f.name for f in dataclasses.fields(OperationResult)] == ["command", "outcome", "started", "elapsed_ms"]
    assert isinstance(OperationResult("open", Fault(FaultKind.AUTH, "x", True), "t", 5).outcome, Fault)
    with pytest.raises(TypeError):
        OperationResult("show", Result(""), "t")


def test_a_target_result_has_no_operations_until_given_some():
    assert TargetResult(R1, "skipped").operations == ()
    assert TargetResult(R1, "ok", (OK,)).operations == (OK,)


def test_a_run_report_defaults_to_not_interrupted_nothing_unkept_and_nothing_pending():
    report = RunReport(*REPORT_ARGS)
    assert (report.interrupted, report.not_kept, report.pending) == (False, 0, {})


def test_run_report_pending_maps_a_target_name_to_its_remaining_minutes():
    assert RunReport(*REPORT_ARGS, pending={"R1": 7}).pending == {"R1": 7}


def test_each_run_report_gets_its_own_pending_dict():
    first, second = RunReport(*REPORT_ARGS), RunReport(*REPORT_ARGS)
    first.pending["R1"] = 3
    assert second.pending == {}


def test_a_run_report_needs_its_counts():
    with pytest.raises(TypeError):
        RunReport(1, "show", "t0", "t1", ())
