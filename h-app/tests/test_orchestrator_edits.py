from fakes import T1, FakeNetconf, FaultKind, fault_of, run

import pytest

from hssh.model import EditSettings, Fault, RunSpec
from hssh.orchestrator import check_comment, check_confirmed_minutes


def spec(mode="edit", lines=("set a 1",), **kw):
    edit = kw.pop("edit", EditSettings(apply=True))
    return RunSpec((T1,), mode, probe=False, config_lines=lines, edit=edit, **kw)


def commits(comm):
    return [c for c in comm.calls if c[0] == "commit"]


def test_a_dry_run_loads_and_diffs_but_never_commits():
    comm = FakeNetconf()
    report = run(spec(edit=EditSettings(apply=False, confirmed_minutes=5)), comm)
    assert [c[0] for c in comm.calls] == ["open", "load", "diff", "close"]
    assert report.ok == 1 and report.pending == {}


def test_an_empty_diff_sends_no_commit():
    comm = FakeNetconf(changed=False)
    report = run(spec(edit=EditSettings(apply=True, confirmed_minutes=5)), comm)
    assert commits(comm) == []
    assert report.ok == 1 and report.pending == {}


def test_an_apply_commits_with_the_comment_and_lists_the_minutes_armed():
    comm = FakeNetconf()
    report = run(spec(edit=EditSettings(apply=True, confirmed_minutes=5, comment="ticket 42 (Bob's)")), comm)
    assert commits(comm) == [("commit", 5, "ticket 42 (Bob's)")]
    assert report.pending == {"r1": 5}


def test_an_unknown_commit_outcome_fails_once_and_is_not_retried():
    comm = FakeNetconf(commit_fault=Fault(FaultKind.OUTCOME_UNKNOWN, "no reply", True))
    report = run(spec(policy=None), comm, pool=True)
    assert len(commits(comm)) == 1
    assert [c for c in comm.calls if c[0] == "open"] == [("open", "r1")]
    assert report.failed == 1
    assert fault_of(report.results[0].operations[-1]).kind is FaultKind.OUTCOME_UNKNOWN


def test_confirm_reads_the_history_and_refuses_when_nothing_is_pending():
    comm = FakeNetconf(pending=False)
    report = run(spec("confirm", lines=()), comm)
    assert ("history", "r1") in comm.calls and ("confirm", "r1") not in comm.calls
    refused = fault_of(report.results[0].operations[1])
    assert refused.kind is FaultKind.REFUSED and refused.reached_device
    assert report.failed == 1


def test_confirm_sends_the_confirm_when_a_commit_is_pending():
    comm = FakeNetconf(pending=True)
    report = run(spec("confirm", lines=()), comm)
    assert [c[0] for c in comm.calls] == ["open", "history", "confirm", "close"]
    assert report.ok == 1


def test_a_refused_payload_fails_the_target_before_open():
    comm = FakeNetconf()
    report = run(spec(lines=("set a\tb",)), comm)
    assert comm.calls == []
    first = report.results[0].operations[0]
    assert first.command == "open" and fault_of(first).kind is FaultKind.LOCAL and "line 1" in fault_of(first).detail


@pytest.mark.parametrize("minutes", [0, 65536, True])
def test_commit_confirmed_minutes_outside_1_to_65535_are_refused(minutes):
    assert check_confirmed_minutes(minutes)


def test_commit_confirmed_minutes_in_range_pass():
    assert check_confirmed_minutes(1) is None and check_confirmed_minutes(65535) is None


@pytest.mark.parametrize("comment", ["", "two\nlines", "tab\there", "x" * 513])
def test_a_comment_that_is_empty_multi_line_control_or_too_long_is_refused(comment):
    assert check_comment(comment)


def test_a_comment_with_quotes_or_non_ascii_passes():
    assert check_comment("ticket 42 (Bob's) \"quoted\" \\ é") is None


def test_an_edit_spec_failing_the_checks_is_refused_before_anything_is_sent():
    comm = FakeNetconf()
    with pytest.raises(Fault) as info:
        run(spec(edit=EditSettings(apply=True, confirmed_minutes=0)), comm)
    assert info.value.kind is FaultKind.LOCAL and comm.calls == []


def test_a_failed_record_write_is_counted_and_never_the_targets_failure():
    class FailingStore:
        def start_run(self, spec, started, *, user):
            return 1

        def add(self, *args, **kw):
            raise OSError("disk full")

        def finish_run(self, report):
            pass

        def close(self):
            pass

    comm = FakeNetconf()
    report = run(spec("show", lines=(), commands=("show version",), edit=None), comm, store=FailingStore())
    assert (report.ok, report.failed, report.not_kept) == (1, 0, 1)
