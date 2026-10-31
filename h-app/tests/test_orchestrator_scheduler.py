import asyncio
import os
import signal
import threading
import time

import pytest
from fakes import T1, T2, FakeNetconf, FaultKind, fault_of, run

from hssh.model import EditSettings, Fault, PolicySettings, RunSpec, SafetySettings, Target, Timeouts
from hssh.orchestrator import policy as policy_module, scheduler as scheduler_module

T3 = Target("r3", "127.0.0.3", "junos", "netconf")


def show_spec(*targets, **kw):
    kw.setdefault("probe", False)
    return RunSpec(targets or (T1,), "show", commands=("show version",), **kw)


def edit_spec(*targets, **kw):
    kw.setdefault("probe", False)
    kw.setdefault("edit", EditSettings(apply=True))
    return RunSpec(targets or (T1,), "edit", config_lines=("set a 1",), **kw)


@pytest.fixture
def sleeps(monkeypatch):
    slept = []

    async def fake_sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr(policy_module.asyncio, "sleep", fake_sleep)
    return slept


def opens(comm):
    return [c for c in comm.calls if c[0] == "open"]


@pytest.mark.parametrize("fault, expected_opens, expected_pauses", [
    (Fault(FaultKind.UNREACHABLE, "refused", False), 1, []),
    (Fault(FaultKind.TIMEOUT, "no banner", False), 3, [0.5, 1.0]),
    (Fault(FaultKind.SESSION_LOST, "dropped during kex", True), 3, [2, 2]),
    (Fault(FaultKind.TIMEOUT, "no hello after the banner", True), 1, []),
    (Fault(FaultKind.AUTH, "denied", True), 1, []),
    (Fault(FaultKind.HOST_KEY, "changed", True), 1, []),
])
def test_the_open_classes_decide_the_retries_and_pauses(sleeps, fault, expected_opens, expected_pauses):
    comm = FakeNetconf(open_fault=fault)
    report = run(show_spec(), comm)
    assert len(opens(comm)) == expected_opens and sleeps == expected_pauses
    assert report.failed == 1 and fault_of(report.results[0].operations[0]).kind is fault.kind


def test_a_read_that_times_out_in_session_is_retried_and_an_edit_is_not(sleeps):
    class TimesOut(FakeNetconf):
        def show(self, session, command):
            self.calls.append(("show", command))
            raise Fault(FaultKind.TIMEOUT, "no reply", True)

        def load(self, session, lines):
            self.calls.append(("load", session["name"]))
            raise Fault(FaultKind.TIMEOUT, "no reply", True)

    comm = TimesOut()
    run(show_spec(), comm)
    assert len([c for c in comm.calls if c[0] == "show"]) == 3 and sleeps == [2, 2]
    comm = TimesOut()
    run(edit_spec(), comm)
    assert len([c for c in comm.calls if c[0] == "load"]) == 1


def test_a_refused_or_timed_out_command_does_not_stop_a_batch_but_a_lost_session_does():
    class Flaky(FakeNetconf):
        def show(self, session, command):
            if command == "refused":
                self.calls.append(("show", command))
                raise Fault(FaultKind.REFUSED, "syntax error", True)
            if command == "lost":
                self.calls.append(("show", command))
                raise Fault(FaultKind.SESSION_LOST, "gone", True)
            return super().show(session, command)

    comm = Flaky()
    spec = RunSpec((T1,), "batch", commands=("refused", "show a", "lost", "show b"), probe=False,
                   policy=PolicySettings(retries=0, retry_pause=0))
    report = run(spec, comm)
    assert [c[1] for c in comm.calls if c[0] == "show"] == ["refused", "show a", "lost"]
    assert [op.command for op in report.results[0].operations] == ["refused", "show a", "lost"]


class Gate:
    def __init__(self, held=()):
        self.held, self.calls = set(held), []

    def check_device(self, target, *, login=True):
        self.calls.append(("check", target.name, login))
        return (target.name not in self.held), "cooling down"

    def holds(self, targets):
        return {t.name: "cooling down" for t in targets if t.name in self.held}

    def release_device(self, target):
        self.calls.append(("release", target.name))

    def set_cooldown(self, target):
        self.calls.append(("cooldown", target.name))

    def close(self):
        self.calls.append(("close",))


def test_a_device_the_gate_holds_is_not_opened():
    comm, gate = FakeNetconf(), Gate(held={"r1"})
    report = run(show_spec(T1, T2), comm, gate=gate)
    assert opens(comm) == [("open", "r2")]
    assert report.results[0].status == "skipped" and "safety gate" in fault_of(report.results[0].operations[0]).detail
    assert ("close",) in gate.calls


def test_cooldown_only_for_what_the_device_did():
    comm = FakeNetconf(commit_fault=Fault(FaultKind.COMMIT_FAILED, "rejected", True))
    gate = Gate()
    run(edit_spec(), comm, gate=gate)
    assert ("cooldown", "r1") in gate.calls
    comm = FakeNetconf(open_fault=Fault(FaultKind.LOCAL, "no descriptor", False))
    gate = Gate()
    run(edit_spec(), comm, gate=gate)
    assert ("release", "r1") in gate.calls and ("cooldown", "r1") not in gate.calls


def test_a_failing_read_never_cools_the_device():
    comm = FakeNetconf(open_fault=Fault(FaultKind.AUTH, "denied", True))
    gate = Gate()
    run(show_spec(), comm, gate=gate)
    assert ("cooldown", "r1") not in gate.calls


def test_the_login_plan_refuses_an_over_budget_run_before_the_gate_is_asked():
    class Untouchable(Gate):
        def check_device(self, target, *, login=True):
            raise AssertionError("the gate was asked")

    comm = FakeNetconf()
    spec = show_spec(policy=PolicySettings(retries=6, retry_pause=0), safety=SafetySettings(300, 6))
    with pytest.raises(Fault) as info:
        run(spec, comm, gate=Untouchable())
    assert info.value.kind is FaultKind.LOCAL and "rate limit" in info.value.detail and comm.calls == []


def test_the_entry_point_plans_the_logins_before_it_builds_the_gate(monkeypatch):
    def no_gate(spec):
        raise AssertionError("the gate was built")

    monkeypatch.setattr(scheduler_module, "_gate", no_gate)
    spec = show_spec(policy=PolicySettings(retries=6, retry_pause=0), safety=SafetySettings(300, 6))
    with pytest.raises(Fault) as info:
        scheduler_module.run(spec)
    assert "rate limit" in info.value.detail


def test_the_login_plan_counts_the_same_device_listed_twice_by_its_effective_port():
    twice = (T1, Target("r1-again", "127.0.0.1", "junos", "netconf", port=830))
    spec = RunSpec(twice, "show", commands=("show version",), probe=False,
                   policy=PolicySettings(retries=2, retry_pause=0), safety=SafetySettings(300, 5))
    with pytest.raises(Fault):
        run(spec, FakeNetconf(), gate=Gate())
    assert run(show_spec(T1, T2, policy=PolicySettings(retries=2, retry_pause=0), safety=SafetySettings(300, 5)),
               FakeNetconf(), gate=Gate()).ok == 2


def test_a_hung_communicator_call_ends_as_a_timeout_on_a_daemon_thread(monkeypatch):
    monkeypatch.setattr("hssh.orchestrator.lifecycle.GRACE_SECONDS", 0.05)
    released, threads = threading.Event(), []

    class Hangs(FakeNetconf):
        def show(self, session, command):
            threads.append(threading.current_thread().daemon)
            released.wait(5)
            return super().show(session, command)

    comm = Hangs()
    t0 = time.monotonic()
    report = run(show_spec(timeouts=Timeouts(1, 1, 0.05, 1), policy=PolicySettings(retries=0, retry_pause=0)), comm)
    released.set()
    assert time.monotonic() - t0 < 2
    fault = fault_of(report.results[0].operations[0])
    assert fault.kind is FaultKind.TIMEOUT and "has not returned" in fault.detail and threads == [True]


def test_an_open_that_never_returns_ends_within_its_budget(monkeypatch):
    monkeypatch.setattr("hssh.orchestrator.scheduler.GRACE_SECONDS", 0.05)
    released = threading.Event()

    class Hangs(FakeNetconf):
        def open(self, *args):
            released.wait(5)
            return super().open(*args)

    comm = Hangs()
    report = run(show_spec(timeouts=Timeouts(0.05, 0.05, 1, 1), policy=PolicySettings(retries=2, retry_pause=0)), comm)
    released.set()
    fault = fault_of(report.results[0].operations[0])
    assert fault.kind is FaultKind.TIMEOUT and fault.reached_device and report.failed == 1


def test_a_worker_that_raises_is_that_targets_failure_and_the_run_goes_on():
    class Buggy(FakeNetconf):
        def show(self, session, command):
            if session["name"] == "r1":
                raise RuntimeError("bug")
            return super().show(session, command)

    report = run(show_spec(T1, T2), Buggy())
    assert (report.failed, report.ok) == (1, 1)
    assert "RuntimeError" in fault_of(report.results[0].operations[0]).detail


def test_an_unknown_driver_or_unsupported_mode_fails_before_open():
    comm = FakeNetconf()
    report = run(RunSpec((Target("x", "h", "nosuch", "netconf"),), "show", commands=("show v",), probe=False), comm)
    assert comm.calls == [] and report.failed == 1
    comm.capabilities = frozenset({"show"})
    report = run(edit_spec(), comm)
    assert comm.calls == [] and fault_of(report.results[0].operations[0]).kind is FaultKind.UNSUPPORTED


def test_structured_mode_needs_a_format():
    with pytest.raises(Fault) as info:
        run(RunSpec((T1,), "structured", commands=("get-x",), probe=False), FakeNetconf())
    assert "format" in info.value.detail


def interrupt_self():
    os.kill(os.getpid(), signal.SIGINT)


def test_a_connect_cut_by_the_interrupt_is_skipped_not_failed():
    class Slow(FakeNetconf):
        def open(self, target, *args):
            self.calls.append(("open", target.name))
            interrupt_self()
            time.sleep(0.2)
            raise Fault(FaultKind.TIMEOUT, "no banner", False)

    report = run(show_spec(T1, T2, T3, workers=1), Slow())
    assert report.interrupted
    assert [r.status for r in report.results] == ["skipped", "skipped", "skipped"]
    assert len(opens(Slow())) == 0 and report.skipped == 3


@pytest.fixture
def interrupt_during_the_pause(monkeypatch):
    real_sleep = asyncio.sleep

    async def interrupting_sleep(seconds):
        interrupt_self()
        await real_sleep(0.2)

    monkeypatch.setattr(policy_module.asyncio, "sleep", interrupting_sleep)


def test_a_stop_during_the_pause_starts_no_new_attempt_and_keeps_the_attempts_own_fault(interrupt_during_the_pause):
    comm = FakeNetconf(open_fault=Fault(FaultKind.SESSION_LOST, "dropped during kex", True))
    report = run(show_spec(T1, workers=1), comm)
    assert report.interrupted and len(opens(comm)) == 1
    assert report.results[0].status == "failed"
    assert fault_of(report.results[0].operations[0]).kind is FaultKind.SESSION_LOST


def test_a_stop_during_the_pause_after_an_unanswered_connect_is_skipped(interrupt_during_the_pause):
    comm = FakeNetconf(open_fault=Fault(FaultKind.TIMEOUT, "no banner", False))
    report = run(show_spec(T1, workers=1), comm)
    assert len(opens(comm)) == 1 and report.results[0].status == "skipped"
    assert fault_of(report.results[0].operations[0]).kind is FaultKind.TIMEOUT


class InterruptsIn(FakeNetconf):
    """Sends the interrupt from inside the named operation, which then takes a moment."""

    def __init__(self, during, **kw):
        super().__init__(**kw)
        self.during = during

    def _hit(self, name, then):
        if name == self.during:
            interrupt_self()
            time.sleep(0.2)
        return then()

    def show(self, session, command):
        return self._hit("show", lambda: super(InterruptsIn, self).show(session, command))

    def load(self, session, lines):
        return self._hit("load", lambda: super(InterruptsIn, self).load(session, lines))

    def diff(self, session):
        return self._hit("diff", lambda: super(InterruptsIn, self).diff(session))


def test_a_target_cancelled_during_a_read_is_skipped_with_the_step_named():
    comm = InterruptsIn("show")
    report = run(show_spec(T1, T2, workers=1), comm)
    first = report.results[0]
    assert first.status == "skipped" and first.operations[0].command == "show version"
    fault = fault_of(first.operations[0])
    assert fault.detail == "interrupted during show version" and fault.reached_device
    assert report.results[1].status == "skipped" and report.interrupted and report.ok == 0


@pytest.mark.parametrize("during", ["load", "diff"])
def test_an_edit_cancelled_before_commit_is_skipped_at_its_step_and_its_session_discarded(during):
    comm, gate = InterruptsIn(during), Gate()
    report = run(edit_spec(T1, workers=1), comm, gate=gate)
    result = report.results[0]
    assert result.status == "skipped" and result.operations[0].command == during
    assert fault_of(result.operations[0]).detail == f"interrupted during {during}"
    assert not commits(comm) and ("discard", "r1") in comm.calls
    assert ("release", "r1") in gate.calls and ("cooldown", "r1") not in gate.calls


def commits(comm):
    return [c for c in comm.calls if c[0] == "commit"]


def test_a_target_past_commit_is_waited_for_when_interrupted():
    class Commits(FakeNetconf):
        def commit(self, session, minutes, comment, synchronize=False):
            interrupt_self()
            time.sleep(0.2)
            return super().commit(session, minutes, comment, synchronize)

    report = run(edit_spec(T1, T2, workers=1), Commits())
    assert report.interrupted
    assert report.results[0].status == "ok" and report.results[1].status == "skipped"


def dead_probe(dead_names):
    async def fake_probe(boxes, seconds, limit=100):
        return {t.name: (Fault(FaultKind.UNREACHABLE, "no TCP answer", False) if t.name in dead_names else None)
                for t, *_ in boxes}
    return fake_probe


def test_an_edit_stops_at_a_dead_box_before_any_device(monkeypatch):
    monkeypatch.setattr("hssh.orchestrator.probe.probe", dead_probe({"r2"}))
    monkeypatch.setattr("hssh.orchestrator.probe.route", lambda host, port, default: (host, port or default))
    comm = FakeNetconf()
    with pytest.raises(Fault) as info:
        run(edit_spec(T1, T2, probe=True), comm)
    assert comm.calls == [] and "r2" in info.value.detail and "skip_unreachable" in info.value.detail


def test_an_edit_goes_on_without_the_dead_box_only_when_told(monkeypatch):
    monkeypatch.setattr("hssh.orchestrator.probe.probe", dead_probe({"r2"}))
    monkeypatch.setattr("hssh.orchestrator.probe.route", lambda host, port, default: (host, port or default))
    comm = FakeNetconf()
    report = run(edit_spec(T1, T2, probe=True, skip_unreachable=True), comm)
    assert opens(comm) == [("open", "r1")]
    assert [r.status for r in report.results] == ["ok", "skipped"]


def test_a_dead_box_fails_a_read_and_the_others_run(monkeypatch):
    monkeypatch.setattr("hssh.orchestrator.probe.probe", dead_probe({"r1"}))
    monkeypatch.setattr("hssh.orchestrator.probe.route", lambda host, port, default: (host, port or default))
    comm = FakeNetconf()
    report = run(show_spec(T1, T2, probe=True), comm)
    assert opens(comm) == [("open", "r2")]
    assert [r.status for r in report.results] == ["failed", "ok"]
    assert fault_of(report.results[0].operations[0]).kind is FaultKind.UNREACHABLE


def test_a_box_the_gate_holds_is_not_probed(monkeypatch):
    probed = []

    async def fake_probe(boxes, seconds, limit=100):
        probed.extend(t.name for t, *_ in boxes)
        return {t.name: None for t, *_ in boxes}

    monkeypatch.setattr("hssh.orchestrator.probe.probe", fake_probe)
    monkeypatch.setattr("hssh.orchestrator.probe.route", lambda host, port, default: (host, port or default))
    run(show_spec(T1, T2, probe=True), FakeNetconf(), gate=Gate(held={"r1"}))
    assert probed == ["r2"]


def test_a_close_fault_is_a_trailing_warning_not_the_targets_failure():
    class BadClose(FakeNetconf):
        def close(self, session):
            raise Fault(FaultKind.SESSION_LOST, "closed on us", True)

    report = run(show_spec(), BadClose())
    result = report.results[0]
    assert result.status == "ok" and report.ok == 1
    assert result.operations[-1].command == "close" and fault_of(result.operations[-1]).kind is FaultKind.SESSION_LOST


def test_the_run_is_recorded_from_begin_to_finish_with_a_row_per_operation():
    class Store:
        def __init__(self):
            self.rows, self.finished = [], None

        def start_run(self, spec, started, *, user):
            return 7

        def add(self, run_id, target, driver, seq, op, *, status):
            self.rows.append((run_id, target.name, driver, seq, op.command, status))

        def finish_run(self, report):
            self.finished = report

        def close(self):
            pass

    store = Store()
    spec = RunSpec((T1,), "batch", commands=("show a", "show b"), probe=False)
    report = run(spec, FakeNetconf(), store=store)
    assert store.rows == [(7, "r1", "junos@netconf", 0, "show a", "ok"), (7, "r1", "junos@netconf", 1, "show b", "ok")]
    assert store.finished is report and report.run_id == 7
