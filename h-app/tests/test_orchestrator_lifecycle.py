import asyncio
import threading

from fakes import FakeNetconf, FaultKind, fault_of

from hssh.model import EditSettings, Fault, Result, Timeouts
from hssh.orchestrator import lifecycle
from hssh.orchestrator.lifecycle import EditLifecycle, operation


def test_a_call_that_returns_is_its_result_with_the_time_it_took():
    op = asyncio.run(operation("show x", lambda: Result("out"), 1))
    assert op.command == "show x" and op.outcome == Result("out") and op.elapsed_ms >= 0 and op.started


def test_a_fault_the_call_raises_is_the_operations_outcome():
    op = asyncio.run(operation("show x", lambda: (_ for _ in ()).throw(Fault(FaultKind.REFUSED, "no", True)), 1))
    assert fault_of(op).kind is FaultKind.REFUSED


def test_a_call_that_never_returns_is_a_timeout_after_the_budget_and_its_thread_is_left(monkeypatch):
    monkeypatch.setattr(lifecycle, "GRACE_SECONDS", 0.05)
    released = threading.Event()

    def hangs():
        released.wait(5)
        return Result("late")

    threading.Timer(0.3, released.set).start()
    op = asyncio.run(operation("show x", hangs, 0.05))
    assert fault_of(op).kind is FaultKind.TIMEOUT and fault_of(op).reached_device and "0.1s" in fault_of(op).detail


def test_without_a_timeout_the_call_is_waited_for():
    assert asyncio.run(operation("x", lambda: Result("ok"))).outcome == Result("ok")


class LineByLine(FakeNetconf):
    def __init__(self, bad_line):
        super().__init__(dialect=type("D", (type(FakeNetconf().dialect),), {"has_candidate": False})())
        self.bad_line = bad_line

    def load(self, session, lines):
        if lines == [self.bad_line]:
            raise Fault(FaultKind.REFUSED, "syntax error", True)
        return super().load(session, lines)


def test_a_line_by_line_load_stops_at_the_first_refused_line():
    comm = LineByLine(bad_line="set b 2")
    ops = asyncio.run(EditLifecycle(comm, comm.dialect, {"name": "r1"}, Timeouts(1, 1, 1, 1))
                      .run(["set a 1", "set b 2", "set c 3"], EditSettings(apply=True)))
    assert [op.command for op in ops] == ["set a 1", "set b 2"] and fault_of(ops[-1]).kind is FaultKind.REFUSED
    assert comm.loaded == {"r1": ["set a 1"]}


def test_a_candidate_load_is_one_operation_for_all_the_lines():
    comm = FakeNetconf()
    ops = asyncio.run(EditLifecycle(comm, comm.dialect, {"name": "r1"}, Timeouts(1, 1, 1, 1))
                      .run(["set a 1", "set b 2"], EditSettings(apply=False)))
    assert [op.command for op in ops] == ["load", "diff"]


def test_a_failed_diff_ends_before_the_commit():
    class BadDiff(FakeNetconf):
        def diff(self, session):
            raise Fault(FaultKind.TIMEOUT, "no reply", True)

    comm = BadDiff()
    ops = asyncio.run(EditLifecycle(comm, comm.dialect, {"name": "r1"}, Timeouts(1, 1, 1, 1))
                      .run(["set a 1"], EditSettings(apply=True)))
    assert ops[-1].command == "diff" and not any(c[0] == "commit" for c in comm.calls)


def test_a_confirmed_commit_is_sent_with_its_minutes():
    comm = FakeNetconf()
    ops = asyncio.run(EditLifecycle(comm, comm.dialect, {"name": "r1"}, Timeouts(1, 1, 1, 1))
                      .run(["set a 1"], EditSettings(apply=True, confirmed_minutes=5)))
    assert ops[-1].command == "commit" and ("commit", 5, None) in comm.calls
