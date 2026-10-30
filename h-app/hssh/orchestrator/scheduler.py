"""Scheduler: expands targets, runs them in parallel up to the worker limit, keeps result order stable, and handles cancellation (sections 3.2, 5.2, 5.4)."""

from __future__ import annotations

import asyncio
import concurrent.futures
import signal
import sys
import dataclasses
import time
from dataclasses import dataclass, field

from hssh.communicators.base import Session
from hssh.drivers import Driver, DriverRegistry
from hssh.model import (Fault, FaultKind, OperationResult, RunReport, RunSpec, Target, TargetResult, TargetStatus)
from hssh.orchestrator import lifecycle, probe
from hssh.orchestrator.defaults import complete
from hssh.orchestrator.lifecycle import EditLifecycle, Stage, now, operation
from hssh.orchestrator.policy import OPEN, Action, Policy, SafetyGate, Verdict, decide, is_read
from hssh.orchestrator.recorder import Recorder, StoreWriter
from hssh.orchestrator.sessions import SessionManager

READ_MODES = ("show", "batch", "structured", "commit_status")


@dataclass
class _Run:
    """One run's live state: its tasks in target order, and what cancellation needs to know."""

    spec: RunSpec
    run_id: int
    started: str
    tasks: list[asyncio.Task] = field(default_factory=list)
    begun: set[int] = field(default_factory=set)
    past_commit: set[int] = field(default_factory=set)
    interrupts: int = 0
    stopping: asyncio.Event = field(default_factory=asyncio.Event)


@dataclass(frozen=True)
class _Attempt:
    """One attempt at a target: its operations, and the policy's verdict on the first fault, None when none."""

    operations: list[OperationResult]
    verdict: Verdict | None = None


class Scheduler:
    """Executes RunSpecs: one task per target, blocking communicator calls on a thread pool sized to the worker limit."""

    def __init__(self, registry: DriverRegistry, policy: Policy, sessions: SessionManager, recorder: Recorder) -> None:
        self.registry = registry
        self.policy = policy
        self.sessions = sessions
        self.recorder = recorder

    async def run(self, spec: RunSpec) -> RunReport:
        """The whole run: probe, every target under the worker limit, the report, always closed in the store."""
        loop = asyncio.get_running_loop()
        loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(spec.workers, thread_name_prefix="hssh"))
        run = _Run(spec, 0, now())
        run.run_id = self.recorder.begin(spec, run.started)
        slots = asyncio.Semaphore(spec.workers)
        dead = await self._probe(spec) if spec.probe else {}
        run.tasks = [asyncio.create_task(self._bounded(run, i, t, slots, dead.get(t.name)))
                     for i, t in enumerate(spec.targets)]
        with _on_interrupt(loop, lambda: self._interrupt(run)):
            results = await self._gather(run)
            late = await asyncio.to_thread(self.sessions.wait_for_closes)
        results = [self._with_close(run, r, late[r.target.name]) if r.target.name in late else r for r in results]
        counts = {status: sum(r.status == status for r in results) for status in ("ok", "failed", "skipped")}
        report = RunReport(run.run_id, spec.mode, run.started, now(), results, counts["ok"], counts["failed"],
                           counts["skipped"], interrupted=run.interrupts > 0, pending=self._pending(spec, results))
        self.recorder.finish(report)
        return report

    async def _probe(self, spec: RunSpec) -> dict[str, Fault | None]:
        """Dead targets by name, asked where the connection will go; a target the gate holds, whose driver is unknown, or reached through a proxy is not probed."""
        held = self.policy.held(spec.targets)
        boxes = []
        for target in spec.targets:
            if target.name in held:
                continue
            try:
                comm = self.registry.resolve(target).communicator
            except Fault:
                continue
            if comm.banner is None:
                boxes.append((target, target.host, target.port if target.port is not None else comm.default_port, None))
                continue
            where = probe.route(target.host, target.port, comm.default_port)
            if where is not None:
                boxes.append((target, where[0], where[1], comm.banner))
        return await probe.probe(boxes, spec.timeouts.connect)

    async def _bounded(self, run: _Run, index: int, target: Target, slots: asyncio.Semaphore,
                       dead: Fault | None) -> TargetResult:
        async with slots:
            run.begun.add(index)
            if dead is not None:
                return self._failed_before(run, target, dead)
            try:
                result = await self._run_target(run, index, target)
            except asyncio.CancelledError:
                result = self._failed_before(run, target, Fault(FaultKind.LOCAL, "interrupted", True))
            except Exception as e:  # noqa: BLE001 - one communicator bug is this target's failure, not the run's end
                self.policy.settle(target, None)
                result = self._failed_before(run, target, Fault(FaultKind.LOCAL, f"{type(e).__name__}: {e}", True))
            try:
                self.recorder.log(result)
            except OSError as e:
                print(f"log: {e}", file=sys.stderr)
            return result

    async def _gather(self, run: _Run) -> list[TargetResult]:
        """Results in target order; a task cancelled before it began is its target skipped (section 5.4)."""
        results = await asyncio.gather(*run.tasks, return_exceptions=True)
        return [r if isinstance(r, TargetResult) else TargetResult(t, "skipped")
                for t, r in zip(run.spec.targets, results)]

    def _interrupt(self, run: _Run) -> None:
        """The first interrupt: no new targets, in-flight ones past COMMIT waited for, the rest cancelled. Later ones only report."""
        run.interrupts += 1
        in_flight = [i for i in run.begun if not run.tasks[i].done()]
        if run.interrupts > 1:
            print(f"interrupted again: {len(in_flight)} target(s) still in flight are waited for and recorded",
                  file=sys.stderr)
            return
        run.stopping.set()
        for i, task in enumerate(run.tasks):
            if i not in run.begun or (i in in_flight and i not in run.past_commit):
                task.cancel()

    async def _run_target(self, run: _Run, index: int, target: Target) -> TargetResult:
        """One target: its driver, attempts while the policy says retry and no interrupt came, then its records."""
        spec = run.spec
        try:
            driver = self.registry.resolve(target)
            self.registry.check_mode(driver, spec.mode)
        except Fault as f:
            return self._failed_before(run, target, f)
        attempt = 1
        while True:
            tried = await self._attempt(run, index, target, driver, attempt)
            if tried.verdict is None or tried.verdict.action is not Action.RETRY or run.stopping.is_set():
                break
            attempt += 1
            await self.policy.pause()
        status: TargetStatus = "ok" if tried.verdict is None else "failed"
        ops = tried.operations
        try:
            for seq, op in enumerate(ops):
                self.recorder.result(run.run_id, target, driver.name, seq, op)
            if spec.mode == "edit":
                self.recorder.changes(run.run_id, target, driver.name, driver.dialect, ops, spec.edit, spec.config_lines)
            elif spec.mode == "confirm":
                self.recorder.changes(run.run_id, target, driver.name, driver.dialect, ops,
                                      dataclasses.replace(spec.edit, apply=True))
            self.recorder.save_output(target, ops)
        except OSError as e:
            ops.append(OperationResult("record", Fault(FaultKind.LOCAL, str(e), False), now(), 0))
            status = "failed"
        return TargetResult(target, status, tuple(ops))

    async def _attempt(self, run: _Run, index: int, target: Target, driver: Driver, attempt: int) -> _Attempt:
        """One login under the safety gate, the mode's operations in order on that session, the close started beside the work, the gate settled."""
        spec = run.spec
        creds, timeouts = spec.credentials, spec.timeouts
        started, t0 = now(), time.monotonic()
        held = self.policy.admit(target, login=not self.sessions.pooled(driver, target, creds))
        if held is not None:
            opened = OperationResult(OPEN, Fault(FaultKind.LOCAL, f"safety gate: {held}", False), started, 0)
            return _Attempt([opened], Verdict(Action.FAIL))
        try:
            session = await self.sessions.acquire(driver, target, creds, timeouts, spec.host_key_policy)
        except Fault as f:
            opened = OperationResult(OPEN, f, started, int((time.monotonic() - t0) * 1000))
            verdict = self._judge(spec, driver, opened, attempt)
            self.policy.settle(target, verdict)
            return _Attempt([opened], verdict)
        ops: list[OperationResult] = []
        try:
            ops = await self._operations(run, index, target, driver, session)
        finally:
            stale = any(isinstance(op.outcome, Fault) and op.outcome.kind in (FaultKind.TIMEOUT, FaultKind.SESSION_LOST)
                        for op in ops)
            await self.sessions.release(driver, target, creds, discard=stale)
        first_fault = next((op for op in ops if isinstance(op.outcome, Fault)), None)
        verdict = None if first_fault is None else self._judge(spec, driver, first_fault, attempt)
        self.policy.settle(target, verdict)
        return _Attempt(ops, verdict)

    async def _operations(self, run: _Run, index: int, target: Target, driver: Driver,
                          session: Session) -> list[OperationResult]:
        """The mode's operations on an open session; a batch goes on after a refused or timed-out command and ends when the session is lost."""
        spec, comm = run.spec, driver.communicator
        if spec.mode in ("show", "batch"):
            ops: list[OperationResult] = []
            for command in spec.commands:
                ops.append(await operation(command, lambda c=command: comm.show(session, c)))
                if isinstance(ops[-1].outcome, Fault) and ops[-1].outcome.kind is FaultKind.SESSION_LOST:
                    break
            return ops
        if spec.mode == "structured":
            return [await operation(c, lambda c=c: comm.structured(session, c, spec.format)) for c in spec.commands]
        if spec.mode == "edit":
            edit = await EditLifecycle(comm, driver.dialect, session).run(list(spec.config_lines), spec.edit)
            if edit.stage in (Stage.COMMIT, Stage.PENDING, Stage.CLOSE):
                run.past_commit.add(index)
            return list(edit.operations)
        if spec.mode == "confirm":
            return [await lifecycle.confirm(comm, session)]
        return [await lifecycle.commit_history(comm, session)]

    def _judge(self, spec: RunSpec, driver: Driver, op: OperationResult, attempt: int) -> Verdict:
        """The policy's verdict on a failed operation; a run reads when its mode and every command do."""
        read = spec.mode in READ_MODES and all(is_read(driver.dialect, c) for c in spec.commands)
        return decide(op.outcome, read=read, editing=spec.mode == "edit", operation=op.command, attempt=attempt,
                      settings=self.policy.settings)

    def _with_close(self, run: _Run, result: TargetResult, late: tuple[str, OperationResult]) -> TargetResult:
        """The close fault appended as the trailing operation and recorded; status untouched."""
        driver, op = late
        self.recorder.result(run.run_id, result.target, driver, len(result.operations), op)
        return dataclasses.replace(result, operations=(*result.operations, op))

    def _failed_before(self, run: _Run, target: Target, fault: Fault) -> TargetResult:
        """A target that failed before any operation: one operation named 'open', recorded without a driver."""
        op = OperationResult(OPEN, fault, now(), 0)
        self.recorder.result(run.run_id, target, "", 0, op)
        return TargetResult(target, "failed", (op,))

    @staticmethod
    def _pending(spec: RunSpec, results: list[TargetResult]) -> dict[str, str]:
        """Targets left with a pending commit-confirmed, and the command that confirms each."""
        edit = spec.edit
        if spec.mode != "edit" or edit is None or not edit.apply or not edit.confirmed_minutes:
            return {}
        return {r.target.name: lifecycle.confirm_command(r.target) for r in results if r.status == "ok"}


class _on_interrupt:
    """SIGINT handed to `handler` while the run is on; where no handler can be installed, the run is left as it was."""

    def __init__(self, loop: asyncio.AbstractEventLoop, handler) -> None:
        self.loop, self.handler, self.installed = loop, handler, False

    def __enter__(self) -> None:
        try:
            self.loop.add_signal_handler(signal.SIGINT, self.handler)
            self.installed = True
        except (NotImplementedError, RuntimeError, ValueError):
            pass

    def __exit__(self, *_exc) -> None:
        if self.installed:
            self.loop.remove_signal_handler(signal.SIGINT)


async def execute(spec: RunSpec, registry: DriverRegistry, *, gate: SafetyGate | None = None,
                  store: StoreWriter | None = None, pool: bool = False) -> RunReport:
    """execute() with injected collaborators, for callers that have an event loop or want to inject."""
    spec = complete(spec)
    if spec.mode == "structured" and not spec.format:
        raise Fault(FaultKind.LOCAL, "structured mode needs a format, json or xml; nothing was sent", False)
    sessions = SessionManager(pool=pool)
    scheduler = Scheduler(registry, Policy(spec.policy, gate), sessions, Recorder(spec.recording, store))
    try:
        return await scheduler.run(spec)
    finally:
        await sessions.close_all()
        if gate is not None:
            gate.close()


def run(spec: RunSpec) -> RunReport:
    """The entry point the front ends call: one RunSpec executed, its RunReport returned. Per-target failures are in the report; a local refusal before any device is contacted raises Fault(LOCAL)."""
    from hssh.drivers import Registry

    spec = complete(spec)
    registry = Registry()
    registry.load_entry_points()
    try:
        gate = _gate(spec)
        store = _store(spec)
    except OSError as e:
        raise Fault(FaultKind.LOCAL, str(e), False) from e
    try:
        return asyncio.run(execute(spec, registry, gate=gate, store=store))
    finally:
        if store is not None:
            store.close()


def _gate(spec: RunSpec) -> SafetyGate | None:
    if spec.safety is None:
        return None
    from hssh.safety import SafetyGate as Gate

    return Gate(spec.safety)


def _store(spec: RunSpec) -> StoreWriter | None:
    if spec.recording is None or spec.recording.store_path is None:
        return None
    from hssh.store import Store

    return Store(spec.recording.store_path)
