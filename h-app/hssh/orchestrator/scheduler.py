"""Scheduler: expands targets, runs them in parallel up to the worker limit, keeps result order stable, and handles cancellation (sections 3.2, 5.2, 5.4)."""

from __future__ import annotations

import asyncio
import concurrent.futures
import time
from dataclasses import dataclass, field

from hssh.communicators.base import Session
from hssh.drivers import Driver, DriverRegistry
from hssh.model import (Credentials, EditSettings, Fault, FaultKind, OperationResult, RunReport, RunSpec,
                        Target, TargetResult, TargetStatus, Timeouts)
from hssh.orchestrator import lifecycle, probe
from hssh.orchestrator.lifecycle import EditLifecycle, Stage, now, operation
from hssh.orchestrator.policy import OPEN, Action, Policy, SafetyGate, Verdict, decide, is_read
from hssh.orchestrator.recorder import AuditWriter, OutputSaver, Recorder, StoreWriter
from hssh.orchestrator.sessions import SessionManager

DEFAULT_TIMEOUTS = Timeouts(connect=10, command=30, commit=120)
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
        results = await self._gather(run)
        counts = {status: sum(r.status == status for r in results) for status in ("ok", "failed", "skipped")}
        report = RunReport(run.run_id, spec.mode, run.started, now(), results, counts["ok"], counts["failed"],
                           counts["skipped"], self._pending(spec, results))
        self.recorder.finish(report)
        return report

    async def _probe(self, spec: RunSpec) -> dict[str, Fault | None]:
        """Dead targets by name; a target the safety gate holds is not probed."""
        timeouts = spec.timeouts or DEFAULT_TIMEOUTS
        free = [t for t in spec.targets if self.policy.admit(t, login=False) is None]
        return await probe.probe(free, timeouts.connect)

    async def _bounded(self, run: _Run, index: int, target: Target, slots: asyncio.Semaphore,
                       dead: Fault | None) -> TargetResult:
        async with slots:
            run.begun.add(index)
            if dead is not None:
                return self._failed_before(run, target, dead)
            return await self._run_target(run, index, target)

    async def _gather(self, run: _Run) -> list[TargetResult]:
        """Results in target order; an interrupt while waiting ends the run as section 5.4 says."""
        try:
            return list(await asyncio.gather(*run.tasks))
        except asyncio.CancelledError:
            return await self._interrupted(run)

    async def _interrupted(self, run: _Run) -> list[TargetResult]:
        """Unstarted targets skipped, targets past COMMIT waited for, the rest cancelled; a second interrupt only reports what is in flight."""
        ...

    async def _run_target(self, run: _Run, index: int, target: Target) -> TargetResult:
        """One target: the safety gate, its driver, attempts while the policy says retry, then its rows."""
        spec = run.spec
        held = self.policy.admit(target, login=True)
        if held is not None:
            return self._failed_before(run, target, Fault(FaultKind.LOCAL, f"safety gate: {held}", False))
        try:
            driver = self.registry.resolve(target)
            self.registry.check_mode(driver, spec.mode)
        except Fault as f:
            self.policy.settle(target, None)
            return self._failed_before(run, target, f)
        attempt = 1
        while True:
            tried = await self._attempt(run, index, target, driver, attempt)
            if tried.verdict is None or tried.verdict.action is not Action.RETRY:
                break
            attempt += 1
            await self.policy.pause()
        self.policy.settle(target, tried.verdict)
        for seq, op in enumerate(tried.operations):
            self.recorder.result(run.run_id, target, driver.name, seq, op, driver.dialect.redaction_patterns)
        status: TargetStatus = "ok" if tried.verdict is None else "failed"
        return TargetResult(target, status, tuple(tried.operations))

    async def _attempt(self, run: _Run, index: int, target: Target, driver: Driver, attempt: int) -> _Attempt:
        """Open, the mode's operations in order on that session, close."""
        spec = run.spec
        creds = spec.credentials or Credentials(username="")
        timeouts = spec.timeouts or DEFAULT_TIMEOUTS
        started, t0 = now(), time.monotonic()
        try:
            session = await self.sessions.acquire(driver, target, creds, timeouts, spec.host_key_policy)
        except Fault as f:
            opened = OperationResult(OPEN, f, started, int((time.monotonic() - t0) * 1000))
            return _Attempt([opened], self._judge(spec, driver, opened, attempt))
        try:
            ops = await self._operations(run, index, target, driver, session)
        finally:
            await self.sessions.release(driver, target, creds)
        first_fault = next((op for op in ops if isinstance(op.outcome, Fault)), None)
        return _Attempt(ops, None if first_fault is None else self._judge(spec, driver, first_fault, attempt))

    async def _operations(self, run: _Run, index: int, target: Target, driver: Driver,
                          session: Session) -> list[OperationResult]:
        """The mode's operations on an open session; a batch stops at its first fault."""
        spec, comm = run.spec, driver.communicator
        if spec.mode in ("show", "batch"):
            ops: list[OperationResult] = []
            for command in spec.commands:
                ops.append(await operation(command, lambda c=command: comm.show(session, c)))
                if isinstance(ops[-1].outcome, Fault):
                    break
            return ops
        if spec.mode == "structured":
            fmt = spec.format or "xml"
            return [await operation(c, lambda c=c: comm.structured(session, c, fmt)) for c in spec.commands]
        if spec.mode == "edit":
            edit = await EditLifecycle(comm, driver.dialect, session).run(list(spec.config_lines),
                                                                           spec.edit or EditSettings())
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

    def _failed_before(self, run: _Run, target: Target, fault: Fault) -> TargetResult:
        """A target that failed before any operation: one operation named 'open', recorded without a driver."""
        op = OperationResult(OPEN, fault, now(), 0)
        self.recorder.result(run.run_id, target, "", 0, op, ())
        return TargetResult(target, "failed", (op,))

    @staticmethod
    def _pending(spec: RunSpec, results: list[TargetResult]) -> dict[str, str]:
        """Targets left with a pending commit-confirmed, and the command that confirms each."""
        edit = spec.edit
        if spec.mode != "edit" or edit is None or not edit.apply or not edit.confirmed_minutes:
            return {}
        return {r.target.name: lifecycle.confirm_command(r.target) for r in results if r.status == "ok"}


async def execute(spec: RunSpec, registry: DriverRegistry, *, gate: SafetyGate | None = None,
                  store: StoreWriter | None = None, audit: AuditWriter | None = None,
                  saver: OutputSaver | None = None, pool: bool = False) -> RunReport:
    """execute() with injected collaborators, for callers that have an event loop or want to inject."""
    sessions = SessionManager(pool=pool)
    scheduler = Scheduler(registry, Policy(spec.policy, gate), sessions, Recorder(spec.recording, store, audit, saver))
    try:
        return await scheduler.run(spec)
    finally:
        await sessions.close_all()
        if gate is not None:
            gate.close()


def run(spec: RunSpec) -> RunReport:
    """The entry point the front ends call: one RunSpec executed, its RunReport returned. Per-target failures are in the report; a local refusal before any device is contacted raises Fault(LOCAL)."""
    from hssh.drivers import Registry

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
