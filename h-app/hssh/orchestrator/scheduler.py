"""Scheduler: expands targets, runs them in parallel up to the worker limit, keeps result order stable, and handles cancellation (sections 3.2, 5.2, 5.4)."""

from __future__ import annotations

import asyncio
import collections
import concurrent.futures
import threading
import signal
import sys
import dataclasses
import time
from dataclasses import dataclass, field

from hssh.communicators.base import Session
from hssh.drivers import Driver, DriverRegistry
from hssh.model import (Fault, FaultKind, OperationResult, Result, RunReport, RunSpec, Target, TargetResult, TargetStatus)
from hssh.orchestrator import lifecycle, probe
from hssh.orchestrator.defaults import GRACE_SECONDS, check_edit, complete, fit_workers
from hssh.orchestrator.lifecycle import EditLifecycle, now, operation
from hssh.orchestrator.policy import OPEN, Action, Policy, SafetyGate, Verdict, decide, is_read
from hssh.orchestrator.recorder import Recorder, StoreWriter
from hssh.orchestrator.sessions import LoginRefused, SessionManager, session_key

READ_MODES = ("show", "batch", "structured", "commit_status")
DISCARDING = (FaultKind.TIMEOUT, FaultKind.SESSION_LOST, FaultKind.OUTCOME_UNKNOWN)


@dataclass
class _Run:
    """One run's live state: its tasks in target order, and what cancellation needs to know."""

    spec: RunSpec
    run_id: int
    started: str
    tasks: list[asyncio.Task] = field(default_factory=list)
    begun: set[int] = field(default_factory=set)
    steps: dict[int, str] = field(default_factory=dict)
    past_commit: set[int] = field(default_factory=set)
    interrupts: int = 0
    probing: asyncio.Task | None = None
    stopping: asyncio.Event = field(default_factory=asyncio.Event)


@dataclass
class _Borrow:
    """The session an attempt holds now (None between a discard and a fresh open), and whether it is in doubt."""

    session: Session | None
    doubtful: bool = False
    fresh_at: int = 0


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
        """The whole run: the record destinations proved, the probe, the run row, every target under the worker limit, the report, the run row closed. A refusal before the first device is Fault(LOCAL)."""
        loop = asyncio.get_running_loop()
        workers = fit_workers(spec.workers)
        self.sessions.workers = workers
        loop.set_default_executor(_DaemonThreads(workers, thread_name_prefix="hssh"))
        run = _Run(spec, 0, now())
        slots = asyncio.Semaphore(workers)
        with _on_interrupt(loop, lambda: self._interrupt(run)):
            try:
                self.recorder.preflight()
                held = self.policy.held([self._device(t) for t in spec.targets])
                dead = await self._probed(run, held) if spec.probe else {}
                if run.stopping.is_set() and spec.mode == "edit":
                    raise Fault(FaultKind.LOCAL, "interrupted during the probe; nothing was sent", False)
                if spec.mode == "edit" and any(dead.values()):
                    self._dead_edit(spec, dead)
                run.run_id = self.recorder.begin(spec, run.started)
            except OSError as e:
                raise Fault(FaultKind.LOCAL, f"{e}; nothing was sent", False) from e
            if run.stopping.is_set():
                stopped = Fault(FaultKind.LOCAL, "interrupted during the probe", False)
                results = [self._failed_before(run, t, stopped, "skipped") for t in spec.targets]
            else:
                run.tasks = [asyncio.create_task(self._bounded(run, i, t, slots, dead.get(t.name), held.get(t.name)))
                             for i, t in enumerate(spec.targets)]
                results = await self._gather(run)
            late = await asyncio.to_thread(self.sessions.wait_for_closes)
        results = [self._with_close(run, r, late[r.target.name]) if r.target.name in late else r for r in results]
        counts = {status: sum(r.status == status for r in results) for status in ("ok", "failed", "skipped")}
        report = RunReport(run.run_id, spec.mode, run.started, now(), results, counts["ok"], counts["failed"],
                           counts["skipped"], interrupted=run.interrupts > 0, not_kept=self.recorder.not_kept,
                           pending=self._pending(spec, results))
        self.recorder.finish(report)
        self.recorder.close()
        if self.recorder.not_kept != report.not_kept:
            report = dataclasses.replace(report, not_kept=self.recorder.not_kept)
        return report

    async def _probed(self, run: _Run, held: dict[str, str]) -> dict[str, Fault | None]:
        """The probe as a task the first interrupt can cancel; cancelled, it found nothing dead."""
        run.probing = asyncio.create_task(self._probe(run.spec, held))
        try:
            return await run.probing
        except asyncio.CancelledError:
            return {}
        finally:
            run.probing = None

    async def _probe(self, spec: RunSpec, held: dict[str, str]) -> dict[str, Fault | None]:
        """Dead targets by name, asked where the connection will go; a target the gate holds, whose driver is unknown, or reached through a proxy is not probed."""
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
                       dead: Fault | None, held: str | None) -> TargetResult:
        async with slots:
            run.begun.add(index)
            if held is not None:
                return self._failed_before(run, target, Fault(FaultKind.LOCAL, f"safety gate: {held}", False), "skipped")
            if dead is not None:
                skipped = run.spec.mode == "edit" and run.spec.skip_unreachable
                return self._failed_before(run, target, dead, "skipped" if skipped else "failed")
            try:
                result = await self._run_target(run, index, target)
            except asyncio.CancelledError:
                step = run.steps.get(index, OPEN)
                fault = Fault(FaultKind.LOCAL, f"interrupted during {step}", step != OPEN)
                result = self._failed_before(run, target, fault, "skipped", step)
            except Exception as e:  # noqa: BLE001 - one communicator bug is this target's failure, not the run's end
                self.policy.settle(self._device(target), None)
                result = self._failed_before(run, target, Fault(FaultKind.LOCAL, f"{type(e).__name__}: {e}", True))
            self.recorder.log(result)
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
        if run.probing is not None:
            run.probing.cancel()
        for i, task in enumerate(run.tasks):
            if i not in run.begun or (i in in_flight and i not in run.past_commit):
                task.cancel()

    async def _run_target(self, run: _Run, index: int, target: Target) -> TargetResult:
        """One target: its driver, the dialect's check of an edit payload, attempts while the policy says retry and no interrupt came, then its records. An interrupt during the pause makes the attempt before it the last."""
        spec = run.spec
        try:
            driver = self.registry.resolve(target)
            self.registry.check_mode(driver, spec.mode)
        except Fault as f:
            return self._failed_before(run, target, f)
        lines = self._lines_for(spec, target)
        if spec.mode == "edit":
            if lines is None:
                return self._failed_before(run, target, Fault(FaultKind.LOCAL, "no configuration for this target", False),
                                           "skipped")
            if why := driver.dialect.check_edit(list(lines)):
                return self._failed_before(run, target, Fault(FaultKind.LOCAL, why, False))
        attempt = 1
        while True:
            tried = await self._attempt(run, index, target, driver, attempt)
            if tried.verdict is None or tried.verdict.action is not Action.RETRY or run.stopping.is_set():
                break
            last = tried.operations[-1]
            unanswered = last.command == OPEN and last.outcome.kind is FaultKind.TIMEOUT and not last.outcome.reached_device
            try:
                await self.policy.pause(attempt, unanswered)
            except asyncio.CancelledError:
                break
            attempt += 1
        status: TargetStatus = "ok" if tried.verdict is None else "skipped" if tried.verdict.action is Action.SKIP else "failed"
        ops = tried.operations
        if run.stopping.is_set() and self._interrupted_connect(ops):
            status = "skipped"
        for seq, op in enumerate(ops):
            self.recorder.result(run.run_id, target, driver.name, seq, op, status)
        if spec.mode == "edit":
            self.recorder.changes(run.run_id, target, driver.name, driver.dialect, ops, spec.edit, lines or ())
        elif spec.mode == "confirm":
            self.recorder.changes(run.run_id, target, driver.name, driver.dialect, ops,
                                  dataclasses.replace(spec.edit, apply=True))
        self.recorder.save_output(target, ops)
        return TargetResult(target, status, tuple(ops))

    async def _attempt(self, run: _Run, index: int, target: Target, driver: Driver, attempt: int) -> _Attempt:
        """One login under the safety gate, the mode's operations in order on that session, the close started beside the work, the gate settled."""
        spec = run.spec
        creds, timeouts = spec.credentials, spec.timeouts
        started, t0 = now(), time.monotonic()
        device = self._device(target, driver)
        try:
            held = self.policy.admit(device, login=not self.sessions.pooled(driver, target, creds, spec.host_key_policy))
        except OSError as e:
            opened = OperationResult(OPEN, Fault(FaultKind.LOCAL, f"safety gate unusable: {e}", False), started, 0)
            return _Attempt([opened], Verdict(Action.FAIL))
        if held is not None:
            opened = OperationResult(OPEN, Fault(FaultKind.LOCAL, f"safety gate: {held}", False), started, 0)
            return _Attempt([opened], Verdict(Action.SKIP))
        run.steps[index] = OPEN
        try:
            session = await asyncio.wait_for(
                self.sessions.acquire(driver, target, creds, timeouts, spec.host_key_policy, lambda: self.policy.login(device)),
                timeouts.connect + timeouts.setup + GRACE_SECONDS)
        except LoginRefused as e:
            opened = OperationResult(OPEN, Fault(FaultKind.LOCAL, f"safety gate: {e}", False), started, 0)
            self.policy.settle(device, None)
            return _Attempt([opened], Verdict(Action.SKIP))
        except (Fault, asyncio.TimeoutError, asyncio.CancelledError) as e:
            if isinstance(e, Fault):
                f = e
            elif isinstance(e, asyncio.TimeoutError):
                f = Fault(FaultKind.TIMEOUT, "open has not returned within its budget", True)
            else:
                f = Fault(FaultKind.LOCAL, "interrupted while connecting", False)
            opened = OperationResult(OPEN, f, started, int((time.monotonic() - t0) * 1000))
            verdict = self._judge(spec, driver, opened, attempt)
            self.policy.settle(device, verdict)
            return _Attempt([opened], verdict)
        ops: list[OperationResult] = []
        borrow = _Borrow(session)
        try:
            ops = await self._operations(run, index, target, driver, borrow)
        except asyncio.CancelledError:
            borrow.doubtful = True
            self.policy.settle(device, None)
            raise
        finally:
            stale = borrow.doubtful or any(isinstance(op.outcome, Fault) and op.outcome.kind in DISCARDING
                                           for op in ops[borrow.fresh_at:])
            await self.sessions.release(driver, target, creds, discard=stale, timeouts=timeouts,
                                        host_key_policy=spec.host_key_policy)
        first_fault = next((op for op in ops if isinstance(op.outcome, Fault)), None)
        verdict = None if first_fault is None else self._judge(spec, driver, first_fault, attempt)
        self.policy.settle(device, verdict)
        return _Attempt(ops, verdict)

    def _device(self, target: Target, driver: Driver | None = None) -> Target:
        """The target as the safety gate keys it: with the port the connection uses, the transport's default when none is given."""
        if target.port is not None:
            return target
        try:
            driver = driver or self.registry.resolve(target)
        except Fault:
            return target
        return dataclasses.replace(target, port=driver.communicator.default_port)

    async def _operations(self, run: _Run, index: int, target: Target, driver: Driver,
                          borrow: _Borrow) -> list[OperationResult]:
        """The mode's operations on the borrowed session, each named in run.steps as it starts. A batch goes on after a refused command on the same session, after a timed-out command on a fresh one, and ends when the session is lost."""
        spec, comm, session = run.spec, driver.communicator, borrow.session

        def step(name: str) -> None:
            run.steps[index] = name

        if spec.mode in ("show", "batch"):
            ops: list[OperationResult] = []
            for command in spec.commands:
                step(command)
                ops.append(await operation(command, lambda c=command: comm.show(session, c), spec.timeouts.command))
                if not isinstance(ops[-1].outcome, Fault):
                    continue
                if ops[-1].outcome.kind is FaultKind.SESSION_LOST:
                    break
                if ops[-1].outcome.kind is FaultKind.TIMEOUT and command != spec.commands[-1]:
                    try:
                        session = await self._fresh(run, index, target, driver, borrow)
                    except Fault as f:
                        ops.append(OperationResult(OPEN, f, now(), 0))
                        break
                    borrow.fresh_at = len(ops)
            return ops
        if spec.mode == "structured":
            ops = []
            for command in spec.commands:
                step(command)
                ops.append(await operation(command, lambda c=command: comm.structured(session, c, spec.format),
                                           spec.timeouts.command))
            return ops
        if spec.mode == "edit":
            def before_commit() -> None:
                step("commit")
                run.past_commit.add(index)

            edit = await EditLifecycle(comm, driver.dialect, session, spec.timeouts).run(
                list(self._lines_for(spec, target) or ()), spec.edit, before_commit=before_commit, on_step=step)
            return list(edit.operations)
        step(spec.mode)
        if spec.mode == "confirm":
            return await lifecycle.confirm(comm, session, spec.timeouts)
        return [await lifecycle.commit_history(comm, session, spec.timeouts)]

    async def _fresh(self, run: _Run, index: int, target: Target, driver: Driver, borrow: _Borrow) -> Session:
        """A timed-out session ends there: torn down, and the rest of the batch gets a new one within the open budget."""
        spec = run.spec
        await self.sessions.release(driver, target, spec.credentials, discard=True, timeouts=spec.timeouts,
                                    host_key_policy=spec.host_key_policy)
        borrow.session = None
        run.steps[index] = OPEN
        if (reason := self.policy.login(self._device(target, driver))) is not None:
            raise Fault(FaultKind.LOCAL, f"safety gate: {reason}", False)
        try:
            borrow.session = await asyncio.wait_for(
                self.sessions.acquire(driver, target, spec.credentials, spec.timeouts, spec.host_key_policy),
                spec.timeouts.connect + spec.timeouts.setup + GRACE_SECONDS)
        except asyncio.TimeoutError as e:
            raise Fault(FaultKind.TIMEOUT, "open has not returned within its budget", True) from e
        return borrow.session

    @staticmethod
    def _lines_for(spec: RunSpec, target: Target) -> tuple[str, ...] | None:
        """The target's own payload, else the configuration lines; None when payloads are given and it has neither."""
        return spec.payloads.get(target.name) or spec.config_lines or (None if spec.payloads else ())

    @staticmethod
    def _interrupted_connect(ops: list[OperationResult]) -> bool:
        """A connect the interrupt cut short, or an unanswered one the interrupt kept from its retry: the only operation is an open fault that reached nothing (never message text)."""
        return len(ops) == 1 and ops[0].command == OPEN and isinstance(ops[0].outcome, Fault) and not ops[0].outcome.reached_device

    def _judge(self, spec: RunSpec, driver: Driver, op: OperationResult, attempt: int) -> Verdict:
        """The policy's verdict on a failed operation; a run reads when its mode and every command do."""
        read = spec.mode in READ_MODES and all(is_read(driver.dialect, c) for c in spec.commands)
        return decide(op.outcome, read=read, editing=spec.mode == "edit", operation=op.command, attempt=attempt,
                      settings=self.policy.settings)

    def _with_close(self, run: _Run, result: TargetResult, late: tuple[str, OperationResult]) -> TargetResult:
        """The close fault appended as the trailing operation and recorded; status untouched."""
        driver, op = late
        self.recorder.result(run.run_id, result.target, driver, len(result.operations), op, result.status)
        return dataclasses.replace(result, operations=(*result.operations, op))

    def _failed_before(self, run: _Run, target: Target, fault: Fault, status: TargetStatus = "failed",
                       command: str = OPEN) -> TargetResult:
        """A target that failed, or was skipped, with no operation completed: one operation, 'open' or the step the interrupt cut, recorded without a driver."""
        op = OperationResult(command, fault, now(), 0)
        self.recorder.result(run.run_id, target, "", 0, op, status)
        return TargetResult(target, status, (op,))

    def _dead_edit(self, spec: RunSpec, dead: dict[str, Fault | None]) -> None:
        """An edit whose probe found a target dead: skipped when the spec says so, else the run stops before any device, one audit entry per dead target and no run row."""
        if spec.skip_unreachable:
            return
        names = [t.name for t in spec.targets if dead.get(t.name) is not None]
        for target in spec.targets:
            if dead.get(target.name) is None:
                continue
            try:
                driver = self.registry.resolve(target)
            except Fault:
                continue
            op = OperationResult(OPEN, dead[target.name], now(), 0)
            self.recorder.change(0, target, driver.name, driver.dialect, "probe", op, spec.edit)
        reachable = len(spec.targets) - len(names)
        raise Fault(FaultKind.LOCAL, f"{len(names)} device(s) unreachable: {', '.join(names)}; aborting to prevent a "
                    f"partial deployment; skip_unreachable goes on with the {reachable} reachable", False)

    @staticmethod
    def _pending(spec: RunSpec, results: list[TargetResult]) -> dict[str, int]:
        """Targets whose commit-confirmed went through, each with the minutes armed; a target whose diff was empty sent no commit."""
        edit = spec.edit
        if spec.mode != "edit" or not edit.apply or not edit.confirmed_minutes:
            return {}
        return {r.target.name: edit.confirmed_minutes for r in results
                if any(op.command == "commit" and isinstance(op.outcome, Result) for op in r.operations)}


class _DaemonThreads(concurrent.futures.ThreadPoolExecutor):
    """Communicator calls on daemon threads, one per call: a call that never returns keeps its thread, never the interpreter's exit."""

    def submit(self, fn, /, *args, **kwargs):
        future: concurrent.futures.Future = concurrent.futures.Future()

        def run() -> None:
            if not future.set_running_or_notify_cancel():
                return
            try:
                future.set_result(fn(*args, **kwargs))
            except BaseException as e:  # noqa: BLE001 - handed to the awaiting task
                future.set_exception(e)

        threading.Thread(target=run, name=self._thread_name_prefix, daemon=True).start()
        return future

def _plan_logins(spec: RunSpec, registry: DriverRegistry) -> None:
    """The logins the run may make per device, retries + 1 per listing, against the rate limit: a run that would pass it is refused here, so the gate never turns a device away half-way."""
    devices: collections.Counter = collections.Counter()
    for target in spec.targets:
        try:
            devices[session_key(registry.resolve(target), target, spec.credentials)] += 1
        except Fault:
            devices[(target.host, target.port)] += 1
    logins = max(devices.values(), default=0) * (spec.policy.retries + 1)
    if logins > spec.safety.rate_limit:
        raise Fault(FaultKind.LOCAL, f"the run may log in {logins} times to one device, above the rate limit of "
                    f"{spec.safety.rate_limit} per minute; lower retries or raise the limit; nothing was sent", False)


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
                  store: StoreWriter | None = None, pool: bool = False,
                  sessions: SessionManager | None = None) -> RunReport:
    """execute() with injected collaborators, for callers that have an event loop or want to inject. A caller's `sessions` is used and left open for its next run; the run's own is closed at the end."""
    spec = complete(spec)
    if spec.mode == "structured" and not spec.format:
        raise Fault(FaultKind.LOCAL, "structured mode needs a format, json or xml; nothing was sent", False)
    if spec.mode == "edit" and (why := check_edit(spec.edit)):
        raise Fault(FaultKind.LOCAL, f"{why}; nothing was sent", False)
    if spec.safety is not None:
        _plan_logins(spec, registry)
    own = sessions is None
    sessions = sessions or SessionManager(pool=pool)
    scheduler = Scheduler(registry, Policy(spec.policy, gate), sessions, Recorder(spec.recording, store))
    try:
        return await scheduler.run(spec)
    finally:
        if own:
            await sessions.close_all()
        if gate is not None:
            _closed_quietly("safety gate", gate.close)


def run(spec: RunSpec, *, sessions: SessionManager | None = None) -> RunReport:
    """The entry point the front ends call: one RunSpec executed, its RunReport returned. Per-target failures are in the report; a local refusal before any device is contacted raises Fault(LOCAL). A caller's `sessions` is used and left open, as with execute()."""
    from hssh.drivers import Registry

    spec = complete(spec)
    registry = Registry()
    registry.load_entry_points()
    if spec.safety is not None:
        _plan_logins(spec, registry)
    try:
        gate = _gate(spec)
        store = _store(spec)
    except OSError as e:
        raise Fault(FaultKind.LOCAL, str(e), False) from e
    try:
        return asyncio.run(execute(spec, registry, gate=gate, store=store, sessions=sessions))
    finally:
        if store is not None:
            _closed_quietly("store", store.close)


def _closed_quietly(what: str, close) -> None:
    """A close on the way out that fails is said, never the run's end: the report, or the refusal, is what reaches the caller."""
    try:
        close()
    except Exception as e:  # noqa: BLE001
        print(f"{what} not closed: {e}", file=sys.stderr)


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
