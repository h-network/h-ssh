"""The Fleet library API (hssh.fleet): commands across many devices from a
script, results as values in completion order, no thread in sight. Every
device here is a fake driver in drivers.MODULES; nothing is contacted."""
import asyncio
import concurrent.futures as cf
import gc
import getpass
import json
import logging
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import types
import warnings
import weakref
from pathlib import Path

import pytest

import hssh
from hssh import Fleet, drivers, limits, pool
from hssh import fleet as fleet_mod
from hssh.core import Target
from hssh.fleet import DeviceResult, Results
from hssh.store import Store

HOSTS = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
BUSY = r"a run is still in progress on this Fleet: iterate it to the end, or close\(\)"


@pytest.fixture(autouse=True)
def clean_pool():
    def reset():
        pool.close_all()
        pool.disable()
        fleet_mod._POOL_FLEETS = 0
        fleet_mod._POOL_WAS_OFF = False
        for k in pool.POOL.stats:
            pool.POOL.stats[k] = 0
    reset()
    yield
    reset()


def install(monkeypatch, names=("junos@netconf", "none@ssh"), **functions):
    """A fake driver module for the given driver names, with the functions
    given (show, show_batch, rpc); the runner believes it on what it has."""
    fake = types.SimpleNamespace(AVAILABLE=True, **functions)
    for name in names:
        monkeypatch.setitem(drivers.MODULES, name, fake)
    return fake


def echo(host, user, passwd, cmd, *a, **kw):
    return f"{cmd} on {host}"


def holding(release, started=None, hosts=None):
    """A fake show that blocks (on `release`) for `hosts`, or for every host,
    as a wedged transport would; `started` is set when the first held call
    is under way."""
    def show(host, user, passwd, cmd, *a, **kw):
        if hosts is None or host in hosts:
            if started is not None:
                started.set()
            release.wait(10)
        return f"{cmd} on {host}"
    return show


def rows(path, sql, *params):
    c = sqlite3.connect(str(path))
    c.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in c.execute(sql, params).fetchall()]
    finally:
        c.close()


def wait_for(condition, seconds=2.0):
    deadline = time.monotonic() + seconds
    while not condition():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


# --- results as values, in completion order ------------------------------------------

def test_results_arrive_in_completion_order_and_all_arrive(monkeypatch):
    def show(host, user, passwd, cmd, *a, **kw):
        time.sleep(0.4 if host == "10.0.0.1" else 0.02)
        return f"$ {cmd}\nreply from {host}\n"          # framed as the text transports frame it

    install(monkeypatch, show=show)
    with Fleet(HOSTS, transport="junos", user="u") as fleet:
        got = list(fleet.show("show version"))
    assert [r.device for r in got][-1] == "10.0.0.1"                 # the slow device finishes last
    assert sorted(r.device for r in got) == HOSTS                     # and every device arrives
    assert all(isinstance(r, DeviceResult) and r.ok and r.error is None for r in got)
    assert {r.output for r in got} == {f"reply from {h}" for h in HOSTS}    # just what the device said
    r = got[-1]
    assert (r.host, r.vendor, r.command) == ("10.0.0.1", "junos", "show version")
    assert r.duration_ms >= 400 and r.ts[:2] == "20" and r.text.startswith("DEVICE: 10.0.0.1\n")
    assert r.result == "$ show version\nreply from 10.0.0.1\n"       # the driver's answer, untouched


def test_at_most_workers_devices_are_in_flight_at_once(monkeypatch):
    state = {"now": 0, "peak": 0}
    guard = threading.Lock()
    gate = threading.Barrier(3, timeout=5)     # the first three calls are inside together, whatever the scheduler does

    def show(host, user, passwd, cmd, *a, **kw):
        with guard:
            state["now"] += 1
            state["peak"] = max(state["peak"], state["now"])
        if host in ("10.0.1.1", "10.0.1.2", "10.0.1.3"):
            gate.wait()
        time.sleep(0.02)
        with guard:
            state["now"] -= 1
        return "ok"

    install(monkeypatch, show=show)
    hosts = [f"10.0.1.{i}" for i in range(1, 10)]
    with Fleet(hosts, transport="junos", user="u", workers=3) as fleet:
        got = list(fleet.show("show version"))
    assert len(got) == 9 and all(r.ok for r in got), [r.error for r in got if not r.ok]
    assert state["peak"] == 3


def test_workers_are_fitted_to_the_open_file_limit(monkeypatch):
    state = {"now": 0, "peak": 0}
    guard = threading.Lock()

    def show(host, user, passwd, cmd, *a, **kw):
        with guard:
            state["now"] += 1
            state["peak"] = max(state["peak"], state["now"])
        time.sleep(0.05)
        with guard:
            state["now"] -= 1
        return "ok"

    # the module the Fleet reads is the CLI's rule, moved
    from hssh import cli
    assert limits.MAX_WORKERS == cli.MAX_WORKERS == 256
    assert cli.fit_workers_to_open_files is limits.fit_workers_to_open_files      # one copy, the CLI's is it
    install(monkeypatch, show=show)
    monkeypatch.setattr(fleet_mod.limits, "fit_workers_to_open_files",      # a machine short of descriptors
                        lambda workers: (2, f"the open-file limit of 44 (ulimit -n) carries 2 workers at ~6 "
                                            f"descriptors each, not {workers}; running 2"))
    hosts = [f"10.0.1.{i}" for i in range(1, 7)]
    with Fleet(hosts, transport="junos", user="u", workers=6) as fleet:
        with pytest.warns(RuntimeWarning, match="carries 2 workers at ~6 descriptors each, not 6; running 2"):
            got = list(fleet.show("show version"))
        assert fleet.workers == 2 and "workers=2" in repr(fleet)
    assert len(got) == 6 and state["peak"] <= 2


def test_a_failure_is_a_value_and_the_rest_still_run(monkeypatch):
    def show(host, user, passwd, cmd, *a, **kw):
        if host == "10.0.0.2":
            raise RuntimeError("Authentication failed.")
        return f"reply from {host}"

    install(monkeypatch, show=show)
    with Fleet(HOSTS, transport="junos", user="u") as fleet:
        got = {r.device: r for r in fleet.show("show version")}
    assert len(got) == 3
    failed = got["10.0.0.2"]
    assert not failed.ok and failed.error == "Authentication failed." and failed.output is None
    assert "ERROR: Authentication failed." in failed.text and failed.result is None
    assert all(got[h].ok and got[h].output == f"reply from {h}" for h in ("10.0.0.1", "10.0.0.3"))


def test_retries_follow_the_runners_classification(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _s: None)     # the backoff between attempts
    calls = {}

    def show(host, user, passwd, cmd, *a, **kw):
        calls[host] = calls.get(host, 0) + 1
        if host == "10.0.0.1" and calls[host] < 3:
            raise RuntimeError("Command timed out after 1s: show version")     # transient: tried again
        if host == "10.0.0.2":
            raise RuntimeError("Authentication failed.")                        # permanent: once
        return "fine"

    install(monkeypatch, show=show)
    with Fleet(HOSTS, transport="junos", user="u") as fleet:               # retries=2, the CLI's default
        got = {r.device: r for r in fleet.show("show version")}
    assert got["10.0.0.1"].ok and calls["10.0.0.1"] == 3
    assert not got["10.0.0.2"].ok and calls["10.0.0.2"] == 1
    assert calls["10.0.0.3"] == 1
    with Fleet(HOSTS, transport="junos", user="u", retries=2) as fleet:
        list(fleet.show("request system reboot"))                   # not a read: sent once, never retried
    assert calls["10.0.0.1"] == 4


# --- time bounds --------------------------------------------------------------------

def test_a_hanging_transport_ends_as_a_failed_result_within_the_bound(monkeypatch):
    monkeypatch.setattr(fleet_mod, "GRACE_SECONDS", 0.2)
    release = threading.Event()
    install(monkeypatch, show=holding(release, hosts={"10.0.0.2"}))
    try:
        started = time.monotonic()
        with Fleet(HOSTS, transport="junos", user="u", session_timeout=1, command_timeout=1, retries=0) as fleet:
            got = {r.device: r for r in fleet.show("show version")}
            elapsed = time.monotonic() - started
            assert elapsed < 5, f"{elapsed:.1f}s: the run waited for the hung device"
            hung = got["10.0.0.2"]
            assert not hung.ok and hung.output is None
            assert hung.error == ("no result within 3.2s (1 attempt(s) at 2 x session_timeout 1s + command_timeout 1s, "
                                  "plus 0.2s): the transport call has not returned")
            assert hung.duration_ms >= 3200
            assert got["10.0.0.1"].ok and got["10.0.0.3"].ok
            assert fleet._stuck_count() == 1              # the held worker is known
            release.set()                                 # the call returns: the worker is free again
            assert wait_for(lambda: fleet._stuck_count() == 0)
    finally:
        release.set()


def test_with_every_worker_held_the_queue_is_failed_at_once_not_waited_for(monkeypatch):
    monkeypatch.setattr(fleet_mod, "GRACE_SECONDS", 0.2)
    release = threading.Event()
    seen = []

    def show(host, user, passwd, cmd, *a, **kw):
        seen.append(host)
        release.wait(10)
        return "fine"

    install(monkeypatch, show=show)
    try:
        started = time.monotonic()
        with Fleet(HOSTS, transport="junos", user="u", workers=1, session_timeout=1, command_timeout=1,
                   retries=0) as fleet:
            got = list(fleet.show("show version"))
        elapsed = time.monotonic() - started
        assert elapsed < 5, f"{elapsed:.1f}s"
        assert [r.ok for r in got] == [False, False, False]
        assert got[0].error.startswith("no result within 3.2s")
        assert all(r.error.startswith("not started: every worker thread (1) was held") for r in got[1:])
        assert seen == ["10.0.0.1"]                                   # the others were never sent
    finally:
        release.set()


def test_a_wedged_device_does_not_poison_later_runs(monkeypatch):
    """A monitoring loop on one Fleet with one device that never answers:
    the call that never returned holds its worker (and, in real life, the
    pool's lock for that router); a later run does not queue another call
    behind it, it fails that device at once and runs the rest in full."""
    monkeypatch.setattr(fleet_mod, "GRACE_SECONDS", 0.1)
    never = threading.Event()
    install(monkeypatch, show=holding(never, hosts={"10.0.0.9"}))
    hosts = [f"10.0.0.{i}" for i in range(1, 10)]
    try:
        with Fleet(hosts, transport="junos", user="u", workers=2, session_timeout=1, command_timeout=1,
                   retries=0) as fleet:
            for n in range(1, 4):
                t0 = time.monotonic()
                got = {r.device: r for r in fleet.show("show version")}
                elapsed = time.monotonic() - t0
                bad = {d: r.error for d, r in got.items() if not r.ok}
                assert len(got) == 9 and list(bad) == ["10.0.0.9"], (n, bad)
                if n == 1:
                    assert bad["10.0.0.9"].startswith("no result within 3.1s") and elapsed >= 3.1
                else:
                    assert bad["10.0.0.9"] == "the previous call to this device has not returned"
                    assert elapsed < 1.5, f"run {n}: {elapsed:.1f}s"
                assert fleet._stuck_count() == 1
    finally:
        never.set()


def test_the_connect_timeout_reaches_every_device_and_is_3_by_default(monkeypatch):
    """#126: Fleet(connect_timeout=) is the CLI's --connect-timeout, its default too."""
    got = []

    def show(host, user, passwd, cmd, st, ct, port=None, vendor_hint=None, connect_timeout=None):
        got.append((host, connect_timeout))
        return "fine"
    install(monkeypatch, show=show)
    with Fleet(HOSTS, transport="junos", user="u") as fleet:
        assert fleet.connect_timeout == 3
        assert all(r.ok for r in fleet.show("show version"))
    with Fleet(HOSTS, transport="junos", user="u", connect_timeout=7) as fleet:
        assert all(r.ok for r in fleet.show("show version"))
    assert sorted(got) == sorted([(h, 3) for h in HOSTS] + [(h, 7) for h in HOSTS])


def test_the_budget_counts_the_transports_connect_phases():
    fleet = Fleet(["R1:10.0.0.1:junos", "R2:10.0.0.2:ssh", "R3:10.0.0.3:ios@openssh", "R4:10.0.0.4:telnet-ios"],
                  user="u", session_timeout=2, command_timeout=3, retries=1)
    r1, r2, r3, r4 = fleet.targets
    grace = fleet_mod.GRACE_SECONDS
    assert fleet_mod._budget(fleet, r1, 1, 2) == 2 * (2 * 2 + 3) + 1 + grace      # NETCONF: the set-up, then the hello
    assert fleet_mod._budget(fleet, r2, 1, 2) == 2 * (3 * 2 + 3) + 1 + grace      # paramiko: connect, banner, auth
    assert fleet_mod._budget(fleet, r3, 1, 2) == fleet_mod._budget(fleet, r4, 1, 2) == fleet_mod._budget(fleet, r2, 1, 2)
    assert fleet_mod._budget(fleet, r1, 2, 2) == 2 * (2 * 2 + 3 * 2) + 1 + grace  # a batch: a timeout per command
    fleet.close()


def test_the_budget_of_a_command_that_is_not_a_read_is_one_attempt():
    """The runner sends `request …` once, whatever `retries` says; the budget
    used to count every retry, so a wedged request held its worker for three
    attempts' worth of time, and the given-up line claimed three attempts."""
    fleet = Fleet(["R1:10.0.0.1:junos", "R2:10.0.0.2:ssh"], user="u", session_timeout=2, command_timeout=3, retries=2)
    grace = fleet_mod.GRACE_SECONDS

    def budgets(mode, command):
        return [t.budget for t in fleet_mod._Run(fleet, mode, command, "text").tasks]
    # a read: three attempts and the backoff before the second and the third
    assert budgets("show", "show version") == [3 * (2 * 2 + 3) + (1 + 3) + grace, 3 * (3 * 2 + 3) + (1 + 3) + grace]
    assert budgets("show", "request system reboot") == [(2 * 2 + 3) + grace, (3 * 2 + 3) + grace]
    # a batch with one command that acts is sent once as a whole, as the runner does
    assert budgets("show-batch", ["show version", "clear bgp neighbor all"]) == [(2 * 2 + 3 * 2) + grace,
                                                                               (3 * 2 + 3 * 2) + grace]
    assert budgets("show-batch", ["show version", "show route"])[0] == 3 * (2 * 2 + 3 * 2) + (1 + 3) + grace
    acting = fleet_mod._Run(fleet, "show", "request system reboot", "text")
    assert [t.attempts for t in acting.tasks] == [1, 1]                        # the runner is told so too
    fleet.close()


def test_the_worker_pool_runs_daemon_threads_with_future_semantics():
    gate = threading.Event()
    p = fleet_mod._DaemonPool(2)
    held = [p.submit(gate.wait, 5) for _ in range(2)]            # both workers busy
    queued = [p.submit(lambda: "late") for _ in range(3)]        # no third worker: queued
    boom = p.submit(lambda: 1 / 0)
    assert wait_for(lambda: all(f.running() for f in held))      # both in a worker's hands
    assert len(p.threads) == 2 and all(t.daemon for t in p.threads)
    assert queued[0].cancel()                                    # a queued call cancelled before a worker reaches it
    p.shutdown(wait=False, cancel_futures=True)                  # the rest of the queue cancelled, and notified
    done, _ = cf.wait(queued + [boom], timeout=1)
    assert done == set(queued + [boom]) and all(f.cancelled() for f in queued + [boom])
    gate.set()
    assert all(f.result(timeout=2) is True for f in held)        # what was running finishes on its own
    with pytest.raises(RuntimeError, match="shut down"):
        p.submit(lambda: None)
    p.shutdown(wait=True)                                        # joins the idle workers
    assert wait_for(lambda: not any(t.is_alive() for t in p.threads))
    q = fleet_mod._DaemonPool(1)
    assert isinstance(q.submit(lambda: 1 / 0).exception(timeout=2), ZeroDivisionError)
    q.shutdown(wait=True)


def test_a_script_that_gave_up_on_a_wedged_device_can_exit(tmp_path):
    """close() leaves a wedged call its thread, a daemon thread: the script
    ends when it is done, not when the device call would have."""
    script = tmp_path / "gaveup.py"
    script.write_text(
        "import sys, time, types\n"
        "import hssh.fleet as fleet_mod\n"
        "from hssh import Fleet, drivers\n"
        "fleet_mod.GRACE_SECONDS = 0.1\n"
        "def show(host, user, passwd, cmd, *a, **kw):\n"
        "    time.sleep(5)\n"
        "    return 'late'\n"
        "drivers.MODULES['junos@netconf'] = types.SimpleNamespace(AVAILABLE=True, show=show)\n"
        "with Fleet(['10.0.0.1'], transport='junos', user='u', session_timeout=1, command_timeout=1,\n"
        "           retries=0, probe=False) as fleet:\n"
        "    r, = fleet.show('show version')\n"
        "    print(r.ok, r.error, flush=True)\n")
    env = {**os.environ, "PYTHONPATH": os.path.dirname(os.path.dirname(hssh.__file__))}
    started = time.monotonic()
    proc = subprocess.run([sys.executable, str(script)], env=env, capture_output=True, text=True, timeout=30)
    elapsed = time.monotonic() - started
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("False no result within 3.1s")
    assert elapsed < 5.0, f"{elapsed:.1f}s: the interpreter waited for the wedged thread"


# --- batch, async, data -------------------------------------------------------------

def test_batch_gives_one_result_per_command(monkeypatch):
    def show_batch(host, user, passwd, cmds, *a, **kw):
        out = []
        for c in cmds:
            if c == "show nothing" and host == "10.0.0.2":
                out.append({"command": c, "ok": False, "error": f"'{c}' was refused by the device"})
            else:
                out.append({"command": c, "ok": True, "output": f"$ {c}\n{c} on {host}"})
        return out

    install(monkeypatch, show_batch=show_batch)
    cmds = ["show version", "show nothing", "show route"]
    with Fleet(HOSTS, transport="junos", user="u") as fleet:
        res = fleet.batch(cmds)
        assert isinstance(res, Results)
        got = {r.device: r for r in res}
    assert all([c["command"] for c in r.commands] == cmds for r in got.values())
    good = got["10.0.0.1"]
    assert good.ok and good.error is None and good.output is None and good.command == cmds
    assert [c["output"] for c in good.commands] == [f"{c} on 10.0.0.1" for c in cmds]
    bad = got["10.0.0.2"]
    assert not bad.ok and bad.error == "'show nothing' was refused by the device"
    assert [c["ok"] for c in bad.commands] == [True, False, True]
    dicts = res.to_dicts()                                        # after the loop: the same three, as data
    assert len(dicts) == 3 and all("commands" in d and "output" not in d for d in dicts)
    json.dumps(dicts)


def test_show_async_yields_the_same_set_in_completion_order(monkeypatch):
    def show(host, user, passwd, cmd, *a, **kw):
        time.sleep(0.3 if host == "10.0.0.3" else 0.02)
        if host == "10.0.0.2":
            raise RuntimeError("Connection refused by 10.0.0.2.")
        return f"{cmd} on {host}"

    install(monkeypatch, show=show)

    async def main(fleet):
        got = []
        async for r in fleet.show_async("show version"):
            got.append(r)
        return got

    with Fleet(HOSTS, transport="junos", user="u") as fleet:
        got = asyncio.run(main(fleet))
        sync = sorted((r.device, r.ok, r.output, r.error) for r in fleet.show("show version"))
    assert got[-1].device == "10.0.0.3"
    assert sorted((r.device, r.ok, r.output, r.error) for r in got) == sync
    assert [(device, ok) for device, ok, _, _ in sync] == [("10.0.0.1", True), ("10.0.0.2", False), ("10.0.0.3", True)]


def test_batch_async_and_a_cancelled_consumer_leave_the_run_intact(monkeypatch, tmp_path):
    release = threading.Event()

    def show_batch(host, user, passwd, cmds, *a, **kw):
        if host == "10.0.0.3":
            release.wait(10)
        return [{"command": c, "ok": True, "output": c} for c in cmds]

    install(monkeypatch, show_batch=show_batch)
    path = tmp_path / "runs.db"

    async def main(fleet):
        got = []

        async def consume():
            async for r in fleet.batch_async(["show a", "show b"]):
                got.append(r)

        consumer = asyncio.create_task(consume())
        for _ in range(200):                                 # two devices answer, the third is held
            await asyncio.sleep(0.01)
            if len(got) == 2:
                break
        consumer.cancel()                                    # the caller gives up waiting
        with pytest.raises(asyncio.CancelledError):
            await consumer
        held = next(t for t in fleet._run.tasks if t.target.host == "10.0.0.3")
        release.set()
        await asyncio.wrap_future(held.future)               # the held device returns on its own thread
        # the run is intact: it wraps up with every device's result, and the next run may start
        rest = [r async for r in fleet.batch_async(["show c"])]
        return got, rest

    try:
        with Fleet(HOSTS, transport="junos", user="u", store=str(path)) as fleet:
            got, rest = asyncio.run(main(fleet))
    finally:
        release.set()
    assert len(got) == 2 and all(r.ok for r in got)
    assert sorted(r.device for r in rest) == HOSTS and all(len(r.commands) == 1 for r in rest)
    runs = rows(path, "SELECT * FROM runs ORDER BY started, rowid")
    assert [(r["ok"], r["failed"], r["skipped"], r["interrupted"]) for r in runs] == [(3, 0, 0, 0), (3, 0, 0, 0)]
    assert len(rows(path, "SELECT * FROM results WHERE run_id = ?", runs[0]["run_id"])) == 6     # 3 devices x 2 commands


@pytest.mark.parametrize("returned", [False, True], ids=["call held", "call returned"])
def test_iterating_again_fails_the_queue_a_cancelled_consumer_had_given_up_on(monkeypatch, returned):
    """Every worker held: the consumer gives up on the queue (cancelled, so
    no worker takes it) and hands it to the loop's executor to be failed.
    An async consumer cancelled right then (asyncio.timeout around `async
    for`, the executor busy) loses that step. The queue sat there cancelled
    and pending for good: iterating again waited forever and every later
    show() was refused as busy. It is given up on again, whether the held
    call has returned by then or not."""
    monkeypatch.setattr(fleet_mod, "GRACE_SECONDS", 0.2)
    release, busy = threading.Event(), threading.Event()
    install(monkeypatch, show=holding(release, hosts={"10.0.0.1"}))
    try:
        with Fleet(HOSTS, transport="junos", user="u", workers=1, session_timeout=1, command_timeout=1,
                   retries=0) as fleet:
            res = fleet.show("show version")                 # 10.0.0.1 held, the other two queued
            queued = [t for t in res._run.tasks if t.target.host != "10.0.0.1"]

            async def main():
                loop = asyncio.get_running_loop()
                loop.set_default_executor(cf.ThreadPoolExecutor(max_workers=1))
                got = []

                async def consume():
                    async for r in res:
                        got.append(r)
                        loop.run_in_executor(None, busy.wait, 10)    # the loop's executor busy from here on

                consumer = asyncio.create_task(consume())
                deadline = loop.time() + 10
                while not all(t.future.cancelled() for t in queued):   # 10.0.0.1 given up on, then the queue
                    assert loop.time() < deadline, "the queue behind the held worker was never given up on"
                    await asyncio.sleep(0.01)
                consumer.cancel()                            # while the queue's failing waits for the executor
                with pytest.raises(asyncio.CancelledError):
                    await consumer
                busy.set()
                return got

            got = asyncio.run(main())
            assert [(r.device, r.ok) for r in got] == [("10.0.0.1", False)]
            assert all(t in res._run.pending for t in queued)    # the queue's failing was lost
            if returned:
                release.set()
                assert wait_for(lambda: fleet._stuck_count() == 0)
            again = []
            consumer = threading.Thread(target=lambda: again.extend(res), daemon=True)
            consumer.start()
            consumer.join(5)
            assert not consumer.is_alive(), "iterating again waits for a queue nobody will finish"
            assert [r.device for r in again] == HOSTS and not any(r.ok for r in again)
            # as of when it was given up on: the held call may have returned since
            assert all(r.error.startswith("not started: every worker thread (1) was held") for r in again[1:])
            assert len(list(fleet.show("show version"))) == 3    # not refused as busy: the run was ended
    finally:
        busy.set()
        release.set()


def test_async_keeps_sqlite_and_the_host_name_off_the_event_loop(monkeypatch, tmp_path):
    install(monkeypatch, show=echo)
    seen = {"begin": set(), "add": set(), "finish": set(), "hostname": set()}
    originals = {name: getattr(Store, name) for name in ("begin_run", "add_entry", "finish_run")}

    def recording(name, key):
        def method(self, *a, **kw):
            seen[key].add(threading.get_ident())
            return originals[name](self, *a, **kw)
        return method

    monkeypatch.setattr(Store, "begin_run", recording("begin_run", "begin"))
    monkeypatch.setattr(Store, "add_entry", recording("add_entry", "add"))
    monkeypatch.setattr(Store, "finish_run", recording("finish_run", "finish"))
    monkeypatch.setattr(fleet_mod.socket, "gethostname",
                        lambda: seen["hostname"].add(threading.get_ident()) or "elsewhere")

    async def main(fleet):
        loop_thread = threading.get_ident()
        got = [r async for r in fleet.show_async("show version")]
        return loop_thread, got

    with Fleet(HOSTS, transport="junos", user="u", store=str(tmp_path / "runs.db")) as fleet:
        loop_thread, got = asyncio.run(main(fleet))
    assert sorted(r.device for r in got) == HOSTS
    for key, threads in seen.items():
        assert threads and loop_thread not in threads, key
    run, = rows(tmp_path / "runs.db", "SELECT * FROM runs")
    assert run["origin"] == "elsewhere" and run["ok"] == 3


def test_async_with_closes_off_the_event_loop(monkeypatch):
    install(monkeypatch, show=echo)
    closed_on = []
    real_close = Fleet.close
    monkeypatch.setattr(Fleet, "close",
                        lambda self, wait=0: closed_on.append(threading.get_ident()) or real_close(self, wait))

    async def main():
        loop_thread = threading.get_ident()
        async with Fleet(HOSTS, transport="junos", user="u") as fleet:
            got = [r async for r in fleet.show_async("show version")]
        assert fleet._closed
        return loop_thread, got

    loop_thread, got = asyncio.run(main())
    assert sorted(r.device for r in got) == HOSTS
    assert closed_on and loop_thread not in closed_on          # close() ran on a worker of the loop


def test_to_dicts_is_json_serialisable_and_shaped_like_the_cli_record(monkeypatch):
    def show(host, user, passwd, cmd, *a, **kw):
        if host == "10.0.0.3":
            raise RuntimeError("Cannot resolve 10.0.0.3.")
        return f"{cmd} on {host}"

    install(monkeypatch, show=show)
    with Fleet(HOSTS, transport="junos", user="u") as fleet:
        dicts = fleet.show("show version").to_dicts()
    text = json.dumps(dicts)
    back = {d["device"]: d for d in json.loads(text)}
    assert set(back) == set(HOSTS)
    assert set(back["10.0.0.1"]) == {"device", "host", "vendor", "ok", "duration_ms", "ts", "command", "output", "error"}
    assert back["10.0.0.1"]["output"] == "show version on 10.0.0.1" and back["10.0.0.1"]["error"] is None
    assert back["10.0.0.3"]["output"] is None and back["10.0.0.3"]["error"] == "Cannot resolve 10.0.0.3."


def test_fmt_json_hands_back_the_routers_data(monkeypatch):
    def rpc(host, user, passwd, cmd, *a, fmt="json", **kw):
        return {"software-information": [{"host-name": [{"data": host}]}]}

    install(monkeypatch, names=("junos@netconf",), rpc=rpc)
    install(monkeypatch, names=("none@ssh",), show=echo)          # a text transport: no rpc()
    with Fleet(["R1:10.0.0.1:junos", "R2:10.0.0.2:none@ssh"], user="u") as fleet:
        got = {r.device: r for r in fleet.show("show version", fmt="json")}
    assert got["R1"].ok and got["R1"].output == {"software-information": [{"host-name": [{"data": "10.0.0.1"}]}]}
    assert not got["R2"].ok and "not supported by the 'none@ssh' transport" in got["R2"].error
    json.dumps([r.to_dict() for r in got.values()])
    with pytest.raises(ValueError, match="fmt must be one of text, json, xml"):
        Fleet(HOSTS, user="u").show("show version", fmt="yaml")


def test_a_batch_under_fmt_json_is_reads_only(monkeypatch):
    """#110: a batch with a `request …` line went whole to rpc_batch under fmt="json"."""
    calls = []

    def rpc_batch(host, user, passwd, cmds, *a, **kw):
        calls.append((host, list(cmds)))
        return [{"command": c, "ok": True, "output": {}} for c in cmds]

    install(monkeypatch, names=("junos@netconf",), rpc_batch=rpc_batch, rpc=lambda *a, **kw: {})
    with Fleet(["R1:10.0.0.1:junos"], user="u") as fleet:
        got = list(fleet.batch(["show version", "request system reboot"], fmt="json"))
        assert len(got) == 1 and not got[0].ok and calls == []
        assert "runs reads only" in got[0].error and "'request system reboot'" in got[0].error
        assert all(r.ok for r in fleet.batch(["show version", "show route summary"], fmt="json"))
    assert calls == [("10.0.0.1", ["show version", "show route summary"])]


def test_a_command_with_a_control_character_is_refused_before_anything_runs(monkeypatch):
    """#110: `show version\\nrequest system reboot` went to the exec channel
    whole, was a read by its first line, and so was retried: both lines
    each time. A command is one line of text, for show() and every entry
    of batch()."""
    sent = []
    install(monkeypatch, show=lambda host, *a, **kw: sent.append(host) or "x",
            show_batch=lambda host, user, passwd, cmds, *a, **kw: sent.append(host) or [])
    with Fleet(HOSTS, transport="junos", user="u") as fleet:
        for cmd, what in (("show version\nrequest system reboot", "a line break"), ("show version\r", "a carriage return"),
                          ("show ver\x00sion", "a NUL"), ("show version\x1b[A", "an ESC")):
            with pytest.raises(ValueError, match=f"show: {what} in .*; a command is one line of text"):
                fleet.show(cmd)
            with pytest.raises(ValueError, match=f"batch: {what} in .*; a command is one line of text"):
                fleet.batch(["show version", cmd])
        assert [r.ok for r in fleet.show("show\tversion")] == [True] * 3       # a tab is text
    assert sorted(sent) == HOSTS


def test_the_lines_of_an_open_file_are_commands_without_their_line_breaks(monkeypatch, tmp_path):
    """#110 review: fleet.batch(open(path)) hands over lines that end in a
    line break. That ran before #110 and was then refused as a line break;
    the closing one is dropped, as the CLI drops it from a batch file's
    lines. One inside a command, or a second one, is still refused."""
    sent = []

    def show_batch(host, user, passwd, cmds, *a, **kw):
        sent.append(list(cmds))
        return [{"command": c, "ok": True, "output": c} for c in cmds]

    install(monkeypatch, show=lambda host, user, passwd, cmd, *a, **kw: sent.append(cmd) or cmd, show_batch=show_batch)
    path = tmp_path / "cmds.txt"
    path.write_text("show version\nshow route summary\n")
    with Fleet(["R1:10.0.0.1:junos"], user="u") as fleet:
        with open(path) as f:
            got = list(fleet.batch(f))
        assert got[0].ok and got[0].command == ["show version", "show route summary"]
        assert [r.command for r in fleet.show("show version\r\n")] == ["show version"]
        for bad in ("show version\nrequest system reboot\n", "show version\n\n", "show version\r"):
            with pytest.raises(ValueError, match="a command is one line of text"):
                fleet.batch(["show version", bad])
            with pytest.raises(ValueError, match="a command is one line of text"):
                fleet.show(bad)
    assert sent == [["show version", "show route summary"], "show version"]


def test_breaking_out_early_loses_nothing(monkeypatch):
    install(monkeypatch, show=echo)
    with Fleet(HOSTS, transport="junos", user="u") as fleet:
        res = fleet.show("show version")
        for r in res:
            first = r
            break
        rest = res.to_dicts()                   # waits for the others, replays the first
        assert len(rest) == 3 and rest[0]["device"] == first.device
        assert [r.device for r in res] == [d["device"] for d in rest]      # a second pass is the same run


# --- one run at a time; what close() leaves ---------------------------------------------

def test_one_run_at_a_time(monkeypatch):
    release = threading.Event()
    install(monkeypatch, show=holding(release))
    try:
        with Fleet(HOSTS, transport="junos", user="u") as fleet:
            res = fleet.show("show version")                    # three devices held in flight
            with pytest.raises(RuntimeError, match=BUSY):
                fleet.show("show route summary")
            with pytest.raises(RuntimeError, match=BUSY):
                fleet.batch(["show version"])

            async def second():
                async for _ in fleet.show_async("show version"):
                    pass
            with pytest.raises(RuntimeError, match=BUSY):
                asyncio.run(second())
            release.set()
            assert all(r.ok for r in res)                       # iterated to the end: the next run may start
            again = fleet.show("show route summary")
            assert len(list(again)) == 3
            # a run nobody iterated is not in progress once its devices have returned
            unread = fleet.show("show version")
            assert wait_for(lambda: all(t.future.done() for t in fleet._run.tasks))
            third = fleet.show("show version")
            assert len(unread.to_dicts()) == 3 and len(list(third)) == 3
    finally:
        release.set()


def test_close_from_another_thread_during_iteration_is_safe(monkeypatch, tmp_path):
    """A watchdog closing the Fleet while the consumer iterates, with a store
    (SQLite lets the GIL go on every row): the run's lock keeps the two
    threads consistent, close() runs every one of its steps, and nothing
    leaks: the workers are down, the pool is off, the store is closed."""
    install(monkeypatch, show=lambda host, user, passwd, cmd, *a, **kw: "x" * 2000)
    hosts = [f"10.0.{i // 250}.{i % 250}" for i in range(40)]
    path = tmp_path / "runs.db"
    closer_errors = []
    monkeypatch.setattr(threading, "excepthook",
                        lambda a: closer_errors.append(f"{a.exc_type.__name__}: {a.exc_value}"))
    rounds, t_end = 0, time.monotonic() + 1.0
    while time.monotonic() < t_end or rounds < 10:
        fleet = Fleet(hosts, transport="junos", user="u", workers=8, store=str(path))
        res = fleet.show("show version")
        timer = threading.Timer(0.0005 * (rounds % 12), fleet.close)
        timer.start()
        got = list(res)                                      # never raises: what came before the close
        timer.join()
        assert not closer_errors, closer_errors
        assert fleet._closed and fleet._workers._down
        assert not pool.POOL.enabled and pool.live() == 0 and fleet_mod._POOL_FLEETS == 0
        with pytest.raises(sqlite3.ProgrammingError):        # the store this Fleet opened is closed
            fleet._store.conn.execute("SELECT 1")
        assert len(got) == len(res._run.done) <= 40
        rounds += 1
    assert rounds >= 10
    assert all(r["finished"] is not None for r in rows(path, "SELECT finished FROM runs"))


def test_a_close_that_catches_the_run_being_started_leaves_no_run_row_open(monkeypatch, tmp_path):
    """close() from another thread while show() is still inside begin_run():
    the run row is opened under the run's lock, so the close waits for it,
    records the run as interrupted and closes the store only after that;
    show() then raises as on a closed Fleet. It used to close the store's
    connection under the INSERT (a ProgrammingError out of show(), or a
    segfault), and leave a caller's store with the run row open."""
    install(monkeypatch, show=echo)
    real_begin = Store.begin_run
    entered = threading.Event()
    fleet = None

    def begin_run(self, *a, **kw):
        entered.set()
        assert wait_for(lambda: fleet._closed, 5)        # the close is under way: it waits for this row
        return real_begin(self, *a, **kw)
    monkeypatch.setattr(Store, "begin_run", begin_run)
    path = tmp_path / "runs.db"
    shared = Store(str(tmp_path / "shared.db"))
    for store in (str(path), shared):                    # a store the Fleet owns, and a caller's
        entered.clear()
        fleet = Fleet(HOSTS, transport="junos", user="u", store=store)
        closer = threading.Thread(target=lambda f: entered.wait(5) and f.close(), args=(fleet,))
        closer.start()
        with pytest.raises(RuntimeError, match="this Fleet is closed"):
            fleet.show("show version")
        closer.join(5)
        assert not closer.is_alive() and fleet._closed and fleet._run is None
    shared.conn.execute("SELECT 1").fetchone()           # the caller's store: still open
    shared.close()
    for db in (path, tmp_path / "shared.db"):
        run, = rows(db, "SELECT * FROM runs")
        assert run["finished"] is not None
        assert (run["ok"], run["failed"], run["skipped"], run["interrupted"]) == (0, 0, 3, 1)
        assert rows(db, "SELECT * FROM results") == []


def test_a_close_armed_before_the_run_never_breaks_the_store(monkeypatch, tmp_path):
    """A Timer closing the Fleet, armed before show(), many rounds in a
    second: whatever the close catches (the admission, the run row, the
    hand-out, the run itself), show() either returns the Results or raises
    as on a closed Fleet, never a sqlite error, and no run row is left open."""
    install(monkeypatch, show=lambda host, user, passwd, cmd, *a, **kw: "x" * 500)
    hosts = [f"10.0.{i // 250}.{i % 250}" for i in range(20)]
    path = tmp_path / "runs.db"
    closer_errors = []
    monkeypatch.setattr(threading, "excepthook",
                        lambda a: closer_errors.append(f"{a.exc_type.__name__}: {a.exc_value}"))
    outcomes = {"results": 0, "closed": 0}
    rounds, t_end = 0, time.monotonic() + 1.0
    while time.monotonic() < t_end or rounds < 20:
        fleet = Fleet(hosts, transport="junos", user="u", workers=4, store=str(path))
        timer = threading.Timer(0.0003 * (rounds % 10), fleet.close)
        timer.start()
        try:
            res = fleet.show("show version")
        except RuntimeError as e:
            assert str(e) == "this Fleet is closed"
            outcomes["closed"] += 1
        else:
            list(res)
            outcomes["results"] += 1
        timer.join()
        assert not closer_errors, closer_errors
        assert fleet._closed and fleet._run is None
        with pytest.raises(sqlite3.ProgrammingError):        # the store this Fleet opened is closed
            fleet._store.conn.execute("SELECT 1")
        rounds += 1
    assert rounds >= 20 and outcomes["results"] + outcomes["closed"] == rounds
    runs = rows(path, "SELECT * FROM runs")
    assert all(r["finished"] is not None for r in runs), [r["run_id"] for r in runs if r["finished"] is None]
    assert all(r["ok"] + r["failed"] + r["skipped"] == 20 for r in runs)


def test_iterating_after_close_ends_instead_of_hanging(monkeypatch, tmp_path):
    release, started = threading.Event(), threading.Event()
    install(monkeypatch, show=holding(release, started, hosts={"10.0.0.2", "10.0.0.3"}))
    path = tmp_path / "runs.db"
    try:
        with Fleet(HOSTS, transport="junos", user="u", workers=1, store=str(path)) as fleet:
            res = fleet.show("show version")
            for r in res:
                assert r.device == "10.0.0.1" and r.ok
                break                                    # one answer was enough
            assert started.wait(2)                       # 10.0.0.2 is in flight, 10.0.0.3 still queued
            held = next(t for t in fleet._run.tasks if t.target.host == "10.0.0.2")
        release.set()                                    # the in-flight call returns after the close
        assert wait_for(lambda: held.future.done())      # a late answer: dropped, as its row says
        t0 = time.monotonic()
        with warnings.catch_warnings():
            warnings.simplefilter("error")               # nothing may be written to the closed store
            got = res.to_dicts()
            replay = list(res)
        assert time.monotonic() - t0 < 1, "iterating a closed Fleet's results hung"
        assert [d["device"] for d in got] == ["10.0.0.1"] and got[0]["ok"] and len(replay) == 1
        run, = rows(path, "SELECT * FROM runs")
        assert (run["ok"], run["failed"], run["skipped"], run["interrupted"]) == (1, 0, 2, 1)
        assert [r["device"] for r in rows(path, "SELECT * FROM results")] == ["10.0.0.1"]
    finally:
        release.set()


def test_iterating_after_close_ends_instead_of_hanging_async(monkeypatch):
    release, started = threading.Event(), threading.Event()
    install(monkeypatch, show=holding(release, started, hosts={"10.0.0.2", "10.0.0.3"}))

    async def main():
        with Fleet(HOSTS, transport="junos", user="u", workers=1) as fleet:
            res = fleet.show("show version")
            async for r in res:
                assert r.device == "10.0.0.1"
                break
            assert started.wait(2)
        release.set()
        t0 = time.monotonic()
        got = [r async for r in res]
        assert time.monotonic() - t0 < 1, "iterating a closed Fleet's results hung"
        return got

    try:
        got = asyncio.run(main())
    finally:
        release.set()
    assert [r.device for r in got] == ["10.0.0.1"] and got[0].ok


def test_a_close_from_another_thread_wakes_the_consumer_at_once(monkeypatch):
    """The consumer waits on the devices in flight; a watchdog's close() must
    not leave it waiting until the wedged device's budget runs out."""
    release, started = threading.Event(), threading.Event()
    install(monkeypatch, show=holding(release, started, hosts={"10.0.0.2"}))
    timers = []
    try:
        fleet = Fleet(HOSTS, transport="junos", user="u", workers=2, session_timeout=5, command_timeout=5, retries=0)
        res = fleet.show("show version")
        assert started.wait(2)
        t0 = time.monotonic()
        timers.append(threading.Timer(0.3, fleet.close))
        timers[0].start()
        got = list(res)                                   # the two that answered; the close ends the wait
        elapsed = time.monotonic() - t0
        assert 0.3 <= elapsed < 1.5, f"{elapsed:.1f}s: the consumer slept through the close"
        assert sorted(r.device for r in got) == ["10.0.0.1", "10.0.0.3"] and all(r.ok for r in got)
    finally:
        release.set()
        # close() wakes the consumer before it gives the pool back: that lands
        # in this test, not in the next one's count
        for t in timers:
            t.join(5)


def test_a_close_from_another_thread_wakes_an_async_consumer_at_once(monkeypatch):
    release, started = threading.Event(), threading.Event()
    install(monkeypatch, show=holding(release, started, hosts={"10.0.0.2"}))

    async def main():
        fleet = Fleet(HOSTS, transport="junos", user="u", workers=2, session_timeout=5, command_timeout=5, retries=0)
        res = fleet.show("show version")
        assert started.wait(2)
        t0 = time.monotonic()
        timers.append(threading.Timer(0.3, fleet.close))
        timers[0].start()
        got = [r async for r in res]
        return got, time.monotonic() - t0

    timers = []
    try:
        got, elapsed = asyncio.run(main())
    finally:
        release.set()
        for t in timers:                                  # as above: the pool given back in this test
            t.join(5)
    assert 0.3 <= elapsed < 1.5, f"{elapsed:.1f}s: the consumer slept through the close"
    assert sorted(r.device for r in got) == ["10.0.0.1", "10.0.0.3"]


@pytest.mark.parametrize("refused", ["hssh-fleet-1", "hssh-fleet-2"], ids=["the first", "a later one"])
def test_a_worker_thread_the_system_refuses_ends_the_run_instead_of_hanging(monkeypatch, tmp_path, refused):
    """`ulimit -u` or memory pressure: Thread.start() raises, for the pool's
    first thread or for one it adds as the work grows. That is the caller's
    error, said at once; the run is recorded as skipped, no pool keeps a
    dead thread (and a Fleet left with no pool is not counted in the
    session pool), and the Fleet is usable once threads can start."""
    release = threading.Event()
    install(monkeypatch, show=holding(release, hosts={"10.0.0.1"}))   # in its call when a second thread is wanted
    refuse = [True]
    real_start = threading.Thread.start

    def start(self):
        if refuse[0] and self.name == refused:
            raise RuntimeError("can't start new thread")
        real_start(self)
    monkeypatch.setattr(threading.Thread, "start", start)
    path = tmp_path / "runs.db"
    try:
        with Fleet(HOSTS, transport="junos", user="u", store=str(path)) as fleet:
            with pytest.raises(RuntimeError, match="can't start new thread"):
                fleet.show("show version")
            run, = rows(path, "SELECT * FROM runs")
            assert run["finished"] is not None and (run["ok"], run["skipped"], run["interrupted"]) == (0, 3, 1)
            if refused == "hssh-fleet-1":
                assert fleet._workers is None and fleet_mod._POOL_FLEETS == 0   # no pool kept, nothing counted
            else:
                assert [t.name for t in fleet._workers.threads] == ["hssh-fleet-1"]   # no dead thread counted
                assert fleet_mod._POOL_FLEETS == 1
            refuse[0] = False
            release.set()
            got = list(fleet.show("show version"))                   # not BUSY: the failed run was ended
            assert len(got) == 3 and all(r.ok for r in got)
            assert all(t.is_alive() for t in fleet._workers.threads)
        assert fleet_mod._POOL_FLEETS == 0
    finally:
        release.set()


def test_close_with_a_grace_yields_the_device_that_finished_inside_it(monkeypatch, tmp_path):
    release, started = threading.Event(), threading.Event()
    install(monkeypatch, show=holding(release, started, hosts={"10.0.0.2", "10.0.0.3"}))
    path = tmp_path / "runs.db"
    fleet = Fleet(HOSTS, transport="junos", user="u", workers=1, store=str(path))
    res = fleet.show("show version")
    for r in res:
        break
    assert started.wait(2)                                   # 10.0.0.2 in flight, 10.0.0.3 queued
    threading.Timer(0.3, release.set).start()
    t0 = time.monotonic()
    fleet.close(wait=3)                                      # a Ctrl-C handler giving the devices a moment
    assert 0.25 <= time.monotonic() - t0 < 2                 # waited for the answer, not for the whole grace
    got = {d["device"]: d for d in res.to_dicts()}
    assert set(got) == {"10.0.0.1", "10.0.0.2"} and all(d["ok"] for d in got.values())
    run, = rows(path, "SELECT * FROM runs")
    assert (run["ok"], run["failed"], run["skipped"], run["interrupted"]) == (2, 0, 1, 1)
    assert sorted(r["device"] for r in rows(path, "SELECT * FROM results")) == ["10.0.0.1", "10.0.0.2"]


@pytest.mark.parametrize("how", ["for", "async for"])
def test_a_close_with_a_grace_skips_the_queued_devices_instead_of_failing_them(monkeypatch, tmp_path, how):
    """close(wait=) with devices still queued: a worker that frees up inside
    the grace drains the cancelled queue and notifies the consumer, which
    took those futures for results: a FAILED "every worker thread was held"
    row per device never started (no worker was held), the run finished
    and not interrupted. The promise is the README's: not started, skipped,
    the run interrupted."""
    hold, release, started = threading.Event(), threading.Event(), threading.Event()

    def show(host, user, passwd, cmd, *a, **kw):
        if host == "10.0.0.1":
            hold.wait(10)
        elif host == "10.0.0.2":
            started.set()
            release.wait(10)
        return f"{cmd} on {host}"

    install(monkeypatch, show=show)
    path = tmp_path / "runs.db"
    fleet = Fleet(HOSTS, transport="junos", user="u", workers=2, store=str(path))
    res = fleet.show("show version")                         # two in flight, 10.0.0.3 queued
    got = []

    async def collect():
        async for r in res:
            got.append(r)

    consumer = threading.Thread(target=(lambda: got.extend(res)) if how == "for" else (lambda: asyncio.run(collect())))
    consumer.start()
    queued = next(t for t in res._run.tasks if t.target.host == "10.0.0.3")
    try:
        assert started.wait(2)
        # The consumer waits on the queued device before the close cancels
        # it (cf.wait's waiter on the future; asyncio's callback once it is
        # wrapped): one that first looked after the cancel never sees it.
        assert wait_for(lambda: queued.future._waiters if how == "for" else len(queued.future._done_callbacks) > 1)
        closer = threading.Thread(target=fleet.close, kwargs={"wait": 5})
        closer.start()
        assert wait_for(lambda: queued.future.cancelled())   # close(wait=) under way: the queue is cancelled
        release.set()                                        # 10.0.0.2 answers: its worker drains the queue
        assert wait_for(lambda: any(r.device == "10.0.0.2" for r in got))
        time.sleep(0.2)                                      # time enough to mistake the notified queue for results
        hold.set()                                           # 10.0.0.1 answers: the grace is over
        closer.join(5)
        consumer.join(5)
        assert not closer.is_alive() and not consumer.is_alive()
    finally:
        hold.set()
        release.set()
    assert sorted(r.device for r in got) == ["10.0.0.1", "10.0.0.2"], [(r.device, r.error) for r in got]
    assert all(r.ok for r in got)
    run, = rows(path, "SELECT * FROM runs")
    assert (run["ok"], run["failed"], run["skipped"], run["interrupted"]) == (2, 0, 1, 1)
    assert sorted(r["device"] for r in rows(path, "SELECT * FROM results")) == ["10.0.0.1", "10.0.0.2"]


def test_a_close_with_a_grace_skips_the_queue_when_every_worker_is_held(monkeypatch, tmp_path):
    """close(wait=) under way when the one worker's call is given up on:
    with every worker held, the consumer fails what is still queued ("not
    started: every worker thread was held"). Those were the close's already,
    cancelled, and cancel() says yes again to a cancelled future; they are
    skipped and the run interrupted, as close() promises."""
    monkeypatch.setattr(fleet_mod, "GRACE_SECONDS", 0.2)
    release, started = threading.Event(), threading.Event()
    install(monkeypatch, show=holding(release, started, hosts={"10.0.0.1"}))
    path = tmp_path / "runs.db"
    fleet = Fleet(HOSTS, transport="junos", user="u", workers=1, session_timeout=1, command_timeout=1,
                  retries=0, store=str(path))
    res = fleet.show("show version")                         # 10.0.0.1 in flight, the other two queued
    got = []
    consumer = threading.Thread(target=lambda: got.extend(res))
    consumer.start()
    try:
        assert started.wait(2)
        closer = threading.Thread(target=fleet.close, kwargs={"wait": 10})
        closer.start()
        queued = [t for t in res._run.tasks if t.target.host != "10.0.0.1"]
        assert wait_for(lambda: all(t.future.cancelled() for t in queued))
        assert wait_for(lambda: fleet._stuck_count() == 1, 6)   # 10.0.0.1 given up on: every worker held
        time.sleep(0.2)                                      # time enough to fail the cancelled queue
        release.set()                                        # the call returns: the grace is over
        closer.join(5)
        consumer.join(5)
        assert not closer.is_alive() and not consumer.is_alive()
    finally:
        release.set()
    assert [(r.device, r.ok) for r in got] == [("10.0.0.1", False)], [(r.device, r.error) for r in got]
    assert got[0].error.startswith("no result within 3.2s")
    run, = rows(path, "SELECT * FROM runs")
    assert (run["ok"], run["failed"], run["skipped"], run["interrupted"]) == (0, 1, 2, 1)


def test_a_close_interrupted_in_its_grace_still_ends_the_run(monkeypatch, tmp_path):
    """Ctrl-C while close(wait=) gives the devices in flight their grace:
    the interrupt is the caller's, and close() still runs every step. The
    run used to be left as it was, its queue cancelled and nothing left to
    end it: a consumer on another thread waited for good, the run row open."""
    release, started = threading.Event(), threading.Event()
    install(monkeypatch, show=holding(release, started, hosts={"10.0.0.1", "10.0.0.2"}))
    real_wait = fleet_mod._Run.wait_for_inflight

    def interrupted(self, seconds):
        real_wait(self, 0.05)                                # the queue cancelled, the grace begun
        raise KeyboardInterrupt
    monkeypatch.setattr(fleet_mod._Run, "wait_for_inflight", interrupted)
    path = tmp_path / "runs.db"
    fleet = Fleet(HOSTS, transport="junos", user="u", workers=2, store=str(path))
    res = fleet.show("show version")                         # two in flight, 10.0.0.3 queued
    got = []
    consumer = threading.Thread(target=lambda: got.extend(res), daemon=True)
    consumer.start()
    try:
        assert started.wait(2)
        with pytest.raises(KeyboardInterrupt):
            fleet.close(wait=10)
        consumer.join(5)
        assert not consumer.is_alive(), "the consumer waits for a run nobody will end"
    finally:
        release.set()
        res._run.end(interrupted=True)                       # a no-op once close() ended it; else the consumer goes
    assert got == []                                         # nothing had answered when the run ended
    run, = rows(path, "SELECT * FROM runs")
    assert run["finished"] is not None
    assert (run["ok"], run["failed"], run["skipped"], run["interrupted"]) == (0, 0, 3, 1)


def test_close_keeps_the_results_of_devices_that_finished_unconsumed(monkeypatch, tmp_path):
    install(monkeypatch, show=echo)
    path = tmp_path / "runs.db"
    with Fleet(HOSTS, transport="junos", user="u", store=str(path)) as fleet:
        res = fleet.show("show version")                 # never iterated
        assert wait_for(lambda: all(t.future.done() for t in fleet._run.tasks))
    run, = rows(path, "SELECT * FROM runs")
    assert (run["ok"], run["failed"], run["skipped"], run["interrupted"]) == (3, 0, 0, 0)
    assert sorted(r["device"] for r in rows(path, "SELECT * FROM results")) == HOSTS
    assert sorted(d["device"] for d in res.to_dicts()) == HOSTS


# --- the store -------------------------------------------------------------------------

def test_the_store_gets_the_run_row_and_one_row_per_result(monkeypatch, tmp_path):
    def show(host, user, passwd, cmd, *a, **kw):
        if host == "10.0.0.2":
            raise RuntimeError("connect to 10.0.0.2 port 830: Connection timed out")
        return f"Hostname: {host}\nroot-authentication encrypted-password \"$9$zz\"\n"

    writers = set()
    real_add = Store.add_entry

    def add_entry(self, *a, **kw):
        writers.add(threading.get_ident())
        return real_add(self, *a, **kw)

    monkeypatch.setattr(Store, "add_entry", add_entry)
    install(monkeypatch, show=show)
    path = tmp_path / "runs.db"
    with Fleet(HOSTS, transport="junos", user="lab", store=str(path)) as fleet:
        res = fleet.show("show version")
        got = list(res)
    assert len(got) == 3 and res.not_kept == 0 and res.store_error is None
    run, = rows(path, "SELECT * FROM runs")
    assert run["mode"] == "show" and run["argv"] == "Fleet.show show version" and run["command"] == "show version"
    assert run["user"] == "lab" and run["origin"] == socket.gethostname() and run["version"] == hssh.__version__
    assert (run["targets"], run["ok"], run["failed"], run["skipped"], run["interrupted"]) == (3, 2, 1, 0, 0)
    assert run["finished"] is not None
    got_rows = {r["device"]: r for r in rows(path, "SELECT * FROM results")}
    assert set(got_rows) == set(HOSTS) and all(r["seq"] == 0 for r in got_rows.values())
    one = got_rows["10.0.0.1"]
    assert (one["host"], one["vendor"], one["command"], one["ok"], one["format"]) == ("10.0.0.1", "junos", "show version", 1, "text")
    assert one["output"] == "Hostname: 10.0.0.1\nroot-authentication encrypted-password \"$9$zz\""   # as it came, hash included
    assert one["duration_ms"] is not None and one["ts"]
    assert got_rows["10.0.0.2"]["ok"] == 0 and got_rows["10.0.0.2"]["output"] is None
    assert got_rows["10.0.0.2"]["error"] == "connect to 10.0.0.2 port 830: Connection timed out"
    assert writers == {threading.get_ident()}            # written from the iterating thread, never a worker


def test_store_loss_is_counted_and_said_but_never_raised(monkeypatch, tmp_path):
    install(monkeypatch, show=echo)
    real_add = Store.add_entry

    def add_entry(self, run_id, entry, *a, **kw):
        if entry["device"] == "10.0.0.2":
            raise sqlite3.OperationalError("disk I/O error")
        return real_add(self, run_id, entry, *a, **kw)

    monkeypatch.setattr(Store, "add_entry", add_entry)
    path = tmp_path / "runs.db"
    with Fleet(HOSTS, transport="junos", user="u", store=str(path)) as fleet:
        res = fleet.show("show version")
        with pytest.warns(RuntimeWarning) as said:
            got = list(res)                                  # every device's result still comes through
    assert sorted(r.device for r in got) == HOSTS and all(r.ok for r in got)
    assert res.not_kept == 1 and res.store_error == "disk I/O error"
    messages = [str(w.message) for w in said]
    run_id = res._run.store_run
    assert messages == [f"store {path}, run {run_id}: disk I/O error; the run goes on, its results are shown but not kept",
                        f"store {path}, run {run_id}: 1 of 3 results were not kept: disk I/O error"]
    run, = rows(path, "SELECT * FROM runs")
    assert run["finished"] is not None and (run["ok"], run["failed"]) == (3, 0)
    assert sorted(r["device"] for r in rows(path, "SELECT * FROM results")) == ["10.0.0.1", "10.0.0.3"]

    # the file deleted under the run: SQLite writes on without a word, so nothing of the run was kept
    monkeypatch.setattr(Store, "add_entry", real_add)
    finished = []
    monkeypatch.setattr(Store, "finish_run", lambda self, *a, **kw: finished.append(a))
    release = threading.Event()
    install(monkeypatch, show=holding(release, hosts={"10.0.0.2", "10.0.0.3"}))
    gone = tmp_path / "gone.db"
    try:
        with Fleet(HOSTS, transport="junos", user="u", store=str(gone)) as fleet:
            res = fleet.show("show version")
            with pytest.warns(RuntimeWarning, match="3 of 3 results were not kept: the store file was deleted during the run"):
                for r in res:
                    if r.device == "10.0.0.1":
                        os.remove(gone)
                        release.set()
    finally:
        release.set()
    assert res.not_kept == 3 and res.store_error == "the store file was deleted during the run"
    assert finished == []                                    # nothing kept: the run row is not closed


def test_store_loss_is_said_for_every_run_not_once_per_process(monkeypatch, tmp_path):
    """The default warning filter prints a message once per place it comes
    from, so a loop whose store kept losing rows was told once and then
    nothing. The message names the run: every run's loss is said. Nor does
    the filter keep each run's message for the life of the process: a
    long-lived loop whose store keeps failing grows nothing."""
    install(monkeypatch, show=echo)
    real_add = Store.add_entry

    def add_entry(self, run_id, entry, *a, **kw):
        if entry["device"] == "10.0.0.2":
            raise sqlite3.OperationalError("disk I/O error")
        return real_add(self, run_id, entry, *a, **kw)
    monkeypatch.setattr(Store, "add_entry", add_entry)
    ids = []
    with warnings.catch_warnings(record=True) as said:
        warnings.simplefilter("default")                     # a script's filter: once per message and place
        with Fleet(HOSTS, transport="junos", user="u", store=str(tmp_path / "runs.db")) as fleet:
            for _ in range(2):
                res = fleet.show("show version")
                assert len(list(res)) == 3 and res.not_kept == 1
                ids.append(res._run.store_run)
        kept = [k for k in vars(fleet_mod).get("__warningregistry__", {}) if any(f"run {i}:" in str(k) for i in ids)]
    lost = [str(w.message) for w in said]
    assert len(lost) == 4, lost                              # said as it happens and at the end, for each run
    assert all(f"run {ids[0]}:" in m for m in lost[:2]) and all(f"run {ids[1]}:" in m for m in lost[2:])
    assert ids[0] != ids[1]
    assert kept == []                                        # nothing kept per message: it was two a run, for good


def test_a_store_loss_a_filter_makes_an_error_still_ends_the_run(monkeypatch, tmp_path):
    """`python -W error`: the store-loss warning said as the run ends is
    raised there, out of the loop, as the filter asks. The run was over
    but never let go of: every later show() on the Fleet was refused as
    busy until close()."""
    install(monkeypatch, show=echo)
    real_finish = Store.finish_run
    failures = [sqlite3.OperationalError("disk I/O error")]

    def finish_run(self, *a, **kw):
        if failures:
            raise failures.pop()
        return real_finish(self, *a, **kw)
    monkeypatch.setattr(Store, "finish_run", finish_run)
    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        with Fleet(HOSTS, transport="junos", user="u", store=str(tmp_path / "runs.db")) as fleet:
            res = fleet.show("show version")
            with pytest.raises(RuntimeWarning, match=r", run \S+: disk I/O error$"):
                list(res)
            assert res._run.ended and res.store_error == "disk I/O error"
            again = list(fleet.show("show version"))         # not refused as busy
            assert len(again) == 3 and all(r.ok for r in again)


def test_a_store_write_that_raises_while_close_settles_still_ends_the_run(monkeypatch, tmp_path):
    """Under an 'error' warnings filter, a result that had returned but was
    never iterated, and that the store could not keep, raised out of end()
    before the run was ended: a consumer polled for good and the run row
    stayed open. The run ends whatever settling it raised."""
    release, returned = threading.Event(), threading.Event()

    def show(host, user, passwd, cmd, *a, **kw):
        if host == "10.0.0.2":
            returned.set()
        else:
            release.wait(10)
        return f"{cmd} on {host}"
    install(monkeypatch, show=show)
    real_add = Store.add_entry

    def add_entry(self, run_id, entry, *a, **kw):
        if entry["device"] == "10.0.0.2":
            raise sqlite3.OperationalError("disk I/O error")
        return real_add(self, run_id, entry, *a, **kw)
    monkeypatch.setattr(Store, "add_entry", add_entry)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", RuntimeWarning)
            fleet = Fleet([f"10.0.0.{i}" for i in range(1, 6)], transport="junos", user="u", workers=2,
                          retries=0, store=str(tmp_path / "runs.db"))
            res = fleet.show("show version")
            assert returned.wait(2)
            settled = next(t for t in res._run.tasks if t.target.host == "10.0.0.2")
            assert wait_for(lambda: settled.future.done())      # returned, never iterated
            with pytest.raises(RuntimeWarning, match="disk I/O error"):
                fleet.close()
        assert res._run.ended
        reader = threading.Thread(target=lambda: list(res), daemon=True)
        reader.start()
        reader.join(3)
        assert not reader.is_alive(), "iterating the closed run's results never ended"
        assert res.not_kept == 1 and res.store_error == "disk I/O error"
    finally:
        release.set()


def test_a_batch_is_one_row_per_command_and_an_open_store_is_left_open(monkeypatch, tmp_path):
    install(monkeypatch, show_batch=lambda host, user, passwd, cmds, *a, **kw:
            [{"command": c, "ok": c != "show nothing", **({"output": f"{c} on {host}"} if c != "show nothing"
                                                          else {"error": "refused"})} for c in cmds])
    path = tmp_path / "runs.db"
    store = Store(str(path))
    with Fleet(["R1:10.0.0.1:junos"], user="lab", store=store) as fleet:
        got = list(fleet.batch(["show version", "show nothing", "show route"]))
    assert len(got) == 1 and not got[0].ok
    run, = rows(path, "SELECT * FROM runs")
    assert run["mode"] == "show-batch" and run["argv"] == "Fleet.batch show version show nothing show route"
    assert run["command"] == "show version\nshow nothing\nshow route" and (run["ok"], run["failed"]) == (0, 1)
    got_rows = rows(path, "SELECT * FROM results ORDER BY seq")
    assert [(r["seq"], r["command"], r["ok"]) for r in got_rows] == \
        [(0, "show version", 1), (1, "show nothing", 0), (2, "show route", 1)]
    assert got_rows[1]["error"] == "refused" and got_rows[2]["output"] == "show route on 10.0.0.1"
    store.conn.execute("SELECT 1").fetchone()            # the caller's store: still open after the Fleet closed
    store.close()


def test_two_fleets_on_one_store_from_two_threads_keep_every_row(monkeypatch, tmp_path):
    """One Store handed to two Fleets, iterated on two threads: two threads
    inside one connection's transactions lost rows ("bad parameter or other
    API misuse", a SystemError out of the loop) beyond what not_kept
    counted, the run rows saying every result was kept. The store takes
    one write at a time."""
    from tests.test_store import writers_meet
    install(monkeypatch, show=lambda host, user, passwd, cmd, *a, **kw: "x" * 2000)
    path = tmp_path / "shared.db"
    store = Store(str(path))
    met = writers_meet(monkeypatch)                          # the two consumers inside one transaction at once?
    fleets = [Fleet([f"10.0.{n}.{i}" for i in range(1, 101)], transport="junos", user="u", workers=8, store=store)
              for n in (1, 2)]
    outcome = {}

    def consume(n, fleet):
        try:
            res = fleet.show("show version")
            outcome[n] = (len(list(res)), res.not_kept, res.store_error)
        except BaseException as e:            # pragma: no cover - the failure we are testing against
            outcome[n] = f"{type(e).__name__}: {e}"

    with warnings.catch_warnings(record=True) as said:
        warnings.simplefilter("always")
        threads = [threading.Thread(target=consume, args=(n, fleet)) for n, fleet in enumerate(fleets)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        for fleet in fleets:
            fleet.close()
    assert met == []                                         # never, whatever the scheduler does
    assert outcome == {0: (100, 0, None), 1: (100, 0, None)}
    assert [str(w.message) for w in said] == []
    assert rows(path, "SELECT COUNT(*) AS n FROM results")[0]["n"] == 200
    runs = rows(path, "SELECT * FROM runs")
    assert [(r["targets"], r["ok"], r["failed"], r["skipped"], r["finished"] is not None) for r in runs] == \
        [(100, 100, 0, 0, True)] * 2
    store.close()


def test_one_reply_is_the_same_row_whether_fleet_or_the_cli_kept_it(monkeypatch, tmp_path, capsys):
    """Fleet still joined the reply's splitlines(), which the CLI no longer
    does (#111): CR, NEL, VT, FF and U+2028/9 became LF in a Fleet row and
    stayed in a CLI row, so `h-ssh-store diff` between the two said the
    device had changed when it had not. A show and a batch's commands alike."""
    from tests.test_store import run_cli
    reply = ("interface Gi0/1\r\n description \x1b[31muplink\x1b[0m\x07\r\n"
             "nel\x85vt\x0bff\x0cls\u2028ps\u2029end\r\n shutdown \r\n")
    fake = install(monkeypatch, show=lambda *a, **kw: reply,
                   show_batch=lambda host, user, passwd, cmds, *a, **kw:
                   [{"command": c, "ok": True, "output": f"$ {c}\n{reply}"} for c in cmds])
    with Fleet(["R1:10.0.0.1:junos"], user="u", store=str(tmp_path / "fleet.db")) as fleet:
        assert all(r.ok for r in fleet.show("show version"))
        assert all(r.ok for r in fleet.batch(["show version", "show route"]))
    batch = tmp_path / "batch.txt"
    batch.write_text("show version\nshow route\n")
    for argv in (["-sC", "show version"], ["--batch", str(batch)]):
        rc, out, err = run_cli(monkeypatch, capsys, ["--store", str(tmp_path / "cli.db"),
                                                     "--target", "R1:10.0.0.1:junos", *argv], fake=fake)
        assert rc == 0, err
    sql = ("SELECT runs.mode, seq, results.command, format, output FROM results JOIN runs USING (run_id) "
           "ORDER BY runs.rowid, seq")
    kept = rows(tmp_path / "fleet.db", sql)
    assert kept == rows(tmp_path / "cli.db", sql) and [r["mode"] for r in kept] == ["show", "show-batch", "show-batch"]
    assert kept[0]["output"] == reply.rstrip()                    # a show: framed without its trailing whitespace
    assert kept[1]["output"] == kept[2]["output"] == reply.rstrip("\n")   # a batch's command: the echo dropped


def test_a_batch_reply_that_opens_like_the_runners_header_is_kept_whole(monkeypatch, tmp_path, capsys):
    """The CLI put each batch command's reply through the stripper of the
    runner's header, which takes leading DEVICE:/HOST:/MODE:/VENDOR: lines
    away: a reply that opens 'MODE: active-standby' lost that line in the
    row, --json and --raw, and no longer matched the row Fleet kept. A
    command's reply loses only the '$ cmd' echo, whoever keeps it."""
    from tests.test_store import run_cli
    reply = "MODE: active-standby\nVENDOR: none\nnode0 primary"
    fake = install(monkeypatch, show_batch=lambda host, user, passwd, cmds, *a, **kw:
                   [{"command": c, "ok": True, "output": f"{reply}\n"} for c in cmds])      # no echo, as NETCONF
    with Fleet(["R1:10.0.0.1:junos"], user="u", store=str(tmp_path / "fleet.db")) as fleet:
        assert all(r.ok for r in fleet.batch(["show chassis cluster status"]))
    batch = tmp_path / "batch.txt"
    batch.write_text("show chassis cluster status\n")
    argv = ["--store", str(tmp_path / "cli.db"), "--target", "R1:10.0.0.1:junos", "--batch", str(batch)]
    rc, out, err = run_cli(monkeypatch, capsys, [*argv, "--json"], fake=fake)
    assert rc == 0, err
    assert json.loads(out)[0]["commands"][0]["output"] == reply
    rc, out, err = run_cli(monkeypatch, capsys, [*argv, "--raw"], fake=fake)
    assert rc == 0 and out == f"R1:\n{reply}\n\n", err
    assert [r["output"] for r in rows(tmp_path / "fleet.db", "SELECT output FROM results")] == [reply]
    assert [r["output"] for r in rows(tmp_path / "cli.db", "SELECT output FROM results")] == [reply, reply]


def test_a_run_the_caller_never_finished_is_recorded_as_interrupted(monkeypatch, tmp_path):
    release, started = threading.Event(), threading.Event()
    install(monkeypatch, show=holding(release, started, hosts={"10.0.0.2", "10.0.0.3"}))
    path = tmp_path / "runs.db"
    try:
        with Fleet(HOSTS, transport="junos", user="lab", workers=1, store=str(path)) as fleet:
            for r in fleet.show("show version"):
                break                                      # one answer was enough
            assert started.wait(2)
        run, = rows(path, "SELECT * FROM runs")
        assert (run["ok"], run["failed"], run["skipped"], run["interrupted"]) == (1, 0, 2, 1)
        assert run["finished"] is not None
        assert [r["device"] for r in rows(path, "SELECT * FROM results")] == ["10.0.0.1"]
    finally:
        release.set()


# --- sessions pooled for the Fleet's lifetime ------------------------------------------------

def test_the_same_fleet_used_twice_reuses_its_sessions(monkeypatch):
    opened, closed = [], []

    def show(host, user, passwd, cmd, *a, **kw):
        with pool.POOL.get_connection((host, 830, user), opener=lambda: opened.append(host) or object(),
                                      closer=lambda dev: closed.append(host)):
            return f"{cmd} on {host}"

    install(monkeypatch, show=show)
    with Fleet(HOSTS, transport="junos", user="u") as fleet:
        assert not pool.POOL.enabled                        # nothing started yet
        assert all(r.ok for r in fleet.show("show version"))
        assert all(r.ok for r in fleet.show("show route summary"))
        assert pool.POOL.enabled and pool.live() == 3
        assert sorted(opened) == HOSTS                     # one session per device, not per command
        assert pool.POOL.stats["opens"] == 3 and pool.POOL.stats["reuses"] == 3
    assert sorted(closed) == HOSTS and pool.live() == 0 and not pool.POOL.enabled


def test_two_fleets_share_the_pool_and_a_callers_pool_is_left_alone(monkeypatch):
    install(monkeypatch, show=echo)
    a, b = Fleet(HOSTS, transport="junos", user="u"), Fleet(["10.0.9.9"], transport="junos", user="u")
    list(a.show("show version"))
    list(b.show("show version"))
    a.close()
    assert pool.POOL.enabled                                 # b still runs on it
    b.close()
    assert not pool.POOL.enabled                             # a Fleet turned it on: the last one turns it off
    pool.enable()                                            # the caller's own pool
    with Fleet(HOSTS, transport="junos", user="u") as fleet:
        list(fleet.show("show version"))
    assert pool.POOL.enabled                                 # never turned off by a Fleet
    with Fleet(HOSTS, transport="junos", user="u") as fleet:
        list(fleet.show("show version"))
        pool.disable()                                       # the caller changes their mind mid-way
    assert not pool.POOL.enabled


def test_a_fleet_dropped_without_close_lets_its_threads_go_and_the_pool_count_back(monkeypatch):
    """A function that makes a Fleet per request and returns the results
    without close(): the worker threads sat on their queue for the life of
    the process (50 requests: 195 threads) and the session pool stayed on,
    its count never coming down. Collected, a Fleet gives both back, as a
    dropped ThreadPoolExecutor ends its workers; one whose device's call
    raised too (the error's frames hold it in a cycle until then)."""
    refusing = set()

    def show(host, user, passwd, cmd, *a, **kw):
        if host in refusing:
            raise ConnectionRefusedError(111, "Connection refused")
        return f"{cmd} on {host}"
    install(monkeypatch, show=show)
    made = []                                                # the threads of this test's Fleets

    def request():
        fleet = Fleet(HOSTS, transport="junos", user="u", retries=0)
        oks = [r.ok for r in fleet.show("show version")]
        made.extend(fleet._workers.threads)
        return sorted(oks)

    def unread():
        fleet = Fleet(HOSTS, transport="junos", user="u")
        fleet.show("show version")                           # never iterated, never closed: a cycle through its run
        assert wait_for(lambda: all(t.future.done() for t in fleet._run.tasks))
        made.extend(fleet._workers.threads)

    for _ in range(5):
        assert request() == [True] * 3
    refusing.add("10.0.0.2")
    assert request() == [False, True, True]
    unread()
    deadline = time.monotonic() + 5
    while any(t.is_alive() for t in made) and time.monotonic() < deadline:
        gc.collect()
        time.sleep(0.05)
    assert not any(t.is_alive() for t in made)
    assert fleet_mod._POOL_FLEETS == 0 and not pool.POOL.enabled


@pytest.mark.parametrize("how", ["for", "async for"])
def test_a_fleet_read_to_the_end_and_dropped_goes_with_its_last_reference(monkeypatch, how):
    """A Fleet per request, its results read to the end, every call
    returned, then dropped: it goes with its last reference, as a
    ThreadPoolExecutor does, and gives its threads and the pool back then,
    no collector pass needed. Each device's future held a callback that
    held its task and the Fleet, a cycle: such Fleets piled up, threads and
    all, until the collector came round to them. (A call that raised, or a
    first import on a worker, leaves frames in a cycle that hold the Fleet
    until the collector's next pass: the test above.)"""
    from hssh.transports import netconf  # noqa: F401 - imported here, not for the first time on a worker
    install(monkeypatch, show=echo)

    async def read(fleet):
        return [r.ok async for r in fleet.show_async("show version")]

    threads = []
    gc.disable()                                             # reference counts only
    try:
        fleet = Fleet(HOSTS, transport="junos", user="u")
        got = [r.ok for r in fleet.show("show version")] if how == "for" else asyncio.run(read(fleet))
        assert got == [True] * 3
        threads, gone = fleet._workers.threads, weakref.ref(fleet)
        del fleet
        outlived = gone() is not None                        # not in the assert: its report would keep the Fleet
        assert not outlived, "the Fleet outlived its last reference"
        assert wait_for(lambda: not any(t.is_alive() for t in threads), 5)
        assert fleet_mod._POOL_FLEETS == 0 and not pool.POOL.enabled
    finally:
        gc.enable()
        gc.collect()                                         # a Fleet that outlived it gives the pool back here,
        wait_for(lambda: not any(t.is_alive() for t in threads), 5)    # not in a later test's count


def test_a_fleet_collected_inside_the_pool_lock_gives_the_pool_back_without_a_hang(monkeypatch):
    """The collector runs on whatever thread it lands on: inside
    _pool_acquire()'s lock, say, as another Fleet starts. A dropped Fleet's
    release taken there, on that thread, would wait for that very lock and
    hang the run for good; it is done on the dropped Fleet's own worker."""
    install(monkeypatch, show=echo)
    monkeypatch.setattr(fleet_mod, "_POOL_LOCK", threading.Lock())   # a hang would hold this one, not the module's

    def drop():
        fleet = Fleet(HOSTS, transport="junos", user="u")
        fleet.show("show version")                           # never iterated: the run and the Fleet hold each other
        assert wait_for(lambda: all(t.future.done() for t in fleet._run.tasks))
        return fleet._workers.threads

    gc.disable()                                                     # the collection runs where this test says
    try:
        threads = drop()
        real_enable = pool.enable

        def enable(*a, **kw):
            gc.collect()                                     # the collector, here: under _POOL_LOCK
            return real_enable(*a, **kw)
        monkeypatch.setattr(pool, "enable", enable)
        got = []

        def another():
            with Fleet(HOSTS, transport="junos", user="u") as fleet:
                got.extend(r.ok for r in fleet.show("show version"))
        t = threading.Thread(target=another, daemon=True)
        t.start()
        t.join(5)
        assert not t.is_alive(), "the run hung in _pool_acquire()"
        assert got == [True] * 3
        assert wait_for(lambda: not any(w.is_alive() for w in threads))
        assert fleet_mod._POOL_FLEETS == 0 and not pool.POOL.enabled
    finally:
        gc.enable()


def test_a_refused_reaper_thread_leaves_the_pool_count_at_zero(monkeypatch):
    """`ulimit -u` at the first run: the session pool's cleanup thread cannot
    start. The error is the caller's at once; the pool stays off and
    uncounted (it was counted as this Fleet's and left on, reaper or not),
    and the Fleet runs once threads can start."""
    install(monkeypatch, show=echo)
    refuse = [True]
    real_start = threading.Thread.start

    def start(self):
        if refuse[0] and self.name == "hssh-pool-cleanup":
            raise RuntimeError("can't start new thread")
        real_start(self)
    monkeypatch.setattr(threading.Thread, "start", start)
    with Fleet(HOSTS, transport="junos", user="u") as fleet:
        with pytest.raises(RuntimeError, match="can't start new thread"):
            fleet.show("show version")
        assert fleet_mod._POOL_FLEETS == 0 and not pool.POOL.enabled and fleet._workers is None
        refuse[0] = False
        assert all(r.ok for r in fleet.show("show version"))     # not BUSY: the refused run was ended
        assert fleet_mod._POOL_FLEETS == 1 and pool.POOL.enabled
    assert fleet_mod._POOL_FLEETS == 0 and not pool.POOL.enabled


def test_a_transport_traceback_stays_off_stderr_unless_the_caller_set_up_logging(monkeypatch, capsys):
    """paramiko logs a traceback at ERROR from its transport thread when a
    wedged device drops the connection mid-handshake, ncclient from its
    session's; with no logging set up, Python's last-resort handler printed
    it to stderr under the library, next to the failed result that says
    the same. (PyEZ quiets paramiko when it is imported; an ssh fleet never
    imports it, and nothing quieted ncclient.) Both get a NullHandler, as
    the CLI gives them; a caller who sets up logging still gets the records."""
    def show(host, user, passwd, cmd, *a, **kw):
        for name in ("paramiko.transport", "ncclient.transport.ssh"):
            try:
                raise EOFError()
            except EOFError:
                logging.getLogger(name).error("Error reading SSH protocol banner", exc_info=True)
        raise RuntimeError(f"no SSH banner from {host}:22 within 1s")

    install(monkeypatch, show=show)
    transports = [logging.getLogger(name) for name in ("paramiko", "ncclient")]
    levels = [lg.level for lg in transports]
    for lg in transports:                                    # as a fresh process has them: the CLI's tests quiet them
        monkeypatch.setattr(lg, "handlers", [])
        lg.setLevel(logging.NOTSET)
    pytests = logging.root.handlers[:]
    logging.root.handlers[:] = []                            # no logging set up, as in a plain script
    try:
        with Fleet(HOSTS, transport="ssh", user="u", retries=0) as fleet:
            assert not any(r.ok for r in fleet.show("show version"))
        err = capsys.readouterr().err
        assert "Error reading SSH protocol banner" not in err and "Traceback" not in err, err
        seen = []
        handler = logging.Handler()
        handler.emit = lambda record: seen.append(record.getMessage())
        logging.root.handlers[:] = [handler]                 # the caller's own logging
        with Fleet(HOSTS, transport="ssh", user="u", retries=0) as fleet:
            list(fleet.show("show version"))
        assert seen.count("Error reading SSH protocol banner") == 6            # three devices, two loggers
    finally:
        logging.root.handlers[:] = pytests
        for lg, level in zip(transports, levels):
            lg.setLevel(level)


def test_a_netconf_fleet_logs_in_once_per_device(monkeypatch):
    from hssh.transports import netconf
    from tests.test_junos import FakeConfig, FakeDevice
    FakeDevice.instances = []
    FakeDevice.open_error = None
    FakeDevice.cli_outputs = {"show version": "v", "show route summary": "r"}
    monkeypatch.setattr(netconf, "AVAILABLE", True)
    monkeypatch.setattr(netconf, "JunosDevice", FakeDevice)
    monkeypatch.setattr(netconf, "JunosConfig", FakeConfig)
    with Fleet(["R1:10.0.0.1:junos", "R2:10.0.0.2:junos"], user="u", passwd="p") as fleet:
        assert {r.device: r.output for r in fleet.show("show version")} == {"R1": "v", "R2": "v"}
        assert {r.device: r.output for r in fleet.show("show route summary")} == {"R1": "r", "R2": "r"}
        assert len(FakeDevice.instances) == 2 and not any(d.closed for d in FakeDevice.instances)
    assert all(d.closed for d in FakeDevice.instances) and pool.live() == 0


def test_close_waits_up_to_close_wait_for_the_routers_to_acknowledge(monkeypatch):
    """close() turns the pool off, and the pool waits for the closes it
    starts before it collects what they leave (#113): until a router has
    acknowledged, pool.CLOSE_WAIT at most. CLOSE_WAIT was read at import,
    so setting it changed nothing: a second, always."""
    from hssh.transports import netconf
    from tests.test_junos import FakeConfig, FakeDevice
    release = threading.Event()

    class Acks(FakeDevice):
        def close(self):
            if self.params["host"] == "10.0.0.2":
                release.wait(5)                  # no acknowledgement, as far as close() waits
            else:
                time.sleep(0.05)                 # the round trip of a <close-session>
            super().close()
    FakeDevice.instances = []
    FakeDevice.open_error = None
    FakeDevice.cli_outputs = {}
    monkeypatch.setattr(netconf, "AVAILABLE", True)
    monkeypatch.setattr(netconf, "JunosDevice", Acks)
    monkeypatch.setattr(netconf, "JunosConfig", FakeConfig)
    monkeypatch.setattr(pool, "CLOSE_WAIT", 0.3)
    try:
        fleet = Fleet(["R1:10.0.0.1:junos", "R2:10.0.0.2:junos"], user="u", passwd="p")
        assert all(r.ok for r in fleet.show("show version"))
        t0 = time.monotonic()
        fleet.close()
        elapsed = time.monotonic() - t0
        r1, r2 = sorted(FakeDevice.instances, key=lambda d: d.params["host"])
        assert r1._closed and not r2._closed                 # waited for the router that answered
        assert 0.25 <= elapsed < 0.9, f"{elapsed:.2f}s"       # and CLOSE_WAIT for the other, no more
    finally:
        release.set()
    assert netconf.wait_for_closes(2) == 0 and r2._closed


# --- targets, credentials, refusals ---------------------------------------------------------

def test_targets_in_every_form_are_accepted(monkeypatch, tmp_path):
    install(monkeypatch, show=echo, names=("junos@netconf", "none@ssh", "ios@telnet"))
    csv = tmp_path / "devices.csv"
    csv.write_text("name,ip,vendor\nR9,10.0.0.9,junos\nR8,10.0.0.8\n")
    fleet = Fleet(["10.0.0.1", "cr1:10.0.0.2:junos", "sw1:10.0.0.3:5000:telnet-ios", "[2001:db8::1]",
                   Target(name="R4", host="10.0.0.4", vendor="ssh"), csv], transport="junos", user="u")
    assert [(t.name, t.host, t.vendor, t.port) for t in fleet.targets] == [
        ("10.0.0.1", "10.0.0.1", "junos", None), ("cr1", "10.0.0.2", "junos", None),
        ("sw1", "10.0.0.3", "telnet-ios", 5000), ("2001:db8::1", "2001:db8::1", "junos", None),
        ("R4", "10.0.0.4", "ssh", None), ("R9", "10.0.0.9", "junos", None), ("R8", "10.0.0.8", "junos", None)]
    assert len(fleet) == 7
    with fleet:
        assert sorted(r.device for r in fleet.show("show version")) == sorted(t.name for t in fleet.targets)
    # one string: an existing file is the inventory, a path that is not there is refused, anything else one target
    assert [t.name for t in Fleet(str(csv), user="u").targets] == ["R9", "R8"]
    assert Fleet(str(csv), user="u").targets[1].vendor == "ssh"                          # the default transport
    assert Fleet("10.0.0.1", user="u").targets == (Target(name="10.0.0.1", host="10.0.0.1", vendor="ssh"),)
    assert Fleet("cr1:10.0.0.1:junos", user="u").targets == (Target(name="cr1", host="10.0.0.1", vendor="junos"),)
    for mistyped in ("nowhere.csv", "inv/devices", "fleet.yaml", "core.yml", "devices.json"):
        with pytest.raises(ValueError, match=f"no inventory file at '{mistyped}'"):
            Fleet(mistyped, user="u")
    assert Fleet(Target(name="one", host="10.0.0.1"), user="u").targets[0].name == "one"
    with pytest.raises(FileNotFoundError):
        Fleet(Path("nowhere.csv"), user="u")                                             # a Path is always a file


def test_duplicates_and_bad_arguments_are_refused_before_anything_runs(monkeypatch):
    sent = []
    install(monkeypatch, show=lambda host, *a, **kw: sent.append(host) or "x")
    with pytest.raises(ValueError, match="listed twice"):
        Fleet(["10.0.0.1", "10.0.0.1"], user="u")
    with pytest.raises(ValueError, match="listed under two names"):
        Fleet(["R1:10.0.0.1:junos", "R2:10.0.0.1:junos"], user="u")
    with pytest.raises(ValueError, match="host 10.0.0.1:830 is listed under two names: 'R1' and 'R2'"):
        Fleet(["R1:10.0.0.1:junos", "R2:10.0.0.1:830:junos"], user="u")        # #110: 830 is R1's port too
    with pytest.raises(ValueError, match="used for two hosts"):
        Fleet(["R1:10.0.0.1:junos", "R1:10.0.0.2:junos"], user="u")
    with pytest.raises(ValueError, match="Unknown vendor"):
        Fleet(["R1:10.0.0.1:nope"], user="u")
    with pytest.raises(ValueError, match="no targets"):
        Fleet([], user="u")
    with pytest.raises(TypeError):
        Fleet([42], user="u")
    with pytest.raises(ValueError, match="workers must be 1..256"):
        Fleet(HOSTS, user="u", workers=0)
    with pytest.raises(ValueError, match="workers must be 1..256"):
        Fleet(HOSTS, user="u", workers=1000)
    with pytest.raises(ValueError, match="session_timeout must be at least 1, got 0"):
        Fleet(HOSTS, user="u", session_timeout=0)
    with pytest.raises(ValueError, match="connect_timeout must be at least 1, got 0"):
        Fleet(HOSTS, user="u", connect_timeout=0)
    with pytest.raises(ValueError, match="command_timeout must be an integer, not 0.5"):
        Fleet(HOSTS, user="u", command_timeout=0.5)
    with pytest.raises(ValueError, match="command_timeout must be an integer, not '20'"):
        Fleet(HOSTS, user="u", command_timeout="20")
    with pytest.raises(ValueError, match="retries must be at least 0"):
        Fleet(HOSTS, user="u", retries=-1)
    with pytest.raises(ValueError, match="passwd: empty; pass None for keys or an agent"):
        Fleet(HOSTS, user="u", passwd="")
    with pytest.raises(TypeError, match="passwd must be a str or None"):
        Fleet(HOSTS, user="u", passwd=b"secret")
    fleet = Fleet(HOSTS, user="u")
    with pytest.raises(ValueError, match="show needs a command"):
        fleet.show("   ")
    with pytest.raises(TypeError, match="batch takes a list"):
        fleet.batch("show version")
    with pytest.raises(ValueError, match="none of them empty"):
        fleet.batch(["show version", ""])
    fleet.close()
    with pytest.raises(RuntimeError, match="closed"):
        fleet.show("show version")
    fleet.close()                                            # a second close is nothing
    assert sent == []


def test_user_defaults_to_the_login_name_and_the_environment_is_not_read(monkeypatch):
    seen = []

    def show(host, user, passwd, cmd, *a, **kw):
        seen.append((user, passwd, kw.get("vendor_hint"), kw.get("port")))
        return "x"

    install(monkeypatch, show=show)
    monkeypatch.setenv("HSSH_USER", "someone-else")
    monkeypatch.setenv("HSSH_PASSWORD", "not-this")
    with Fleet(["R1:10.0.0.1:830:junos"]) as fleet:
        assert fleet.user == getpass.getuser() and fleet.retries == 2      # the CLI's defaults
        list(fleet.show("show version"))
    assert seen == [(getpass.getuser(), None, "junos@netconf", 830)]
    with Fleet(["10.0.0.1"], transport="junos", user="admin", passwd="s3cret") as fleet:
        list(fleet.show("show version"))
    assert seen[-1] == ("admin", "s3cret", "junos@netconf", None)
    assert repr(fleet) == "Fleet(1 target(s), transport='junos', user='admin', workers=32)"
