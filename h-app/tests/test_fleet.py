"""The Fleet library API (hssh.fleet): commands across many devices from a
script, results as values in completion order, no thread in sight. Every
device here is a fake driver in drivers.MODULES; nothing is contacted."""
import asyncio
import concurrent.futures as cf
import getpass
import json
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import types
import warnings
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
    assert limits.fit_workers_to_open_files(4) == cli.fit_workers_to_open_files(4)
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
            assert elapsed < 4, f"{elapsed:.1f}s: the run waited for the hung device"
            hung = got["10.0.0.2"]
            assert not hung.ok and hung.output is None
            assert hung.error == ("no result within 2.2s (1 attempt(s) at session_timeout 1s + command_timeout 1s, "
                                  "plus 0.2s): the transport call has not returned")
            assert hung.duration_ms >= 2200
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
        assert elapsed < 4, f"{elapsed:.1f}s"
        assert [r.ok for r in got] == [False, False, False]
        assert got[0].error.startswith("no result within 2.2s")
        assert all(r.error.startswith("not started: every worker thread (1) is held") for r in got[1:])
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
                    assert bad["10.0.0.9"].startswith("no result within 2.1s") and elapsed >= 2.1
                else:
                    assert bad["10.0.0.9"] == "the previous call to this device has not returned"
                    assert elapsed < 1.5, f"run {n}: {elapsed:.1f}s"
                assert fleet._stuck_count() == 1
    finally:
        never.set()


def test_the_budget_counts_the_transports_connect_phases():
    fleet = Fleet(["R1:10.0.0.1:junos", "R2:10.0.0.2:ssh", "R3:10.0.0.3:ios@openssh", "R4:10.0.0.4:telnet-ios"],
                  user="u", session_timeout=2, command_timeout=3, retries=1)
    r1, r2, r3, r4 = fleet.targets
    grace = fleet_mod.GRACE_SECONDS
    assert fleet_mod._budget(fleet, r1, 1) == 2 * (2 + 3) + 1 + grace          # NETCONF: one deadline for the set-up
    assert fleet_mod._budget(fleet, r2, 1) == 2 * (3 * 2 + 3) + 1 + grace      # paramiko: connect, banner, auth
    assert fleet_mod._budget(fleet, r3, 1) == fleet_mod._budget(fleet, r4, 1) == fleet_mod._budget(fleet, r2, 1)
    assert fleet_mod._budget(fleet, r1, 2) == 2 * (2 + 3 * 2) + 1 + grace      # a batch: a timeout per command
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
        "           retries=0) as fleet:\n"
        "    r, = fleet.show('show version')\n"
        "    print(r.ok, r.error, flush=True)\n")
    env = {**os.environ, "PYTHONPATH": os.path.dirname(os.path.dirname(hssh.__file__))}
    started = time.monotonic()
    proc = subprocess.run([sys.executable, str(script)], env=env, capture_output=True, text=True, timeout=30)
    elapsed = time.monotonic() - started
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("False no result within 2.1s")
    assert elapsed < 4.0, f"{elapsed:.1f}s: the interpreter waited for the wedged thread"


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
    try:
        fleet = Fleet(HOSTS, transport="junos", user="u", workers=2, session_timeout=5, command_timeout=5, retries=0)
        res = fleet.show("show version")
        assert started.wait(2)
        t0 = time.monotonic()
        threading.Timer(0.3, fleet.close).start()
        got = list(res)                                   # the two that answered; the close ends the wait
        elapsed = time.monotonic() - t0
        assert 0.3 <= elapsed < 1.5, f"{elapsed:.1f}s: the consumer slept through the close"
        assert sorted(r.device for r in got) == ["10.0.0.1", "10.0.0.3"] and all(r.ok for r in got)
    finally:
        release.set()


def test_a_close_from_another_thread_wakes_an_async_consumer_at_once(monkeypatch):
    release, started = threading.Event(), threading.Event()
    install(monkeypatch, show=holding(release, started, hosts={"10.0.0.2"}))

    async def main():
        fleet = Fleet(HOSTS, transport="junos", user="u", workers=2, session_timeout=5, command_timeout=5, retries=0)
        res = fleet.show("show version")
        assert started.wait(2)
        t0 = time.monotonic()
        threading.Timer(0.3, fleet.close).start()
        got = [r async for r in res]
        return got, time.monotonic() - t0

    try:
        got, elapsed = asyncio.run(main())
    finally:
        release.set()
    assert 0.3 <= elapsed < 1.5, f"{elapsed:.1f}s: the consumer slept through the close"
    assert sorted(r.device for r in got) == ["10.0.0.1", "10.0.0.3"]


def test_a_worker_thread_the_system_refuses_ends_the_run_instead_of_hanging(monkeypatch, tmp_path):
    """`ulimit -u` or memory pressure: Thread.start() raises. That is the
    caller's error, said at once; the run is recorded as skipped, the pool
    counts no dead thread, and the Fleet is usable once threads can start."""
    install(monkeypatch, show=echo)
    refuse = [True]
    real_start = threading.Thread.start

    def start(self):
        if refuse[0] and self.name.startswith("hssh-fleet-"):
            raise RuntimeError("can't start new thread")
        real_start(self)
    monkeypatch.setattr(threading.Thread, "start", start)
    path = tmp_path / "runs.db"
    with Fleet(HOSTS, transport="junos", user="u", store=str(path)) as fleet:
        with pytest.raises(RuntimeError, match="can't start new thread"):
            fleet.show("show version")
        run, = rows(path, "SELECT * FROM runs")
        assert run["finished"] is not None and (run["ok"], run["skipped"], run["interrupted"]) == (0, 3, 1)
        assert fleet._workers.threads == []                          # no dead thread counted
        refuse[0] = False
        got = list(fleet.show("show version"))                       # not BUSY: the failed run was ended
        assert len(got) == 3 and all(r.ok for r in got)
        assert all(t.is_alive() for t in fleet._workers.threads)


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
    assert messages == [f"store {path}: disk I/O error; the run goes on, its results are shown but not kept",
                        f"store {path}: 1 of 3 results were not kept: disk I/O error"]
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
