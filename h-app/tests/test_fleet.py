"""The Fleet library API (hssh.fleet): commands across many devices from a
script, results as values in completion order, no thread in sight. Every
device here is a fake driver in drivers.MODULES; nothing is contacted."""
import asyncio
import getpass
import json
import socket
import sqlite3
import threading
import time
import types

import pytest

import hssh
from hssh import Fleet, drivers, pool
from hssh import fleet as fleet_mod
from hssh.core import Target
from hssh.fleet import DeviceResult, Results
from hssh.store import Store

HOSTS = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


@pytest.fixture(autouse=True)
def clean_pool():
    def reset():
        pool.close_all()
        pool.disable()
        fleet_mod._POOL_FLEETS = 0
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


def rows(path, sql, *params):
    c = sqlite3.connect(str(path))
    c.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in c.execute(sql, params).fetchall()]
    finally:
        c.close()


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

    def show(host, user, passwd, cmd, *a, **kw):
        with guard:
            state["now"] += 1
            state["peak"] = max(state["peak"], state["now"])
        time.sleep(0.05)
        with guard:
            state["now"] -= 1
        return "ok"

    install(monkeypatch, show=show)
    hosts = [f"10.0.1.{i}" for i in range(1, 10)]
    with Fleet(hosts, transport="junos", user="u", workers=3) as fleet:
        got = list(fleet.show("show version"))
    assert len(got) == 9 and all(r.ok for r in got)
    assert 2 <= state["peak"] <= 3


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
    with Fleet(HOSTS, transport="junos", user="u", retries=2) as fleet:
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

    def show(host, user, passwd, cmd, *a, **kw):
        if host == "10.0.0.2":
            release.wait(10)          # ignores its timeouts, as a wedged transport would
        return "fine"

    install(monkeypatch, show=show)
    try:
        started = time.monotonic()
        with Fleet(HOSTS, transport="junos", user="u", session_timeout=0.2, command_timeout=0.3) as fleet:
            got = {r.device: r for r in fleet.show("show version")}
            elapsed = time.monotonic() - started
            assert elapsed < 2.5, f"{elapsed:.1f}s: the run waited for the hung device"
            hung = got["10.0.0.2"]
            assert not hung.ok and hung.output is None
            assert hung.error.startswith("no result within 0.7s (1 attempt(s) at session_timeout 0.2s + "
                                         "command_timeout 0.3s, plus 0.2s): the transport call has not returned")
            assert hung.duration_ms >= 700
            assert got["10.0.0.1"].ok and got["10.0.0.3"].ok
            # the hung thread holds a worker; the rest of the fleet still runs
            assert [r.ok for r in fleet.show("show version") if r.device != "10.0.0.2"] == [True, True]
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
        with Fleet(HOSTS, transport="junos", user="u", workers=1, session_timeout=0.2, command_timeout=0.2) as fleet:
            got = list(fleet.show("show version"))
        elapsed = time.monotonic() - started
        assert elapsed < 2.5, f"{elapsed:.1f}s"
        assert [r.ok for r in got] == [False, False, False]
        assert got[0].error.startswith("no result within 0.6s")
        assert all(r.error.startswith("not started: every worker thread (1) is held") for r in got[1:])
        assert seen == ["10.0.0.1"]                                   # the others were never sent
    finally:
        release.set()


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


def test_batch_async_and_a_cancelled_consumer_leave_the_run_intact(monkeypatch):
    install(monkeypatch, show_batch=lambda host, user, passwd, cmds, *a, **kw:
            [{"command": c, "ok": True, "output": c} for c in cmds])

    async def main(fleet):
        got = []
        async for r in fleet.batch_async(["show a", "show b"]):
            got.append(r)
        return got

    with Fleet(HOSTS, transport="junos", user="u") as fleet:
        got = asyncio.run(main(fleet))
    assert sorted(r.device for r in got) == HOSTS and all(len(r.commands) == 2 for r in got)


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
        got = list(fleet.show("show version"))
    assert len(got) == 3
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
    release = threading.Event()

    def show(host, user, passwd, cmd, *a, **kw):
        if host != "10.0.0.1":
            release.wait(10)
        return "fine"

    install(monkeypatch, show=show)
    path = tmp_path / "runs.db"
    try:
        with Fleet(HOSTS, transport="junos", user="lab", workers=1, store=str(path)) as fleet:
            for r in fleet.show("show version"):
                break                                      # one answer was enough
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
    assert not pool.POOL.enabled
    pool.enable()                                            # the caller's own pool
    with Fleet(HOSTS, transport="junos", user="u") as fleet:
        list(fleet.show("show version"))
    assert pool.POOL.enabled


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
    assert [t.name for t in Fleet(str(csv), user="u").targets] == ["R9", "R8"]          # a str is an inventory
    assert Fleet(str(csv), user="u").targets[1].vendor == "ssh"                          # the default transport
    assert Fleet(Target(name="one", host="10.0.0.1"), user="u").targets[0].name == "one"


def test_duplicates_and_bad_arguments_are_refused_before_anything_runs(monkeypatch):
    sent = []
    install(monkeypatch, show=lambda host, *a, **kw: sent.append(host) or "x")
    with pytest.raises(ValueError, match="listed twice"):
        Fleet(["10.0.0.1", "10.0.0.1"], user="u")
    with pytest.raises(ValueError, match="listed under two names"):
        Fleet(["R1:10.0.0.1:junos", "R2:10.0.0.1:junos"], user="u")
    with pytest.raises(ValueError, match="used for two hosts"):
        Fleet(["R1:10.0.0.1:junos", "R1:10.0.0.2:junos"], user="u")
    with pytest.raises(ValueError, match="Unknown vendor"):
        Fleet(["R1:10.0.0.1:nope"], user="u")
    with pytest.raises(ValueError, match="no targets"):
        Fleet([], user="u")
    with pytest.raises(TypeError):
        Fleet([42], user="u")
    with pytest.raises(FileNotFoundError):
        Fleet("nowhere.csv", user="u")
    with pytest.raises(ValueError, match="workers must be 1..256"):
        Fleet(HOSTS, user="u", workers=0)
    with pytest.raises(ValueError, match="workers must be 1..256"):
        Fleet(HOSTS, user="u", workers=1000)
    with pytest.raises(ValueError, match="session_timeout must be a number of seconds above 0"):
        Fleet(HOSTS, user="u", session_timeout=0)
    with pytest.raises(ValueError, match="command_timeout must be a number of seconds above 0"):
        Fleet(HOSTS, user="u", command_timeout="20")
    with pytest.raises(ValueError, match="retries must be at least 0"):
        Fleet(HOSTS, user="u", retries=-1)
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
        assert fleet.user == getpass.getuser()
        list(fleet.show("show version"))
    assert seen == [(getpass.getuser(), None, "junos@netconf", 830)]
    with Fleet(["10.0.0.1"], transport="junos", user="admin", passwd="s3cret") as fleet:
        list(fleet.show("show version"))
    assert seen[-1] == ("admin", "s3cret", "junos@netconf", None)
    assert repr(fleet) == "Fleet(1 target(s), transport='junos', user='admin', workers=32)"
