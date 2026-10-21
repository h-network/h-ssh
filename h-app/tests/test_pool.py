"""Session pool: reuse, isolation per router, discard on failure, reaping,
and the junos driver's behaviour on a pooled session."""
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hssh import pool
from hssh.errors import AmbiguousCommitError, NotAppliedError
from hssh.vendors import junos
from tests.test_junos import FakeConfig, FakeDevice, FakeHost, rpc_timeout


@pytest.fixture(autouse=True)
def fake_pyez(monkeypatch):
    FakeDevice.instances = []
    FakeDevice.open_error = None
    FakeDevice.cli_outputs = {}
    FakeConfig.instances = []
    FakeConfig.diff_text = "[edit]\n+  system host-name r1;"
    FakeConfig.raise_on = {}
    monkeypatch.setattr(junos, "AVAILABLE", True)
    monkeypatch.setattr(junos, "JunosDevice", FakeDevice)
    monkeypatch.setattr(junos, "JunosConfig", FakeConfig)
    yield
    pool.POOL.disable()
    for k in pool.POOL.stats:
        pool.POOL.stats[k] = 0


@pytest.fixture
def pooled():
    pool.enable(idle_timeout=300)
    yield pool.POOL


def show(host="10.0.0.1", cmd="show version", timeout=30, **kw):
    return junos.show(host, "u", None, cmd, 5, timeout, **kw)


def devices():
    return FakeDevice.instances


def in_threads(target, kwargs_list):
    """Run target in one thread per kwargs; re-raise the first worker error."""
    errors = []

    def wrap(kw):
        try:
            target(**kw)
        except Exception as e:  # pragma: no cover - only on failure
            errors.append(e)

    threads = [threading.Thread(target=wrap, args=(kw,)) for kw in kwargs_list]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        raise errors[0]


# --- off by default -----------------------------------------------------

def test_disabled_is_one_session_per_call():
    show()
    show()
    assert len(devices()) == 2
    assert all(d.closed for d in devices())
    assert pool.POOL.stats["opens"] == 0


def test_idle_timeout_default_and_override():
    pool.enable()
    assert pool.POOL.idle_timeout == 300
    pool.enable(idle_timeout=60)
    assert pool.POOL.idle_timeout == 60


# --- reuse --------------------------------------------------------------

def test_same_router_reuses_one_session(pooled):
    for _ in range(3):
        assert show() == "output of show version"
    assert len(devices()) == 1
    assert not devices()[0].closed
    assert devices()[0].cli_calls == ["show version"] * 3
    assert pooled.stats == {"opens": 1, "reuses": 2, "discards": 0, "reaped": 0}
    assert pooled.live() == 1


def test_key_is_host_port_and_user(pooled):
    show(host="10.0.0.1")
    show(host="10.0.0.2")
    show(host="10.0.0.1", port=22)
    junos.show("10.0.0.1", "other", None, "show version", 5, 30)
    show(host="10.0.0.1")
    assert len(devices()) == 4
    assert pooled.stats["reuses"] == 1


def test_command_timeout_follows_each_call(pooled):
    show(timeout=10)
    show(timeout=99)
    assert devices()[0].timeout == 99


def test_batch_and_show_share_the_session(pooled):
    junos.show_batch("10.0.0.1", "u", None, ["show a", "show b"], 5, 30)
    show()
    assert len(devices()) == 1
    assert devices()[0].cli_calls == ["show a", "show b", "show version"]


# --- liveness -----------------------------------------------------------

def test_session_closed_by_pyez_is_replaced(pooled):
    show()
    devices()[0].connected = False
    show()
    assert len(devices()) == 2
    assert devices()[0].closed and not devices()[1].closed
    assert pooled.stats["discards"] == 1


def test_idle_session_is_probed_with_a_short_timeout(pooled, monkeypatch):
    monkeypatch.setattr(junos, "PROBE_AFTER", 0)

    class Rpc:
        calls = []

        def get_system_uptime_information(self, **kw):
            Rpc.calls.append(kw)
            raise junos.TransportError("gone")

    show()
    devices()[0].rpc = Rpc()
    show()
    assert Rpc.calls == [{"dev_timeout": junos.SHORT_TIMEOUT}]
    assert len(devices()) == 2
    assert devices()[0].closed


def test_first_borrow_is_never_probed_and_a_failed_probe_means_reopen(pooled, monkeypatch):
    monkeypatch.setattr(junos, "PROBE_AFTER", 0)
    show()  # FakeDevice has no .rpc, so a probe here would have failed
    assert pooled.stats == {"opens": 1, "reuses": 0, "discards": 0, "reaped": 0}
    show()  # reused + idle >= PROBE_AFTER: probe raises, session replaced
    assert pooled.stats["opens"] == 2 and pooled.stats["discards"] == 1
    assert devices()[0].closed and not devices()[1].closed


def test_close_uses_a_short_timeout_and_tears_down_a_stuck_transport():
    class Stuck(FakeDevice):
        torn_down = False

        def close(self):
            self.timeout_at_close = self.timeout
            raise rpc_timeout("close")

    dev = Stuck()
    dev.timeout = 300

    class Session:
        def close(self):
            Stuck.torn_down = True

    class Conn:
        _session = Session()

    dev._conn = Conn()
    junos._close(dev)
    assert dev.timeout_at_close == junos.SHORT_TIMEOUT
    assert Stuck.torn_down


def test_read_on_a_dead_reused_session_is_retried_once(pooled):
    show()
    dead = devices()[0]
    FakeDevice.cli_outputs = {"show version": junos.TransportError("closed")}

    class Second(FakeDevice):
        def cli(self, cmd, warning=True):
            self.cli_calls.append(cmd)
            return "fresh"

    junos.JunosDevice = Second
    assert show() == "fresh"
    assert dead.closed
    assert len(devices()) == 2
    assert pooled.stats["discards"] == 1


def test_read_on_a_dead_fresh_session_is_not_retried(pooled):
    FakeDevice.cli_outputs = {"show version": junos.TransportError("closed")}
    with pytest.raises(junos.TransportError):
        show()
    assert len(devices()) == 1
    assert devices()[0].closed
    assert pooled.live() == 0


def test_rpc_timeout_discards_without_retry(pooled):
    FakeDevice.cli_outputs = {"show version": rpc_timeout("show version")}
    with pytest.raises(junos.RpcTimeoutError):
        show()
    assert devices()[0].closed
    FakeDevice.cli_outputs = {}
    show()
    assert len(devices()) == 2


def test_batch_on_a_dead_reused_session_is_rerun_on_a_fresh_one(pooled):
    show()
    FakeDevice.cli_outputs = {"show b": junos.TransportError("closed")}

    class Second(FakeDevice):
        def cli(self, cmd, warning=True):
            self.cli_calls.append(cmd)
            return "fresh " + cmd

    junos.JunosDevice = Second
    res = junos.show_batch("10.0.0.1", "u", None, ["show a", "show b"], 5, 30)
    assert [r["output"] for r in res] == ["fresh show a", "fresh show b"]
    assert devices()[0].closed and devices()[0].cli_calls == ["show version", "show a", "show b"]
    assert devices()[1].cli_calls == ["show a", "show b"]


def test_batch_keeps_going_after_a_timeout_but_drops_the_session(pooled):
    FakeDevice.cli_outputs = {"show b": rpc_timeout("show b")}
    res = junos.show_batch("10.0.0.1", "u", None, ["show a", "show b", "show c"], 5, 30)
    assert [r["ok"] for r in res] == [True, False, True]
    assert devices()[0].closed
    assert pooled.live() == 0


# --- edits on a pooled session ------------------------------------------

def edit(payload="set system host-name r1\n", **kw):
    return junos.edit("10.0.0.1", "u", None, payload, 5, 30, **kw)


def cfg():
    return FakeConfig.instances[-1]


def test_dry_run_keeps_the_session_and_leaves_no_lock(pooled):
    out = edit(dry_run=True)
    assert out.startswith("DRY-RUN")
    assert cfg().names[-2:] == ["rollback", "unlock"]
    assert not devices()[0].closed
    show()
    assert len(devices()) == 1


def test_commit_keeps_the_session(pooled):
    assert edit().startswith("COMMIT OK")
    assert cfg().names == ["lock", "load", "diff", "commit_check", "commit", "unlock"]
    assert not devices()[0].closed


def test_unlock_failure_discards_the_session(pooled):
    FakeConfig.raise_on = {"unlock": RuntimeError("session gone")}
    assert edit().startswith("COMMIT OK")
    assert devices()[0].closed
    assert pooled.live() == 0


def test_rollback_failure_discards_the_session(pooled):
    FakeConfig.raise_on = {"commit_check": junos.CommitError("bad"), "rollback": RuntimeError("x")}
    with pytest.raises(RuntimeError, match="Config error"):
        edit()
    assert devices()[0].closed


def test_ambiguous_commit_discards_the_session(pooled):
    FakeConfig.raise_on = {"commit": rpc_timeout()}
    with pytest.raises(AmbiguousCommitError):
        edit()
    assert "rollback" not in cfg().names
    assert "unlock" not in cfg().names
    assert devices()[0].closed


def test_lock_on_a_dead_session_is_not_applied(pooled):
    FakeConfig.raise_on = {"lock": junos.TransportError("closed")}
    with pytest.raises(NotAppliedError, match="session lost"):
        edit()
    assert "unlock" not in cfg().names
    assert devices()[0].closed


def test_lock_wrapped_by_pyez_around_a_timeout_drops_the_session(pooled, monkeypatch):
    # PyEZ turns a timed-out <lock-configuration> into LockError; the device
    # may have granted it, so the session (and with it the lock) must go.
    def lock_wrapping_a_timeout(self):
        try:
            raise rpc_timeout("lock")
        except junos.RpcTimeoutError:
            raise junos.LockError("timeout")

    monkeypatch.setattr(FakeConfig, "lock", lock_wrapping_a_timeout)
    with pytest.raises(NotAppliedError, match="Failed to lock"):
        edit()
    assert devices()[0].closed


def test_lock_held_elsewhere_keeps_the_session(pooled):
    FakeConfig.raise_on = {"lock": junos.LockError("held")}
    with pytest.raises(NotAppliedError):
        edit()
    assert not devices()[0].closed


def test_session_dying_after_the_lock_is_a_plain_failure_and_drops_it(pooled):
    FakeConfig.raise_on = {"load": junos.TransportError("closed")}
    with pytest.raises(junos.TransportError):
        edit()
    assert cfg().names[-2:] == ["rollback", "unlock"]
    assert devices()[0].closed


def test_confirm_timeout_discards_the_session(pooled):
    FakeConfig.raise_on = {"commit": rpc_timeout()}
    with pytest.raises(AmbiguousCommitError):
        junos.confirm("10.0.0.1", "u", None, 5, 30)
    assert devices()[0].closed


# --- concurrency --------------------------------------------------------

def test_same_router_calls_never_overlap(pooled):
    overlap = {"max": 0, "now": 0}
    guard = threading.Lock()

    class Slow(FakeDevice):
        def cli(self, cmd, warning=True):
            with guard:
                overlap["now"] += 1
                overlap["max"] = max(overlap["max"], overlap["now"])
            time.sleep(0.02)
            with guard:
                overlap["now"] -= 1
            return super().cli(cmd, warning)

    junos.JunosDevice = Slow
    in_threads(show, [{}] * 6)
    assert overlap["max"] == 1
    assert len(devices()) == 1
    assert pooled.stats["opens"] == 1 and pooled.stats["reuses"] == 5


def test_different_routers_run_in_parallel(pooled):
    started = threading.Barrier(2, timeout=5)

    class Blocking(FakeDevice):
        def cli(self, cmd, warning=True):
            started.wait()  # both threads must be inside at the same time
            return super().cli(cmd, warning)

    junos.JunosDevice = Blocking
    in_threads(show, [{"host": "10.0.0.1"}, {"host": "10.0.0.2"}])
    assert not started.broken
    assert len(devices()) == 2


# --- lifecycle ----------------------------------------------------------

def test_reap_closes_idle_sessions_only(pooled):
    show()
    show(host="10.0.0.2")
    pooled.idle_timeout = 60
    assert pooled.reap(now=time.time()) == 0
    assert pooled.reap(now=time.time() + 61) == 2
    assert all(d.closed for d in devices())
    assert pooled.live() == 0
    assert pooled.stats["reaped"] == 2
    show()
    assert len(devices()) == 3


def test_reap_skips_a_busy_session(pooled):
    show()
    pooled.idle_timeout = 0
    entry = pooled._get_or_create_entry(("10.0.0.1", 830, "u"))
    held, release = threading.Event(), threading.Event()

    def borrower():                      # another thread holds the session
        with entry["lock"]:
            held.set()
            release.wait(2)

    t = threading.Thread(target=borrower)
    t.start()
    held.wait(2)
    assert pooled.reap() == 0
    release.set()
    t.join()
    assert pooled.reap() == 1


def test_same_thread_may_reuse_its_borrowed_session():
    """The lock is re-entrant: a show() inside an open borrow (a Transaction)
    rides the same session instead of deadlocking."""
    pool.enable()
    key = ("10.0.0.1", 830, "u")
    with pool.POOL.get_connection(key, opener=lambda: FakeDevice(), closer=junos._close) as lease:
        show()
        assert len(devices()) == 1 and devices()[0] is lease.dev


def test_cleanup_thread_is_replaced_not_duplicated(pooled, monkeypatch):
    monkeypatch.setattr(pool, "CLEANUP_INTERVAL", 0.05)
    pool.disable()
    pool.enable()
    first = pooled._cleanup_thread
    pool.disable()
    pool.enable()
    assert pooled._cleanup_thread is not first
    first.join(timeout=2)
    assert not first.is_alive()


def test_close_all_then_reopen(pooled):
    show()
    pool.close_all()
    assert devices()[0].closed
    show()
    show()
    assert len(devices()) == 2 and not devices()[1].closed
    assert pooled.enabled


def test_close_all_during_a_borrow_closes_it_on_return(pooled):
    show()
    entry = pooled._get_or_create_entry(("10.0.0.1", 830, "u"))
    released = threading.Event()

    def hold():
        with pooled.get_connection(("10.0.0.1", 830, "u"), opener=None, closer=junos._close):
            released.wait(2)

    t = threading.Thread(target=hold)
    t.start()
    time.sleep(0.05)
    pool.close_all()                # shutdown: busy entries are skipped, not waited on
    assert not devices()[0].closed  # still borrowed
    released.set()
    t.join()
    assert devices()[0].closed      # closed on return, not re-pooled
    assert entry["device"] is None


def test_disable_closes_and_returns_to_per_call(pooled):
    show()
    pool.disable()
    assert devices()[0].closed
    show()
    assert len(devices()) == 2 and devices()[1].closed


def test_open_failure_leaves_the_slot_empty(pooled):
    FakeDevice.open_error = junos.ConnectError(FakeHost(), "refused")
    with pytest.raises(NotAppliedError):
        show()
    assert pooled.live() == 0
    FakeDevice.open_error = None
    show()
    assert pooled.stats["opens"] == 1


# --- what came over from junos-mcp-server's ConnectionPool -------------------------

def test_half_opened_device_is_closed_not_leaked():
    class Half(FakeDevice):
        def open(self):
            self.opened = True
            raise junos.ConnectError(FakeHost(), "auth failed after the transport came up")

    junos.JunosDevice = Half
    with pytest.raises(NotAppliedError):
        show()
    assert devices()[0].opened and devices()[0].closed


def test_idle_timeout_from_the_environment(monkeypatch):
    monkeypatch.setenv("HSSH_POOL_IDLE_TIMEOUT", "42")
    assert pool.ConnectionPool().idle_timeout == 42
    monkeypatch.setenv("HSSH_POOL_IDLE_TIMEOUT", "soon")
    assert pool.ConnectionPool().idle_timeout == pool.DEFAULT_IDLE_TIMEOUT   # warns, keeps the default
    assert pool.ConnectionPool(idle_timeout=7).idle_timeout == 7


def test_close_all_waits_when_not_shutting_down(pooled):
    show()
    entry = pooled._get_or_create_entry(("10.0.0.1", 830, "u"))
    released = threading.Event()

    def hold():
        with pooled.get_connection(("10.0.0.1", 830, "u"), opener=None, closer=junos._close):
            released.wait(2)

    t = threading.Thread(target=hold)
    t.start()
    time.sleep(0.05)
    threading.Timer(0.1, released.set).start()
    pool.close_all(shutdown=False)  # waits for the borrower, then closes
    t.join()
    assert devices()[0].closed and entry["device"] is None
