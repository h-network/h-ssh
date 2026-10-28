"""Session pool: reuse, isolation per router, discard on failure, reaping,
and the junos driver's behaviour on a pooled session."""
import gc
import os
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hssh import pool
from hssh.errors import AmbiguousCommitError, NotAppliedError
from hssh.transports import netconf
from tests.test_junos import FakeConfig, FakeDevice, FakeHost, rpc_timeout

# The driver's pool key: host, port, user and a digest of the password (#43).
KEY = netconf._pool_key("10.0.0.1", 830, "u", None)   # show() and edit() here use key auth


@pytest.fixture(autouse=True)
def fake_pyez(monkeypatch):
    FakeDevice.instances = []
    FakeDevice.open_error = None
    FakeDevice.cli_outputs = {}
    FakeConfig.instances = []
    FakeConfig.diff_text = "[edit]\n+  system host-name r1;"
    FakeConfig.raise_on = {}
    monkeypatch.setattr(netconf, "AVAILABLE", True)
    monkeypatch.setattr(netconf, "JunosDevice", FakeDevice)
    monkeypatch.setattr(netconf, "JunosConfig", FakeConfig)
    yield
    pool.POOL.disable()
    netconf.wait_for_closes()       # a close still in flight is this test's, not the next one's
    for k in pool.POOL.stats:
        pool.POOL.stats[k] = 0


@pytest.fixture
def pooled(monkeypatch):
    pool.enable(idle_timeout=300)
    # A confirm first asks the device whether anything is waiting (#63).
    monkeypatch.setattr(netconf, "_pending_on", lambda dev, t: {"seq": 0, "pending_rollback_minutes": 5})
    yield pool.POOL


def show(host="10.0.0.1", cmd="show version", timeout=30, **kw):
    return netconf.show(host, "u", None, cmd, 5, timeout, **kw)


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
    netconf.show("10.0.0.1", "other", None, "show version", 5, 30)
    show(host="10.0.0.1")
    assert len(devices()) == 4
    assert pooled.stats["reuses"] == 1


def test_command_timeout_follows_each_call(pooled):
    show(timeout=10)
    show(timeout=99)
    assert devices()[0].timeout == 99


def test_batch_and_show_share_the_session(pooled):
    netconf.show_batch("10.0.0.1", "u", None, ["show a", "show b"], 5, 30)
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
    monkeypatch.setattr(netconf, "PROBE_AFTER", 0)

    class Rpc:
        calls = []

        def get_system_uptime_information(self, **kw):
            Rpc.calls.append(kw)
            raise netconf.TransportError("gone")

    show()
    devices()[0].rpc = Rpc()
    show()
    assert Rpc.calls == [{"dev_timeout": netconf.SHORT_TIMEOUT}]
    assert len(devices()) == 2
    assert devices()[0].closed


def test_first_borrow_is_never_probed_and_a_failed_probe_means_reopen(pooled, monkeypatch):
    monkeypatch.setattr(netconf, "PROBE_AFTER", 0)
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
    netconf._close(dev).join(2)                 # the close runs in its helper thread
    assert dev.timeout_at_close == netconf.SHORT_TIMEOUT
    assert Stuck.torn_down


def test_read_on_a_dead_reused_session_is_retried_once(pooled):
    show()
    dead = devices()[0]
    FakeDevice.cli_outputs = {"show version": netconf.TransportError("closed")}

    class Second(FakeDevice):
        def cli(self, cmd, warning=True):
            self.cli_calls.append(cmd)
            return "fresh"

    netconf.JunosDevice = Second
    assert show() == "fresh"
    assert dead.closed
    assert len(devices()) == 2
    assert pooled.stats["discards"] == 1


def test_read_on_a_dead_fresh_session_is_not_retried(pooled):
    FakeDevice.cli_outputs = {"show version": netconf.TransportError("closed")}
    with pytest.raises(netconf.TransportError):
        show()
    assert len(devices()) == 1
    assert devices()[0].closed
    assert pooled.live() == 0


def test_rpc_timeout_discards_without_retry(pooled):
    FakeDevice.cli_outputs = {"show version": rpc_timeout("show version")}
    with pytest.raises(netconf.RpcTimeoutError):
        show()
    assert devices()[0].closed
    FakeDevice.cli_outputs = {}
    show()
    assert len(devices()) == 2


def test_batch_on_a_dead_reused_session_is_rerun_on_a_fresh_one(pooled):
    show()
    FakeDevice.cli_outputs = {"show b": netconf.TransportError("closed")}

    class Second(FakeDevice):
        def cli(self, cmd, warning=True):
            self.cli_calls.append(cmd)
            return "fresh " + cmd

    netconf.JunosDevice = Second
    res = netconf.show_batch("10.0.0.1", "u", None, ["show a", "show b"], 5, 30)
    assert [r["output"] for r in res] == ["fresh show a", "fresh show b"]
    assert devices()[0].closed and devices()[0].cli_calls == ["show version", "show a", "show b"]
    assert devices()[1].cli_calls == ["show a", "show b"]


def test_a_command_that_is_not_a_read_is_not_sent_again_on_a_fresh_session(pooled):
    """show() and show_batch() reopened a dead reused session and ran again
    whatever the command, so a job's second entry or a Fleet's second run
    could send `request system reboot` twice; rpc() never did. Only a read
    runs once more, and a string with a line break is none (#110 review)."""
    for cmd in ("request system reboot", "show version\nrequest system reboot"):
        show()                                   # a session, reused below
        FakeDevice.cli_outputs = {cmd: netconf.TransportError("closed")}
        with pytest.raises(netconf.TransportError):
            show(cmd=cmd)
        assert devices()[-1].closed and devices()[-1].cli_calls == ["show version", cmd]
    show()
    FakeDevice.cli_outputs = {"request system reboot": netconf.TransportError("closed")}
    with pytest.raises(netconf.TransportError):
        netconf.show_batch("10.0.0.1", "u", None, ["show a", "request system reboot"], 5, 30)
    assert devices()[-1].closed and devices()[-1].cli_calls == ["show version", "show a", "request system reboot"]
    assert len(devices()) == 3 and pooled.live() == 0


def test_batch_keeps_going_after_a_timeout_but_drops_the_session(pooled):
    FakeDevice.cli_outputs = {"show b": rpc_timeout("show b")}
    res = netconf.show_batch("10.0.0.1", "u", None, ["show a", "show b", "show c"], 5, 30)
    assert [r["ok"] for r in res] == [True, False, True]
    assert devices()[0].closed
    assert pooled.live() == 0


# --- edits on a pooled session ------------------------------------------

def edit(payload="set system host-name r1\n", **kw):
    return netconf.edit("10.0.0.1", "u", None, payload, 5, 30, **kw)


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
    FakeConfig.raise_on = {"commit_check": netconf.CommitError("bad"), "rollback": RuntimeError("x")}
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
    FakeConfig.raise_on = {"lock": netconf.TransportError("closed")}
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
        except netconf.RpcTimeoutError:
            raise netconf.LockError("timeout")

    monkeypatch.setattr(FakeConfig, "lock", lock_wrapping_a_timeout)
    with pytest.raises(NotAppliedError, match="Failed to lock"):
        edit()
    assert devices()[0].closed


def test_lock_held_elsewhere_keeps_the_session(pooled):
    FakeConfig.raise_on = {"lock": netconf.LockError("held")}
    with pytest.raises(NotAppliedError):
        edit()
    assert not devices()[0].closed


def test_session_dying_after_the_lock_is_a_plain_failure_and_drops_it(pooled):
    FakeConfig.raise_on = {"load": netconf.TransportError("closed")}
    with pytest.raises(netconf.TransportError):
        edit()
    assert cfg().names[-2:] == ["rollback", "unlock"]
    assert devices()[0].closed


def test_confirm_timeout_discards_the_session(pooled):
    FakeConfig.raise_on = {"commit": rpc_timeout()}
    with pytest.raises(AmbiguousCommitError):
        netconf.confirm("10.0.0.1", "u", None, 5, 30)
    assert devices()[0].closed


def test_confirm_lock_held_elsewhere_keeps_the_session(pooled):
    FakeConfig.raise_on = {"lock": netconf.LockError("held")}
    with pytest.raises(NotAppliedError):
        netconf.confirm("10.0.0.1", "u", None, 5, 30)
    assert cfg().names == ["lock"] and not devices()[0].closed


def test_confirm_unlock_failure_discards_the_session(pooled):
    FakeConfig.raise_on = {"unlock": RuntimeError("session gone")}
    assert netconf.confirm("10.0.0.1", "u", None, 5, 30) == "COMMIT CONFIRMED OK"
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

    netconf.JunosDevice = Slow
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

    netconf.JunosDevice = Blocking
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
    entry = pooled._get_or_create_entry(KEY)
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
    key = KEY
    with pool.POOL.get_connection(key, opener=lambda: FakeDevice(), closer=netconf._close) as lease:
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
    entry = pooled._get_or_create_entry(KEY)
    released = threading.Event()

    def hold():
        with pooled.get_connection(KEY, opener=None, closer=netconf._close):
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
    FakeDevice.open_error = netconf.ConnectError(FakeHost(), "refused")
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
            raise netconf.ConnectError(FakeHost(), "auth failed after the transport came up")

    netconf.JunosDevice = Half
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
    entry = pooled._get_or_create_entry(KEY)
    released = threading.Event()

    def hold():
        with pooled.get_connection(KEY, opener=None, closer=netconf._close):
            released.wait(2)

    t = threading.Thread(target=hold)
    t.start()
    time.sleep(0.05)
    threading.Timer(0.1, released.set).start()
    pool.close_all(shutdown=False)  # waits for the borrower, then closes
    t.join()
    assert devices()[0].closed and entry["device"] is None


# --- a call nested inside an open transaction -----------------------------------

def test_nested_call_that_dies_does_not_close_the_outer_session(pooled):
    """show() inside an open Transaction hits a dead transport: the session is
    marked, not closed, so the transaction finishes on its own terms — and
    commit() refuses with NotAppliedError instead of sending into the void."""
    tx = netconf.begin("10.0.0.1", "u", None, "set system host-name r1\n", 5, 30)
    dev = devices()[0]
    FakeDevice.cli_outputs = {"show version": netconf.TransportError("closed")}
    with pytest.raises(netconf.TransportError):
        show()                                   # nested borrow, same thread, same session
    assert not dev.closed and tx.open            # still the transaction's session
    assert pooled.live() == 1
    with pytest.raises(NotAppliedError, match="session lost during the transaction"):
        tx.commit()
    assert dev.closed and not tx.open and pooled.live() == 0
    assert "commit" not in FakeConfig.instances[0].names


def test_nested_show_on_a_healthy_session_is_plain_reuse(pooled):
    with netconf.begin("10.0.0.1", "u", None, "set system host-name r1\n", 5, 30) as tx:
        assert show() == "output of show version"
        assert tx.show("show version") == "output of show version"
        assert len(devices()) == 1 and pooled.stats["opens"] == 1
    assert pooled.live() == 1                    # abort on exit keeps the session


def test_nested_discard_is_honoured_once_the_outer_borrow_returns(pooled):
    key = KEY
    with pooled.get_connection(key, opener=lambda: FakeDevice(), closer=netconf._close) as outer:
        with pooled.get_connection(key, opener=None, closer=netconf._close) as inner:
            inner.discard()
        assert not devices()[0].closed and outer.doomed
    assert devices()[0].closed and pooled.live() == 0
    assert pooled._get_or_create_entry(key)["doomed"] is False   # reset for the next borrow


# --- #43: credentials, threads, exit -------------------------------------------

def test_a_different_credential_gets_its_own_session(pooled):
    """The key had no credential: a call with a wrong, different or absent
    password rode the session the first password opened."""
    netconf.show("10.0.0.1", "u", "correct-horse", "show version", 5, 30)
    netconf.show("10.0.0.1", "u", "correct-horse", "show version", 5, 30)
    netconf.show("10.0.0.1", "u", "wrong", "show version", 5, 30)
    netconf.show("10.0.0.1", "u", None, "show version", 5, 30)
    assert pooled.stats["opens"] == 3 and pooled.stats["reuses"] == 1
    assert [d.params.get("passwd") for d in devices()] == ["correct-horse", "wrong", None]
    assert not any("correct-horse" in str(k) for k in pooled._connections)   # a digest, never the password


def test_a_transaction_finished_on_another_thread_sends_nothing_and_wedges_nothing(pooled):
    """commit() from a thread other than begin()'s once landed the commit, then
    raised from the RLock release and left the router's slot locked forever."""
    tx = netconf.begin("10.0.0.1", "u", None, "set system host-name r1\n", 5, 30)
    outcome = {}

    def elsewhere():
        try:
            tx.commit()
        except Exception as e:
            outcome["error"] = f"{type(e).__name__}: {e}"
    t = threading.Thread(target=elsewhere); t.start(); t.join(5)
    assert "thread that opened it" in outcome["error"]
    assert [c[0] for c in FakeConfig.instances[0].calls] == ["lock", "load", "diff", "commit_check"]
    assert tx.open
    tx.abort()                                     # the owner can still finish it
    done = threading.Event()

    def other_borrower():                          # and the slot is free again
        show()
        done.set()
    threading.Thread(target=other_borrower).start()
    assert done.wait(5)


def test_leaving_the_with_block_on_another_thread_does_not_abort_for_the_owner(pooled):
    tx = netconf.begin("10.0.0.1", "u", None, "set system host-name r1\n", 5, 30)

    def elsewhere():
        with tx:
            pass
    t = threading.Thread(target=elsewhere); t.start(); t.join(5)
    assert tx.open and "rollback" not in [c[0] for c in FakeConfig.instances[0].calls]
    tx.abort()


def test_close_all_closes_sessions_side_by_side(monkeypatch):
    """Serial closes with a slow router each cost one close timeout in a row;
    a 350-router exit stalled for minutes."""
    p = pool.ConnectionPool(idle_timeout=300)
    p.enable()
    closed = []

    def slow_closer(dev):
        time.sleep(0.2)
        closed.append(dev)
    for i in range(20):
        with p.get_connection(("r%d" % i, 830, "u"), opener=lambda: object(), closer=slow_closer):
            pass
    assert p.live() == 20
    t0 = time.monotonic()
    p.close_all(shutdown=False)
    assert len(closed) == 20 and p.live() == 0 and time.monotonic() - t0 < 2.0


# --- #58: a closed session's descriptors are released with the session -------------

class _PipeDevice:
    """A device whose descriptors live and die with it, like ncclient's selector."""

    def __init__(self):
        self.r, self.w = os.pipe()
        self.connected = True

    def __del__(self):
        for fd in (self.r, self.w):
            try:
                os.close(fd)
            except OSError:
                pass


def _close_in_a_cycle(dev):
    """What ncclient's reader thread leaves behind: the frame that closed the
    session survives in a cycle with the exception that ended its loop."""
    dev.connected = False
    try:
        raise RuntimeError("session closed")
    except RuntimeError as e:
        dev.cycle = (dev, e)             # dev -> tuple -> exception -> traceback -> frame -> dev


def _fd_open(fd):
    try:
        os.fstat(fd)
        return True
    except OSError:
        return False


def test_close_all_releases_the_descriptors_of_closed_sessions_without_waiting_for_the_gc():
    import gc
    gc.disable()
    try:
        pool.enable(idle_timeout=300)
        fds = []
        for i in range(5):
            with pool.POOL.get_connection(("p", i), opener=_PipeDevice, closer=_close_in_a_cycle) as lease:
                fds += [lease.dev.r, lease.dev.w]
            del lease                      # the test holds no reference; only the pool does
        assert all(_fd_open(fd) for fd in fds)
        pool.close_all()
        assert not any(_fd_open(fd) for fd in fds), "descriptors outlived close_all"
    finally:
        gc.enable()


def test_the_reaper_releases_the_descriptors_of_what_it_closed():
    import gc
    gc.disable()
    try:
        pool.enable(idle_timeout=1)
        with pool.POOL.get_connection(("p", "idle"), opener=_PipeDevice, closer=_close_in_a_cycle) as lease:
            fds = [lease.dev.r, lease.dev.w]
        del lease
        assert pool.reap(now=time.time() + 5) == 1
        assert not any(_fd_open(fd) for fd in fds)
    finally:
        gc.enable()


# --- #59: a refused probe is a live session ------------------------------------------

def test_a_probe_the_router_refuses_keeps_the_session(pooled, monkeypatch):
    """cRPD answers the uptime RPC with 'command is not valid on the crpd':
    the router replied, so the session is alive and reused, not replaced."""
    monkeypatch.setattr(netconf, "PROBE_AFTER", 0)

    class Rpc:
        def get_system_uptime_information(self, **kw):
            raise netconf.RpcError("command is not valid on the crpd")

    show()
    devices()[0].rpc = Rpc()
    show()
    assert pooled.stats == {"opens": 1, "reuses": 1, "discards": 0, "reaped": 0}
    assert len(devices()) == 1 and not devices()[0].closed


def test_a_probe_that_times_out_still_means_dead(pooled, monkeypatch):
    monkeypatch.setattr(netconf, "PROBE_AFTER", 0)

    class Rpc:
        def get_system_uptime_information(self, **kw):
            raise rpc_timeout("get-system-uptime-information")

    show()
    devices()[0].rpc = Rpc()
    show()
    assert pooled.stats["opens"] == 2 and pooled.stats["discards"] == 1
    assert devices()[0].closed and not devices()[1].closed


# --- #113: the collection waits for the closes it is there for ----------------------

def _recording_close(order, delay=0.1):
    """The junos closer only starts a thread (#98): a close that takes its
    ~100 ms on the device and says when it is done."""
    class SlowClose(FakeDevice):
        def close(self):
            time.sleep(delay)
            super().close()
            order.append("closed")
    return SlowClose


def test_close_all_collects_after_the_closes_it_started(pooled, monkeypatch):
    """close_all() collected right after _drop(), which only starts the close
    threads: the collection ran with every session still open, and the
    descriptor of #58 was held until Python's next full collection."""
    order = []
    netconf.JunosDevice = _recording_close(order)
    monkeypatch.setattr(pool.gc, "collect", lambda *a, **k: order.append("collected"))
    for host in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        show(host=host)
    pool.close_all(shutdown=False)
    assert order == ["closed"] * 3 + ["collected"]
    assert netconf.wait_for_closes(timeout=0) == 0      # nothing left in flight


def test_the_reaper_collects_after_the_closes_it_started(pooled, monkeypatch):
    order = []
    netconf.JunosDevice = _recording_close(order)
    monkeypatch.setattr(pool.gc, "collect", lambda *a, **k: order.append("collected"))
    show()
    show(host="10.0.0.2")
    assert pooled.reap(now=time.time() + 301) == 2
    assert order == ["closed", "closed", "collected"]


def test_the_reaper_thread_sees_a_slow_close_through_before_it_collects(monkeypatch):
    """Nobody waits on the cleanup thread, yet it collected after CLOSE_WAIT
    like close_all(): a close slower than that (a router that never
    acknowledges gives up after SHORT_TIMEOUT) kept its descriptor until
    Python's next full collection, one per slow router in a long-lived
    process."""
    order = []
    netconf.JunosDevice = _recording_close(order, delay=0.3)
    monkeypatch.setattr(pool.gc, "collect", lambda *a, **k: order.append("collected"))
    monkeypatch.setattr(pool, "CLOSE_WAIT", 0.05)
    monkeypatch.setattr(pool, "CLEANUP_INTERVAL", 0.05)
    monkeypatch.setattr(pool.POOL, "idle_timeout", 0)
    pool.enable()
    show()
    deadline = time.monotonic() + 5
    while "collected" not in order and time.monotonic() < deadline:
        time.sleep(0.02)
    assert order == ["closed", "collected"]


def test_close_all_closes_on_its_own_clock_when_the_system_refuses_the_close_thread(pooled, monkeypatch):
    """The pool logged the closer's RuntimeError and went on: the session
    stayed open on the router, and the never-started thread made every
    later wait_for_closes() raise."""
    show()
    real_start = threading.Thread.start

    def start(self):
        if self.name == "hssh-netconf-close":
            raise RuntimeError("can't start new thread")
        real_start(self)
    monkeypatch.setattr(threading.Thread, "start", start)
    pool.close_all(shutdown=False)
    assert devices()[0]._closed and pooled.live() == 0
    assert not netconf._CLOSES and netconf.wait_for_closes() == 0


def test_close_all_closes_every_session_itself_when_the_system_refuses_every_thread(pooled, monkeypatch):
    """ulimit -u or a container's pids.max refuses the executor's threads
    too, not only the close helper: with two sessions or more close_all()
    raised before any close, every session stayed open on its router, and a
    --job run ended in a traceback before its log and summary."""
    show()
    show(host="10.0.0.2")

    def start(self):
        raise RuntimeError("can't start new thread")
    monkeypatch.setattr(threading.Thread, "start", start)
    pool.close_all(shutdown=False)
    assert [d._closed for d in devices()] == [True, True] and pooled.live() == 0
    assert not netconf._CLOSES and netconf.wait_for_closes() == 0


@pytest.mark.skipif((3, 12) <= sys.version_info[:3] < (3, 12, 3), reason="3.12 before 3.12.3 starts no thread at exit")
def test_the_close_all_at_interpreter_exit_closes_every_session_side_by_side(tmp_path):
    """concurrent.futures takes no more work once the interpreter is
    exiting, before atexit runs: with two sessions or more the close_all()
    there raised 'cannot schedule new futures after interpreter shutdown'
    and closed none of them. Closed on the exiting thread instead, they
    went one after another, a close timeout per router in a row, though
    plain threads still start there."""
    script = tmp_path / "leaves.py"
    script.write_text(
        "import time\n"
        "from hssh import pool\n"
        "def closer(dev):\n"
        "    start = time.monotonic()\n"
        "    time.sleep(0.3)\n"
        "    print('closed', dev, start, time.monotonic(), flush=True)\n"
        "pool.enable()\n"
        "for host in ('r1', 'r2', 'r3'):\n"
        "    with pool.POOL.get_connection((host, 830, 'u'), opener=lambda: host, closer=closer):\n"
        "        pass\n")
    env = {**os.environ, "PYTHONPATH": os.path.dirname(os.path.dirname(pool.__file__))}
    proc = subprocess.run([sys.executable, str(script)], env=env, capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0 and "Traceback" not in proc.stderr, proc.stderr
    closes = sorted(line.split() for line in proc.stdout.splitlines())
    assert [c[:2] for c in closes] == [["closed", "r1"], ["closed", "r2"], ["closed", "r3"]]
    starts, ends = [float(c[2]) for c in closes], [float(c[3]) for c in closes]
    assert max(starts) < min(ends), proc.stdout          # side by side, not one after another


def test_a_closer_that_returns_something_else_is_not_waited_for():
    """Only a Thread is waited for. A closer such as `lambda m:
    m.close_session()` (ncclient hands back the reply) made close_all() and
    the reaper raise AttributeError instead of collecting."""
    p = pool.ConnectionPool(idle_timeout=300)
    p.enable()
    try:
        for host in ("r1", "r2"):
            with p.get_connection((host, 830, "u"), opener=lambda: object(), closer=lambda dev: True):
                pass
        t0 = time.monotonic()
        p.close_all(shutdown=False)
        assert p.live() == 0 and time.monotonic() - t0 < 0.5      # CLOSE_WAIT is a second
        with p.get_connection(("r1", 830, "u"), opener=lambda: object(), closer=lambda dev: "<ok/>"):
            pass
        t0 = time.monotonic()
        assert p.reap(now=time.time() + 301) == 1 and p.live() == 0
        assert time.monotonic() - t0 < 0.5
    finally:
        p.disable()


# --- #147: a transaction nobody finishes, and a router another thread waits for -----

def tx_on(host="10.0.0.1"):
    return netconf.begin(host, "u", None, "set system host-name r1\n", 5, 30)


def in_thread(fn, timeout):
    """fn() on a thread of its own: ("done", value), ("raised", exception),
    or ("still waiting", None) once `timeout` seconds have gone by."""
    out = []

    def run():
        try:
            out.append(("done", fn()))
        except Exception as e:
            out.append(("raised", e))
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)
    return out[0] if out else ("still waiting", None)


def test_a_transaction_dropped_without_commit_or_abort_closes_its_session(pooled):
    """A Transaction dropped on its own thread went back to the pool with the
    device's lock and the loaded candidate: the next edit reused that
    session, and its commit took the abandoned change with it."""
    tx = tx_on()
    first = devices()[0]
    del tx
    assert first.closed and pooled.live() == 0 and pooled.stats["discards"] == 1
    assert FakeConfig.instances[0].names == ["lock", "load", "diff", "commit_check"]    # nothing more on it
    assert edit().startswith("COMMIT OK")
    assert len(devices()) == 2 and cfg().dev is devices()[1]                           # a fresh session
    assert cfg().names == ["lock", "load", "diff", "commit_check", "commit", "unlock"]


def test_a_transaction_dropped_on_another_thread_frees_the_router(pooled):
    """Opened on a thread that has ended since (asyncio.to_thread hands it to
    the event loop's thread) and dropped on another: the RLock stayed owned
    by the thread that opened it, and every later borrower of the router
    waited for good."""
    made = []
    t = threading.Thread(target=lambda: made.append(tx_on()))
    t.start()
    t.join(5)
    first = devices()[0]
    made.clear()                                     # the last reference, dropped on this thread
    assert first.closed and pooled.live() == 0
    assert in_thread(show, 5) == ("done", "output of show version")
    assert len(devices()) == 2


def test_a_transaction_in_a_reference_cycle_is_ended_wherever_the_collector_frees_it(pooled):
    holder = {}

    def open_one():
        cycle = [tx_on()]
        cycle.append(cycle)                          # only the garbage collector frees it
        holder["cycle"] = cycle
    t = threading.Thread(target=open_one)
    t.start()
    t.join(5)
    first = devices()[0]
    holder.clear()
    collector = threading.Thread(target=gc.collect)  # neither the thread that opened it nor this one
    collector.start()
    collector.join(5)
    assert first.closed and pooled.live() == 0
    assert in_thread(show, 5) == ("done", "output of show version")


def test_an_abandoned_transaction_inside_an_open_borrow_leaves_the_session_to_it(pooled):
    """Nested in a borrow the same thread still holds, an abandoned
    transaction does not pull the session from under it: it is marked, and
    closed when that borrow ends."""
    with pooled.get_connection(KEY, opener=lambda: FakeDevice(), closer=netconf._close) as outer:
        tx = tx_on()                                 # the same thread, the same session
        del tx
        assert not devices()[0]._closed and outer.doomed
    assert devices()[0].closed and pooled.live() == 0


def test_a_change_nested_in_an_open_transaction_is_refused_and_sends_nothing(pooled):
    """A change on the thread that holds a transaction open went into the
    router's lock again, locked the transaction's session once more and
    committed its candidate with its own: the abandoned change going in with
    the next one, from the except block of code that raised before commit()
    or abort(), where the traceback still holds the transaction. Refused
    now, nothing sent; a read still rides the session."""
    tx = tx_on()
    changes = {
        "edit": edit,
        "rollback": lambda: netconf.rollback("10.0.0.1", "u", None, 1, 5, 30),
        "confirm": lambda: netconf.confirm("10.0.0.1", "u", None, 5, 30),
        "begin": tx_on,
    }
    try:
        for name, change in changes.items():
            with pytest.raises(NotAppliedError) as refused:
                change()
            assert str(refused.value) == ("this thread holds a transaction open on this session: commit() or abort() "
                                          "it first, or its candidate goes in with this change; nothing was sent"), name
        assert len(FakeConfig.instances) == 1 and cfg().names == ["lock", "load", "diff", "commit_check"]
        assert show() == "output of show version"    # a read rides it
        assert tx.commit().startswith("COMMIT OK")   # the transaction is still the caller's to finish
    finally:
        if tx.open:
            tx.abort()
    assert cfg().names == ["lock", "load", "diff", "commit_check", "commit", "unlock"]
    assert edit().startswith("COMMIT OK") and len(devices()) == 1 and pooled.live() == 1


def test_an_edit_that_lands_on_the_thread_holding_an_open_transaction_is_refused(pooled):
    """asyncio.to_thread() runs each call on one of the executor's threads:
    an edit() made while a transaction opened that way was still open landed
    on the thread holding it, rode its session and committed the open
    candidate with its own change."""
    import asyncio
    import concurrent.futures

    async def main():
        asyncio.get_running_loop().set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=1))
        tx = await asyncio.to_thread(tx_on)
        try:
            await asyncio.to_thread(edit, "set system host-name other\n")
        except NotAppliedError as e:
            return e
        finally:
            await asyncio.to_thread(tx.abort)
    refused = asyncio.run(main())
    assert isinstance(refused, NotAppliedError) and str(refused).endswith("nothing was sent"), refused
    assert len(FakeConfig.instances) == 1
    assert cfg().names == ["lock", "load", "diff", "commit_check", "rollback", "unlock"]   # the abort, no commit


def test_a_thread_given_the_ident_of_a_transactions_ended_thread_does_not_ride_its_session(pooled):
    """The router's lock and the transaction knew their thread by its ident,
    which the system gives again to a thread started once that one has
    ended: a transaction opened on a thread that has ended (asyncio.to_thread
    hands it back) let such a later thread into its session as if it held
    it, to read, edit, or commit it. That thread waits for it as any other
    thread does now, and cannot finish it."""
    opened = []

    def opener():
        opened.append((threading.get_ident(), tx_on()))
    t = threading.Thread(target=opener)
    t.start()
    t.join(5)
    ident, tx = opened.pop()
    held, out = [tx], []
    del tx

    def attempt(fn):
        try:
            return ("done", fn())
        except Exception as e:                       # its text: a traceback would keep the transaction alive
            return ("raised", type(e).__name__, str(e))

    def later():
        if threading.get_ident() != ident:
            return
        t0 = time.monotonic()
        out.append(attempt(lambda: show(timeout=1)))
        out.append(time.monotonic() - t0)
        out.append(attempt(held[0].commit))
    try:
        for _ in range(200):                         # an ended thread's ident is handed out again, and soon
            u = threading.Thread(target=later)
            u.start()
            u.join(10)
            if out:
                break
        else:
            pytest.skip("no thread was given that ident again")
        waited_for, waited, finished = out
        assert waited_for == ("raised", "NotAppliedError", "router busy: a transaction is open on this session")
        assert 0.9 <= waited < 2.5, f"{waited:.2f}s"
        assert finished[:2] == ("raised", "RuntimeError") and "thread that opened it" in finished[2], finished
        assert devices()[0].cli_calls == [] and cfg().names == ["lock", "load", "diff", "commit_check"]
    finally:
        held.clear()                                 # dropped: its session closes, the router is free
    assert devices()[0].closed and in_thread(show, 5) == ("done", "output of show version")


def test_a_borrower_behind_an_open_transaction_gives_up_after_its_command_timeout(pooled):
    """show() from another thread behind an open Transaction waited with no
    end: while the transaction stayed open, and for good once it was
    abandoned on a thread that could not give the router back."""
    hold, opened, result = threading.Event(), threading.Event(), {}

    def owner():
        tx = tx_on()
        opened.set()
        hold.wait(10)
        result["commit"] = tx.commit()
    a = threading.Thread(target=owner)
    a.start()
    try:
        assert opened.wait(5)
        t0 = time.monotonic()
        how, error = in_thread(lambda: show(timeout=1), 5)
        elapsed = time.monotonic() - t0
        assert how == "raised" and isinstance(error, NotAppliedError), (how, error)
        assert str(error) == "router busy: a transaction is open on this session"
        assert 0.9 <= elapsed < 2.5, f"{elapsed:.2f}s"
        assert devices()[0].cli_calls == []          # nothing was sent
    finally:
        hold.set()
        a.join(5)
    assert result["commit"].startswith("COMMIT OK")  # the transaction is the owner's to finish
    assert in_thread(show, 5) == ("done", "output of show version")


def test_a_borrower_behind_a_call_in_flight_waits_for_it_past_its_own_timeout(pooled):
    """Only a transaction held open is waited for at most the command timeout:
    a call in flight is bounded by its own timeouts, and the waiter behind a
    slow one gets the router when it ends."""
    entered, release = threading.Event(), threading.Event()

    class Slow(FakeDevice):
        def cli(self, cmd, warning=True):
            if cmd == "show slow":
                entered.set()
                release.wait(5)
            return super().cli(cmd, warning)
    netconf.JunosDevice = Slow
    a = threading.Thread(target=lambda: show(cmd="show slow"))
    a.start()
    try:
        assert entered.wait(5)
        threading.Timer(1.5, release.set).start()
        assert in_thread(lambda: show(timeout=1), 5) == ("done", "output of show version")
    finally:
        release.set()
        a.join(5)


def test_a_borrower_behind_an_edits_commit_waits_for_it_past_its_own_timeout(pooled, monkeypatch):
    """edit() and rollback() run a transaction of their own and finish it
    within the call: a call in flight, which its own timeouts bound. It was
    held open as one begin() hands back is, and a show() from a monitoring
    thread behind a 30-second commit was refused "router busy" after its
    own command timeout, where it had waited for the commit."""
    entered, release, result = threading.Event(), threading.Event(), {}

    def slow_commit(config):
        entered.set()
        release.wait(5)
    monkeypatch.setattr(FakeConfig, "on", {"commit": slow_commit})
    a = threading.Thread(target=lambda: result.setdefault("edit", edit()))
    a.start()
    try:
        assert entered.wait(5)
        threading.Timer(1.5, release.set).start()
        assert in_thread(lambda: show(timeout=1), 5) == ("done", "output of show version")
    finally:
        release.set()
        a.join(5)
    assert result["edit"].startswith("COMMIT OK")
    assert len(devices()) == 1 and devices()[0].cli_calls == ["show version"]     # after the commit, on its session


def test_close_all_waits_for_an_open_transaction_at_most_busy_wait_then_says_so(pooled):
    show(host="10.0.0.2")                            # an idle session beside it
    hold, opened = threading.Event(), threading.Event()

    def owner():
        tx = tx_on()
        opened.set()
        hold.wait(10)
        tx.abort()
    a = threading.Thread(target=owner)
    a.start()
    try:
        assert opened.wait(5)
        t0 = time.monotonic()
        how, error = in_thread(lambda: pool.close_all(shutdown=False, busy_wait=0.5), 5)
        elapsed = time.monotonic() - t0
        assert how == "raised" and isinstance(error, NotAppliedError), (how, error)
        assert str(error) == ("router busy: a transaction is open on this session: 1 session(s) left open, "
                              "each closed when its transaction ends")
        assert 0.4 <= elapsed < 2.0, f"{elapsed:.2f}s"
        idle, held = sorted(devices(), key=lambda d: d.params["host"], reverse=True)
        assert idle.closed and not held._closed      # the others are closed all the same
    finally:
        hold.set()
        a.join(5)
    assert held.closed and pooled.live() == 0       # and that one once its transaction ended


# --- #147: room under the open-file limit --------------------------------------------

def test_the_least_recently_used_idle_session_is_closed_when_the_limit_holds_no_more(monkeypatch):
    """With even the hard limit short of the sessions kept, the next open
    failed with "Too many open files" for a healthy router. The least
    recently used idle session is closed first now, and a later call to
    that router opens it again."""
    p = pool.ConnectionPool(idle_timeout=300)
    p.enable()
    # FDS_BASE 32, one borrow in flight 6, two sessions open at 4: the third open fills it
    monkeypatch.setattr(pool.limits, "open_file_limit", lambda: 32 + 6 + 2 * 4)
    closed = []

    def borrow(host):
        with p.get_connection((host, 830, "u"), opener=lambda: host, closer=closed.append):
            pass
    try:
        for host in ("r1", "r2", "r3"):
            borrow(host)
        assert closed == [] and p.live() == 3
        borrow("r1")                                 # reused: r2 is now the least recently used
        borrow("r4")
        assert closed == ["r2"] and p.live() == 3 and p.stats["reaped"] == 1
        borrow("r2")                                 # opened again, and r3 makes room for it
        assert closed == ["r2", "r3"] and p.live() == 3
        assert p.stats == {"opens": 5, "reuses": 1, "discards": 0, "reaped": 2}
    finally:
        p.disable()


def test_closed_sessions_are_collected_before_an_idle_one_is_closed(monkeypatch):
    """A closed session keeps a descriptor until the garbage collector runs
    (#58), and a job that closes each device's session after its last entry
    piles them up: near the limit they are collected first, and no session
    a later call may want is closed for them."""
    p = pool.ConnectionPool(idle_timeout=300)
    p.enable()
    monkeypatch.setattr(pool.limits, "open_file_limit", lambda: 32 + 6 + 4 + 8)   # one kept, eight closed
    collected, closed = [], []
    monkeypatch.setattr(pool.gc, "collect", lambda *a, **k: collected.append(1))
    try:
        with p.get_connection(("keep", 830, "u"), opener=lambda: "keep", closer=closed.append):
            pass
        for i in range(10):
            key = (f"r{i}", 830, "u")
            with p.get_connection(key, opener=lambda i=i: f"r{i}", closer=closed.append):
                pass
            assert p.release(key) is True
        assert len(collected) == 1 and p.stats["reaped"] == 0
        assert "keep" not in closed and p.live() == 1
    finally:
        p.disable()


def test_a_session_under_a_call_in_flight_counts_once_against_the_open_file_limit(monkeypatch):
    """A borrow in flight was counted as a worker's descriptors, its session's
    among them, and its session's four again. A --job whose soft limit was
    raised for the sessions it keeps between entries, its workers and the
    base closed 32 of them all the same at 300 routers, each a login more
    that the safety gate never counted. Two calls in flight on open sessions
    and one session kept idle are what the limit was raised for: nothing is
    closed."""
    p = pool.ConnectionPool(idle_timeout=300)
    p.enable()
    monkeypatch.setattr(pool.limits, "open_file_limit", lambda: 32 + 2 * 6 + 1 * 4)   # 2 workers, 1 kept
    closed = []

    def borrow(host):
        return p.get_connection((host, 830, "u"), opener=lambda: host, closer=closed.append)
    inside, done = threading.Event(), threading.Event()

    def worker():
        with borrow("a"):
            inside.set()
            done.wait(5)
    try:
        with borrow("kept"):
            pass                                     # idle until its next entry
        t = threading.Thread(target=worker)
        t.start()
        assert inside.wait(5)
        with borrow("b"):                            # the second worker's session fills the limit
            assert closed == [] and p.live() == 3
        done.set()
        t.join(5)
        assert p.stats == {"opens": 3, "reuses": 0, "discards": 0, "reaped": 0}
    finally:
        done.set()
        p.disable()


def test_nothing_is_closed_when_a_borrow_ends_while_the_pool_looks_for_room(monkeypatch):
    """Past the limit at its first look and back under it by the time it has
    listed the idle sessions (a borrow ended, a session closed): an eighth of
    the idle sessions were closed all the same."""
    p = pool.ConnectionPool(idle_timeout=300)
    p.enable()
    monkeypatch.setattr(pool.limits, "open_file_limit", lambda: 1000)
    closed = []
    try:
        for i in range(16):
            with p.get_connection((f"r{i}", 830, "u"), opener=lambda i=i: f"r{i}", closer=closed.append):
                pass
        looks = iter([1004])                         # over at its first look, room at the next
        monkeypatch.setattr(p, "_descriptors", lambda: next(looks, 1000))
        with p.get_connection(("new", 830, "u"), opener=lambda: "new", closer=closed.append):
            pass
        assert closed == [] and p.stats["reaped"] == 0 and p.live() == 17
    finally:
        p.disable()


def test_release_closes_the_routers_session_now(pooled):
    """What a --job runs after a device's last entry (#147): the session
    goes then, not at the end of the run."""
    show()
    assert netconf.release("10.0.0.1", "u", None) is True
    assert devices()[0].closed and pooled.live() == 0
    assert netconf.release("10.0.0.1", "u", None) is False          # nothing left to close
    assert netconf.release("10.0.0.9", "u", None) is False          # never opened
    show()
    assert len(devices()) == 2                                       # a later call opens it again
    hold, opened = threading.Event(), threading.Event()

    def owner():
        tx = tx_on()
        opened.set()
        hold.wait(10)
        tx.abort()
    a = threading.Thread(target=owner)
    a.start()
    try:
        assert opened.wait(5)
        assert pooled.release(KEY, wait=0.3) is False                # a transaction holds it: left to it
        assert not devices()[1]._closed
    finally:
        hold.set()
        a.join(5)
