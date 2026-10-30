import asyncio
import threading
import time

from fakes import T1, FakeNetconf, FaultKind, fault_of, registry_for

from hssh.model import Credentials, Fault, Target, Timeouts
from hssh.orchestrator.sessions import SessionManager, session_key

CREDS = Credentials("adm")
TIMEOUTS = Timeouts(1, 1, 1, 1)


def driver_for(comm):
    return registry_for(comm).resolve(T1)


def test_the_session_key_is_the_effective_port_so_an_omitted_port_and_830_are_one_device():
    driver = driver_for(FakeNetconf())
    assert session_key(driver, T1, CREDS) == session_key(driver, Target("other", "127.0.0.1", "junos", "netconf", port=830), CREDS)
    assert session_key(driver, T1, CREDS) != session_key(driver, Target("x", "127.0.0.1", "junos", "netconf", port=22), CREDS)
    assert session_key(driver, T1, CREDS) != session_key(driver, T1, Credentials("someone-else"))


def test_the_session_key_carries_no_secret():
    driver = driver_for(FakeNetconf())
    assert "pw" not in repr(session_key(driver, T1, Credentials("adm", "pw")))


def test_without_pooling_release_closes_and_the_next_acquire_opens_again():
    comm = FakeNetconf()
    driver = driver_for(comm)

    async def go():
        sessions = SessionManager(pool=False)
        await sessions.acquire(driver, T1, CREDS, TIMEOUTS, "off")
        await sessions.release(driver, T1, CREDS)
        assert not sessions.pooled(driver, T1, CREDS)
        await sessions.acquire(driver, T1, CREDS, TIMEOUTS, "off")
        sessions.wait_for_closes()
        await sessions.close_all()

    asyncio.run(go())
    assert [c[0] for c in comm.calls] == ["open", "close", "open", "discard"]


def test_with_pooling_the_session_waits_for_the_next_acquire_and_counts_as_no_login():
    comm = FakeNetconf()
    driver = driver_for(comm)

    async def go():
        sessions = SessionManager(pool=True)
        first = await sessions.acquire(driver, T1, CREDS, TIMEOUTS, "off")
        await sessions.release(driver, T1, CREDS)
        assert sessions.pooled(driver, T1, CREDS)
        assert await sessions.acquire(driver, T1, CREDS, TIMEOUTS, "off") is first
        await sessions.release(driver, T1, CREDS, discard=True)
        assert not sessions.pooled(driver, T1, CREDS)
        sessions.wait_for_closes()
        await sessions.close_all()

    asyncio.run(go())
    assert [c[0] for c in comm.calls] == ["open", "release", "reuse", "discard"]


def test_the_close_runs_beside_the_work_and_its_fault_comes_back_from_the_join():
    started = threading.Event()

    class SlowClose(FakeNetconf):
        def close(self, session):
            started.set()
            time.sleep(0.2)
            raise Fault(FaultKind.SESSION_LOST, "closed on us", True)

    driver = driver_for(SlowClose())

    async def go():
        sessions = SessionManager()
        await sessions.acquire(driver, T1, CREDS, TIMEOUTS, "off")
        t0 = time.monotonic()
        await sessions.release(driver, T1, CREDS)
        assert time.monotonic() - t0 < 0.1 and started.wait(1)
        late = await asyncio.to_thread(sessions.wait_for_closes)
        return late

    late = asyncio.run(go())
    driver_name, op = late["r1"]
    assert driver_name == "junos@netconf" and op.command == "close" and fault_of(op).kind is FaultKind.SESSION_LOST


def test_a_close_still_running_after_the_wait_is_left_to_the_process():
    class NeverCloses(FakeNetconf):
        def close(self, session):
            time.sleep(5)

    driver = driver_for(NeverCloses())

    async def go():
        sessions = SessionManager()
        await sessions.acquire(driver, T1, CREDS, TIMEOUTS, "off")
        await sessions.release(driver, T1, CREDS)
        t0 = time.monotonic()
        late = sessions.wait_for_closes(timeout=0.1)
        assert time.monotonic() - t0 < 1 and late == {}

    asyncio.run(go())
    assert all(t.daemon for t in threading.enumerate() if t.name == "hssh-close")


def test_a_communicator_bug_in_close_is_a_local_warning():
    class Buggy(FakeNetconf):
        def close(self, session):
            raise RuntimeError("bug")

    driver = driver_for(Buggy())

    async def go():
        sessions = SessionManager()
        await sessions.acquire(driver, T1, CREDS, TIMEOUTS, "off")
        await sessions.release(driver, T1, CREDS)
        return sessions.wait_for_closes()

    late = asyncio.run(go())
    assert fault_of(late["r1"][1]).kind is FaultKind.LOCAL and "RuntimeError" in fault_of(late["r1"][1]).detail
