"""#57: a job's entries share one NETCONF session per device."""
import asyncio
import json
import os
import sys
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hssh import cli, pool
from hssh.transports import netconf
from tests.test_junos import FakeConfig, FakeDevice


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
    monkeypatch.setattr(netconf, "_pending_on", lambda dev, t: None)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    pool.close_all()
    pool.disable()
    yield
    pool.close_all()
    pool.disable()
    for k in pool.POOL.stats:
        pool.POOL.stats[k] = 0


def _run(monkeypatch, capsys, tmp_path, entries, *extra, cancel_after=None):
    job = tmp_path / "job.json"
    job.write_text(json.dumps(entries))
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "-y",
                                      "--job", str(job), "--json", *extra])
    if cancel_after is None:
        rc = asyncio.run(cli.main())
    else:
        async def go():
            asyncio.get_running_loop().call_later(cancel_after, asyncio.current_task().cancel)
            return await cli.main()
        rc = asyncio.run(go())
    out, err = capsys.readouterr()
    return rc, out, err


def test_a_job_opens_one_session_per_device_not_per_entry(monkeypatch, capsys, tmp_path):
    FakeDevice.cli_outputs = {"show version": "v", "show route summary": "r", "show ospf neighbor": "o"}
    rc, out, err = _run(monkeypatch, capsys, tmp_path, [
        {"target": "R1:10.0.0.1:junos", "show": "show version"},
        {"target": "R1:10.0.0.1:junos", "show": "show route summary"},
        {"target": "R1:10.0.0.1:junos", "show": "show ospf neighbor"},
        {"target": "R2:10.0.0.2:junos", "show": "show version"},
    ], "--workers", "4")
    assert rc == 0, err
    data = json.loads(out)
    # results land in completion order (R2 runs beside R1); a host's own entries stay in file order
    assert [e["output"] for e in data if e["device"] == "R1"] == ["v", "r", "o"]
    assert [e["output"] for e in data if e["device"] == "R2"] == ["v"]
    assert len(FakeDevice.instances) == 2                         # one login per device, not four
    assert sorted(d.params["host"] for d in FakeDevice.instances) == ["10.0.0.1", "10.0.0.2"]
    assert all(d.closed for d in FakeDevice.instances) and pool.live() == 0 and not pool.POOL.enabled


def test_an_edit_entry_and_the_show_after_it_share_the_session(monkeypatch, capsys, tmp_path):
    FakeDevice.cli_outputs = {"show configuration | compare rollback 1": "+ host-name r1"}
    rc, out, err = _run(monkeypatch, capsys, tmp_path, [
        {"target": "R1:10.0.0.1:junos", "edit": "set system host-name r1"},
        {"target": "R1:10.0.0.1:junos", "show": "show configuration | compare rollback 1"},
    ], "--workers", "2")
    assert rc == 0, err
    data = json.loads(out)
    assert [e["ok"] for e in data] == [True, True] and data[1]["output"] == "+ host-name r1"
    assert len(FakeDevice.instances) == 1
    assert [c[0] for c in FakeConfig.instances[0].calls][:4] == ["lock", "load", "diff", "commit_check"]


def test_a_plain_show_run_still_opens_one_session_per_device_and_leaves_the_pool_off(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("HSSH_PASSWORD", "p")
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u",
                                      "--target", "R1:10.0.0.1:junos", "-sC", "show version", "--json"])
    assert asyncio.run(cli.main()) == 0
    assert not pool.POOL.enabled and len(FakeDevice.instances) == 1 and FakeDevice.instances[0].closed


def test_ctrl_c_mid_job_leaves_no_session_open(monkeypatch, capsys, tmp_path):
    import time
    slow = FakeDevice.cli  # noqa: F841

    def cli_slow(self, cmd, warning=True):
        time.sleep(0.5)
        return "v"
    monkeypatch.setattr(FakeDevice, "cli", cli_slow)
    rc, out, err = _run(monkeypatch, capsys, tmp_path, [
        {"target": f"R{i}:10.0.0.{i}:junos", "show": "show version"} for i in range(1, 5)
    ], "--workers", "1", cancel_after=0.2)
    assert rc == 130
    assert pool.live() == 0 and not pool.POOL.enabled
    assert all(d.closed for d in FakeDevice.instances)


def test_the_end_of_a_job_gives_the_closes_one_second_in_all(monkeypatch, capsys, tmp_path):
    """close_all() waits up to a second for the closes it starts (#113), and
    the run's own wait for closes in flight then gave the same closes
    another second: a router that never acknowledged its close cost the end
    of every job two seconds instead of one."""
    import threading
    import time
    release, closing = threading.Event(), []

    class Wedged(FakeDevice):
        def close(self):
            closing.append(time.monotonic())
            release.wait(10)
            super().close()
    monkeypatch.setattr(netconf, "JunosDevice", Wedged)
    try:
        rc, out, err = _run(monkeypatch, capsys, tmp_path, [{"target": "R1:10.0.0.1:junos", "show": "show version"}])
        elapsed = time.monotonic() - closing[0]         # from the close to the end of the run
    finally:
        release.set()
    assert rc == 0, err
    assert 0.9 <= elapsed < 1.6, f"{elapsed:.2f}s"
    assert FakeDevice.instances[0].closed and pool.live() == 0


def test_a_run_that_ends_early_gives_the_closes_half_a_second_in_all(monkeypatch, capsys):
    """A second Ctrl-C or a crash ends main() with the job's sessions still
    pooled; the way out closes them. close_all() there waited up to a
    second for its closes, then the exit gave the same closes the half
    second it always had: a router that never acknowledged held the exit
    one and a half seconds."""
    import threading
    import time
    release = threading.Event()

    class Wedged(FakeDevice):
        def close(self):
            release.wait(10)
            super().close()
    monkeypatch.setattr(netconf, "JunosDevice", Wedged)

    async def main():
        pool.enable()
        netconf.show("10.0.0.1", "u", "p", "show version", 5, 30)
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "main", main)
    try:
        t0 = time.monotonic()
        with pytest.raises(SystemExit) as exc:
            cli.main_sync()
        elapsed = time.monotonic() - t0
    finally:
        release.set()
    assert exc.value.code == 130 and "Interrupted" in capsys.readouterr().err
    assert 0.45 <= elapsed < 1.0, f"{elapsed:.2f}s"
    assert FakeDevice.instances[0].closed and pool.live() == 0
