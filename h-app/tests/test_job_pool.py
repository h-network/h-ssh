"""#57: a job's entries share one NETCONF session per device."""
import asyncio
import json
import os
import sys
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hssh import cli, pool
from hssh.vendors import junos
from tests.test_junos import FakeConfig, FakeDevice


async def _reachable(target, timeout=2):
    return (target.name, True, "reachable")


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
    monkeypatch.setattr(junos, "_pending_on", lambda dev, t: None)
    monkeypatch.setattr(cli, "check_reachability", _reachable)
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
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "--password", "p", "-y",
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
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "--password", "p",
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
