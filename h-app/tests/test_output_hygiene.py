"""#63: a closed stdout (`| head`) is not an error, paramiko's transport
tracebacks stay off the screen, the confirm reminder prints only for timers
that are running, and a confirm with nothing pending commits nothing."""
import asyncio
import io
import logging
import os
import sys
import types
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hssh import cli, drivers, runner
from hssh.errors import NothingToConfirmError, NotAppliedError


async def _reachable(target, timeout=2):
    return (target.name, True, "reachable")


def run_main(monkeypatch, capsys, argv, driver):
    monkeypatch.setitem(drivers.MODULES, "junos@netconf", driver)
    monkeypatch.setattr(cli, "check_reachability", _reachable)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE", "HSSH_PASSWORD", "HSSH_USER"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(sys, "argv", ["h-ssh", "--config", os.devnull, "--user", "u", "--password", "p", *argv])
    rc = asyncio.run(cli.main())
    out, err = capsys.readouterr()
    return rc, out, err


# --- M9: the reader went away -------------------------------------------------

def test_a_broken_pipe_is_exit_0_with_stdout_parked(monkeypatch):
    async def main():
        raise BrokenPipeError
    dups = []
    monkeypatch.setattr(cli, "main", main)
    monkeypatch.setattr(os, "dup2", lambda a, b: dups.append((a, b)))
    with pytest.raises(SystemExit) as exc:
        cli.main_sync()
    assert exc.value.code == 0
    assert [d[1] for d in dups] == [sys.stdout.fileno(), sys.stderr.fileno()]


def test_ctrl_c_still_exits_130(monkeypatch, capsys):
    async def main():
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "main", main)
    with pytest.raises(SystemExit) as exc:
        cli.main_sync()
    assert exc.value.code == 130 and "Interrupted" in capsys.readouterr().err


def test_a_progress_line_into_a_closed_pipe_is_not_a_device_error(monkeypatch):
    class Gone:
        def write(self, s):
            raise BrokenPipeError
        def flush(self):
            pass
    monkeypatch.setattr(sys, "stdout", Gone())
    runner._say("R1 STARTED")          # no exception: the device's result stands


# --- M10: paramiko's tracebacks -----------------------------------------------

def test_transport_loggers_are_silenced_unless_verbose(monkeypatch, capsys):
    for name in ("paramiko", "ncclient"):
        lg = logging.getLogger(name)
        monkeypatch.setattr(lg, "level", logging.NOTSET)
        monkeypatch.setattr(lg, "handlers", [])
    drv = types.SimpleNamespace(AVAILABLE=True, show=lambda *a, **kw: "ok")
    run_main(monkeypatch, capsys, ["--target", "R1:10.0.0.1:junos", "-sC", "show version"], drv)
    assert logging.getLogger("paramiko").level == logging.CRITICAL
    assert any(isinstance(h, logging.NullHandler) for h in logging.getLogger("paramiko").handlers)
    assert logging.getLogger("ncclient").level == logging.CRITICAL
    for name in ("paramiko", "ncclient"):
        lg = logging.getLogger(name)
        lg.setLevel(logging.NOTSET)
        lg.handlers[:] = []
    run_main(monkeypatch, capsys, ["--target", "R1:10.0.0.1:junos", "-sC", "show version", "-v"], drv)
    assert logging.getLogger("paramiko").level == logging.NOTSET


# --- L6: the reminder is for timers that run ----------------------------------

@pytest.mark.parametrize("reply, banner", [
    ("COMMIT OK\n", True),
    ("NO CHANGES\n", False),
    (ValueError("--commit-confirmed is not supported by the 'openssh' transport"), False),
])
def test_confirm_reminder_only_when_a_timer_was_armed(monkeypatch, capsys, reply, banner):
    def edit(*a, **kw):
        if isinstance(reply, Exception):
            raise reply
        return reply
    drv = types.SimpleNamespace(AVAILABLE=True, edit=edit)
    rc, out, err = run_main(monkeypatch, capsys,
                            ["--target", "R1:10.0.0.1:junos", "-eC", "set system host-name x", "--commit-confirmed", "5", "-y"], drv)
    assert ("DON'T FORGET TO CONFIRM" in out) is banner, out


# --- L7: a confirm with nothing pending ---------------------------------------

def test_junos_confirm_with_nothing_pending_sends_nothing(monkeypatch):
    from hssh.transports import netconf
    from tests.test_junos import FakeDevice, FakeConfig
    FakeDevice.instances, FakeConfig.instances = [], []
    monkeypatch.setattr(netconf, "AVAILABLE", True)
    monkeypatch.setattr(netconf, "JunosDevice", FakeDevice)
    monkeypatch.setattr(netconf, "JunosConfig", FakeConfig)
    monkeypatch.setattr(netconf, "_pending_on", lambda dev, t: None)
    with pytest.raises(NothingToConfirmError, match="nothing to confirm"):
        netconf.confirm("10.0.0.1", "u", "p", 5, 30)
    assert FakeConfig.instances == []           # no lock, no commit


def test_junos_pending_on_reads_the_history(monkeypatch):
    from hssh.transports import netconf
    doc = {"commit-information": [{"commit-history": [
        {"sequence-number": [{"data": "0"}], "user": [{"data": "u"}], "client": [{"data": "netconf"}],
         "date-time": [{"data": "x", "attributes": {"junos:seconds": "1"}}],
         "comment": [{"data": "commit confirmed, rollback in 5mins"}]}]}]}
    monkeypatch.setattr(netconf, "_rpc_reply", lambda dev, cmd, args, fmt: doc)
    assert netconf._pending_on(object(), 5)["pending_rollback_minutes"] == 5
    doc["commit-information"][0]["commit-history"][0]["comment"] = [{"data": ""}]
    assert netconf._pending_on(object(), 5) is None


def test_telnet_confirm_with_nothing_pending_sends_nothing():
    from hssh.transports import telnet
    from tests.test_telnet import ScriptedTelnetServer, junos_cli, HISTORY_CLEAN, _received
    srv = ScriptedTelnetServer(junos_cli(history=HISTORY_CLEAN))
    with pytest.raises(NothingToConfirmError, match="nothing to confirm"):
        telnet.confirm("127.0.0.1", "lab", "secret", session_timeout=5, command_timeout=5,
                       port=srv.port, vendor_hint="telnet-junos")
    assert _received(srv) == ["show system commit"]


def test_nothing_to_confirm_is_not_retried_and_fails_the_device(monkeypatch, capsys):
    calls = []

    def confirm(*a, **kw):
        calls.append(1)
        raise NothingToConfirmError("nothing to confirm: no commit-confirmed is pending on the device")
    drv = types.SimpleNamespace(AVAILABLE=True, confirm=confirm, edit=lambda *a, **kw: "COMMIT OK\n")
    rc, out, err = run_main(monkeypatch, capsys,
                            ["--target", "R1:10.0.0.1:junos", "-eC", "commit", "-y", "--retries", "3"], drv)
    assert rc == 1 and len(calls) == 1
    assert "nothing to confirm" in out + err
    assert "COMMIT CONFIRMED OK" not in out
