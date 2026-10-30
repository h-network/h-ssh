"""Exit codes: 0, 1 a device failed, 2 refused, 3 not everything ran, 4 a record not kept, 130 interrupted; a watch takes the worst."""

import pytest

from cli_helpers import report
from hssh.frontends import cli
from hssh.model import Fault, FaultKind

R1 = "R1:10.0.0.1:junos"
BASE = ["-sC", "show version", "--transport", "netconf", "--raw"]


@pytest.mark.parametrize("fields, code", [
    ({"ok": 2}, 0),
    ({"ok": 1, "failed": 1}, 1),
    ({"ok": 1, "skipped": 1}, 3),
    ({"failed": 1, "skipped": 1}, 1),
    ({"ok": 1, "not_kept": 1}, 4),
    ({"failed": 1, "not_kept": 1}, 4),
    ({"failed": 1, "not_kept": 1, "interrupted": True}, 130),
])
def test_the_exit_code_reads_the_report(cli_run, fields, code):
    rc, _, _, _ = cli_run(R1, *BASE, reports=[report(**fields)])
    assert rc == code


@pytest.mark.parametrize("a, b, expected", [(1, 3, 1), (3, 0, 3), (4, 1, 4), (0, 130, 130), (2, 4, 4), (2, 1, 2)])
def test_worst_follows_the_order_130_4_2_1_3_0(a, b, expected):
    assert cli.worst(a, b) == expected == cli.worst(b, a)


WATCH = ["-sC", "show version", "--transport", "netconf", "--every", "1", "--times", "3"]


@pytest.fixture
def no_store_rows(monkeypatch):
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    monkeypatch.setattr(cli, "read_rows", lambda path, run_id: {})


def test_a_watch_exits_with_its_worst_tick_not_its_last(cli_run, no_store_rows):
    ticks = [report(skipped=1), report(failed=1), report(ok=1)]
    rc, specs, _, _ = cli_run(R1, *WATCH, reports=ticks)
    assert rc == 1 and len(specs) == 3


def test_a_watch_stops_at_an_interrupted_tick(cli_run, no_store_rows):
    ticks = [report(ok=1), report(skipped=1, interrupted=True), report(ok=1)]
    rc, specs, _, _ = cli_run(R1, *WATCH, reports=ticks)
    assert rc == 130 and len(specs) == 2


def test_a_watch_sleeps_between_ticks_not_before_the_first(cli_run, monkeypatch):
    slept = []
    monkeypatch.setattr(cli.time, "sleep", slept.append)
    monkeypatch.setattr(cli, "read_rows", lambda path, run_id: {})
    cli_run(R1, *WATCH[:-4], "--every", "2.5", "--times", "3")
    assert slept == [2.5, 2.5]


def test_a_local_refusal_out_of_the_run_is_one_error_line_and_exit_2(monkeypatch, capsys):
    def refusing(spec):
        raise Fault(FaultKind.LOCAL, "the store cannot be opened", False)

    monkeypatch.setenv("HSSH_PASSWORD", "x")
    rc = cli.main([R1, *BASE], runner=refusing)
    assert rc == 2 and capsys.readouterr().err == "ERROR: LOCAL: the store cannot be opened\n"


def test_main_sync_turns_ctrl_c_into_130(monkeypatch):
    def interrupted(argv=None, runner=None):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "main", interrupted)
    with pytest.raises(SystemExit) as stop:
        cli.main_sync()
    assert stop.value.code == 130
