"""What the CLI prints: the text report, --raw, --json, the [h-ssh] summary line and the commit-confirmed reminder."""

import json

import pytest

from cli_helpers import report
from hssh.frontends import cli
from hssh.model import CommitStatus, Fault, FaultKind, OperationResult, Result, Target, TargetResult

T = Target("R1", "10.0.0.1", "junos", "netconf")
NETCONF = ("--transport", "netconf")


def op(command, outcome, ms=5):
    return OperationResult(command, outcome, "2026-10-30T10:00:00+00:00", ms)


def one(status, *ops, target=T):
    return TargetResult(target, status, tuple(ops))


def test_the_text_report_frames_each_output_and_ends_with_the_counts(cli_run):
    rep = report(results=[one("ok", op("show version", Result("Junos: 24.2")))], ok=1)
    _, _, out, _ = cli_run("R1:10.0.0.1:junos", "-sC", "show version", *NETCONF, reports=[rep])
    assert out.splitlines() == ["=== R1 (10.0.0.1) show version [5 ms]", "Junos: 24.2", "run 1: 1 ok, 0 failed, 0 skipped"]


def test_raw_prints_the_output_alone(cli_run):
    rep = report(results=[one("ok", op("show version", Result("Junos: 24.2")))], ok=1)
    _, _, out, _ = cli_run("R1:10.0.0.1:junos", "-sC", "show version", "--raw", *NETCONF, reports=[rep])
    assert out == "R1:\nJunos: 24.2\n"


def test_a_failed_operation_is_a_fail_line_with_kind_and_detail(cli_run):
    rep = report(results=[one("failed", op("open", Fault(FaultKind.AUTH, "denied", True)))], failed=1)
    rc, _, out, _ = cli_run("R1:10.0.0.1:junos", "-sC", "x", "--raw", *NETCONF, reports=[rep])
    assert rc == 1 and out == "R1: FAIL open: AUTH denied\n"


def test_a_skipped_target_is_one_line_with_its_reason(cli_run):
    rep = report(results=[one("skipped", op("open", Fault(FaultKind.LOCAL, "interrupted while connecting", False))),
                          one("skipped", target=Target("R2", "h", "junos", "netconf"))], skipped=2, interrupted=True)
    rc, _, out, _ = cli_run("R1:10.0.0.1:junos", "R2:h:junos", "-sC", "x", "--raw", *NETCONF, reports=[rep])
    assert rc == 130 and out.splitlines() == ["R1: SKIPPED: interrupted while connecting", "R2: SKIPPED"]


def test_a_close_fault_is_a_warning_on_stderr_not_a_failure(cli_run):
    ops = (op("show v", Result("out")), op("close", Fault(FaultKind.SESSION_LOST, "socket closed", True)))
    rc, _, out, err = cli_run("R1:10.0.0.1:junos", "-sC", "x", "--raw", *NETCONF, reports=[report(results=[one("ok", *ops)], ok=1)])
    assert rc == 0 and out == "R1:\nout\n" and "WARNING: R1: close failed: socket closed" in err


def test_the_summary_line_is_json_on_stderr_with_the_counts(cli_run):
    rep = report(ok=2, failed=1, skipped=1, results=[one("ok")] * 4, not_kept=2, interrupted=True)
    _, _, _, err = cli_run("R1:10.0.0.1:junos", "-sC", "x", "--raw", *NETCONF, reports=[rep])
    summary = json.loads(err.strip().splitlines()[-1].removeprefix("[h-ssh] "))
    assert summary == {"targets": 4, "ok": 2, "fail": 1, "skipped": 1, "interrupted": True, "not_kept": 2,
                       "elapsed_ms": 1500, "mode": "show"}


def test_the_summary_line_omits_what_did_not_happen(cli_run):
    _, _, _, err = cli_run("R1:10.0.0.1:junos", "-sC", "x", "--raw", *NETCONF, reports=[report(ok=1)])
    assert set(json.loads(err.strip().removeprefix("[h-ssh] "))) == {"targets", "ok", "fail", "skipped", "elapsed_ms", "mode"}


def test_json_carries_the_whole_report_with_dataclass_data_as_dicts(cli_run):
    status = CommitStatus(pending=True, remaining_minutes=4, newest="<entry/>")
    ops = (op("commit_history", Result("hist", data=status)), op("confirm", Result("ok", data={"a": [1]})))
    rep = report(mode="confirm", results=[one("ok", *ops)], ok=1, not_kept=1, pending={"R1": 10})
    _, _, out, _ = cli_run("R1:10.0.0.1:junos", "--confirm", "--json", *NETCONF, reports=[rep])
    doc = json.loads(out)
    assert doc["mode"] == "confirm" and doc["not_kept"] == 1 and doc["pending"] == {"R1": 10}
    assert [o["data"] for o in doc["results"][0]["operations"]] == [{"pending": True, "remaining_minutes": 4, "newest": "<entry/>"}, {"a": [1]}]


def test_json_marks_a_failed_operation(cli_run):
    rep = report(results=[one("failed", op("open", Fault(FaultKind.TIMEOUT, "no answer", False)))], failed=1)
    _, _, out, _ = cli_run("R1:10.0.0.1:junos", "-sC", "x", "--json", *NETCONF, reports=[rep])
    operation = json.loads(out)["results"][0]["operations"][0]
    assert operation == {"command": "open", "started": "2026-10-30T10:00:00+00:00", "elapsed_ms": 5, "ok": False,
                         "fault": "TIMEOUT", "detail": "no answer", "reached_device": False}


def test_the_reminder_names_the_minutes_and_the_confirm_command(cli_run):
    rep = report(mode="edit", results=[one("ok", op("commit", Result("ok")))], ok=1, pending={"R1": 10})
    _, _, out, _ = cli_run("R1:10.0.0.1:junos", "-eC", "set x", "-y", "--commit-confirmed", *NETCONF, reports=[rep])
    assert "pending commit on R1: rolls back in 10 minutes" in out
    assert out.splitlines()[-1] == "confirm with: h-ssh --confirm R1:10.0.0.1:junos --transport netconf"


def test_no_reminder_without_a_pending_commit_or_under_raw(cli_run):
    rep = report(mode="edit", results=[one("ok", op("commit", Result("ok")))], ok=1, pending={"R1": 10})
    _, _, out, _ = cli_run("R1:10.0.0.1:junos", "-eC", "set x", "-y", *NETCONF, reports=[report(mode="edit", ok=1)])
    assert "confirm with" not in out
    _, _, out, _ = cli_run("R1:10.0.0.1:junos", "-eC", "set x", "-y", "--raw", *NETCONF, reports=[rep])
    assert "confirm with" not in out


@pytest.mark.parametrize("argv, expected", [
    (["10.0.0.1", "--target", "R2:10.0.0.2:junos", "--user", "adm"],
     "h-ssh --confirm --user adm 10.0.0.1 --target R2:10.0.0.2:junos"),
    (["--devices", "inv/prod.csv"], "h-ssh --confirm --devices inv/prod.csv"),
    (["R1:10.0.0.1", "--transport", "netconf", "--vendor", "junos"],
     "h-ssh --confirm R1:10.0.0.1 --transport netconf --vendor junos"),
    (["R1:10.0.0.1", "--user", "a b"], "h-ssh --confirm --user 'a b' R1:10.0.0.1"),
])
def test_the_confirm_command_is_rebuilt_from_the_run_as_typed(argv, expected, monkeypatch):
    monkeypatch.setattr(cli.sys, "argv", ["h-ssh", *argv])
    parser = cli.build_parser()
    args = parser.parse_intermixed_args(argv)
    args.target = (list(args.hosts) + list(args.target or [])) or None
    args.typed = cli.typed_dests(parser, argv)
    assert cli.confirm_command(args) == expected


def test_the_confirm_command_names_a_script_as_it_was_started(monkeypatch):
    parser = cli.build_parser()
    args = parser.parse_intermixed_args(["R1:10.0.0.1"])
    args.target, args.typed = args.hosts, set()
    monkeypatch.setattr(cli.sys, "argv", ["./h-app/h-ssh.py", "R1:10.0.0.1"])
    assert cli.confirm_command(args).startswith("./h-app/h-ssh.py --confirm")
