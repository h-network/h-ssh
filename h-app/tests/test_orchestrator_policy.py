import asyncio

import pytest

from hssh.model import Fault, FaultKind, PolicySettings, Target
from hssh.orchestrator.defaults import CONNECT_BACKOFF, DEFAULT_POLICY
from hssh.orchestrator.policy import OPEN, Action, Policy, Verdict, decide, is_read

T = Target("r1", "10.0.0.1", "junos", "netconf")


def at_open(kind, reached, attempt=1, editing=False):
    return decide(Fault(kind, "x", reached), read=not editing, editing=editing, operation=OPEN, attempt=attempt)


def in_session(kind, reached, *, read, attempt=1):
    return decide(Fault(kind, "x", reached), read=read, editing=not read, operation="show", attempt=attempt)


@pytest.mark.parametrize("kind", [FaultKind.UNREACHABLE, FaultKind.AUTH, FaultKind.HOST_KEY, FaultKind.UNSUPPORTED, FaultKind.LOCAL])
def test_a_clear_answer_at_open_fails_once(kind):
    assert at_open(kind, False).action is Action.FAIL


def test_an_unanswered_connect_is_retried_while_retries_remain():
    assert at_open(FaultKind.TIMEOUT, False, attempt=1).action is Action.RETRY
    assert at_open(FaultKind.TIMEOUT, False, attempt=2).action is Action.RETRY
    assert at_open(FaultKind.TIMEOUT, False, attempt=3).action is Action.FAIL


def test_a_setup_the_device_dropped_is_retried():
    assert at_open(FaultKind.SESSION_LOST, True).action is Action.RETRY


def test_a_setup_that_ran_out_after_the_banner_fails_once():
    assert at_open(FaultKind.TIMEOUT, True).action is Action.FAIL


def test_an_edit_retries_an_unanswered_connect_too():
    assert at_open(FaultKind.TIMEOUT, False, editing=True).action is Action.RETRY


@pytest.mark.parametrize("kind", [FaultKind.UNREACHABLE, FaultKind.TIMEOUT, FaultKind.SESSION_LOST, FaultKind.AUTH, FaultKind.HOST_KEY, FaultKind.LOCAL])
def test_no_fault_at_open_cools_the_device_down(kind):
    assert not at_open(kind, True, editing=True).cool_down


def test_a_read_that_timed_out_or_lost_its_session_is_retried():
    assert in_session(FaultKind.TIMEOUT, True, read=True).action is Action.RETRY
    assert in_session(FaultKind.SESSION_LOST, True, read=True).action is Action.RETRY


def test_an_edit_that_timed_out_fails_and_cools_only_when_it_reached_the_device():
    assert in_session(FaultKind.TIMEOUT, True, read=False) == Verdict(Action.FAIL, cool_down=True)
    assert in_session(FaultKind.TIMEOUT, False, read=False) == Verdict(Action.FAIL, cool_down=False)


def test_a_refusal_cools_the_device_only_for_an_edit_that_reached_it():
    assert in_session(FaultKind.REFUSED, True, read=False).cool_down
    assert not in_session(FaultKind.REFUSED, False, read=False).cool_down
    assert not in_session(FaultKind.REFUSED, True, read=True).cool_down


def test_a_local_failure_never_cools_the_device():
    assert in_session(FaultKind.LOCAL, True, read=False) == Verdict(Action.FAIL)


def test_an_unknown_commit_outcome_fails_cools_and_is_flagged():
    verdict = in_session(FaultKind.OUTCOME_UNKNOWN, True, read=False)
    assert verdict.action is Action.FAIL and verdict.cool_down and "check the device" in verdict.note


def test_retries_come_from_the_settings():
    settings = PolicySettings(retries=0, retry_pause=1)
    assert decide(Fault(FaultKind.TIMEOUT, "x", False), read=True, editing=False, operation=OPEN, attempt=1,
                  settings=settings).action is Action.FAIL


class Dialect:
    def is_read(self, command):
        return command.startswith("show")


def test_a_command_with_a_line_break_is_never_a_read():
    assert is_read(Dialect(), "show version")
    assert not is_read(Dialect(), "show version\nshow chassis")
    assert not is_read(Dialect(), "show version\rrequest system reboot")


def pauses(policy, unanswered, attempts=3):
    slept = []

    async def go():
        real = asyncio.sleep
        asyncio.sleep = lambda s: slept.append(s) or real(0)
        try:
            for attempt in range(1, attempts + 1):
                await policy.pause(attempt, unanswered)
        finally:
            asyncio.sleep = real

    asyncio.run(go())
    return slept


def test_an_unanswered_connect_backs_off_half_a_second_then_one():
    assert pauses(Policy(DEFAULT_POLICY, None), unanswered=True) == [CONNECT_BACKOFF[0], CONNECT_BACKOFF[1], CONNECT_BACKOFF[1]]


def test_every_other_retry_waits_the_retry_pause():
    assert pauses(Policy(PolicySettings(retries=2, retry_pause=2), None), unanswered=False) == [2, 2, 2]


class Gate:
    def __init__(self, admit=True, reason="held"):
        self.admit, self.reason, self.calls = admit, reason, []

    def check_device(self, target, *, login=True):
        self.calls.append(("check", target.name, login))
        return self.admit, "" if self.admit else self.reason

    def holds(self, targets):
        return {t.name: "cooling" for t in targets}

    def release_device(self, target):
        self.calls.append(("release", target.name))

    def set_cooldown(self, target):
        self.calls.append(("cooldown", target.name))

    def close(self):
        pass


def test_the_gate_decides_admission_and_the_reason_comes_back():
    assert Policy(None, Gate(admit=False, reason="cooling down")).admit(T) == "cooling down"
    assert Policy(None, Gate()).admit(T, login=False) is None


def test_settle_cools_down_on_a_cooling_verdict_and_releases_otherwise():
    gate = Gate()
    policy = Policy(None, gate)
    policy.settle(T, Verdict(Action.FAIL, cool_down=True))
    policy.settle(T, Verdict(Action.FAIL))
    policy.settle(T, None)
    assert gate.calls == [("cooldown", "r1"), ("release", "r1"), ("release", "r1")]


def test_without_a_gate_everything_is_admitted_and_nothing_is_held():
    policy = Policy(None, None)
    assert policy.admit(T) is None and policy.held([T]) == {}
    policy.settle(T, Verdict(Action.FAIL, cool_down=True))
