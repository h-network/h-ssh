"""--raw output mode and JSON output shape."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hssh.cli import strip_result_header

HEADER = "DEVICE: cr1\nHOST:   10.0.1.1\nMODE:   show\nVENDOR: openssh\n\n"


def test_strips_the_runner_header():
    out = HEADER + "Junos: 24.2R1-S2.5"
    assert strip_result_header(out) == "Junos: 24.2R1-S2.5"


def test_strips_the_command_echo():
    out = HEADER + "$ show version\nJunos: 24.2R1-S2.5"
    assert strip_result_header(out, "show version") == "Junos: 24.2R1-S2.5"


def test_keeps_an_echo_that_is_not_the_command():
    """Device output starting with '$ ' must survive."""
    out = HEADER + "$ something else\nJunos: 24.2R1-S2.5"
    assert strip_result_header(out, "show version").startswith("$ something else")


def test_keeps_dollar_lines_inside_output():
    out = HEADER + "$ show version\nprompt$ still output"
    assert "prompt$ still output" in strip_result_header(out, "show version")


def test_multiline_output_is_preserved():
    body = "set routing-options graceful-restart\nset chassis redundancy graceful-switchover"
    out = HEADER + "$ show configuration\n" + body
    assert strip_result_header(out, "show configuration") == body


def test_handles_output_with_no_header():
    assert strip_result_header("Junos: 24.2R1-S2.5") == "Junos: 24.2R1-S2.5"


def test_handles_empty_output():
    assert strip_result_header(HEADER) == ""


def test_blank_lines_inside_output_survive():
    out = HEADER + "$ show version\nfirst\n\nsecond"
    assert strip_result_header(out, "show version") == "first\n\nsecond"


@pytest.mark.parametrize("flags", [["--raw", "-v"], ["--raw", "--json"]])
def test_raw_conflicts_are_refused(flags, tmp_path):
    import subprocess
    hssh = os.path.join(os.path.dirname(__file__), "..", "h-ssh.py")
    proc = subprocess.run(
        [sys.executable, hssh, "--target", "x:1.2.3.4:openssh", "-sC", "show version"] + flags,
        capture_output=True, text=True, timeout=30)
    assert proc.returncode == 2
    assert "mutually exclusive" in proc.stderr
