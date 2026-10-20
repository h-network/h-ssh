"""Default-mode output for edits, and the commit-confirmed reminder."""
import asyncio
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hssh import cli, vendors
from hssh.cli import build_confirm_command, format_edit_result

HEADER = "DEVICE: R1\nHOST:   10.0.0.1\nMODE:   edit-cmd\nVENDOR: junos\n\n"
DIFF = "DIFF:\n[edit system]\n+   host-name R1-new;\n"


def test_edit_result_is_indented_under_the_status_line():
    assert format_edit_result(HEADER + "COMMIT OK\n\n" + DIFF) == (
        "  COMMIT OK\n"
        "\n"
        "  DIFF:\n"
        "  [edit system]\n"
        "  +   host-name R1-new;"
    )


def test_edit_result_without_a_diff_is_one_line():
    assert format_edit_result(HEADER + "NO CHANGES\n") == "  NO CHANGES"


def run_cli(monkeypatch, capsys, tmp_path, argv, result):
    """Run main() in-process against a fake junos driver; nothing is contacted."""
    fake = types.SimpleNamespace(AVAILABLE=True, edit=lambda *a, **kw: result)
    monkeypatch.setitem(vendors.VENDORS, "junos", fake)
    monkeypatch.setitem(cli.VENDOR_MODULES, "junos", fake)
    for var in ("HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(sys, "argv", [
        "h-ssh.py", "--config", str(tmp_path / "no-config"), "--user", "u", "--password", "p",
        "--target", "R1:10.0.0.1:junos", *argv])
    rc = asyncio.run(cli.main())
    return rc, capsys.readouterr().out


def test_default_mode_prints_the_dry_run_diff(monkeypatch, capsys, tmp_path):
    rc, out = run_cli(monkeypatch, capsys, tmp_path,
                      ["-eC", "set system host-name R1-new", "--dry-run"],
                      "DRY-RUN: commit check passed, nothing committed\n\n" + DIFF)
    assert rc == 0
    assert "  DRY-RUN: commit check passed, nothing committed\n" in out
    assert "  +   host-name R1-new;\n" in out
    assert "--- Output from R1 ---" not in out  # the frame belongs to -v


def test_show_mode_default_output_is_still_the_status_line(monkeypatch, capsys, tmp_path):
    rc, out = run_cli(monkeypatch, capsys, tmp_path, ["-sC", "show version", "--dry-run"], "")
    assert rc == 0
    status = [ln for ln in out.splitlines() if ln.endswith(" OK")]
    assert len(status) == 1 and "R1" in status[0]
    assert "DRY-RUN show" not in out


async def _reachable(target, timeout=2):
    return (target.name, True, "reachable")


def test_reminder_repeats_the_run_targets(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(cli, "check_reachability", _reachable)
    rc, out = run_cli(monkeypatch, capsys, tmp_path,
                      ["-eC", "set system host-name R1-new", "--commit-confirmed", "5", "-y"],
                      "COMMIT CONFIRMED (5 minutes)\n\n" + DIFF)
    assert rc == 0
    assert "  COMMIT CONFIRMED (5 minutes)\n" in out
    assert '\n  ./h-app/h-ssh.py -eC "commit" --user u --target R1:10.0.0.1:junos\n' in out


def test_confirm_command_repeats_inline_targets_as_typed():
    cmd = build_confirm_command("admin", ["R1:10.0.1.1:junos", "R2:10.0.1.2:830:junos"],
                                "devices.csv", "ssh")
    assert cmd == ('./h-app/h-ssh.py -eC "commit" --user admin '
                   '--target R1:10.0.1.1:junos --target R2:10.0.1.2:830:junos')


def test_confirm_command_names_the_inventory_file():
    cmd = build_confirm_command("admin", None, "/lab/core.csv", "ssh")
    assert cmd == './h-app/h-ssh.py -eC "commit" --user admin --devices /lab/core.csv'


@pytest.mark.parametrize("transport", ["ssh", "openssh", "arista", "telnet"])
def test_confirm_command_drops_a_transport_that_cannot_confirm(transport):
    cmd = build_confirm_command("admin", ["R1:10.0.1.1:junos"], "devices.csv", transport)
    assert "--transport" not in cmd


def test_confirm_command_keeps_a_transport_that_can():
    cmd = build_confirm_command("admin", ["R1:10.0.1.1:junos"], "devices.csv", "junos")
    assert cmd.endswith(" --target R1:10.0.1.1:junos --transport junos")


def test_confirm_command_quotes_for_the_shell():
    cmd = build_confirm_command("lab admin", None, "/lab/my devices.csv", "ssh")
    assert cmd == """./h-app/h-ssh.py -eC "commit" --user 'lab admin' --devices '/lab/my devices.csv'"""
