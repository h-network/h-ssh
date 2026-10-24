"""Regression coverage for building the published h-ssh distribution."""

from pathlib import Path
import subprocess
import sys
import zipfile


ROOT = Path(__file__).resolve().parents[2]


def test_wheel_build_includes_hssh_without_top_level_commands(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--wheel-dir",
            str(tmp_path),
            ".",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    wheel = next(tmp_path.glob("h_ssh-*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
    assert "hssh/cli.py" in names
    assert not any(name.startswith("commands/") for name in names)
    # The shortcut libraries ship next to their dialects (#81).
    assert {"hssh/dialects/junos.json", "hssh/dialects/eos.json", "hssh/dialects/none.json"} <= set(names)
    assert not any(name.startswith("hssh/commands/") for name in names)
