import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cli_helpers import report  # noqa: E402


@pytest.fixture
def cli_run(monkeypatch, capsys):
    """Run the CLI with a fake runner and no terminal: (exit code, specs the runner got, stdout, stderr)."""
    from hssh.frontends import cli

    monkeypatch.setenv("HSSH_PASSWORD", "x")
    for name in ("HSSH_USER", "HSSH_STORE", "HSSH_AUDIT_LOG", "HSSH_SAFETY_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli, "default_devices_path", lambda: "devices.csv")
    monkeypatch.setattr(cli, "config_path", lambda: Path("/nonexistent/h-ssh-config"))
    render = cli.render
    monkeypatch.setattr(cli, "render", lambda report, args: render(report, args, out=sys.stdout))

    def run(*argv, reports=None):
        specs = []
        queue = list(reports or [])

        def runner(spec):
            specs.append(spec)
            return queue.pop(0) if queue else report(spec)

        monkeypatch.setattr(sys, "argv", ["h-ssh", *argv])
        rc = cli.main(list(argv), runner=runner)
        captured = capsys.readouterr()
        return rc, specs, captured.out, captured.err

    return run
