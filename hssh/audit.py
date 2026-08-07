"""JSONL audit trail for edit operations."""

import json
from datetime import datetime, timezone
from pathlib import Path


def write_audit_entry(path: str, device: str, host: str, vendor: str,
                      mode: str, payload: str, ok: bool,
                      diff: str = None, error: str = None,
                      dry_run: bool = False,
                      commit_confirmed: int = None) -> None:
    """Append a single audit entry (one line of JSON) to the audit log."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "device": device,
        "host": host,
        "vendor": vendor,
        "payload": payload,
        "dry_run": dry_run,
        "ok": ok,
    }
    if commit_confirmed:
        entry["commit_confirmed"] = commit_confirmed
    if diff:
        entry["diff"] = diff
    if error:
        entry["error"] = error

    log_path = Path(path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a") as f:
        f.write(json.dumps(entry) + "\n")
