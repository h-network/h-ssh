"""Tests for hssh.audit module."""

import json
import os
import tempfile
import threading
from pathlib import Path

from hssh.audit import write_audit_entry, redact_secrets


def test_write_audit_entry_basic():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        tmp = f.name

    try:
        ok = write_audit_entry(
            path=tmp,
            device="R1",
            host="10.0.1.1",
            vendor="junos",
            mode="edit-cmd",
            payload="set system host-name R1",
            ok=True,
            diff="[edit]\n+ host-name R1;",
            commit_confirmed=10,
        )
        assert ok is True

        # Check file contents
        with open(tmp, "r", encoding="utf-8") as f:
            lines = f.readlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["device"] == "R1"
        assert record["host"] == "10.0.1.1"
        assert record["vendor"] == "junos"
        assert record["mode"] == "edit-cmd"
        assert record["payload"] == "set system host-name R1"
        assert record["ok"] is True
        assert record["diff"] == "[edit]\n+ host-name R1;"
        assert record["commit_confirmed"] == 10
        assert "timestamp" in record

        # Check permissions
        mode = os.stat(tmp).st_mode & 0o777
        assert mode == 0o600
    finally:
        Path(tmp).unlink(missing_ok=True)


def test_audit_secret_redaction():
    secret_text = 'set system root-authentication encrypted-password "$9$secret123" secret 5 $1$foobar'
    redacted = redact_secrets(secret_text)
    assert "$9$secret123" not in redacted
    assert "$1$foobar" not in redacted
    assert "[REDACTED]" in redacted

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        tmp = f.name
    try:
        write_audit_entry(
            path=tmp,
            device="R1",
            host="10.0.1.1",
            vendor="junos",
            mode="edit-cmd",
            payload='password: "supersecretpassword"',
            ok=True,
            diff='encrypted-password "$9$something"',
        )
        with open(tmp, "r", encoding="utf-8") as f:
            record = json.loads(f.readline())
        assert "supersecretpassword" not in record["payload"]
        assert "$9$something" not in record["diff"]
    finally:
        Path(tmp).unlink(missing_ok=True)


def test_write_audit_concurrent_locking():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        tmp = f.name

    try:
        def worker(idx):
            for i in range(20):
                write_audit_entry(
                    path=tmp,
                    device=f"R{idx}",
                    host=f"10.0.1.{idx}",
                    vendor="junos",
                    mode="edit-cmd",
                    payload=f"step {i}",
                    ok=True,
                )

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        with open(tmp, "r", encoding="utf-8") as f:
            lines = f.readlines()
        assert len(lines) == 100
        # Every line must be valid JSON
        for line in lines:
            rec = json.loads(line)
            assert "device" in rec
    finally:
        Path(tmp).unlink(missing_ok=True)


def test_audit_graceful_failure():
    # Attempting to write to an invalid path should return False without raising
    ok = write_audit_entry(
        path="/nonexistent/dir/cannot_write/audit.jsonl",
        device="R1",
        host="10.0.1.1",
        vendor="junos",
        mode="show",
        payload="show version",
        ok=True,
    )
    assert ok is False


def test_audit_extended_secret_redaction():
    """M3: Audit redacts community, pre-shared-key, ascii-text, hex keys, and error messages."""
    text_samples = [
        ('set snmp community public authorization read-only', 'public'),
        ('snmp-server community secret123 RO', 'secret123'),
        ('pre-shared-key ascii-text "$9$secret"', '$9$secret'),
        ('pre-shared-key hexadecimal 1234abcd', '1234abcd'),
        ('pre-shared-key rawsecret', 'rawsecret'),
        ('ascii-text plainsecret', 'plainsecret'),
        ('hex-key deadbeef1234', 'deadbeef1234'),
        ('hexadecimal abcd5678', 'abcd5678'),
    ]
    for sample, secret in text_samples:
        redacted = redact_secrets(sample)
        assert secret not in redacted, f"Failed to redact {secret} from {sample}"
        assert "[REDACTED]" in redacted

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        tmp = f.name
    try:
        write_audit_entry(
            path=tmp,
            device="R1",
            host="10.0.1.1",
            vendor="junos",
            mode="edit-cmd",
            payload='set snmp community secretcomm',
            ok=False,
            error='failed on pre-shared-key ascii-text "$9$badpass"',
        )
        with open(tmp, "r", encoding="utf-8") as f:
            record = json.loads(f.readline())
        assert "secretcomm" not in record["payload"]
        assert "$9$badpass" not in record["error"]
        assert "[REDACTED]" in record["payload"]
        assert "[REDACTED]" in record["error"]
    finally:
        Path(tmp).unlink(missing_ok=True)


def test_audit_show_diff_suppressed():
    """M3: Show operations do not record diff."""
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        tmp = f.name
    try:
        write_audit_entry(
            path=tmp,
            device="R1",
            host="10.0.1.1",
            vendor="junos",
            mode="show",
            payload="show version",
            ok=True,
            diff=None,
        )
        with open(tmp, "r", encoding="utf-8") as f:
            record = json.loads(f.readline())
        assert "diff" not in record
    finally:
        Path(tmp).unlink(missing_ok=True)

