"""Tests for hssh.audit module."""

import json
import os
import tempfile
import threading
import time
from pathlib import Path

import pytest

from hssh.audit import write_audit_entry, redact_secrets, redact_values, secure_append


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


def test_audit_graceful_failure(tmp_path):
    # Attempting to write to an invalid path should return False without raising.
    # The parent is a regular file, so this fails for root too (CI runs as root).
    (tmp_path / "not_a_dir").write_text("")
    ok = write_audit_entry(
        path=str(tmp_path / "not_a_dir" / "audit.jsonl"),
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


def test_redact_values_keeps_the_shape_and_loses_the_secrets():
    """A --log record: strings get redact_secrets(), a reply carried as data
    loses the whole value under a secret-named key, the rest is untouched."""
    record = {
        "command": "set snmp community public authorization read-only",
        "output": {"configuration": {"system": {"root-authentication": {
            "encrypted-password": [{"data": "$9$hash"}]}}}},
        "commands": [{"ok": True, "output": 'pre-shared-key ascii-text "$9$psk"'},
                     {"ok": False, "error": "password: hunter2 rejected"}],
        "ok": True, "duration_ms": 3, "dry_run": False,
    }
    out = redact_values(record)
    assert out["command"] == "set snmp community [REDACTED] authorization read-only"
    assert out["output"]["configuration"]["system"]["root-authentication"]["encrypted-password"] == "[REDACTED]"
    assert out["commands"][0]["output"] == "pre-shared-key ascii-text [REDACTED]"
    assert out["commands"][1]["error"] == "password: [REDACTED] rejected"
    assert (out["ok"], out["duration_ms"], out["dry_run"]) == (True, 3, False)
    for secret in ("public", "$9$hash", "$9$psk", "hunter2"):
        assert secret not in json.dumps(out)


def test_secure_append_is_0600_whatever_the_umask(tmp_path):
    old = os.umask(0o022)
    try:
        path = tmp_path / "logs" / "run.jsonl"
        secure_append(str(path), '{"a": 1}\n')
        secure_append(str(path), '{"b": 2}\n')
    finally:
        os.umask(old)
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert path.read_text() == '{"a": 1}\n{"b": 2}\n'


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



# --- #41: the log file must be a plain file of our own --------------------------

def test_secure_append_refuses_a_planted_symlink(tmp_path):
    """A symlink at the --audit-log/--log path once redirected the trail into,
    and chmod'ed 0600, whatever it pointed at."""
    victim = tmp_path / "victim.txt"
    victim.write_text("victim content\n")
    os.chmod(victim, 0o644)
    link = tmp_path / "audit.jsonl"
    link.symlink_to(victim)
    with pytest.raises(OSError, match="not a plain file"):
        secure_append(str(link), '{"written": "through the symlink"}\n')
    assert victim.read_text() == "victim content\n"
    assert oct(victim.stat().st_mode & 0o777) == "0o644"


def test_secure_append_refuses_a_planted_fifo_without_blocking(tmp_path):
    """A FIFO at the log path once blocked the whole fleet run at open()."""
    fifo = tmp_path / "audit.jsonl"
    os.mkfifo(fifo)
    t0 = time.monotonic()
    with pytest.raises(OSError):
        secure_append(str(fifo), "x\n")
    assert time.monotonic() - t0 < 2


def test_secure_append_finishes_a_short_write(tmp_path, monkeypatch):
    real_write = os.write
    calls = []

    def short_write(fd, data):
        calls.append(len(data))
        return real_write(fd, data[:5])     # the kernel wrote less than asked
    monkeypatch.setattr(os, "write", short_write)
    path = tmp_path / "run.jsonl"
    secure_append(str(path), "0123456789abcdef\n")
    assert path.read_text() == "0123456789abcdef\n" and len(calls) > 1

# --- #42: the forms that leaked -------------------------------------------------

LEAKED_FORMS = [
    'set system login user bob authentication plain-text-password-value hunter2',
    'set protocols ospf area 0.0.0.0 interface ge-0/0/0 authentication md5 1 key mykey',
    'set system ntp authentication-key 1 value "$9$NTPKEY"',
    '    authentication-key 1 type md5 value "$9$NTPKEY"; ## SECRET-DATA',
    '    md5 1 key "$9$OSPFKEY"; ## SECRET-DATA',
    '+   authentication-key "$9$DIFFKEY"; ## SECRET-DATA',
    'set snmp v3 usm local-engine user u privacy-aes128 privacy-key "$9$V3PRIV"',
    'username admin secret sha512 $6$EOSHASH',
    'enable password sha512 $6$ENHASH',
    'tacacs-server key 7 0F1A2B',
    'tacacs-server host 1.1.1.1 key MYKEY',
    'radius-server host 1.1.1.1 key 7 ABCD',
    'ntp authentication-key 1 md5 7 DEAD',
    'ip ospf message-digest-key 1 md5 7 BEEF',
    'key-string 7 CAFE',
    'crypto isakmp key MYPSK address 1.2.3.4',
]
SECRETS = ["hunter2", "mykey", "$9$NTPKEY", "$9$OSPFKEY", "$9$DIFFKEY", "$9$V3PRIV", "$6$EOSHASH", "$6$ENHASH",
           "0F1A2B", "MYKEY", "ABCD", "DEAD", "BEEF", "CAFE", "MYPSK"]


@pytest.mark.parametrize("line", LEAKED_FORMS)
def test_every_form_that_leaked_is_redacted(line):
    out = redact_secrets(line)
    assert "[REDACTED]" in out and not any(s in out for s in SECRETS), out


def test_the_type_words_stay_and_only_the_value_goes():
    assert redact_secrets('ntp authentication-key 1 md5 7 DEAD') == 'ntp authentication-key 1 md5 7 [REDACTED]'
    assert redact_secrets('ip ospf message-digest-key 1 md5 7 BEEF') == 'ip ospf message-digest-key 1 md5 7 [REDACTED]'
    assert redact_secrets('    md5 1 key "$9$X"; ## SECRET-DATA') == '    md5 1 key [REDACTED]; ## SECRET-DATA'


def test_descriptions_with_the_word_key_are_left_alone():
    line = 'set interfaces ge-0/0/0 description "key customer uplink"'
    assert redact_secrets(line) == line
    assert redact_secrets("set system host-name R1") == "set system host-name R1"


def test_format_xml_replies_are_redacted_element_by_element():
    xml = ("<rpc-reply><configuration><system><root-authentication><encrypted-password>$6$ROOTHASH"
           "</encrypted-password></root-authentication><tacplus-server><secret>$9$TACSEC</secret></tacplus-server>"
           "<login><user><authentication><plain-text-password-value>hunter2</plain-text-password-value>"
           "</authentication></user></login></system><snmp><community><name>public</name><authorization>read-only"
           "</authorization></community></snmp><protocols><ospf><md5><name>1</name><key>$9$K</key></md5></ospf>"
           "</protocols></configuration></rpc-reply>")
    out = redact_secrets(xml)
    assert out.count("[REDACTED]") == 5
    for secret in ("$6$ROOTHASH", "$9$TACSEC", "hunter2", "public", "$9$K"):
        assert secret not in out
    assert "<authorization>read-only</authorization>" in out and "<name>1</name>" in out


def test_json_replies_lose_the_keys_that_carry_secrets():
    data = {"configuration": {"protocols": {"ospf": {"md5": [{"name": 1, "key": "$9$X"}]}},
                              "snmp": {"v3": {"privacy-key": "$9$Y"}},
                              "login": {"plain-text-password-value": "hunter2"},
                              "interfaces": {"description": "key customer uplink"}}}
    out = redact_values(data)
    assert out["configuration"]["protocols"]["ospf"]["md5"][0] == {"name": 1, "key": "[REDACTED]"}
    assert out["configuration"]["snmp"]["v3"]["privacy-key"] == "[REDACTED]"
    assert out["configuration"]["login"]["plain-text-password-value"] == "[REDACTED]"
    assert out["configuration"]["interfaces"]["description"] == "key customer uplink"


def test_secure_write_is_0600_and_refuses_a_symlink(tmp_path):
    from hssh.audit import secure_write
    os.umask(0o022)
    path = tmp_path / "R1.output"
    secure_write(str(path), "show configuration\n")
    assert oct(path.stat().st_mode & 0o777) == "0o600" and path.read_text() == "show configuration\n"
    secure_write(str(path), "again\n")
    assert path.read_text() == "again\n"
    victim = tmp_path / "victim"; victim.write_text("keep")
    link = tmp_path / "R2.output"; link.symlink_to(victim)
    with pytest.raises(OSError):
        secure_write(str(link), "x")
    assert victim.read_text() == "keep"
