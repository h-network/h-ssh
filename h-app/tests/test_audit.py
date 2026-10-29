"""Tests for hssh.audit module."""

import json
import os
import tempfile
import threading
import time
from pathlib import Path

import pytest

from hssh.audit import write_audit_entry, redact_secrets, redact_values, secure_append, secure_write, probe_append


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


def test_every_directory_made_for_a_log_is_private_whatever_the_umask(tmp_path):
    """The parents made for the audit log, --log and a --save-output file
    were the umask's, 0777 under umask 000 (#149): each one made is 0700."""
    old = os.umask(0o000)
    try:
        secure_append(str(tmp_path / "a" / "b" / "audit.jsonl"), "{}\n")
        secure_write(str(tmp_path / "c" / "d" / "R1.output"), "x")
        probe_append(str(tmp_path / "e" / "f" / "run.jsonl"))
    finally:
        os.umask(old)
    made = ("a", "a/b", "c", "c/d", "e", "e/f")
    assert [os.stat(tmp_path / d).st_mode & 0o777 for d in made] == [0o700] * 6
    assert [os.stat(tmp_path / f).st_mode & 0o777 for f in ("a/b/audit.jsonl", "c/d/R1.output", "e/f/run.jsonl")] == [0o600] * 3


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


# --- #151: what the review's corpus found ---------------------------------------------

LEAKED_TOO = [
    # IOS SNMPv3 user: the auth and the priv passwords
    ('snmp-server user admin netops v3 auth sha AUTHPASS priv aes 128 PRIVPASS', ["AUTHPASS", "PRIVPASS"]),
    ('snmp-server user admin netops v3 auth md5 AUTHPASS', ["AUTHPASS"]),
    # IOS trap and inform hosts: the community after the version words
    ('snmp-server host 10.0.0.1 version 2c C0MMUNITY', ["C0MMUNITY"]),
    ('snmp-server host 10.0.0.1 traps version 2c C0MMUNITY udp-port 1162', ["C0MMUNITY"]),
    ('snmp-server host 10.0.0.1 C0MMUNITY', ["C0MMUNITY"]),
    # IOS wireless pre-shared key
    ('wpa-psk ascii 7 0822455D0A16', ["0822455D0A16"]),
    ('wpa-psk ascii 0 plainpsk', ["plainpsk"]),
    # Junos: a trap group's name is its community
    ('set snmp trap-group TRAPGRP targets 10.0.0.1', ["TRAPGRP"]),
    ('    trap-group TRAPGRP {', ["TRAPGRP"]),
    # an escaped quote inside the value: the tail after it leaked
    ('password "abc\\"def"', ["abc", "def"]),
    ('    secret "ab\\"cd"; ## SECRET-DATA', ["ab", "cd"]),
]


@pytest.mark.parametrize("line, secrets", LEAKED_TOO, ids=[line[:40] for line, _ in LEAKED_TOO])
def test_the_forms_the_review_found_are_redacted(line, secrets):
    out = redact_secrets(line)
    assert "[REDACTED]" in out and not any(s in out for s in secrets), out


def test_xml_and_json_names_ending_in_a_secret_word_are_redacted():
    """--format xml and json replies of `show configuration` kept the type 9
    values of hello-authentication-key, simple-password and chap-secret: the
    XML and JSON patterns matched exact names, while the text form of the
    same config was redacted. A tag or a key is known by its last word."""
    xml = ("<interface><hello-authentication-key>$9$OSPF</hello-authentication-key></interface>"
           "<rip><simple-password>$9$RIP</simple-password></rip><ppp><chap-secret>$9$CHAP</chap-secret></ppp>"
           "<description>key customer uplink</description><keyboard>qwerty</keyboard>")
    out = redact_secrets(xml)
    assert out.count("[REDACTED]") == 3 and "$9$" not in out, out
    assert "<description>key customer uplink</description>" in out and "<keyboard>qwerty</keyboard>" in out
    data = {"hello-authentication-key": "$9$OSPF", "simple-password": "$9$RIP", "chap-secret": "$9$CHAP",
            "keyboard": "qwerty", "description": "key customer uplink"}
    assert redact_values(data) == {"hello-authentication-key": "[REDACTED]", "simple-password": "[REDACTED]",
                                   "chap-secret": "[REDACTED]", "keyboard": "qwerty",
                                   "description": "key customer uplink"}


def test_a_json_reply_carried_as_text_is_redacted_like_parsed_data():
    """`show configuration | display json` on junos@ssh and openssh comes
    back as JSON text, not data, and --log kept the five secrets the tester
    planted on a cRPD: the key's closing quote put `"encrypted-password" :
    "$6$…"` out of the `password:` pattern's reach, and redact_values only
    sees parsed data. A quoted key is known by the last-word rule
    redact_values uses and its scalar goes, so the text reads as the parsed
    reply would; the names and key-ids beside the secrets stay."""
    text = json.dumps({"configuration": {
        "system": {"login": {"user": [{"name": "t151", "authentication": {"encrypted-password": "$6$ROOT"}}]}},
        "protocols": {
            "bgp": {"group": [{"name": "peers", "authentication-key": "$9$BGP"}]},
            "ospf": {"area": [{"name": "0.0.0.0", "interface": [{"name": "ge-0/0/0.0", "authentication": {
                "md5": [{"name": 1, "key": "$9$MD5"}], "simple-password": "$9$OSPF"}}]}]},
            "isis": {"interface": [{"name": "ge-0/0/0.0", "hello-authentication-key": "$9$ISIS"}]}}}},
        indent=4, separators=(",", " : "))
    out = redact_secrets(text)
    for secret in ("$6$ROOT", "$9$BGP", "$9$MD5", "$9$OSPF", "$9$ISIS"):
        assert secret not in out, out
    assert json.loads(out) == redact_values(json.loads(text))
    assert '"name" : "t151"' in out and '"name" : 1' in out and out.count('"[REDACTED]"') == 5
    compact = '{"password":"x","api_token":123,"keyboard":"qwerty","key":null,"key-chain":"K"}'
    assert redact_secrets(compact) == ('{"password":"[REDACTED]","api_token":"[REDACTED]","keyboard":"qwerty",'
                                       '"key":"[REDACTED]","key-chain":"K"}')


def test_what_is_not_a_secret_stays():
    """Over-redaction the review found: a `key N` line took the next line's
    first word for its value (a key-string keyword, a cryptographic-algorithm),
    a BGP community's name went, and a quoted command lost its closing
    quote. SNMP communities still go, in every form they are written. A
    description with the word password in it still loses the word after
    it: sparing it opened leaks (a secret whose value has the word
    description in it), and a log that says too little beats one that
    says a secret."""
    chain = ("key chain K\n key 1\n  key-string 7 0822455D0A16\n  cryptographic-algorithm hmac-sha-256\n"
             " key 2\n  key-string 7 0822455D0A17")
    assert redact_secrets(chain) == ("key chain K\n key 1\n  key-string 7 [REDACTED]\n  cryptographic-algorithm hmac-sha-256\n"
                                     " key 2\n  key-string 7 [REDACTED]")
    for line in ("set policy-options community CUST members 65000:100",
                 "    community CUST members [ 65000:100 65000:200 ];"):
        assert redact_secrets(line) == line
    assert redact_secrets("'show password X'") == "'show password [REDACTED]'"
    assert redact_secrets('set interfaces ge-0/0/0 description "password reset portal"') == \
        'set interfaces ge-0/0/0 description "password [REDACTED] portal"'
    assert redact_secrets("set snmp community public authorization read-only") == \
        "set snmp community [REDACTED] authorization read-only"
    assert redact_secrets("    community public {") == "    community [REDACTED] {"
    assert redact_secrets("snmp-server community C0MM RO") == "snmp-server community [REDACTED] RO"


def test_a_quoted_credential_command_is_redacted_and_a_description_spares_no_secret():
    """#151 review: the openssh transport repeats a refused command in
    quotes in its error, and a credential in it must still go, the closing
    quote kept. Sparing a description's words opened leaks (a secret whose
    value has the word description in it), so none is spared: the keyword
    patterns apply wherever the keyword is, a description included."""
    assert redact_secrets("'password hunter2' was refused by the device: bad command") == \
        "'password [REDACTED]' was refused by the device: bad command"
    assert redact_secrets('"set system login user bob authentication plain-text-password-value hunter2" was refused') == \
        '"set system login user bob authentication plain-text-password-value [REDACTED]" was refused'
    assert redact_secrets('    description "customer password reset portal";\n    encrypted-password "$9$x";') == \
        '    description "customer password [REDACTED] portal";\n    encrypted-password [REDACTED];'
    assert redact_values({"description": "customer password reset portal", "password": "x"}) == \
        {"description": "customer password [REDACTED] portal", "password": "[REDACTED]"}
    assert redact_secrets('password "description hunter2"') == 'password [REDACTED]'
    assert redact_secrets('encrypted-password "has description words";') == 'encrypted-password [REDACTED];'
    assert redact_secrets('<password>description hunter2</password>') == '<password>[REDACTED]</password>'
    assert redact_secrets('snmp-server user admin netops v3 auth sha description priv aes 128 PRIVPASS') == \
        'snmp-server user admin netops v3 auth sha [REDACTED] priv aes 128 [REDACTED]'
    assert redact_secrets('    secret "description hunter2"; ## SECRET-DATA') == '    secret [REDACTED]; ## SECRET-DATA'
    assert redact_secrets('encrypted-password "has description words";') == 'encrypted-password [REDACTED];'
    assert redact_secrets('<password>description hunter2</password>') == '<password>[REDACTED]</password>'
    assert redact_secrets('snmp-server user admin netops v3 auth sha description priv aes 128 PRIVPASS') == \
        'snmp-server user admin netops v3 auth sha [REDACTED] priv aes 128 [REDACTED]'
    assert redact_secrets('    secret "description hunter2"; ## SECRET-DATA') == '    secret [REDACTED]; ## SECRET-DATA'


def test_the_comment_is_redacted_too(tmp_path):
    """An entry's `comment` was written as given, where every other text of
    the entry is redacted; a comment can quote the secret it rotated."""
    path = tmp_path / "audit.jsonl"
    write_audit_entry(path=str(path), device="R1", host="10.0.1.1", vendor="junos", mode="edit-cmd",
                      payload="set system host-name R1", ok=True, comment="rotated: password hunter2")
    record = json.loads(path.read_text())
    assert record["comment"] == "rotated: password [REDACTED]" and "hunter2" not in path.read_text()


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
