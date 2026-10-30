import json

import pytest

from hssh.audit import redact_secrets
from hssh.dialects import junos


@pytest.mark.parametrize('text,expected', [
    ('set system login user example authentication plain-text-password-value hunter2',
     'set system login user example authentication plain-text-password-value [REDACTED]'),
    ('set protocols ospf area 0.0.0.0 interface ge-0/0/0 authentication md5 1 key mykey',
     'set protocols ospf area 0.0.0.0 interface ge-0/0/0 authentication md5 1 key [REDACTED]'),
    ('set system ntp authentication-key 1 value "$9$NTPKEY"',
     'set system ntp authentication-key 1 value [REDACTED]'),
    ('set snmp v3 usm local-engine user u privacy-aes128 privacy-key "$9$V3PRIV"',
     'set snmp v3 usm local-engine user u privacy-aes128 privacy-key [REDACTED]'),
    ('username admin secret sha512 $6$EOSHASH', 'username admin secret sha512 [REDACTED]'),
    ('enable password sha512 $6$ENHASH', 'enable password sha512 [REDACTED]'),
    ('tacacs-server key 7 0F1A2B', 'tacacs-server key 7 [REDACTED]'),
    ('tacacs-server host 192.0.2.1 key MYKEY', 'tacacs-server host 192.0.2.1 key [REDACTED]'),
    ('radius-server host 192.0.2.1 key 7 ABCD', 'radius-server host 192.0.2.1 key 7 [REDACTED]'),
    ('ntp authentication-key 1 md5 7 DEAD', 'ntp authentication-key 1 md5 7 [REDACTED]'),
    ('ip ospf message-digest-key 1 md5 7 BEEF', 'ip ospf message-digest-key 1 md5 7 [REDACTED]'),
    ('key-string 7 CAFE', 'key-string 7 [REDACTED]'),
    ('crypto isakmp key MYPSK address 192.0.2.1', 'crypto isakmp key [REDACTED] address 192.0.2.1'),
    ('set snmp community public authorization read-only', 'set snmp community [REDACTED] authorization read-only'),
    ('snmp-server community secret123 RO', 'snmp-server community [REDACTED] RO'),
    ('    community public {', '    community [REDACTED] {'),
    ('pre-shared-key ascii-text "$9$secret"', 'pre-shared-key ascii-text [REDACTED]'),
    ('pre-shared-key hexadecimal 1234abcd', 'pre-shared-key hexadecimal [REDACTED]'),
    ('pre-shared-key rawsecret', 'pre-shared-key [REDACTED]'),
    ('ascii-text plainsecret', 'ascii-text [REDACTED]'),
    ('hex-key deadbeef1234', 'hex-key [REDACTED]'),
    ('hexadecimal abcd5678', 'hexadecimal [REDACTED]'),
    ('password: "supersecretpassword"', 'password: [REDACTED]'),
    ('api_key=abcdef', 'api_key=[REDACTED]'),
    ('password "abc\\"def"', 'password [REDACTED]'),
    ("password 'abc\\'def'", 'password [REDACTED]'),
    ("'password hunter2' was refused", "'password [REDACTED]' was refused"),
    ('password "description hunter2"', 'password [REDACTED]'),
    ('description "customer password reset portal";', 'description "customer password [REDACTED] portal";'),
])
def test_shared_credential_values_are_masked_and_context_is_kept(redacting_dialect, text, expected):
    assert redact_secrets(text, redacting_dialect) == expected


@pytest.mark.parametrize('text,expected', [
    ('    authentication-key 1 type md5 value "$9$NTPKEY"; ## SECRET-DATA',
     '    authentication-key 1 type md5 value [REDACTED]; ## SECRET-DATA'),
    ('    md5 1 key "$9$OSPFKEY"; ## SECRET-DATA', '    md5 1 key [REDACTED]; ## SECRET-DATA'),
    ('+   authentication-key "$9$DIFFKEY"; ## SECRET-DATA', '+   authentication-key [REDACTED]; ## SECRET-DATA'),
    ('    secret "ab\\"cd"; ## SECRET-DATA', '    secret [REDACTED]; ## SECRET-DATA'),
    ('+ custom-credential "abc\\"def"; ## SECRET-DATA', '+ custom-credential [REDACTED]; ## SECRET-DATA'),
])
def test_junos_secret_data_keeps_statement_and_marker(text, expected):
    assert redact_secrets(text, junos.DIALECT) == expected


@pytest.mark.parametrize('text,expected', [
    ('set snmp trap-group TRAPGRP targets 192.0.2.1', 'set snmp trap-group [REDACTED] targets 192.0.2.1'),
    ('    trap-group TRAPGRP {', '    trap-group [REDACTED] {'),
])
def test_junos_trap_group_name_is_a_community(text, expected):
    assert redact_secrets(text, junos.DIALECT) == expected


@pytest.mark.parametrize('text', [
    'set interfaces ge-0/0/0 description "key customer uplink"', 'set system host-name R1',
    'set policy-options community CUST members 65000:100',
    '    community CUST members [ 65000:100 65000:200 ];',
    'key 1\n cryptographic-algorithm hmac-sha-256',
    '<description>key customer uplink</description><keyboard>qwerty</keyboard>',
])
def test_nonsecret_text_and_next_line_survive(redacting_dialect, text):
    assert redact_secrets(text, redacting_dialect) == text


def test_key_identifiers_do_not_swallow_the_next_keyword(redacting_dialect):
    text = ('key chain K\n key 1\n  key-string 7 0822455D0A16\n'
            '  cryptographic-algorithm hmac-sha-256\n key 2\n  key-string 7 0822455D0A17')
    expected = ('key chain K\n key 1\n  key-string 7 [REDACTED]\n'
                '  cryptographic-algorithm hmac-sha-256\n key 2\n  key-string 7 [REDACTED]')
    assert redact_secrets(text, redacting_dialect) == expected


@pytest.mark.parametrize('tag', [
    'encrypted-password', 'plain-text-password-value', 'hello-authentication-key',
    'simple-password', 'chap-secret', 'key', 'api_key', 'j:password',
])
def test_xml_secret_name_keeps_its_tags(redacting_dialect, tag):
    assert redact_secrets(f'<{tag}>$9$SECRET</{tag}>', redacting_dialect) == f'<{tag}>[REDACTED]</{tag}>'


def test_xml_snmp_community_name_is_masked(redacting_dialect):
    text = '<community><name>public</name><authorization>read-only</authorization></community>'
    expected = '<community><name>[REDACTED]</name><authorization>read-only</authorization></community>'
    assert redact_secrets(text, redacting_dialect) == expected


@pytest.mark.parametrize('key', [
    'password', 'PASSWORD', 'encrypted-password', 'plain-text-password-value', 'hello-authentication-key',
    'chap-secret', 'api_token', 'key', 'key-string', 'community', 'ascii-text', 'key-hex', 'passwd', 'token',
])
def test_json_secret_key_snippet_matches(redacting_dialect, key):
    assert any(p.search(json.dumps(key) + ': "x"') for p in redacting_dialect.redaction_patterns)


@pytest.mark.parametrize('key', ['keyboard', 'key-chain', 'name', 'description', 'key_id', 'password_policy'])
def test_json_nonsecret_key_snippet_does_not_match(redacting_dialect, key):
    assert not any(p.search(json.dumps(key) + ': "x"') for p in redacting_dialect.redaction_patterns)


@pytest.mark.parametrize('fragment,expected', [
    ('"encrypted-password": "abc\\"def"', '"encrypted-password": "[REDACTED]"'),
    ('"api_token": 123', '"api_token": "[REDACTED]"'),
    ('"key": null', '"key": "[REDACTED]"'),
])
def test_json_text_fragment_keeps_key_and_quoted_mask(redacting_dialect, fragment, expected):
    assert redact_secrets(fragment, redacting_dialect) == expected


@pytest.mark.parametrize('secret', ['hunter2', 123, None, {'data': '$9$HASH'}, [{'data': '$9$HASH'}]])
def test_json_secret_keys_mask_whole_values_and_preserve_neighbours(redacting_dialect, secret):
    text = json.dumps({'configuration': {'encrypted-password': secret, 'name': 'example', 'key-chain': 'K'}})
    assert json.loads(redact_secrets(text, redacting_dialect)) == {
        'configuration': {'encrypted-password': '[REDACTED]', 'name': 'example', 'key-chain': 'K'},
    }
