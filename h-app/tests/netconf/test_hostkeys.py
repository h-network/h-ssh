import fcntl
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from ncclient.transport import ssh
import paramiko
import pytest

from hssh.communicators import netconf
from hssh.model import Credentials, Fault, FaultKind, Target, Timeouts


HOST = '127.0.0.1'
PORT = 830
NAME = f'[{HOST}]:{PORT}'


def entry(key, name=NAME, marker=''):
    return f'{marker}{name} {key.get_name()} {key.get_base64()}\n'.encode()


@pytest.fixture(scope='module')
def keys():
    return paramiko.RSAKey.generate(1024), paramiko.RSAKey.generate(1024)


@pytest.fixture
def known_hosts(tmp_path):
    path = tmp_path / '.ssh' / 'known_hosts'
    path.parent.mkdir()
    path.write_bytes(b'')
    return path


@pytest.fixture
def handshake(monkeypatch, keys):
    key, other = keys

    class Socket:
        def settimeout(self, *args):
            pass

        def connect(self, *args):
            pass

        def close(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class Transport:
        on_start = None

        def __init__(self, *args):
            pass

        def set_log_channel(self, *args):
            pass

        def start_client(self, *args, **kwargs):
            if self.on_start:
                self.on_start()

        def get_remote_server_key(self):
            return key

        def close(self):
            pass

        def is_active(self):
            return False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    netconf._install_setup_hooks()
    netconf._install_host_key_loader()
    monkeypatch.setattr(ssh.socket, 'socket', lambda *args, **kwargs: Socket())
    monkeypatch.setattr(netconf.socket, 'create_connection', lambda *args, **kwargs: Socket())
    monkeypatch.setattr(ssh.paramiko, 'replacement', Transport)
    monkeypatch.setattr(paramiko, 'Transport', Transport)
    auth = Mock(side_effect=ValueError('authentication reached'))
    monkeypatch.setattr(ssh.SSHSession, '_auth', auth)
    return Transport, auth


@pytest.fixture
def open_verified(communicator):
    def connect(policy):
        with pytest.raises(Fault) as caught:
            communicator.open(Target('local', HOST, 'junos', 'netconf'), Credentials('user', password='fixture'),
                              Timeouts(1, 2, 7, 11), policy)
        return caught.value
    return connect


@pytest.mark.parametrize('policy', ['strict', 'accept-new'])
@pytest.mark.parametrize('normal_entry', [False, True])
def test_revoked_key_is_refused_even_with_matching_pin(keys, known_hosts, handshake, open_verified, policy, normal_entry):
    key, other = keys
    content = (entry(key) if normal_entry else b'') + entry(key, marker='@revoked ')
    known_hosts.write_bytes(content)
    fault = open_verified(policy)
    assert fault.kind == FaultKind.HOST_KEY and not fault.reached_device
    assert '@revoked' in fault.detail
    assert known_hosts.read_bytes() == content
    handshake[1].assert_not_called()


@pytest.mark.parametrize('policy', ['strict', 'accept-new'])
def test_certificate_authority_line_is_skipped(keys, known_hosts, handshake, open_verified, policy):
    key, other = keys
    known_hosts.write_bytes(entry(other, marker='@cert-authority ') + entry(key))
    fault = open_verified(policy)
    assert fault.detail == 'authentication reached'
    handshake[1].assert_called_once()


@pytest.mark.parametrize('policy', ['strict', 'accept-new'])
@pytest.mark.parametrize('name', [HOST, NAME])
def test_changed_key_is_refused_before_auth(keys, known_hosts, handshake, open_verified, policy, name):
    key, other = keys
    content = entry(other, name=name)
    known_hosts.write_bytes(content)
    fault = open_verified(policy)
    assert fault.kind == FaultKind.HOST_KEY and not fault.reached_device
    assert known_hosts.read_bytes() == content
    handshake[1].assert_not_called()


def test_strict_unknown_host_does_not_pin(known_hosts, handshake, open_verified):
    fault = open_verified('strict')
    assert fault.kind == FaultKind.HOST_KEY and not fault.reached_device
    assert known_hosts.read_bytes() == b''
    handshake[1].assert_not_called()


def test_off_bypasses_all_host_key_checks(known_hosts, handshake, open_verified, monkeypatch):
    known_hosts.write_bytes(b'@revoked broken\n# comment \xff\n')
    read = Mock(side_effect=AssertionError('verification off must not read known_hosts'))
    monkeypatch.setattr(netconf, '_known_keys', read)
    assert open_verified('off').detail == 'authentication reached'
    read.assert_not_called()


@pytest.mark.parametrize('before', [b'# comment \xff\xfe without newline', b'# comment\n', b''])
def test_accept_new_appends_without_rewriting_and_refreshes_cache(keys, known_hosts, handshake, open_verified, before):
    key, other = keys
    known_hosts.write_bytes(before)
    assert open_verified('accept-new').detail == 'authentication reached'
    assert netconf._SessionKeys(known_hosts, PORT).check(NAME, key)
    assert not netconf._SessionKeys(known_hosts, PORT).check(HOST, key)
    assert open_verified('accept-new').detail == 'authentication reached'
    newline = b'\n' if before and not before.endswith(b'\n') else b''
    assert known_hosts.read_bytes() == before + newline + entry(key)


def test_malformed_revocation_is_not_silently_ignored(known_hosts, handshake, open_verified):
    known_hosts.write_bytes(b'@revoked *\n')
    fault = open_verified('strict')
    assert fault.kind == FaultKind.LOCAL and 'invalid revoked key' in fault.detail
    handshake[1].assert_not_called()


@pytest.mark.parametrize('pin_kind', ['same', 'different', 'revoked'])
def test_accept_new_rechecks_pin_written_during_handshake(keys, known_hosts, handshake, open_verified, pin_kind):
    key, other = keys
    addition = entry(other if pin_kind == 'different' else key, marker='@revoked ' if pin_kind == 'revoked' else '')
    known_hosts.write_bytes(b'# before\n')
    netconf._known_keys(known_hosts, HOST, PORT)

    def concurrent_pin(self):
        type(self).on_start = None
        with known_hosts.open('ab') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            stream.write(addition)

    handshake[0].on_start = concurrent_pin
    fault = open_verified('accept-new')
    if pin_kind == 'same':
        assert fault.detail == 'authentication reached'
    else:
        assert fault.kind == FaultKind.HOST_KEY
        handshake[1].assert_not_called()
    assert known_hosts.read_bytes() == b'# before\n' + addition


def test_stuck_known_hosts_lock_is_bounded_local_fault(known_hosts, handshake):
    with known_hosts.open('ab') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        with pytest.raises(Fault) as caught:
            netconf._accept_new(HOST, PORT, Timeouts(0.05, 1, 7, 11))
    assert caught.value.kind == FaultKind.LOCAL and not caught.value.reached_device
    assert 'lock timed out after 0.05s' in caught.value.detail
    assert known_hosts.read_bytes() == b''


def test_hashed_lookup_matches_paramiko_without_its_loader(keys, known_hosts, monkeypatch):
    key, other = keys
    names = [HOST, NAME, '127.0.0.2', '[127.0.0.2]:1830']
    known_hosts.write_bytes(b''.join(entry(key if index % 2 else other, paramiko.HostKeys.hash_host(name))
                                   for index, name in enumerate(names)))
    expected = paramiko.HostKeys(str(known_hosts))
    monkeypatch.setattr(paramiko.HostKeys, 'load', Mock(side_effect=AssertionError('quadratic loader used')))
    for name in names:
        resolved = netconf._SessionKeys(known_hosts, PORT if '1830' not in name else 1830)
        assert {kind: value.asbytes() for kind, value in resolved.lookup(name).items()} == {
            kind: value.asbytes() for kind, value in expected.lookup(name).items()}
        assert resolved.check(name, key) == expected.check(name, key)
        assert resolved.check(name, other) == expected.check(name, other)


def test_host_file_and_hashed_resolution_are_cached(keys, known_hosts, monkeypatch):
    key, other = keys
    known_hosts.write_bytes(entry(key, paramiko.HostKeys.hash_host(HOST)))
    read_text = Path.read_text
    reads = []

    def read(path, *args, **kwargs):
        reads.append(path)
        return read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'read_text', read)
    digest = Mock(wraps=netconf.hmac.digest)
    compare = Mock(wraps=netconf.hmac.compare_digest)
    monkeypatch.setattr(netconf.hmac, 'digest', digest)
    monkeypatch.setattr(netconf.hmac, 'compare_digest', compare)
    for _ in range(3):
        assert netconf._SessionKeys(known_hosts, PORT).check(HOST, key)
    assert reads == [known_hosts]
    assert digest.call_count == 2 and compare.call_count == 2


def test_each_session_owns_its_key_mapping(keys, known_hosts):
    key, other = keys
    known_hosts.write_bytes(entry(key, HOST) + entry(other, NAME))
    first = netconf._SessionKeys(known_hosts, PORT)
    first.lookup(HOST).update(first.lookup(NAME))
    second = netconf._SessionKeys(known_hosts, PORT)
    assert second.check(HOST, key) and not second.check(HOST, other)


def test_known_host_loader_hook_is_scoped(monkeypatch, known_hosts, keys):
    key, other = keys
    known_hosts.write_bytes(entry(key))
    original = Mock()
    monkeypatch.setattr(ssh.SSHSession, 'load_known_hosts', original)
    netconf._install_host_key_loader()
    session = SimpleNamespace()
    ssh.SSHSession.load_known_hosts(session, str(known_hosts))
    original.assert_called_once_with(session, str(known_hosts))
    token = netconf._HOST_KEY_PORT.set(PORT)
    try:
        ssh.SSHSession.load_known_hosts(session, str(known_hosts))
    finally:
        netconf._HOST_KEY_PORT.reset(token)
    assert isinstance(session._host_keys, netconf._SessionKeys)
    assert session._host_keys.check(NAME, key)
    assert original.call_count == 1
