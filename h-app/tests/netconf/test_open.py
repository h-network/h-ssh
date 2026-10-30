from contextlib import contextmanager
import errno
import socket
from threading import Event, Thread, Timer
import time
from types import SimpleNamespace
from unittest.mock import Mock

from jnpr.junos import Device, exception as pyez
from ncclient.devices.junos import JunosDeviceHandler
from ncclient.transport import ssh
from ncclient.transport.errors import SSHError
import paramiko
import pytest

from hssh.communicators import netconf
from hssh.model import Credentials, Fault, FaultKind, Target, Timeouts


@pytest.fixture
def open_local(communicator):
    def connect(port=830, connect=0.3, setup=0.6, policy='off'):
        return communicator.open(Target('local', '127.0.0.1', 'junos', 'netconf', port),
                                 Credentials('user', password='fixture-password'),
                                 Timeouts(connect, setup, 7, 11), policy)
    return connect


@pytest.fixture(scope='module')
def server_key():
    return paramiko.RSAKey.generate(1024)


@pytest.fixture
def fake_server(server_key):
    @contextmanager
    def serve(mode):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(3)
        stop = Event()
        state = {'auth': 0}

        class Server(paramiko.ServerInterface):
            def get_allowed_auths(self, user):
                return 'password'

            def check_auth_password(self, user, password):
                state['auth'] += 1
                if mode in ('reject-password', 'reject-password-and-close'):
                    if mode == 'reject-password-and-close':
                        state['drop_timer'] = Timer(0.05, state['transport'].close)
                        state['drop_timer'].start()
                    return paramiko.AUTH_FAILED
                if mode == 'slow-auth-and-hello':
                    stop.wait(0.35)
                if mode == 'stall-auth':
                    stop.wait(3)
                return paramiko.AUTH_SUCCESSFUL

            def check_channel_request(self, kind, chanid):
                return (paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED if mode == 'reject-channel'
                        else paramiko.OPEN_SUCCEEDED)

            def check_channel_subsystem_request(self, channel, name):
                if mode == 'stall-subsystem':
                    stop.wait(3)
                return name == 'netconf'

        def run():
            try:
                sock, address = listener.accept()
                state['socket'] = sock
                if mode in ('no-banner', 'only-banner'):
                    if mode == 'only-banner':
                        sock.sendall(b'SSH-2.0-local-test\r\n')
                    stop.wait(3)
                    return
                transport = paramiko.Transport(sock)
                state['transport'] = transport
                transport.add_server_key(server_key)
                transport.start_server(server=Server())
                channel = transport.accept(3)
                if channel is None:
                    return
                if mode == 'drop-before-hello':
                    transport.close()
                    return
                if mode == 'slow-auth-and-hello':
                    stop.wait(0.35)
                if mode in ('success', 'slow-auth-and-hello'):
                    channel.sendall(b'<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities>'
                                    b'<capability>urn:ietf:params:netconf:base:1.0</capability></capabilities>'
                                    b'<session-id>123</session-id></hello>]]>]]>')
                stop.wait(3)
            except (OSError, EOFError, paramiko.SSHException) as error:
                state['error'] = error

        thread = Thread(target=run, daemon=True)
        thread.start()
        try:
            yield listener.getsockname()[1], state
        finally:
            stop.set()
            if 'drop_timer' in state:
                state['drop_timer'].cancel()
                state['drop_timer'].join(3)
            if 'transport' in state:
                state['transport'].close()
                state['transport'].join(3)
            if 'socket' in state:
                state['socket'].close()
            listener.close()
            thread.join(4)
            assert not thread.is_alive()
    return serve


@pytest.mark.parametrize('mode,reached,detail', [
    ('no-banner', False, 'no SSH banner'),
    ('only-banner', True, 'key exchange did not finish'),
    ('no-hello', True, 'no NETCONF hello'),
    ('stall-auth', True, 'no NETCONF hello'),
    ('stall-subsystem', True, 'no NETCONF hello'),
    ('slow-auth-and-hello', True, 'no NETCONF hello'),
])
def test_setup_deadlines_report_phase(open_local, fake_server, mode, reached, detail):
    with fake_server(mode) as (port, state):
        start = time.monotonic()
        with pytest.raises(Fault) as caught:
            open_local(port)
        elapsed = time.monotonic() - start
        assert caught.value.kind == FaultKind.TIMEOUT and caught.value.reached_device is reached
        assert detail in caught.value.detail
        assert elapsed < 2


@pytest.mark.parametrize('mode', ['reject-channel', 'drop-before-hello'])
def test_setup_disconnect_is_session_lost(open_local, fake_server, mode):
    with fake_server(mode) as (port, state):
        with pytest.raises(Fault) as caught:
            open_local(port)
        assert caught.value.kind == FaultKind.SESSION_LOST and caught.value.reached_device


@pytest.mark.parametrize('mode', ['reject-password', 'reject-password-and-close'])
def test_password_rejection_is_auth_not_session_lost(open_local, fake_server, mode):
    with fake_server(mode) as (port, state):
        with pytest.raises(Fault) as caught:
            open_local(port)
        assert caught.value.kind == FaultKind.AUTH and caught.value.reached_device
        assert state['auth'] == 1


def test_success_cancels_setup_watchdog(open_local, fake_server, communicator):
    with fake_server('success') as (port, state):
        session = open_local(port)
        try:
            time.sleep(0.7)
            assert session.device._conn._session.transport.is_active()
        finally:
            communicator._discard(session)
    assert netconf._OPENING.get() is None and netconf._HOST_KEY_PORT.get() is None


def test_tcp_refusal_is_unreachable_without_banner(open_local):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
        with pytest.raises(Fault) as caught:
            open_local(port)
    assert caught.value.kind == FaultKind.UNREACHABLE and not caught.value.reached_device
    assert str(errno.ECONNREFUSED) in caught.value.detail


@pytest.mark.parametrize('error', [OSError(errno.EHOSTUNREACH, 'No route to host'),
                                   OSError(errno.ENETUNREACH, 'Network is unreachable'),
                                   socket.gaierror(-2, 'Name not known')])
def test_unreachable_keeps_os_cause(open_local, monkeypatch, error):
    def fail(*args):
        raise error
    monkeypatch.setattr(socket.socket, 'connect', fail)
    with pytest.raises(Fault) as caught:
        open_local()
    assert caught.value.kind == FaultKind.UNREACHABLE and not caught.value.reached_device
    assert caught.value.detail == str(error)


def test_tcp_timeout_reports_no_answer(open_local, monkeypatch):
    def fail(*args):
        raise TimeoutError('timed out')
    monkeypatch.setattr(socket.socket, 'connect', fail)
    with pytest.raises(Fault) as caught:
        open_local()
    assert caught.value.kind == FaultKind.TIMEOUT and not caught.value.reached_device
    assert caught.value.detail == 'no TCP answer from 127.0.0.1:830 within 0.3s'


@pytest.mark.parametrize('code', [errno.EMFILE, errno.ENFILE])
def test_descriptor_exhaustion_survives_ncclient_socket_wrapper(open_local, monkeypatch, code):
    def exhausted(*args, **kwargs):
        raise OSError(code, 'Too many open files')
    monkeypatch.setattr(socket.socket, '__init__', exhausted)
    with pytest.raises(Fault) as caught:
        open_local()
    assert caught.value.kind == FaultKind.LOCAL and not caught.value.reached_device
    assert caught.value.detail == str(OSError(code, 'Too many open files'))
    unrelated = ssh.SSHSession(JunosDeviceHandler({}))
    with pytest.raises(SSHError, match='Could not open socket'):
        unrelated.connect(host='127.0.0.1', port=830, hostkey_verify=False)
    assert netconf._HOST_KEY_PORT.get() is None


@pytest.mark.parametrize('port', [23, '23'])
def test_telnet_port_is_rejected_before_device_construction(communicator, monkeypatch, port):
    constructor = Mock(side_effect=AssertionError('Device must not be constructed'))
    monkeypatch.setattr('jnpr.junos.Device', constructor)
    with pytest.raises(Fault) as caught:
        communicator.open(Target('local', '127.0.0.1', 'junos', 'netconf', port),
                          Credentials('user'), Timeouts(1, 2, 7, 11), 'off')
    assert caught.value == Fault(FaultKind.LOCAL, 'port 23 is telnet, not NETCONF', False)
    constructor.assert_not_called()


@pytest.mark.parametrize('port,expected', [(None, 830), (1830, 1830)])
@pytest.mark.parametrize('policy', ['off', 'strict', 'accept-new'])
def test_device_options_and_host_key_policy(communicator, monkeypatch, port, expected, policy):
    device = SimpleNamespace(port=expected, open=Mock(), close=Mock())
    constructor = Mock(return_value=device)
    pin = Mock()
    monkeypatch.setattr('jnpr.junos.Device', constructor)
    monkeypatch.setattr(netconf, '_accept_new', pin)
    communicator.open(Target('local', '127.0.0.1', 'junos', 'netconf', port),
                      Credentials('user', password='password'), Timeouts(1, 2, 7, 11), policy)
    options = constructor.call_args.kwargs
    assert options['host'] == '127.0.0.1' and options['port'] == expected
    assert options['user'] == 'user' and options['passwd'] == 'password'
    assert options['conn_open_timeout'] == 1 and device.timeout == 7
    assert options['hostkey_verify'] is (policy != 'off')
    assert options['gather_facts'] is False and options['huge_tree'] is True
    assert 'mode' not in options and 'console' not in options
    assert pin.call_count == (1 if policy == 'accept-new' else 0)


@pytest.mark.parametrize('credentials,discovery', [
    (Credentials('user'), True), (Credentials('user', password='password'), False),
    (Credentials('user', key_file='~/key'), False),
])
def test_explicit_credentials_disable_discovery(communicator, monkeypatch, tmp_path, credentials, discovery):
    constructor = Mock(return_value=SimpleNamespace(port=830, open=Mock(), close=Mock()))
    monkeypatch.setattr('jnpr.junos.Device', constructor)
    communicator.open(Target('local', '127.0.0.1', 'junos', 'netconf'), credentials, Timeouts(1, 2, 7, 11), 'off')
    options = constructor.call_args.kwargs
    assert options['allow_agent'] is discovery and options['look_for_keys'] is discovery
    assert options['ssh_private_key_file'] == (str(tmp_path / 'key') if credentials.key_file else None)


@pytest.mark.parametrize('error,kind,reached', [
    (EOFError('closed'), FaultKind.SESSION_LOST, True),
    (ConnectionResetError('reset'), FaultKind.SESSION_LOST, True),
    (paramiko.SSHException('Channel closed.'), FaultKind.SESSION_LOST, True),
    (PermissionError('key unreadable'), FaultKind.LOCAL, False),
])
def test_open_library_errors_become_faults(open_local, monkeypatch, error, kind, reached):
    monkeypatch.setattr(Device, 'open', Mock(side_effect=error))
    closed = Mock()
    monkeypatch.setattr(Device, 'close', closed)
    with pytest.raises(Fault) as caught:
        open_local()
    assert caught.value.kind == kind and caught.value.reached_device is reached
    assert caught.value.detail == str(error)
    closed.assert_called_once()


def test_wrapped_host_key_failure_keeps_underlying_detail(open_local, monkeypatch):
    underlying = ssh.SSHUnknownHostError('example', 'fingerprint')
    outer = pyez.ConnectRefusedError(SimpleNamespace(hostname='example'))
    outer._orig = underlying
    monkeypatch.setattr(Device, 'open', Mock(side_effect=outer))
    with pytest.raises(Fault) as caught:
        open_local()
    assert caught.value.kind == FaultKind.HOST_KEY and not caught.value.reached_device
    assert caught.value.detail == str(underlying)


def test_setup_hooks_do_not_change_unrelated_sessions():
    netconf._install_setup_hooks()
    with ssh.socket.socket() as sock:
        assert type(sock) is socket.socket
    assert ssh.paramiko.Transport is paramiko.Transport


def test_send_tick_is_ten_milliseconds():
    from ncclient.transport import session
    assert session.TICK == 0.01


def test_addresses_share_one_connect_deadline(open_local, monkeypatch):
    timeouts = []

    def connect(sock, address):
        timeouts.append(sock.gettimeout())
        time.sleep(min(0.2, sock.gettimeout()))
        raise TimeoutError('timed out')

    addresses = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('127.0.0.1', 830))] * 2
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args, **kwargs: addresses)
    monkeypatch.setattr(socket.socket, 'connect', connect)
    with pytest.raises(Fault) as caught:
        open_local()
    assert caught.value.kind == FaultKind.TIMEOUT and not caught.value.reached_device
    assert len(timeouts) == 2 and timeouts[1] < timeouts[0] - 0.15


@pytest.mark.parametrize('mode,detail,reached', [('no-banner', 'no SSH banner', False),
                                                ('only-banner', 'key exchange did not finish', True)])
def test_accept_new_handshake_uses_same_setup_deadlines(open_local, fake_server, mode, detail, reached):
    with fake_server(mode) as (port, state):
        with pytest.raises(Fault) as caught:
            open_local(port, policy='accept-new')
        assert caught.value.kind == FaultKind.TIMEOUT and caught.value.reached_device is reached
        assert detail in caught.value.detail


def test_one_expired_open_does_not_close_another(open_local, fake_server, communicator):
    from concurrent.futures import ThreadPoolExecutor

    with fake_server('success') as (fast, _), fake_server('no-hello') as (slow, _):
        with ThreadPoolExecutor(max_workers=2) as pool:
            good = pool.submit(open_local, fast)
            bad = pool.submit(open_local, slow)
            session = good.result(timeout=3)
            try:
                with pytest.raises(Fault) as caught:
                    bad.result(timeout=3)
                assert caught.value.kind == FaultKind.TIMEOUT
                assert session.device._conn._session.transport.is_active()
            finally:
                communicator._discard(session)
