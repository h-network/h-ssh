import socket

from jnpr.junos import Device
from lxml import etree
from ncclient.devices.junos import JunosDeviceHandler
from ncclient.operations.rpc import RPCError
from ncclient.transport import ssh
from ncclient.xml_ import NCElement
import pytest

from hssh.communicators import netconf
from hssh.dialects.junos import DIALECT
from hssh.model import Timeouts


class RpcWire:
    def __init__(self):
        self.timeout = 7
        self._device_handler = JunosDeviceHandler({})
        self._session = self
        self.closed = False
        self.calls = []
        self.errors = {}
        self.diff = '\n+ system { host-name example; }\n'
        self.history = ('<commit-history><sequence-number>0</sequence-number>'
                        '<comment>commit confirmed, rollback in 3mins</comment></commit-history>')
        self.show = '<rpc-reply><output>\nHostname: example\n</output></rpc-reply>'

    def rpc(self, rpc, *args):
        self.calls.append((etree.fromstring(etree.tostring(rpc)), self.timeout))
        error = self.errors.get(rpc.tag)
        if callable(error):
            error = error(rpc)
        if error:
            raise error
        if rpc.tag == 'command':
            return NCElement(self.show, self._device_handler.transform_reply())
        if rpc.tag == 'get-configuration':
            body = etree.Element('configuration-information')
            etree.SubElement(body, 'configuration-output').text = self.diff
        elif rpc.tag == 'get-commit-information':
            body = etree.fromstring('<commit-information>' + self.history + '</commit-information>')
        else:
            body = etree.Element('ok')
        reply = etree.Element('rpc-reply')
        reply.append(body)
        return NCElement(etree.tostring(reply, encoding="unicode"), self._device_handler.transform_reply())

    def close_session(self):
        self.calls.append((etree.Element('close-session'), self.timeout))
        if error := self.errors.get('close-session'):
            raise error

    def close(self):
        self.closed = True
        if error := self.errors.get('transport-close'):
            raise error

    @property
    def names(self):
        return [rpc.tag for rpc, timeout in self.calls]


@pytest.fixture(autouse=True)
def isolate_libraries(monkeypatch, tmp_path):
    monkeypatch.setenv('HOME', str(tmp_path))
    for name in ('_HOST_KEYS', '_REVOKED', '_RESOLVED'):
        monkeypatch.setattr(netconf, name, {})
    for name in ('_HOST_KEY_LOADER_INSTALLED', '_SETUP_HOOKS_INSTALLED'):
        monkeypatch.setattr(netconf, name, False)
    for name in ('socket', 'paramiko'):
        monkeypatch.setattr(ssh, name, getattr(ssh, name))
    for name in ('_post_connect', 'load_known_hosts'):
        monkeypatch.setattr(ssh.SSHSession, name, getattr(ssh.SSHSession, name))
    resolve = socket.getaddrinfo

    def local_only(host, *args, **kwargs):
        assert host == '127.0.0.1', f'unexpected network destination: {host}'
        return resolve(host, *args, **kwargs)

    monkeypatch.setattr(socket, 'getaddrinfo', local_only)
    opening = netconf._OPENING.set(None)
    port = netconf._HOST_KEY_PORT.set(None)
    yield
    netconf._OPENING.reset(opening)
    netconf._HOST_KEY_PORT.reset(port)


@pytest.fixture
def communicator():
    return netconf.NetconfCommunicator(DIALECT)


@pytest.fixture
def rpc_session():
    device = Device(host='example', gather_facts=False)
    wire = RpcWire()
    device._conn = wire
    device.connected = True
    return netconf.NetconfSession(device, Timeouts(1, 2, 7, 11)), wire


@pytest.fixture
def loaded(communicator, rpc_session):
    session, wire = rpc_session
    communicator.load(session, ['set system host-name example'])
    return session, wire


@pytest.fixture
def rpc_error():
    def make(message='denied', severity='error'):
        root = etree.Element('{urn:ietf:params:xml:ns:netconf:base:1.0}rpc-reply')
        error = etree.SubElement(root, '{urn:ietf:params:xml:ns:netconf:base:1.0}rpc-error')
        for key, value in [('error-type', 'protocol'), ('error-tag', 'operation-failed'),
                           ('error-severity', severity), ('error-message', message)]:
            etree.SubElement(error, '{urn:ietf:params:xml:ns:netconf:base:1.0}' + key).text = value
        if severity == 'warning':
            etree.SubElement(root, '{urn:ietf:params:xml:ns:netconf:base:1.0}ok')
        return RPCError(error)
    return make
