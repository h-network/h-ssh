"""Arista driver tests — fakes of pyeapi, no live switches needed."""
import datetime
import os
import socket
import ssl
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pyeapi.client
from pyeapi.eapilib import CommandError, ConnectionError as EapiConnectionError

from hssh.vendors import arista


@pytest.fixture(autouse=True)
def no_env(monkeypatch):
    for var in ("HSSH_EAPI_CA", "HSSH_EAPI_VERIFY"):
        monkeypatch.delenv(var, raising=False)


# --- what reaches pyeapi.connect() --------------------------------------------

class FakeSock:
    def __init__(self):
        self.timeouts = []

    def settimeout(self, value):
        self.timeouts.append(value)


class FakeHttps:
    """The http.client connection pyeapi drives: connect() opens the socket."""

    def __init__(self):
        self.sock = None
        self.connects = 0

    def connect(self):
        self.connects += 1
        self.sock = FakeSock()


class FakeNode:
    def __init__(self):
        self.connection = types.SimpleNamespace(transport=FakeHttps())

    def enable(self, commands, **kw):
        return [{"result": {"version": "4.30.1F", "modelName": "vEOS"}}]


@pytest.fixture
def recorder(monkeypatch):
    """pyeapi.connect() as a recorder of its keyword arguments."""
    seen = {}

    def connect(**kwargs):
        seen.update(kwargs)
        seen["node"] = FakeNode()
        return seen["node"]

    monkeypatch.setattr(arista, "pyeapi", types.SimpleNamespace(connect=connect))
    return seen


def test_connect_asks_for_a_node_with_a_verifying_context(recorder):
    """Regression: without return_node=True every call died on .enable()/.config()
    before a request was sent, and pyeapi's default context verified nothing."""
    out = arista.show("192.0.2.1", "admin", "pw", "show version", 5, 99)
    assert "version: 4.30.1F" in out
    assert recorder["return_node"] is True
    assert recorder["transport"] == "https" and recorder["port"] == 443
    assert recorder["timeout"] == 5
    context = recorder["context"]
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True


def test_verify_no_is_the_explicit_escape_hatch(recorder, monkeypatch):
    monkeypatch.setenv("HSSH_EAPI_VERIFY", "no")
    arista.show("192.0.2.1", "admin", "pw", "show version", 5, 99)
    context = recorder["context"]
    assert context.verify_mode == ssl.CERT_NONE and context.check_hostname is False


def lab_ca_pem(common_name):
    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


def test_lab_ca_is_the_trust_anchor_when_given(recorder, monkeypatch, tmp_path):
    ca = tmp_path / "lab-ca.pem"
    ca.write_bytes(lab_ca_pem("h-ssh lab CA"))
    monkeypatch.setenv("HSSH_EAPI_CA", str(ca))
    arista.show("192.0.2.1", "admin", "pw", "show version", 5, 99)
    context = recorder["context"]
    assert context.verify_mode == ssl.CERT_REQUIRED
    subjects = [pair for cert in context.get_ca_certs() for rdn in cert["subject"] for pair in rdn]
    assert subjects == [("commonName", "h-ssh lab CA")]


def test_handshake_and_requests_run_under_their_own_timeouts(recorder):
    arista.show("192.0.2.1", "admin", "pw", "show version", 5, 99)
    https = recorder["node"].connection.transport
    https.connect()  # what http.client does before every request
    https.connect()
    assert https.connects == 2
    assert https.sock.timeouts == [99.0]


# --- the as-shipped driver against the real pyeapi, no socket ------------------

def refuse_sockets(monkeypatch):
    def refuse(*args, **kwargs):
        raise OSError("offline test, no socket")
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.mark.parametrize("call", [
    lambda: arista.show("192.0.2.1", "admin", "pw", "show version", 5, 10),
    lambda: arista.show_structured("192.0.2.1", "admin", "pw", "show version", 5, 10),
    lambda: arista.edit("192.0.2.1", "admin", "pw", "hostname SW1\n", 5, 10),
])
def test_real_pyeapi_gets_as_far_as_the_request(monkeypatch, call):
    """Regression: the failure must be the (blocked) request, not a missing method."""
    refuse_sockets(monkeypatch)
    with pytest.raises(EapiConnectionError, match="offline test"):
        call()


def test_real_pyeapi_batch_reports_the_request_failure(monkeypatch):
    refuse_sockets(monkeypatch)
    results = arista.show_batch("192.0.2.1", "admin", "pw", ["show version"], 5, 10)
    assert results[0]["ok"] is False
    assert "offline test" in results[0]["error"]


# --- edit: the real pyeapi Node on a fake eAPI ---------------------------------

class FakeEapi:
    """eAPI as a recorder: each request's command list, in order.

    Commands run in order inside one request and the first failure ends it,
    the way EOS does; whatever ran before it stays applied.
    """

    def __init__(self, fail_on=None, diff="+hostname SW1-new"):
        self.requests = []
        self.fail_on = fail_on
        self.diff = diff

    def execute(self, commands, encoding="json", **kwargs):
        self.requests.append(list(commands))
        out = []
        for i, cmd in enumerate(commands):
            if cmd == self.fail_on:
                raise CommandError(1002, "CLI command %d of %d '%s' failed: invalid command"
                                   % (i + 1, len(commands), cmd),
                                   command_error="Invalid input", output=out, commands=commands)
            out.append({"output": self.diff} if cmd == "show session-config diffs" else {})
        return {"result": out}


@pytest.fixture
def session(monkeypatch):
    def install(**kw):
        eapi = FakeEapi(**kw)
        node = pyeapi.client.Node(eapi)
        monkeypatch.setattr(arista, "_connect", lambda *a, **k: node)
        return eapi
    return install


def flat(eapi):
    return [cmd for request in eapi.requests for cmd in request]


def test_edit_loads_diffs_and_commits_inside_one_session(session):
    eapi = session()
    out = arista.edit("192.0.2.1", "admin", "pw", "interface Ethernet1\n description first\n", 5, 10)
    assert out == "COMMIT OK\n\nDIFF:\n+hostname SW1-new"
    name = eapi.requests[0][1]
    assert name.startswith("configure session ")
    assert [req[:2] for req in eapi.requests] == [["enable", name]] * 3
    assert [req[2:] for req in eapi.requests] == [
        ["interface Ethernet1", "description first"],
        ["show session-config diffs"],
        ["commit"],
    ]
    assert "configure terminal" not in flat(eapi)


def test_a_rejected_line_aborts_the_session_and_commits_nothing(session):
    """Regression: a failing line used to leave the lines before it in running-config."""
    eapi = session(fail_on="bad command")
    with pytest.raises(CommandError, match="bad command"):
        arista.edit("192.0.2.1", "admin", "pw",
                    "interface Ethernet1\n description first\nbad command\n description never\n", 5, 10)
    assert "commit" not in flat(eapi)
    assert eapi.requests[-1][2:] == ["abort"]


def test_no_changes_aborts_rather_than_commits(session):
    eapi = session(diff="")
    assert arista.edit("192.0.2.1", "admin", "pw", "hostname SW1\n", 5, 10) == "NO CHANGES"
    assert "commit" not in flat(eapi)
    assert eapi.requests[-1][2:] == ["abort"]


def test_edit_refuses_a_rollback_timer_instead_of_dropping_it(recorder):
    """commit_confirmed= was accepted and the session committed with no timer (#40)."""
    with pytest.raises(ValueError, match="not supported by the 'arista' transport; nothing was sent"):
        arista.edit("10.0.0.1", "u", "p", "hostname NEW\n", 5, 10, commit_confirmed=5)
    assert recorder == {}
