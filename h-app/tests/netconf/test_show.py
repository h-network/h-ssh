from ncclient.operations.errors import TimeoutExpiredError
from ncclient.transport.errors import SessionCloseError
import pytest

from hssh.model import Fault, FaultKind


@pytest.mark.parametrize('xml', [
    '<rpc-reply>protocol: operation-failed\nerror: could not resolve file: no-such-file</rpc-reply>',
    '<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">\nprotocol: operation-failed\nerror: could not resolve file: no-such-file\n</rpc-reply>',
    '<rpc-reply><output>\nerror: could not resolve file: no-such-file\n</output></rpc-reply>',
    '<rpc-reply><output>syntax error</output></rpc-reply>',
])
def test_refusal_shapes_are_faults(communicator, rpc_session, xml):
    session, wire = rpc_session
    wire.show = xml
    with pytest.raises(Fault) as caught:
        communicator.show(session, 'show log no-such-file')
    assert caught.value.kind == FaultKind.REFUSED and caught.value.reached_device
    assert 'error' in caught.value.detail
    assert not caught.value.detail.startswith('\n') and not caught.value.detail.endswith('\n')


@pytest.mark.parametrize('xml,expected', [
    ('<rpc-reply><output>\nHostname: example\nModel: cRPD\n</output></rpc-reply>', 'Hostname: example\nModel: cRPD'),
    ('<rpc-reply><output>\nMessages log:\nerror: sample log entry\n</output></rpc-reply>', 'Messages log:\nerror: sample log entry'),
    ('<rpc-reply><output>protocol: operation-failed\nerror: logged event</output></rpc-reply>', 'protocol: operation-failed\nerror: logged event'),
    ('<rpc-reply>warning: no matching entries</rpc-reply>', 'warning: no matching entries'),
    ('<rpc-reply/>', ''),
    ('<rpc-reply><output/></rpc-reply>', ''),
    ('<rpc-reply><configuration-information><configuration-output>\nsystem { host-name example; }\n</configuration-output></configuration-information></rpc-reply>', 'system { host-name example; }'),
    ('<rpc-reply><output>first\n</output><output>second\nerror: logged event\n</output></rpc-reply>', 'first\nsecond\nerror: logged event'),
])
def test_show_output_is_preserved_without_false_refusals(communicator, rpc_session, xml, expected):
    session, wire = rpc_session
    wire.show = xml
    result = communicator.show(session, 'show version | no-more')
    assert result.output == expected and result.data is None
    rpc = wire.calls[0][0]
    assert rpc.tag == 'command' and rpc.get('format') == 'text' and rpc.text == 'show version'


def test_rpc_error_becomes_refused_with_device_message(communicator, rpc_session, rpc_error):
    session, wire = rpc_session
    wire.errors['command'] = rpc_error('syntax error')
    with pytest.raises(Fault) as caught:
        communicator.show(session, 'show bad-command')
    assert caught.value.kind == FaultKind.REFUSED and caught.value.reached_device
    assert caught.value.detail == 'syntax error'


@pytest.mark.parametrize('error,kind', [(TimeoutExpiredError('no reply'), FaultKind.TIMEOUT),
                                       (SessionCloseError('', ''), FaultKind.SESSION_LOST)])
def test_show_library_failures_become_faults(communicator, rpc_session, error, kind):
    session, wire = rpc_session
    wire.errors['command'] = error
    with pytest.raises(Fault) as caught:
        communicator.show(session, 'show version')
    assert caught.value.kind == kind and caught.value.reached_device


def test_batch_calls_do_not_mix_outputs(communicator, rpc_session):
    session, wire = rpc_session
    wire.show = '<rpc-reply><output>version</output></rpc-reply>'
    first = communicator.show(session, 'show version')
    wire.show = '<rpc-reply><output>interfaces</output></rpc-reply>'
    second = communicator.show(session, 'show interfaces terse')
    assert first.output == 'version' and second.output == 'interfaces'
    assert [rpc.text for rpc, timeout in wire.calls] == ['show version', 'show interfaces terse']
