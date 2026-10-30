from types import SimpleNamespace

from ncclient.operations.errors import TimeoutExpiredError
import pytest

from hssh.model import Fault, FaultKind


@pytest.mark.parametrize('locked,dirty,expected', [
    (False, False, []), (False, True, []), (True, False, ['unlock']), (True, True, ['rollback', 'unlock']),
])
def test_close_cleans_only_owned_state(communicator, rpc_session, locked, dirty, expected):
    session, wire = rpc_session
    calls = []
    session.config = SimpleNamespace(rollback=lambda: calls.append('rollback'), unlock=lambda: calls.append('unlock'))
    session.locked, session.dirty = locked, dirty
    communicator.close(session)
    assert calls == expected
    assert wire.names == ['close-session']
    assert not session.locked and not session.dirty and session.config is None


def test_close_session_uses_five_seconds_not_command_timeout(communicator, rpc_session):
    session, wire = rpc_session
    wire.timeout = 300
    communicator.close(session)
    assert wire.calls[-1][1] == 5


@pytest.mark.parametrize('teardown_error', [None, OSError('teardown failed')])
def test_close_timeout_tears_down_transport_and_keeps_first_fault(communicator, rpc_session, teardown_error):
    session, wire = rpc_session
    wire.errors['close-session'] = TimeoutExpiredError('no close answer')
    wire.errors['transport-close'] = teardown_error
    with pytest.raises(Fault) as caught:
        communicator.close(session)
    assert caught.value.kind == FaultKind.TIMEOUT and caught.value.reached_device
    assert caught.value.detail == 'no close answer'
    assert wire.closed


def test_cleanup_failure_discards_without_more_rpcs(communicator, loaded, rpc_error):
    session, wire = loaded
    wire.errors['load-configuration'] = rpc_error('rollback denied')
    with pytest.raises(Fault) as caught:
        communicator.close(session)
    assert caught.value.kind == FaultKind.REFUSED and 'rollback denied' in caught.value.detail
    assert wire.names[-1] == 'load-configuration'
    assert 'unlock-configuration' not in wire.names and 'close-session' not in wire.names
    assert wire.closed and session.config is None and not session.locked and not session.dirty


def test_unlock_failure_after_commit_never_rolls_back(communicator, loaded, rpc_error):
    session, wire = loaded
    communicator.commit(session, None, None)
    wire.errors['unlock-configuration'] = rpc_error('unlock failed')
    with pytest.raises(Fault) as caught:
        communicator.close(session)
    assert caught.value.kind == FaultKind.REFUSED
    assert wire.names.count('load-configuration') == 1 and wire.names[-1] == 'unlock-configuration'
    assert wire.closed and 'close-session' not in wire.names
