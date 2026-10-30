from ncclient.operations.errors import TimeoutExpiredError
from ncclient.transport.errors import SessionCloseError
import pytest

from hssh.dialects.junos import JunosDialect, SET_PREFIX_VERBS
from hssh.model import CommitStatus, Fault, FaultKind


def test_dry_run_checks_candidate_then_discards(communicator, loaded):
    session, wire = loaded
    result = communicator.diff(session)
    assert result.data is True
    assert result.output == wire.diff
    communicator.close(session)
    assert wire.names == ['lock-configuration', 'load-configuration', 'get-configuration',
                          'commit-configuration', 'load-configuration', 'unlock-configuration', 'close-session']
    assert wire.calls[3][0].find('check') is not None
    assert wire.calls[3][1] == session.timeouts.command


@pytest.mark.parametrize('minutes,comment', [(None, None), (None, 'change'), (7, 'change')])
def test_commit_arguments_and_cleanup(communicator, loaded, minutes, comment):
    session, wire = loaded
    communicator.diff(session)
    result = communicator.commit(session, minutes, comment)
    assert result.data is None
    rpc, timeout = wire.calls[4]
    assert timeout == session.timeouts.commit
    assert rpc.findtext('log') == comment
    assert (rpc.find('confirmed') is not None) == (minutes is not None)
    assert rpc.findtext('confirm-timeout') == (str(minutes) if minutes else None)
    communicator.close(session)
    assert wire.names.count('load-configuration') == 1
    assert wire.names[-2:] == ['unlock-configuration', 'close-session']


@pytest.mark.parametrize('empty', ['', None, '\n'])
def test_empty_compare_stays_empty_without_commit_check(communicator, loaded, empty):
    session, wire = loaded
    wire.diff = empty
    result = communicator.diff(session)
    assert result.output == '' and result.data is False
    assert 'commit-configuration' not in wire.names
    communicator.close(session)
    assert wire.names[-3:] == ['load-configuration', 'unlock-configuration', 'close-session']


def test_failed_load_still_discards_partial_candidate(communicator, rpc_session, rpc_error):
    session, wire = rpc_session
    wire.errors['load-configuration'] = rpc_error('bad syntax')
    with pytest.raises(Fault) as caught:
        communicator.load(session, ['set a b'])
    assert caught.value.kind == FaultKind.REFUSED and caught.value.reached_device
    assert 'bad syntax' in caught.value.detail
    wire.errors.clear()
    communicator.close(session)
    assert wire.names[-3:] == ['load-configuration', 'unlock-configuration', 'close-session']


def test_statement_not_found_warning_is_allowed(communicator, rpc_session, rpc_error):
    session, wire = rpc_session
    wire.errors['load-configuration'] = rpc_error('statement not found', 'warning')
    communicator.load(session, ['delete system services telnet'])
    assert session.locked and session.dirty


@pytest.mark.parametrize('message,severity', [('other warning', 'warning'), ('statement not found', 'error')])
def test_other_load_warnings_and_errors_are_refused(communicator, rpc_session, rpc_error, message, severity):
    session, wire = rpc_session
    wire.errors['load-configuration'] = rpc_error(message, severity)
    with pytest.raises(Fault) as caught:
        communicator.load(session, ['delete system services telnet'])
    assert caught.value.kind == FaultKind.REFUSED
    assert message in caught.value.detail


def test_failed_commit_check_fails_dry_run(communicator, loaded, rpc_error):
    session, wire = loaded
    wire.errors['commit-configuration'] = rpc_error('missing statement')
    with pytest.raises(Fault) as caught:
        communicator.diff(session)
    assert caught.value.kind == FaultKind.REFUSED
    communicator.close(session)
    assert wire.names[-3:] == ['load-configuration', 'unlock-configuration', 'close-session']


@pytest.mark.parametrize('operation', ['load', 'confirm'])
def test_failed_lock_sends_neither_load_nor_unlock(communicator, rpc_session, rpc_error, operation):
    session, wire = rpc_session
    wire.errors['lock-configuration'] = rpc_error('configuration database locked')
    with pytest.raises(Fault) as caught:
        if operation == 'load':
            communicator.load(session, ['set a b'])
        else:
            communicator.confirm(session)
    assert caught.value.kind == FaultKind.REFUSED and caught.value.reached_device
    communicator.close(session)
    assert wire.names == ['lock-configuration', 'close-session']


@pytest.mark.parametrize('error,kind', [
    (TimeoutExpiredError('lock no reply'), FaultKind.TIMEOUT),
    (SessionCloseError('', ''), FaultKind.SESSION_LOST),
])
def test_failed_lock_on_dead_session_discards(communicator, rpc_session, error, kind):
    session, wire = rpc_session
    wire.errors['lock-configuration'] = error
    with pytest.raises(Fault) as caught:
        communicator.load(session, ['set a b'])
    assert caught.value.kind == kind and caught.value.reached_device
    assert wire.closed and not session.device.connected
    communicator.close(session)
    assert 'unlock-configuration' not in wire.names


def test_commit_rejection_is_known_and_discards_candidate(communicator, loaded, rpc_error):
    session, wire = loaded
    wire.errors['commit-configuration'] = rpc_error('commit denied')
    with pytest.raises(Fault) as caught:
        communicator.commit(session, None, None)
    assert caught.value.kind == FaultKind.COMMIT_FAILED and caught.value.reached_device
    assert 'commit denied' in caught.value.detail
    communicator.close(session)
    assert wire.names[-3:] == ['load-configuration', 'unlock-configuration', 'close-session']


@pytest.mark.parametrize('error', [TimeoutExpiredError('no commit reply'), SessionCloseError('', '')])
@pytest.mark.parametrize('operation', ['commit', 'confirm'])
def test_unanswered_commit_never_rolls_back_or_unlocks(communicator, loaded, error, operation):
    session, wire = loaded
    wire.errors['commit-configuration'] = error
    with pytest.raises(Fault) as caught:
        if operation == 'commit':
            communicator.commit(session, 3, None)
        else:
            communicator.confirm(session)
    assert caught.value.kind == FaultKind.OUTCOME_UNKNOWN and caught.value.reached_device
    assert wire.closed and not session.device.connected
    communicator.close(session)
    assert wire.names.count('load-configuration') == 1
    assert 'unlock-configuration' not in wire.names


def test_close_during_commit_only_discards_transport(communicator, loaded):
    session, wire = loaded

    def interrupted(rpc):
        communicator.close(session)
        return SessionCloseError('', '')

    wire.errors['commit-configuration'] = interrupted
    with pytest.raises(Fault) as caught:
        communicator.commit(session, 3, None)
    assert caught.value.kind == FaultKind.OUTCOME_UNKNOWN
    assert wire.closed and not session.dirty and not session.locked
    assert wire.names.count('load-configuration') == 1
    assert 'unlock-configuration' not in wire.names


def test_confirm_rechecks_history_under_lock(communicator, rpc_session):
    session, wire = rpc_session
    communicator.confirm(session)
    communicator.close(session)
    assert wire.names == ['lock-configuration', 'get-commit-information', 'commit-configuration',
                          'unlock-configuration', 'close-session']
    assert wire.calls[2][1] == session.timeouts.commit
    assert wire.calls[2][0].find('confirmed') is None


def test_confirm_refuses_when_pending_disappeared(communicator, rpc_session):
    session, wire = rpc_session
    assert communicator.commit_history(session).data.pending
    wire.history = '<commit-history><sequence-number>0</sequence-number><log>confirmed</log></commit-history>'
    with pytest.raises(Fault) as caught:
        communicator.confirm(session)
    assert caught.value.kind == FaultKind.REFUSED and caught.value.reached_device
    assert caught.value.detail == 'nothing to confirm'
    communicator.close(session)
    assert wire.names[-3:] == ['get-commit-information', 'unlock-configuration', 'close-session']
    assert 'commit-configuration' not in wire.names and 'load-configuration' not in wire.names


def test_history_uses_newest_sequence_and_device_minutes(communicator, rpc_session):
    session, wire = rpc_session
    wire.history = ('<commit-history><sequence-number>1</sequence-number>'
                    '<comment>rollback in 9mins</comment></commit-history>') + wire.history
    result = communicator.commit_history(session)
    assert isinstance(result.data, CommitStatus)
    assert result.data.pending and result.data.remaining_minutes == 3
    assert '<sequence-number>0</sequence-number>' in result.data.newest
    assert '<sequence-number>1</sequence-number>' not in result.data.newest
    assert '<sequence-number>1</sequence-number>' in result.output


def test_old_pending_note_and_user_log_do_not_arm_timer(communicator, rpc_session):
    session, wire = rpc_session
    wire.history = ('<commit-history><sequence-number>0</sequence-number><log>rollback in 8mins</log></commit-history>'
                    '<commit-history><sequence-number>1</sequence-number><comment>rollback in 3mins</comment></commit-history>')
    status = communicator.commit_history(session).data
    assert not status.pending and status.remaining_minutes is None
    assert 'rollback in 8mins' in status.newest


def test_empty_history_has_no_pending_commit(communicator, rpc_session):
    session, wire = rpc_session
    wire.history = ''
    assert communicator.commit_history(session).data == CommitStatus(False, None, '')


@pytest.mark.parametrize('verb', SET_PREFIX_VERBS)
def test_set_format_uses_shared_verbs_and_keeps_inline_hash(communicator, rpc_session, verb):
    session, wire = rpc_session
    line = verb + 'a b # inline'
    communicator.load(session, ['# full-line comment', line])
    rpc = wire.calls[1][0]
    assert rpc.get('action') == 'set'
    assert rpc.findtext('configuration-set') == line


def test_comment_prefixes_come_from_dialect(communicator, rpc_session):
    class PrefixDialect(JunosDialect):
        comment_prefixes = ('#', '!')

    communicator.dialect = PrefixDialect()
    session, wire = rpc_session
    communicator.load(session, ['! comment', 'set a b'])
    assert wire.calls[1][0].findtext('configuration-set') == 'set a b'


@pytest.mark.parametrize('lines', [['set a b', 'system {', '}'], ['system {', '  host-name example;', '}']])
def test_text_format_keeps_payload_when_any_line_is_not_set(communicator, rpc_session, monkeypatch, lines):
    monkeypatch.setattr(communicator.dialect, 'check_edit', lambda lines: None)
    session, wire = rpc_session
    communicator.load(session, lines)
    rpc = wire.calls[1][0]
    assert rpc.get('action') == 'replace'
    assert rpc.findtext('configuration-text') == '\n'.join(lines)


@pytest.mark.parametrize('lines', [[], ['# comment'], ['commit'], ['commit;'], ['com'], ['set\ta b']])
def test_payload_guard_is_local_before_any_rpc(communicator, rpc_session, lines):
    session, wire = rpc_session
    with pytest.raises(Fault) as caught:
        communicator.load(session, lines)
    assert caught.value.kind == FaultKind.LOCAL and not caught.value.reached_device
    assert not wire.calls
