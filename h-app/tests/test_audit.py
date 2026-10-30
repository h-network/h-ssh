import errno
import fcntl
import json
import multiprocessing
import os
import re
import stat
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from hssh import audit
from hssh.dialects.junos import DIALECT
from hssh.model import EditSettings, Fault, FaultKind, OperationResult, Result, Target


@pytest.fixture
def write_entry(tmp_path):
    def write(**overrides):
        arguments = dict(
            path=str(tmp_path / "audit.jsonl"), run_id=42, user="operator",
            target=Target("R1", "192.0.2.1", "junos", "netconf"), driver="junos@netconf",
            dialect=DIALECT, action="commit", edit=EditSettings(True, 2, "maintenance"),
            operation=OperationResult("commit", Result("complete"), "2026-10-30T00:00:00+00:00", 17),
            diff="+ host-name R1;",
        )
        arguments.update(overrides)
        audit.write_audit_entry(**arguments)
        return json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[-1])
    return write


def _append_worker(path, worker, barrier):
    real_write = os.write
    barrier.wait(timeout=5)
    with patch.object(audit.os, "write", side_effect=lambda fd, data: real_write(fd, data[:97])):
        for sequence in range(20):
            text = json.dumps({"worker": worker, "seq": sequence, "text": "é☃" * 512}, ensure_ascii=False)
            audit.secure_append(path, text + "\n")


def _try_append(path, result):
    try:
        audit.secure_append(path, "{}\n")
    except OSError as error:
        result.send(str(error))
    else:
        result.send(None)
    finally:
        result.close()


def test_appends_preserve_existing_json_lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text('{"before": true}\n')
    audit.secure_append(str(path), '{"after": true}\n')
    assert path.read_text() == '{"before": true}\n{"after": true}\n'


def test_short_writes_finish_utf8_text(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    text = '{"text": "é☃"}\n'
    real_write = os.write
    monkeypatch.setattr(audit.os, "write", lambda fd, data: real_write(fd, data[:1]))
    audit.secure_append(str(path), text)
    assert path.read_bytes() == text.encode("utf-8")


def test_lock_covers_every_short_write_and_is_released(tmp_path, monkeypatch):
    path = tmp_path / "audit.jsonl"
    rival = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    real_write = os.write

    def write(fd, data):
        with pytest.raises(BlockingIOError):
            fcntl.flock(rival, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return real_write(fd, data[:3])

    monkeypatch.setattr(audit.os, "write", write)
    try:
        audit.secure_append(str(path), '{"complete": true}\n')
        fcntl.flock(rival, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(rival)
    assert path.read_text() == '{"complete": true}\n'


def test_concurrent_processes_append_complete_json_records(tmp_path):
    path = tmp_path / "audit.jsonl"
    context = multiprocessing.get_context("fork")
    barrier = context.Barrier(4)
    workers = [context.Process(target=_append_worker, args=(str(path), worker, barrier)) for worker in range(4)]
    try:
        for process in workers:
            process.start()
        for process in workers:
            process.join(timeout=10)
            assert process.exitcode == 0
    finally:
        for process in workers:
            if process.is_alive():
                process.kill()
            if process.pid is not None:
                process.join(timeout=2)
                process.close()
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(rows) == 80
    assert {(row["worker"], row["seq"]) for row in rows} == {(w, s) for w in range(4) for s in range(20)}
    assert all(row["text"] == "é☃" * 512 for row in rows)


def test_symlink_refusal_leaves_destination_and_mode_untouched(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep\n")
    victim.chmod(0o644)
    path = tmp_path / "audit.jsonl"
    path.symlink_to(victim)
    with pytest.raises(OSError) as caught:
        audit.secure_append(str(path), "{}\n")
    assert str(path) in str(caught.value)
    assert victim.read_text() == "keep\n"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644


@pytest.mark.parametrize("with_reader", [False, True])
def test_fifo_is_refused_without_blocking(tmp_path, with_reader):
    path = tmp_path / "audit.fifo"
    os.mkfifo(path)
    reader = os.open(path, os.O_RDONLY | os.O_NONBLOCK) if with_reader else None
    context = multiprocessing.get_context("fork")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=_try_append, args=(str(path), send))
    try:
        process.start()
        send.close()
        assert receive.poll(2), "append blocked on a FIFO"
        error = receive.recv()
        process.join(timeout=2)
        assert process.exitcode == 0
        assert error is not None and str(path) in error
        if reader is not None:
            assert os.read(reader, 1024) == b""
    finally:
        if process.is_alive():
            process.kill()
        if process.pid is not None:
            process.join(timeout=2)
            process.close()
        receive.close()
        send.close()
        if reader is not None:
            os.close(reader)


def test_new_files_are_private_with_permissive_umask(tmp_path):
    path = tmp_path / "audit.jsonl"
    previous = os.umask(0)
    try:
        audit.secure_append(str(path), "{}\n")
    finally:
        os.umask(previous)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_existing_file_is_made_private(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("{}\n")
    path.chmod(0o666)
    audit.secure_append(str(path), "{}\n")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_private_dir_creates_each_parent_0700(tmp_path):
    path = tmp_path / "parent" / "child"
    previous = os.umask(0)
    try:
        audit.private_dir(path)
    finally:
        os.umask(previous)
    assert stat.S_IMODE(path.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_existing_parent_permissions_are_unchanged(tmp_path):
    parent = tmp_path / "existing"
    parent.mkdir(mode=0o755)
    parent.chmod(0o755)
    audit.secure_append(str(parent / "new" / "audit.jsonl"), "{}\n")
    assert stat.S_IMODE(parent.stat().st_mode) == 0o755
    assert stat.S_IMODE((parent / "new").stat().st_mode) == 0o700


def test_entry_matches_the_audit_schema(write_entry):
    assert write_entry() == {
        "time": "2026-10-30T00:00:00+00:00", "run_id": 42, "user": "operator",
        "target": "R1", "host": "192.0.2.1", "driver": "junos@netconf", "action": "commit",
        "payload": "", "dry_run": False, "confirmed_minutes": 2, "comment": "maintenance",
        "diff": "+ host-name R1;", "ok": True, "fault": None,
    }


def test_entry_is_one_json_line_with_embedded_newlines_and_unicode(tmp_path, write_entry):
    diff = '+ announcement "é☃";\n- announcement "old";\n'
    assert write_entry(diff=diff)["diff"] == diff
    data = (tmp_path / "audit.jsonl").read_bytes()
    assert data.endswith(b"\n") and data.count(b"\n") == 1


@pytest.mark.parametrize("apply", [False, True])
def test_dry_run_follows_requested_apply_even_on_failure(write_entry, apply):
    fault = Fault(FaultKind.REFUSED, "refused", True)
    operation = OperationResult("load", fault, "2026-10-30T00:00:00+00:00", 1)
    assert write_entry(operation=operation, edit=EditSettings(apply))["dry_run"] is not apply


def test_absent_edit_options_are_null(write_entry):
    row = write_entry(edit=EditSettings(True), diff="")
    assert row["confirmed_minutes"] is None
    assert row["comment"] is None
    assert row["diff"] == ""


def test_fault_keeps_kind_reachability_and_full_detail(write_entry):
    detail = "first diagnostic\nsecond diagnostic"
    operation = OperationResult("open", Fault(FaultKind.UNREACHABLE, detail, False), "2026-10-30T01:02:03+00:00", 9)
    row = write_entry(action="probe", operation=operation)
    assert row["action"] == "probe" and row["time"] == operation.started
    assert row["ok"] is False
    assert row["fault"] == {"kind": "UNREACHABLE", "detail": detail, "reached_device": False}


def test_diff_redaction_keeps_keyword_and_secret_data_suffix(write_entry):
    diff = '+ custom-credential "abc\\"tail"; ## SECRET-DATA'
    row = write_entry(diff=diff)
    assert row["diff"] == '+ custom-credential [REDACTED]; ## SECRET-DATA'


def test_comment_redacts_quoted_credentials(write_entry):
    edit = EditSettings(True, comment="rotated: 'password hunter2'")
    row = write_entry(edit=edit)
    assert row["comment"] == "rotated: 'password [REDACTED]'"
    assert edit.comment == "rotated: 'password hunter2'"


def test_fault_redaction_keeps_surrounding_diagnostic(write_entry):
    fault = Fault(FaultKind.COMMIT_FAILED, "'password hunter2' was refused\ncheck configuration", True)
    row = write_entry(operation=OperationResult("commit", fault, "2026-10-30T00:00:00+00:00", 1))
    assert row["fault"]["detail"] == "'password [REDACTED]' was refused\ncheck configuration"
    assert fault.detail == "'password hunter2' was refused\ncheck configuration"


@pytest.mark.parametrize("field", ["diff", "comment", "fault"])
def test_json_secret_values_are_masked_in_each_written_field(write_entry, field):
    text = json.dumps([{"encrypted-password": [{"data": "LISTSECRET"}],
                        "chap-secret": {"data": "OBJECTSECRET"}, "name": "keep", "enabled": True,
                        "count": 3, "optional": None, "note": "password WORDSECRET"}])
    argument = {"diff": {"diff": text}, "comment": {"edit": EditSettings(True, comment=text)},
                "fault": {"operation": OperationResult("load", Fault(FaultKind.REFUSED, text, True), "start", 1)}}[field]
    row = write_entry(**argument)
    redacted = row["fault"]["detail"] if field == "fault" else row[field]
    assert json.loads(redacted) == [{"encrypted-password": "[REDACTED]", "chap-secret": "[REDACTED]",
                                     "name": "keep", "enabled": True, "count": 3, "optional": None,
                                     "note": "password [REDACTED]"}]


def test_writer_uses_supplied_dialect_patterns(write_entry):
    dialect = SimpleNamespace(redaction_patterns=(re.compile(r"(opaque=)(\w+)"),))
    row = write_entry(dialect=dialect, diff="opaque=PRIVATE; name=keep")
    assert row["diff"] == "opaque=[REDACTED]; name=keep"


def test_failed_open_raises_with_path_instead_of_returning_false(tmp_path, write_entry):
    parent = tmp_path / "not-a-directory"
    parent.write_text("keep")
    path = parent / "audit.jsonl"
    with pytest.raises(OSError) as caught:
        write_entry(path=str(path))
    assert str(path) in str(caught.value)
    assert "cannot append recording" in str(caught.value)
    assert parent.read_text() == "keep"


def test_disk_full_raises_with_cause_and_releases_lock(tmp_path, monkeypatch, write_entry):
    def disk_full(fd, data):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(audit.os, "write", disk_full)
    with pytest.raises(OSError) as caught:
        write_entry()
    path = tmp_path / "audit.jsonl"
    assert caught.value.errno == errno.ENOSPC
    assert str(path) in str(caught.value) and "No space left" in str(caught.value)
    fd = os.open(path, os.O_WRONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(fd)


def test_zero_length_write_raises_instead_of_looping(tmp_path, monkeypatch, write_entry):
    writes = iter([0, OSError("repeated write after no progress")])

    def no_progress(fd, data):
        result = next(writes)
        if isinstance(result, OSError):
            raise result
        return result

    monkeypatch.setattr(audit.os, "write", no_progress)
    with pytest.raises(OSError, match="no progress") as caught:
        write_entry()
    assert str(tmp_path / "audit.jsonl") in str(caught.value)
    assert next(writes).args == ("repeated write after no progress",)


def test_lock_failure_is_reported_without_writing(tmp_path, monkeypatch, write_entry):
    def no_lock(fd, operation):
        raise OSError(errno.ENOLCK, "No locks available")

    monkeypatch.setattr(audit.fcntl, "flock", no_lock)
    with pytest.raises(OSError, match="No locks available"):
        write_entry()
    assert (tmp_path / "audit.jsonl").read_bytes() == b""
