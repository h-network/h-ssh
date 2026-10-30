"""Read retained runs and results without changing the store."""

from __future__ import annotations

import argparse
import itertools
import json
import os
import re
import stat
import sys
from collections.abc import Sequence
from contextlib import closing, contextmanager

from hssh.audit import private_dir, private_file
from hssh.frontends.settings import load_config, store_path
from hssh.screen import is_terminal, terminal_safe
from hssh.store import Store


_MISSING = object()


def _shown(text: object, stream=None) -> str:
    text = str(text)
    return terminal_safe(text) if is_terminal(sys.stdout if stream is None else stream) else text


def _short(text: object, width: int = 48) -> str:
    lines = _shown("" if text is None else text).strip().splitlines()
    value = lines[0] if lines else ""
    if len(lines) > 1:
        value += f" (+{len(lines) - 1} lines)"
    return value if len(value) <= width else value[:width - 1] + "…"


def _write(stream, text: str) -> None:
    if stream is not None:
        stream.write(text)


def _table(head, rows, *, widths: tuple[int, ...], numeric: tuple[int, ...] = ()) -> None:
    terminal = is_terminal(sys.stdout)
    for row in itertools.chain((head,), rows):
        if terminal:
            cells = (_short(cell, width).replace("\t", " ") for cell, width in zip(row, widths))
            cells = (cell.rjust(width) if i in numeric else cell.ljust(width)
                     for i, (cell, width) in enumerate(zip(cells, widths)))
            line = "  ".join(cells).rstrip()
        else:
            line = "\t".join(str(cell) for cell in row)
        _write(sys.stdout, line + "\n")


def _run_filter(store: Store, value: str | None) -> int | None:
    return store.resolve_run(value) if value is not None else None


def _filters(args) -> dict:
    return {name: getattr(args, name, None) for name in ("target", "command", "seq")}


def _runs(store: Store, args) -> int:
    with closing(store.runs(args.last)) as records:
        rows = ((r["id"], _short(r["started"], 32), _shown(r["mode"]), _shown(r["user"]),
                 "/".join(str(r[key]) if r[key] is not None else "?" for key in ("targets", "ok", "failed", "skipped")),
                 r["not_kept"], "interrupted" if r["interrupted"] else "", _short(r["argv"], 60))
                for r in records)
        _table(("run", "started", "mode", "user", "targets/ok/failed/skipped", "not_kept", "state", "argv"), rows,
               widths=(6, 32, 13, 12, 23, 8, 11, 60), numeric=(0, 4, 5))
    return 0


def _failed(store: Store, args) -> int:
    run = store.resolve_run(args.run)
    with closing(store.results(run, ok=False, status="failed", **_filters(args))) as rows:
        first = next(rows, None)
        args.verdict = int(first is not None)
        selected = itertools.chain((first,), rows) if first is not None else ()
        _write(sys.stdout, f"run {run}: failed operations\n")
        _table(("target", "seq", "command", "fault", "detail"),
               ((r["target"], r["seq"], _short(r["command"]), r["fault"], _short(r["detail"], 80)) for r in selected),
               widths=(24, 5, 48, 15, 80), numeric=(1,))
    return args.verdict


def _output(store: Store, args) -> int:
    row = store.output(store.resolve_run(args.run), args.target, args.seq)
    args.verdict = int(not row["ok"])
    if row["output"] is not None:
        _write(sys.stdout, _shown(row["output"]))
    if not row["ok"]:
        _write(sys.stderr, _shown(f"ERROR: {row['fault']}: {row['detail']}", sys.stderr) + "\n")
    return args.verdict


def _grep(store: Store, args) -> int:
    pattern = re.compile(args.pattern, re.IGNORECASE if args.ignore_case else 0)
    args.verdict = 1
    with closing(store.results(_run_filter(store, args.run), ok=True, **_filters(args))) as rows:
        for row in rows:
            for line in row["output"].splitlines():
                if pattern.search(line):
                    args.verdict = 0
                    _write(sys.stdout, f"{row['run_id']}  {_shown(row['target'])}  {_short(row['command'], 32)}: {_shown(line)}\n")
    return args.verdict


def _json_path(value: object, path: str) -> object:
    for key in path.split("."):
        if isinstance(value, dict):
            value = value.get(key, _MISSING)
        elif isinstance(value, list) and re.fullmatch(r"-?[0-9]+", key):
            try:
                value = value[int(key)]
            except (IndexError, ValueError):
                return _MISSING
        else:
            return _MISSING
    return value


def _field(store: Store, args) -> int:
    if any(not key for key in args.path.split(".")):
        raise ValueError("field path has an empty component")
    args.verdict = 1
    with closing(store.results(_run_filter(store, args.run), ok=True, **_filters(args))) as rows:
        for row in rows:
            try:
                data = json.loads(row["data"] if row["data"] is not None else row["output"])
            except ValueError:
                continue
            value = _json_path(data, args.path)
            if value is not _MISSING:
                args.verdict = 0
                text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
                _write(sys.stdout, f"{row['run_id']}  {_shown(row['target'])}  {_shown(args.path)} = {_shown(text)}\n")
    return args.verdict


def _diff(store: Store, args) -> int:
    text = store.compare(store.resolve_run(args.before), store.resolve_run(args.after), args.target, args.seq)
    args.verdict = int(bool(text))
    if text:
        _write(sys.stdout, _shown(text) + "\n")
    return args.verdict


def _history(store: Store, args) -> int:
    with closing(store.results(order="newest", limit=args.last, **_filters(args))) as rows:
        _table(("started", "run", "seq", "command", "ok", "status", "ms"),
               ((_short(r["started"], 32), r["run_id"], r["seq"], _short(r["command"]),
                 "OK" if r["ok"] else "FAIL", r["target_status"], r["elapsed_ms"]) for r in rows),
               widths=(32, 6, 5, 48, 4, 7, 9), numeric=(1, 2, 6))
    return 0


def _slowest(store: Store, args) -> int:
    with closing(store.results(_run_filter(store, args.run), order="slowest", limit=args.last, **_filters(args))) as rows:
        _table(("ms", "target", "run", "seq", "command", "ok", "status"),
               ((r["elapsed_ms"], r["target"], r["run_id"], r["seq"], _short(r["command"]),
                 "OK" if r["ok"] else "FAIL", r["target_status"]) for r in rows),
               widths=(9, 24, 6, 5, 48, 4, 7), numeric=(0, 2, 3))
    return 0


def _export_alias(store: Store, path: str | None = None, info: os.stat_result | None = None) -> bool:
    base = str(store._resolved)
    for name in (base, *(base + suffix for suffix in ("-wal", "-shm", "-journal"))):
        if path is not None and os.path.realpath(path) == name:
            return True
        try:
            source = os.stat(name)
            destination = info if info is not None else os.stat(path)
        except FileNotFoundError:
            continue
        if (source.st_dev, source.st_ino) == (destination.st_dev, destination.st_ino):
            return True
    return False


@contextmanager
def _destination(store: Store, path: str | None):
    if path is None:
        try:
            info = os.fstat(sys.stdout.fileno())
        except (AttributeError, OSError, ValueError):
            info = None
        if info is not None and _export_alias(store, info=info):
            raise ValueError("stdout names the store or one of its sidecars")
        yield sys.stdout
        return
    if _export_alias(store, path):
        raise ValueError("export destination names the store or one of its sidecars")
    from pathlib import Path

    private_dir(Path(path).parent)
    with private_file(path, os.O_WRONLY | os.O_CREAT, allow_character=True) as fd:
        info = os.fstat(fd)
        if _export_alias(store, path, info):
            raise ValueError("export destination names the store or one of its sidecars")
        if stat.S_ISREG(info.st_mode):
            os.fchmod(fd, 0o600)
            os.ftruncate(fd, 0)
        with os.fdopen(fd, "w", encoding="utf-8", newline="", closefd=False) as stream:
            yield stream


def _export(store: Store, args) -> int:
    if args.all and args.run is not None:
        raise ValueError("--all and a run selector cannot be used together")
    run = None if args.all else store.resolve_run(args.run)
    with closing(store.results(run, limit=1, **_filters(args))) as rows:
        args.verdict = int(next(rows, None) is None)
    with _destination(store, args.out) as stream:
        with closing(store.export(run, format=args.format, **_filters(args))) as records:
            for index, record in enumerate(records):
                if args.format != "csv" or index > 0:
                    args.verdict = 0
                _write(stream, terminal_safe(record) if is_terminal(stream) else record)
    return args.verdict


def _nonempty(text: str) -> str:
    if not text.strip():
        raise argparse.ArgumentTypeError("value must not be empty")
    return text


def _number(text: str, minimum: int = 0) -> int:
    try:
        value = int(text)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected an integer") from error
    if value < minimum:
        raise argparse.ArgumentTypeError(f"expected an integer >= {minimum}")
    return value


def _last(text: str) -> int:
    return _number(text, 1)


def _selectors(parser, *, target: bool = True) -> None:
    if target:
        parser.add_argument("--device", "--target", dest="target", type=_nonempty)
    parser.add_argument("--command", type=_nonempty, help="exact command filter")
    parser.add_argument("--seq", type=_number)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="h-ssh-store", description="Read retained runs and raw device output.")
    parser.add_argument("--store", type=_nonempty, help="store path: flag, HSSH_STORE, config, then h-ssh.db")
    parser.add_argument("--config", type=_nonempty, help="defaults file (default: ~/.h-ssh/config)")
    commands = parser.add_subparsers(dest="command_name", required=True)
    runs = commands.add_parser("runs", help="list runs, newest first")
    runs.add_argument("--last", type=_last, default=20)
    runs.set_defaults(fn=_runs)
    failed = commands.add_parser("failed", help="failed operations on failed targets")
    failed.add_argument("run", nargs="?", type=_nonempty)
    _selectors(failed)
    failed.set_defaults(fn=_failed)
    output = commands.add_parser("output", help="one operation's raw output")
    output.add_argument("target", type=_nonempty)
    output.add_argument("run", nargs="?", type=_nonempty)
    output.add_argument("--seq", type=_number, default=0)
    output.set_defaults(fn=_output)
    grep = commands.add_parser("grep", help="match lines in successful outputs")
    grep.add_argument("pattern", type=_nonempty)
    grep.add_argument("--run", type=_nonempty)
    grep.add_argument("-i", "--ignore-case", action="store_true")
    _selectors(grep)
    grep.set_defaults(fn=_grep)
    field = commands.add_parser("field", help="extract a dotted JSON field, including present null values")
    field.add_argument("path", type=_nonempty)
    field.add_argument("--run", type=_nonempty)
    _selectors(field)
    field.set_defaults(fn=_field)
    diff = commands.add_parser("diff", help="compare successful operations as logical lines")
    diff.add_argument("target", type=_nonempty)
    diff.add_argument("before", type=_nonempty)
    diff.add_argument("after", type=_nonempty)
    diff.add_argument("--seq", type=_number, default=0)
    diff.set_defaults(fn=_diff)
    history = commands.add_parser("history", help="one target's operations, newest first")
    history.add_argument("target", type=_nonempty)
    history.add_argument("--last", type=_last, default=50)
    _selectors(history, target=False)
    history.set_defaults(fn=_history)
    slowest = commands.add_parser("slowest", help="operations ordered by elapsed milliseconds")
    slowest.add_argument("run", nargs="?", type=_nonempty)
    slowest.add_argument("--last", type=_last, default=20)
    _selectors(slowest)
    slowest.set_defaults(fn=_slowest)
    export = commands.add_parser("export", help="stream CSV or JSONL, latest run by default")
    export.add_argument("run", nargs="?", type=_nonempty)
    export.add_argument("--all", action="store_true")
    export.add_argument("--format", choices=("csv", "jsonl"), default="csv")
    export.add_argument("--out", type=_nonempty)
    _selectors(export)
    export.set_defaults(fn=_export)
    return parser


def _error(text: str) -> int:
    try:
        _write(sys.stderr, _shown("ERROR: " + text, sys.stderr) + "\n")
    except BrokenPipeError:
        pass
    return 2


def _flush(stream) -> None:
    if stream is not None:
        stream.flush()


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        store = Store(store_path(args.store, load_config(args.config)), readonly=True)
    except (OSError, ValueError) as error:
        return _error(str(error))
    args.verdict, error = 0, None
    try:
        result = args.fn(store, args)
    except BrokenPipeError:
        result = args.verdict
    except (OSError, ValueError, re.error) as caught:
        result, error = 2, str(caught)
    finally:
        try:
            store.close()
        except OSError as caught:
            result, error = 2, str(caught)
    try:
        _flush(sys.stdout)
    except BrokenPipeError:
        pass
    except OSError as caught:
        result, error = 2, str(caught)
    return _error(error) if error is not None else result


def _silence_closed_pipe() -> None:
    fd = os.open(os.devnull, os.O_WRONLY)
    try:
        for stream in (sys.stdout, sys.stderr):
            try:
                os.dup2(fd, stream.fileno())
            except (AttributeError, OSError, ValueError):
                pass
    finally:
        os.close(fd)


def main_sync() -> None:
    try:
        result = main()
    except BrokenPipeError:
        result = 0
    except SystemExit as error:
        result = error.code if isinstance(error.code, int) else 2
    try:
        _flush(sys.stdout)
        _flush(sys.stderr)
    except BrokenPipeError:
        _silence_closed_pipe()
    except OSError:
        result = 2
    raise SystemExit(result)
