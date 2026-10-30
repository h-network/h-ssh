import inspect
from collections.abc import Iterator
from pathlib import Path
import sqlite3
from typing import get_type_hints

import pytest

from hssh.model import OperationResult, Result, Target, TargetStatus
from hssh.paths import path_inside, validate_device_name
from hssh.store import Store, json_data


def test_store_add_requires_explicit_keyword_target_status():
    signature = inspect.signature(Store.add)
    args = (object(), 42, Target("r1", "host", "junos", "netconf"),
            "junos@netconf", 0, OperationResult("load", Result(""), "now", 1))
    with pytest.raises(TypeError):
        signature.bind(*args)
    with pytest.raises(TypeError):
        signature.bind(*args, "skipped")
    assert signature.bind(*args, status="skipped").arguments["status"] == "skipped"
    assert get_type_hints(Store.add)["status"] == TargetStatus


def test_reader_can_select_across_runs_without_materializing_rows():
    signature = inspect.signature(Store.results)
    bound = signature.bind(object(), target="r1", command="show version", ok=False,
                           status="failed", seq=1, order="newest", limit=50)
    bound.apply_defaults()
    assert bound.arguments["run_id"] is None
    assert get_type_hints(Store.results)["return"] == Iterator[sqlite3.Row]
    assert get_type_hints(Store.runs)["return"] == Iterator[sqlite3.Row]
    assert get_type_hints(Store.resolve_run)["selector"] == int | str | None
    assert get_type_hints(Store.resolve_run)["return"] is int


def test_export_accepts_filtered_all_run_csv_stream():
    signature = inspect.signature(Store.export)
    bound = signature.bind(object(), format="csv", target="r1", command="show version",
                           ok=True, status="ok", seq=1)
    bound.apply_defaults()
    assert bound.arguments["run_id"] is None
    assert get_type_hints(Store.export)["return"] == Iterator[str]


def test_json_converter_returns_values_not_serialized_text():
    hints = get_type_hints(json_data)
    assert hints["value"] is object
    assert hints["return"] == bool | None | dict[str, object] | list[object]


def test_shared_path_signatures_match_payload_file_callers():
    assert inspect.signature(validate_device_name).bind("r1").arguments == {"name": "r1"}
    assert get_type_hints(validate_device_name) == {"name": str, "return": str}
    assert inspect.signature(path_inside).bind(Path("payloads"), "r1.set").arguments == {
        "base": Path("payloads"), "filename": "r1.set",
    }
    assert get_type_hints(path_inside) == {"base": Path, "filename": str, "return": Path}
