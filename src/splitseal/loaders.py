"""Strict structured-record loaders."""

from __future__ import annotations

import csv
import importlib
import io
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from splitseal.canonical import JSONValue, Record, ensure_record
from splitseal.errors import SplitSealError, fail


def _object_pairs(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
    result: dict[str, JSONValue] = {}
    for key, value in pairs:
        if key in result:
            raise fail("SS020", "JSON object contains a duplicate key", key=key)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise fail("SS020", "JSON contains a non-finite number", value=value)


def _load_jsonl(path: Path) -> list[Record]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise fail("SS020", "JSONL input must be readable UTF-8", path=path.name) from exc
    records: list[Record] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            raise fail("SS020", "JSONL input cannot contain blank lines", line=line_number)
        try:
            value = json.loads(
                line,
                object_pairs_hook=_object_pairs,
                parse_constant=_reject_constant,
            )
        except SplitSealError:
            raise
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise fail("SS020", "malformed JSONL record", line=line_number) from exc
        records.append(ensure_record(value, location=f"line {line_number}"))
    if not records:
        raise fail("SS020", "dataset split cannot be empty", path=path.name)
    return records


def _load_csv(path: Path) -> list[Record]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise fail("SS020", "CSV input must be readable UTF-8", path=path.name) from exc
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
        headers = reader.fieldnames
        if not headers or any(not header for header in headers):
            raise fail("SS020", "CSV input must have non-empty headers")
        if len(set(headers)) != len(headers):
            raise fail("SS020", "CSV input contains duplicate headers")
        records: list[Record] = []
        for row_number, row in enumerate(reader, start=2):
            if None in row:
                raise fail("SS020", "CSV row has more fields than its header", row=row_number)
            if any(value is None for value in row.values()):
                raise fail("SS020", "CSV row has fewer fields than its header", row=row_number)
            records.append({key: value for key, value in row.items() if value is not None})
    except csv.Error as exc:
        raise fail("SS020", "malformed CSV input") from exc
    if not records:
        raise fail("SS020", "dataset split cannot be empty", path=path.name)
    return records


def _load_parquet(path: Path) -> list[Record]:
    try:
        parquet = importlib.import_module("pyarrow.parquet")
    except ImportError as exc:
        raise fail(
            "SS022",
            "Parquet support is optional; install splitseal[parquet]",
        ) from exc
    try:
        rows = cast("list[dict[str, Any]]", parquet.read_table(path).to_pylist())
    except Exception as exc:
        raise fail("SS020", "malformed Parquet input", path=path.name) from exc
    if not rows:
        raise fail("SS020", "dataset split cannot be empty", path=path.name)
    return [ensure_record(row, location=f"row {index}") for index, row in enumerate(rows)]


_LOADERS: dict[str, Callable[[Path], list[Record]]] = {
    "jsonl": _load_jsonl,
    "csv": _load_csv,
    "parquet": _load_parquet,
}


def load_records(path: Path, format_name: str) -> list[Record]:
    try:
        loader = _LOADERS[format_name]
    except KeyError as exc:
        raise fail("SS010", "unsupported split format", format=format_name) from exc
    return loader(path)
