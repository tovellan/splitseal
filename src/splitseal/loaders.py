"""Strict structured-record loaders."""

from __future__ import annotations

import codecs
import csv
import importlib
import json
from collections.abc import Callable, Iterator
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


_SPLITLINE_SEPARATORS = frozenset(
    {"\n", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"}
)
_PARQUET_BATCH_SIZE = 1024


def _iter_text_lines(path: Path, encoding: str) -> Iterator[str]:  # noqa: PLR0912
    decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
    line: list[str] = []
    pending_cr = False
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(64 * 1024):
                text = decoder.decode(chunk)
                for character in text:
                    if pending_cr:
                        yield "".join(line)
                        line = []
                        pending_cr = False
                        if character == "\n":
                            continue
                    if character == "\r":
                        pending_cr = True
                    elif character in _SPLITLINE_SEPARATORS:
                        yield "".join(line)
                        line = []
                    else:
                        line.append(character)
            for character in decoder.decode(b"", final=True):
                if pending_cr:
                    yield "".join(line)
                    line = []
                    pending_cr = False
                    if character == "\n":
                        continue
                if character == "\r":
                    pending_cr = True
                elif character in _SPLITLINE_SEPARATORS:
                    yield "".join(line)
                    line = []
                else:
                    line.append(character)
    except (OSError, UnicodeDecodeError) as exc:
        raise fail(
            "SS020", "structured input must be readable Unicode text", path=path.name
        ) from exc
    if pending_cr or line:
        yield "".join(line)


def _iter_jsonl(path: Path) -> Iterator[Record]:
    found = False
    for line_number, line in enumerate(_iter_text_lines(path, "utf-8"), start=1):
        found = True
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
        yield ensure_record(value, location=f"line {line_number}")
    if not found:
        raise fail("SS020", "dataset split cannot be empty", path=path.name)


def _load_jsonl(path: Path) -> list[Record]:
    return list(_iter_jsonl(path))


def _iter_csv(path: Path) -> Iterator[Record]:
    try:
        with path.open("r", encoding="utf-8-sig") as stream:
            reader = csv.DictReader(stream, strict=True)
            headers = reader.fieldnames
            if not headers or any(not header for header in headers):
                raise fail("SS020", "CSV input must have non-empty headers")
            if len(set(headers)) != len(headers):
                raise fail("SS020", "CSV input contains duplicate headers")
            found = False
            for row_number, row in enumerate(reader, start=2):
                found = True
                if None in row:
                    raise fail("SS020", "CSV row has more fields than its header", row=row_number)
                if any(value is None for value in row.values()):
                    raise fail("SS020", "CSV row has fewer fields than its header", row=row_number)
                yield {key: value for key, value in row.items() if value is not None}
    except (OSError, UnicodeDecodeError) as exc:
        raise fail("SS020", "CSV input must be readable UTF-8", path=path.name) from exc
    except csv.Error as exc:
        raise fail("SS020", "malformed CSV input") from exc
    if not found:
        raise fail("SS020", "dataset split cannot be empty", path=path.name)


def _load_csv(path: Path) -> list[Record]:
    return list(_iter_csv(path))


def _iter_parquet(path: Path) -> Iterator[Record]:
    try:
        parquet = importlib.import_module("pyarrow.parquet")
    except ImportError as exc:
        raise fail(
            "SS022",
            "Parquet support is optional; install splitseal[parquet]",
        ) from exc
    try:
        parquet_file = parquet.ParquetFile(path)
        found = False
        row_index = 0
        for batch in parquet_file.iter_batches(batch_size=_PARQUET_BATCH_SIZE):
            rows = cast("list[dict[str, Any]]", batch.to_pylist())
            for row in rows:
                found = True
                yield ensure_record(row, location=f"row {row_index}")
                row_index += 1
    except SplitSealError:
        raise
    except Exception as exc:
        raise fail("SS020", "malformed Parquet input", path=path.name) from exc
    if not found:
        raise fail("SS020", "dataset split cannot be empty", path=path.name)


def _load_parquet(path: Path) -> list[Record]:
    return list(_iter_parquet(path))


_LOADERS: dict[str, Callable[[Path], list[Record]]] = {
    "jsonl": _load_jsonl,
    "csv": _load_csv,
    "parquet": _load_parquet,
}

_ITERATORS: dict[str, Callable[[Path], Iterator[Record]]] = {
    "jsonl": _iter_jsonl,
    "csv": _iter_csv,
    "parquet": _iter_parquet,
}


def load_records(path: Path, format_name: str) -> list[Record]:
    try:
        loader = _LOADERS[format_name]
    except KeyError as exc:
        raise fail("SS010", "unsupported split format", format=format_name) from exc
    return loader(path)


def iter_records(path: Path, format_name: str) -> Iterator[Record]:
    """Yield strict structured records without retaining the full split in memory."""

    try:
        iterator = _ITERATORS[format_name]
    except KeyError as exc:
        raise fail("SS010", "unsupported split format", format=format_name) from exc
    yield from iterator(path)
