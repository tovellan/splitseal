"""Canonical serialization and domain-separated digests."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Iterable, Mapping
from typing import TypeAlias, cast

import rfc8785

from splitseal.errors import SplitSealError, fail

JSONScalar: TypeAlias = bool | int | float | str | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]
Record: TypeAlias = dict[str, JSONValue]

_RECORD_DOMAIN = b"splitseal-record-v1\x00"
_SEQUENCE_DOMAIN = b"splitseal-sequence-v1\x00"
_DATASET_DOMAIN = b"splitseal-dataset-v1\x00"
_MAX_INTEROPERABLE_INTEGER = 9_007_199_254_740_991
_MAX_NESTING_DEPTH = 100
_MAX_RECORD_COUNT = 2**64 - 1
_SPLIT_DIGEST_ENTRY_SIZE = 2
_SHA256_HEX = re.compile(r"[0-9A-Fa-f]{64}")


def _validate_json(value: object, location: str = "$", depth: int = 0) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if abs(value) > _MAX_INTEROPERABLE_INTEGER:
            raise fail(
                "SS011",
                "integer is outside the interoperable JSON range",
                location=location,
            )
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise fail("SS011", "non-finite numbers are not canonical JSON", location=location)
        return
    if isinstance(value, list):
        if depth >= _MAX_NESTING_DEPTH:
            raise fail(
                "SS011",
                "structured value exceeds the maximum nesting depth",
                location=location,
                maximum_depth=_MAX_NESTING_DEPTH,
            )
        for index, item in enumerate(value):
            _validate_json(item, f"{location}[{index}]", depth + 1)
        return
    if isinstance(value, Mapping):
        if depth >= _MAX_NESTING_DEPTH:
            raise fail(
                "SS011",
                "structured value exceeds the maximum nesting depth",
                location=location,
                maximum_depth=_MAX_NESTING_DEPTH,
            )
        for key, item in value.items():
            if not isinstance(key, str):
                raise fail("SS011", "JSON object keys must be strings", location=location)
            _validate_json(item, f"{location}.{key}", depth + 1)
        return
    raise fail("SS011", "unsupported value in structured record", location=location)


def canonicalize(value: JSONValue) -> bytes:
    """Return RFC 8785 canonical JSON bytes after strict input validation."""

    try:
        _validate_json(value)
    except RecursionError as exc:
        raise fail("SS011", "structured value exceeds the maximum nesting depth") from exc
    try:
        return rfc8785.dumps(value)
    except (RecursionError, rfc8785.CanonicalizationError, UnicodeError) as exc:
        raise fail("SS011", "value cannot be encoded as canonical JSON") from exc


def _framed(data: bytes) -> bytes:
    return len(data).to_bytes(8, "big") + data


def record_digest(record: Record) -> str:
    """Hash one structured record with an explicit domain and byte length."""

    payload = canonicalize(record)
    return hashlib.sha256(_RECORD_DOMAIN + _framed(payload)).hexdigest()


def sequence_digest(record_digests: Iterable[str]) -> str:
    """Hash an ordered sequence of hexadecimal record digests."""

    if isinstance(record_digests, (str, bytes, bytearray)) or not isinstance(
        record_digests, Iterable
    ):
        raise fail("SS012", "record digests must be an iterable of strings")
    digest = hashlib.sha256(_SEQUENCE_DOMAIN)
    for item in record_digests:
        if not isinstance(item, str):
            raise fail("SS012", "record digest must be a string")
        if not _SHA256_HEX.fullmatch(item):
            raise fail("SS012", "record digest must contain exactly 64 hexadecimal characters")
        raw = bytes.fromhex(item)
        digest.update(_framed(raw))
    return digest.hexdigest()


def dataset_digest(splits: Mapping[str, tuple[int, str]]) -> str:
    """Hash named split roots and counts in split-name order."""

    if not isinstance(splits, Mapping):
        raise fail("SS012", "dataset splits must be a mapping")
    validated: list[tuple[str, int, str]] = []
    for name, value in splits.items():
        if not isinstance(name, str):
            raise fail("SS012", "split names must be strings")
        if not isinstance(value, tuple) or len(value) != _SPLIT_DIGEST_ENTRY_SIZE:
            raise fail("SS012", "split digest entry must be a count and digest pair", split=name)
        count, split_digest = value
        if type(count) is not int or count < 0 or count > _MAX_RECORD_COUNT:
            raise fail(
                "SS012",
                "record count must be an unsigned 64-bit integer",
                split=name,
            )
        if not isinstance(split_digest, str):
            raise fail("SS012", "split digest must be a string", split=name)
        validated.append((name, count, split_digest))

    digest = hashlib.sha256(_DATASET_DOMAIN)
    for name, count, split_digest in sorted(validated, key=lambda item: item[0]):
        if not _SHA256_HEX.fullmatch(split_digest):
            raise fail(
                "SS012",
                "split digest must contain exactly 64 hexadecimal characters",
                split=name,
            )
        raw_digest = bytes.fromhex(split_digest)
        try:
            encoded_name = name.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise fail("SS012", "split name is not valid UTF-8") from exc
        digest.update(_framed(encoded_name))
        digest.update(count.to_bytes(8, "big"))
        digest.update(_framed(raw_digest))
    return digest.hexdigest()


def ensure_record(value: object, *, location: str) -> Record:
    if not isinstance(value, dict):
        raise fail("SS021", "each dataset record must be a JSON object", location=location)
    _validate_json(value, location)
    return cast("Record", value)


__all__ = [
    "JSONValue",
    "Record",
    "SplitSealError",
    "canonicalize",
    "dataset_digest",
    "ensure_record",
    "record_digest",
    "sequence_digest",
]
