"""Canonical serialization and domain-separated digests."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping, Sequence
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


def sequence_digest(record_digests: Sequence[str]) -> str:
    """Hash an ordered sequence of hexadecimal record digests."""

    digest = hashlib.sha256(_SEQUENCE_DOMAIN)
    for item in record_digests:
        try:
            raw = bytes.fromhex(item)
        except ValueError as exc:
            raise fail("SS012", "record digest is not hexadecimal") from exc
        if len(raw) != hashlib.sha256().digest_size:
            raise fail("SS012", "record digest has an invalid length")
        digest.update(_framed(raw))
    return digest.hexdigest()


def dataset_digest(splits: Mapping[str, tuple[int, str]]) -> str:
    """Hash named split roots and counts in split-name order."""

    digest = hashlib.sha256(_DATASET_DOMAIN)
    for name in sorted(splits):
        count, split_digest = splits[name]
        if count < 0:
            raise fail("SS012", "record count cannot be negative", split=name)
        try:
            raw_digest = bytes.fromhex(split_digest)
        except ValueError as exc:
            raise fail("SS012", "split digest is not hexadecimal", split=name) from exc
        if len(raw_digest) != hashlib.sha256().digest_size:
            raise fail("SS012", "split digest has an invalid length", split=name)
        encoded_name = name.encode("utf-8")
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
