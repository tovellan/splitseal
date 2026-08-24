"""Disk-spooled exact-only manifest construction."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, cast

from splitseal import __version__
from splitseal.canonical import JSONValue, canonicalize, dataset_digest, record_digest
from splitseal.canonical import sequence_digest as ordered_digest
from splitseal.errors import fail
from splitseal.loaders import iter_records
from splitseal.models import DatasetConfig
from splitseal.paths import safe_input_path

_SQLITE_CACHE_KIB = 2048


@dataclass(frozen=True)
class StreamingManifest:
    path: Path
    release_name: str
    release_version: str
    record_count: int
    split_count: int
    split_counts: tuple[int, ...]


@dataclass(frozen=True)
class _SplitSpool:
    name: str
    format: str
    record_count: int
    content_digest: str
    digests_path: Path


def _configure_digest_database(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA journal_mode=OFF")
    connection.execute("PRAGMA synchronous=OFF")
    connection.execute("PRAGMA temp_store=FILE")
    connection.execute(f"PRAGMA cache_size=-{_SQLITE_CACHE_KIB}")
    connection.execute(
        "CREATE TABLE digests (digest TEXT PRIMARY KEY, owner TEXT NOT NULL) WITHOUT ROWID"
    )


def _digest_lines(path: Path) -> Iterator[str]:
    with path.open("r", encoding="ascii") as stream:
        for line in stream:
            yield line.removesuffix("\n")


def _spool_splits(config: DatasetConfig, root: Path, directory: Path) -> list[_SplitSpool]:
    database_path = directory / "digest-owners.sqlite3"
    connection = sqlite3.connect(database_path)
    duplicate_count = 0
    spools: list[_SplitSpool] = []
    try:
        _configure_digest_database(connection)
        for index, split in enumerate(sorted(config.splits, key=lambda item: item.name)):
            source = safe_input_path(root, split.path)
            digests_path = directory / f"split-{index}.digests"
            record_count = 0
            with digests_path.open("w", encoding="ascii", newline="\n") as digests:
                for record in iter_records(source, split.format):
                    digest = record_digest(record)
                    cursor = connection.execute(
                        "INSERT OR IGNORE INTO digests (digest, owner) VALUES (?, ?)",
                        (digest, split.name),
                    )
                    if cursor.rowcount == 0:
                        owner_row = connection.execute(
                            "SELECT owner FROM digests WHERE digest = ?",
                            (digest,),
                        ).fetchone()
                        if owner_row is not None and owner_row[0] != split.name:
                            duplicate_count += 1
                    digests.write(digest + "\n")
                    record_count += 1
            spools.append(
                _SplitSpool(
                    name=split.name,
                    format=split.format,
                    record_count=record_count,
                    content_digest=ordered_digest(_digest_lines(digests_path)),
                    digests_path=digests_path,
                )
            )
    finally:
        connection.close()
    if duplicate_count:
        raise fail(
            "SS030",
            "exact duplicate records were found across dataset splits",
            duplicate_count=duplicate_count,
        )
    return spools


def _write_json_value(stream: BinaryIO, value: JSONValue) -> None:
    stream.write(canonicalize(value))


def _write_split(stream: BinaryIO, split: _SplitSpool) -> None:
    stream.write(b'{"content_digest":')
    _write_json_value(stream, split.content_digest)
    stream.write(b',"format":')
    _write_json_value(stream, split.format)
    stream.write(b',"name":')
    _write_json_value(stream, split.name)
    stream.write(b',"record_count":')
    _write_json_value(stream, split.record_count)
    stream.write(b',"record_digests":[')
    first = True
    for digest in _digest_lines(split.digests_path):
        if not first:
            stream.write(b",")
        _write_json_value(stream, digest)
        first = False
    stream.write(b"]}")


def _write_manifest(
    path: Path,
    config: DatasetConfig,
    spools: list[_SplitSpool],
) -> None:
    split_roots = {split.name: (split.record_count, split.content_digest) for split in spools}
    record_count = sum(split.record_count for split in spools)
    canonicalization = cast(
        "JSONValue",
        {
            "profile": "RFC8785",
            "record_hash": "sha256",
            "sequence_hash": "splitseal-sequence-v1",
            "dataset_hash": "splitseal-dataset-v1",
        },
    )
    checks = cast(
        "JSONValue",
        {
            "exact_cross_split_duplicates": "pass",
            "similarity": "not_run",
            "similarity_plugins": [],
        },
    )
    with path.open("wb") as stream:
        stream.write(b'{"canonicalization":')
        _write_json_value(stream, canonicalization)
        stream.write(b',"checks":')
        _write_json_value(stream, checks)
        stream.write(b',"dataset":{"content_digest":')
        _write_json_value(stream, dataset_digest(split_roots))
        stream.write(b',"record_count":')
        _write_json_value(stream, record_count)
        stream.write(b',"split_count":')
        _write_json_value(stream, len(spools))
        stream.write(b',"splits":[')
        for index, split in enumerate(spools):
            if index:
                stream.write(b",")
            _write_split(stream, split)
        stream.write(b']},"release":')
        _write_json_value(
            stream,
            cast(
                "JSONValue",
                {"name": config.release.name, "version": config.release.version},
            ),
        )
        stream.write(b',"schema_version":"splitseal.private-manifest.v1","tool":')
        _write_json_value(
            stream,
            cast("JSONValue", {"name": "splitseal", "version": __version__}),
        )
        stream.write(b"}")
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o600)


@contextmanager
def build_streaming_manifest(
    config: DatasetConfig,
    root: Path,
) -> Iterator[StreamingManifest]:
    """Build an exact-only canonical manifest using bounded Python memory and temp disk."""

    if config.similarity:
        raise ValueError("streaming manifests do not accept similarity plugins")
    with tempfile.TemporaryDirectory(prefix="splitseal-streaming-") as raw_directory:
        directory = Path(raw_directory)
        spools = _spool_splits(config, root, directory)
        manifest_path = directory / "private-manifest.json"
        _write_manifest(manifest_path, config, spools)
        yield StreamingManifest(
            path=manifest_path,
            release_name=config.release.name,
            release_version=config.release.version,
            record_count=sum(split.record_count for split in spools),
            split_count=len(spools),
            split_counts=tuple(sorted(split.record_count for split in spools)),
        )


__all__ = ["StreamingManifest", "build_streaming_manifest"]
