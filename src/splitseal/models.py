"""Configuration and result models."""

from __future__ import annotations

import re
import tomllib
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from splitseal.errors import fail

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_FORMATS = frozenset({"jsonl", "csv", "parquet"})


@dataclass(frozen=True)
class ReleaseConfig:
    name: str
    version: str


@dataclass(frozen=True)
class SplitConfig:
    name: str
    path: str
    format: str


@dataclass(frozen=True)
class SimilarityConfig:
    plugin: str
    settings: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DatasetConfig:
    release: ReleaseConfig
    splits: tuple[SplitConfig, ...]
    similarity: tuple[SimilarityConfig, ...] = ()


def _table(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise fail("SS010", f"{name} must be a TOML table")
    return value


def _required_string(table: Mapping[str, Any], key: str, context: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        raise fail("SS010", f"{context}.{key} must be a non-empty string")
    if unicodedata.normalize("NFC", value) != value:
        raise fail("SS010", f"{context}.{key} must use Unicode NFC normalization")
    return value


def _validate_name(value: str, context: str) -> None:
    if not _NAME.fullmatch(value):
        raise fail("SS010", f"{context} contains unsupported characters", value=value)


def parse_config_bytes(data: bytes) -> DatasetConfig:
    try:
        raw = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise fail("SS010", "configuration is not valid UTF-8 TOML") from exc
    if raw.get("schema_version") != "splitseal.config.v1":
        raise fail("SS010", "configuration schema_version must be splitseal.config.v1")
    release_raw = _table(raw.get("release"), "release")
    release = ReleaseConfig(
        name=_required_string(release_raw, "name", "release"),
        version=_required_string(release_raw, "version", "release"),
    )
    _validate_name(release.name, "release.name")
    _validate_name(release.version, "release.version")

    splits_raw = raw.get("splits")
    if not isinstance(splits_raw, list) or not splits_raw:
        raise fail("SS010", "configuration must contain at least one [[splits]] table")
    splits: list[SplitConfig] = []
    names: set[str] = set()
    for index, value in enumerate(splits_raw):
        table = _table(value, f"splits[{index}]")
        name = _required_string(table, "name", f"splits[{index}]")
        _validate_name(name, f"splits[{index}].name")
        if name in names:
            raise fail("SS010", "split names must be unique", split=name)
        names.add(name)
        format_name = _required_string(table, "format", f"splits[{index}]").lower()
        if format_name not in _FORMATS:
            raise fail("SS010", "unsupported split format", format=format_name)
        splits.append(
            SplitConfig(
                name=name,
                path=_required_string(table, "path", f"splits[{index}]"),
                format=format_name,
            )
        )

    similarity_raw = raw.get("similarity", [])
    if not isinstance(similarity_raw, list):
        raise fail("SS010", "similarity must be an array of tables")
    similarity: list[SimilarityConfig] = []
    plugin_names: set[str] = set()
    for index, value in enumerate(similarity_raw):
        table = _table(value, f"similarity[{index}]")
        plugin = _required_string(table, "plugin", f"similarity[{index}]")
        _validate_name(plugin, f"similarity[{index}].plugin")
        if plugin in plugin_names:
            raise fail("SS010", "similarity plugin names must be unique", plugin=plugin)
        plugin_names.add(plugin)
        settings = table.get("settings", {})
        if not isinstance(settings, dict):
            raise fail("SS010", "similarity plugin settings must be a TOML table", plugin=plugin)
        similarity.append(SimilarityConfig(plugin=plugin, settings=settings))

    return DatasetConfig(release=release, splits=tuple(splits), similarity=tuple(similarity))


def load_config(path: Path) -> DatasetConfig:
    try:
        return parse_config_bytes(path.read_bytes())
    except OSError as exc:
        raise fail("SS001", "configuration could not be read", path=str(path)) from exc
