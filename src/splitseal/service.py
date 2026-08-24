"""High-level release freeze, verification, and comparison operations."""

from __future__ import annotations

import hmac
import json
import os
import re
import tempfile
import unicodedata
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from splitseal import __version__
from splitseal.canonical import JSONValue, Record, canonicalize, dataset_digest, record_digest
from splitseal.canonical import sequence_digest as ordered_digest
from splitseal.crypto import (
    commitment,
    commitment_file,
    open_seal,
    seal_manifest,
    seal_manifest_file,
)
from splitseal.errors import SplitSealError, fail
from splitseal.loaders import load_records
from splitseal.models import DatasetConfig, load_config
from splitseal.paths import safe_input_path, safe_output_path
from splitseal.plugins import SimilarityPlugin, load_similarity_plugin
from splitseal.streaming import StreamingManifest, build_streaming_manifest

PRIVATE_SCHEMA = "splitseal.private-manifest.v1"
ATTESTATION_SCHEMA = "splitseal.public-attestation.v1"
_PUBLIC_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

PluginLoader = Callable[[str], SimilarityPlugin]


def _json_value(value: Any) -> JSONValue:
    return cast("JSONValue", value)


def _build_manifest(
    config: DatasetConfig,
    root: Path,
    *,
    plugin_loader: PluginLoader = load_similarity_plugin,
) -> dict[str, Any]:
    split_records: dict[str, Sequence[Record]] = {}
    split_manifests: list[dict[str, Any]] = []
    digest_owners: dict[str, str] = {}
    cross_split_duplicates = 0

    for split in sorted(config.splits, key=lambda item: item.name):
        source = safe_input_path(root, split.path)
        records = load_records(source, split.format)
        split_records[split.name] = records
        record_digests: list[str] = []
        for record in records:
            digest = record_digest(record)
            owner = digest_owners.setdefault(digest, split.name)
            if owner != split.name:
                cross_split_duplicates += 1
            record_digests.append(digest)
        split_manifests.append(
            {
                "name": split.name,
                "format": split.format,
                "record_count": len(records),
                "content_digest": ordered_digest(record_digests),
                "record_digests": record_digests,
            }
        )

    if cross_split_duplicates:
        raise fail(
            "SS030",
            "exact duplicate records were found across dataset splits",
            duplicate_count=cross_split_duplicates,
        )

    plugin_evidence: list[dict[str, Any]] = []
    similarity_finding_count = 0
    for plugin_config in config.similarity:
        plugin = plugin_loader(plugin_config.plugin)
        try:
            findings = list(plugin.analyze(split_records, plugin_config.settings))
        except SplitSealError:
            raise
        except Exception as exc:
            raise fail(
                "SS061",
                "similarity plugin execution failed",
                plugin=plugin_config.plugin,
            ) from exc
        similarity_finding_count += len(findings)
        plugin_evidence.append(
            {
                "name": plugin_config.plugin,
                "version": str(plugin.version),
                "status": "pass" if not findings else "fail",
            }
        )
    if similarity_finding_count:
        raise fail(
            "SS062",
            "similarity analysis found cross-split candidates",
            finding_count=similarity_finding_count,
        )

    split_roots = {
        str(item["name"]): (int(item["record_count"]), str(item["content_digest"]))
        for item in split_manifests
    }
    total_records = sum(count for count, _digest in split_roots.values())
    return {
        "schema_version": PRIVATE_SCHEMA,
        "tool": {"name": "splitseal", "version": __version__},
        "release": {"name": config.release.name, "version": config.release.version},
        "canonicalization": {
            "profile": "RFC8785",
            "record_hash": "sha256",
            "sequence_hash": "splitseal-sequence-v1",
            "dataset_hash": "splitseal-dataset-v1",
        },
        "dataset": {
            "content_digest": dataset_digest(split_roots),
            "record_count": total_records,
            "split_count": len(split_manifests),
            "splits": split_manifests,
        },
        "checks": {
            "exact_cross_split_duplicates": "pass",
            "similarity": "pass" if plugin_evidence else "not_run",
            "similarity_plugins": plugin_evidence,
        },
    }


def _manifest_parts(
    manifest: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], list[Any]]:
    if manifest.get("schema_version") != PRIVATE_SCHEMA:
        raise fail("SS043", "private manifest has an unsupported schema")
    release = manifest.get("release")
    dataset = manifest.get("dataset")
    if not isinstance(release, dict) or not isinstance(dataset, dict):
        raise fail("SS043", "private manifest is missing release metadata")
    splits = dataset.get("splits")
    if not isinstance(splits, list):
        raise fail("SS043", "private manifest is missing split metadata")
    return release, dataset, splits


def _public_attestation(manifest: Mapping[str, Any], secret: bytes) -> dict[str, Any]:
    release, dataset, splits = _manifest_parts(manifest)
    split_counts: list[int] = []
    for split in splits:
        if not isinstance(split, dict) or not isinstance(split.get("record_count"), int):
            raise fail("SS043", "private manifest contains malformed split metadata")
        split_counts.append(split["record_count"])
    checks = manifest.get("checks")
    if not isinstance(checks, dict):
        raise fail("SS043", "private manifest is missing check metadata")
    manifest_bytes = canonicalize(_json_value(dict(manifest)))
    return {
        "schema_version": ATTESTATION_SCHEMA,
        "tool": {"name": "splitseal", "version": __version__},
        "release": {
            "name": str(release.get("name", "")),
            "version": str(release.get("version", "")),
        },
        "commitment": {
            "algorithm": "hmac-sha256",
            "value": commitment(manifest_bytes, secret),
        },
        "aggregates": {
            "record_count": int(dataset.get("record_count", -1)),
            "split_count": int(dataset.get("split_count", -1)),
            "split_counts": sorted(split_counts),
        },
        "checks": {
            "exact_cross_split_duplicates": str(checks.get("exact_cross_split_duplicates", "")),
            "similarity": str(checks.get("similarity", "")),
        },
    }


def _write_temp(target: Path, content: bytes, mode: int) -> Path:
    descriptor, raw_path = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary = Path(raw_path)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return temporary


def _reserve_backup(target: Path) -> Path:
    descriptor, raw_path = tempfile.mkstemp(
        prefix=f".{target.name}.backup.",
        dir=target.parent,
    )
    os.close(descriptor)
    return Path(raw_path)


def _output_state(targets: tuple[Path, Path], *, force: bool) -> dict[Path, bool]:
    existing: dict[Path, bool] = {}
    for target in targets:
        target_exists = target.exists()
        existing[target] = target_exists
        if target_exists and not force:
            raise fail(
                "SS004",
                "output already exists; pass --force to replace it",
                path=target.name,
            )
    return existing


def _install_staged_pair(  # noqa: PLR0912
    first: tuple[Path, Path],
    second: tuple[Path, Path],
    *,
    existing: Mapping[Path, bool],
) -> None:
    outputs = (first, second)
    backups: dict[Path, Path] = {}
    installed: set[Path] = set()
    preserve_backups = False
    try:
        for target, _temporary in outputs:
            if existing[target]:
                backup = _reserve_backup(target)
                try:
                    os.replace(target, backup)
                except BaseException:
                    backup.unlink(missing_ok=True)
                    raise
                backups[target] = backup

        for target, temporary in outputs:
            os.replace(temporary, target)
            installed.add(target)
    except BaseException:
        rollback_errors: list[BaseException] = []
        for target, backup in reversed(tuple(backups.items())):
            try:
                os.replace(backup, target)
            except BaseException as exc:
                rollback_errors.append(exc)
        for target in installed - backups.keys():
            try:
                target.unlink(missing_ok=True)
            except BaseException as exc:
                rollback_errors.append(exc)
        if rollback_errors:
            preserve_backups = True
            recovery_files = sorted(backup.name for backup in backups.values() if backup.exists())
            raise fail(
                "SS005",
                "release output rollback failed; recovery backup retained",
                recovery_files=recovery_files,
            ) from rollback_errors[0]
        raise
    finally:
        for _target, temporary in outputs:
            temporary.unlink(missing_ok=True)
        if not preserve_backups:
            for backup in backups.values():
                backup.unlink(missing_ok=True)


def _atomic_write_pair(
    first: tuple[Path, bytes, int],
    second: tuple[Path, bytes, int],
    *,
    force: bool,
) -> None:
    existing = _output_state((first[0], second[0]), force=force)
    first_temp = _write_temp(*first)
    try:
        second_temp = _write_temp(*second)
    except BaseException:
        first_temp.unlink(missing_ok=True)
        raise
    _install_staged_pair(
        (first[0], first_temp),
        (second[0], second_temp),
        existing=existing,
    )


def _streaming_attestation(manifest: StreamingManifest, secret: bytes) -> dict[str, Any]:
    return {
        "schema_version": ATTESTATION_SCHEMA,
        "tool": {"name": "splitseal", "version": __version__},
        "release": {"name": manifest.release_name, "version": manifest.release_version},
        "commitment": {
            "algorithm": "hmac-sha256",
            "value": commitment_file(manifest.path, secret),
        },
        "aggregates": {
            "record_count": manifest.record_count,
            "split_count": manifest.split_count,
            "split_counts": list(manifest.split_counts),
        },
        "checks": {
            "exact_cross_split_duplicates": "pass",
            "similarity": "not_run",
        },
    }


def _freeze_streaming(  # noqa: PLR0913
    *,
    config: DatasetConfig,
    root: Path,
    seal_file: Path,
    attestation_file: Path,
    secret: bytes,
    force: bool,
) -> dict[str, Any]:
    existing = _output_state((seal_file, attestation_file), force=force)
    with build_streaming_manifest(config, root) as manifest:
        attestation = _streaming_attestation(manifest, secret)
        descriptor, raw_seal_temp = tempfile.mkstemp(
            prefix=f".{seal_file.name}.",
            dir=seal_file.parent,
        )
        os.fchmod(descriptor, 0o600)
        os.close(descriptor)
        seal_temp = Path(raw_seal_temp)
        try:
            seal_manifest_file(manifest.path, seal_temp, secret)
            attestation_temp = _write_temp(
                attestation_file,
                canonicalize(_json_value(attestation)) + b"\n",
                0o644,
            )
        except BaseException:
            seal_temp.unlink(missing_ok=True)
            raise
        _install_staged_pair(
            (seal_file, seal_temp),
            (attestation_file, attestation_temp),
            existing=existing,
        )
    return {
        "status": "created",
        "release": attestation["release"],
        "record_count": manifest.record_count,
        "split_count": manifest.split_count,
    }


def freeze_release(  # noqa: PLR0913
    *,
    root: Path,
    config_path: str | Path,
    seal_path: str | Path,
    attestation_path: str | Path,
    secret: bytes,
    force: bool = False,
    plugin_loader: PluginLoader = load_similarity_plugin,
) -> dict[str, Any]:
    """Freeze one configured release into a private seal and public attestation."""

    config_file = safe_input_path(root, config_path)
    seal_file = safe_output_path(root, seal_path)
    attestation_file = safe_output_path(root, attestation_path)
    if seal_file == attestation_file:
        raise fail("SS004", "seal and attestation paths must differ")
    config = load_config(config_file)
    if not config.similarity:
        return _freeze_streaming(
            config=config,
            root=root,
            seal_file=seal_file,
            attestation_file=attestation_file,
            secret=secret,
            force=force,
        )
    manifest = _build_manifest(config, root, plugin_loader=plugin_loader)
    attestation = _public_attestation(manifest, secret)
    seal_bytes = seal_manifest(_json_value(manifest), secret)
    attestation_bytes = canonicalize(_json_value(attestation)) + b"\n"
    _atomic_write_pair(
        (seal_file, seal_bytes, 0o600),
        (attestation_file, attestation_bytes, 0o644),
        force=force,
    )
    aggregates = cast("dict[str, Any]", attestation["aggregates"])
    release = cast("dict[str, Any]", attestation["release"])
    return {
        "status": "created",
        "release": release,
        "record_count": aggregates["record_count"],
        "split_count": aggregates["split_count"],
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise fail("SS044", "artifact JSON contains a duplicate key", key=key)
        result[key] = value
    return result


def _load_json_file(path: Path, description: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except SplitSealError:
        raise
    except (OSError, RecursionError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise fail("SS044", f"{description} is not valid UTF-8 JSON", path=path.name) from exc
    if not isinstance(value, dict):
        raise fail("SS044", f"{description} must be a JSON object", path=path.name)
    try:
        canonical = canonicalize(_json_value(value)) + b"\n"
    except SplitSealError as exc:
        raise fail("SS044", f"{description} contains invalid JSON values", path=path.name) from exc
    if raw != canonical:
        raise fail("SS044", f"{description} is not canonically encoded", path=path.name)
    return value


def _require_public_fields(
    value: Mapping[str, Any],
    expected: set[str],
    context: str,
) -> None:
    actual = set(value)
    extra = sorted(actual - expected)
    if extra:
        raise fail(
            "SS046",
            "public attestation contains disclosure-unsafe or unknown fields",
            context=context,
            fields=extra,
        )
    missing = sorted(expected - actual)
    if missing:
        raise fail(
            "SS045",
            "public attestation is missing required fields",
            context=context,
            fields=missing,
        )


def _public_table(value: object, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise fail("SS045", "public attestation field must be an object", field=context)
    _require_public_fields(value, expected, context)
    return value


def _public_token(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not _PUBLIC_TOKEN.fullmatch(value)
        or unicodedata.normalize("NFC", value) != value
    ):
        raise fail("SS045", "public attestation field has an invalid string value", field=field)
    return value


def _public_count(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise fail("SS045", "public attestation count must be a non-negative integer", field=field)
    return value


def validate_public_attestation(
    *,
    root: Path,
    attestation_path: str | Path,
) -> dict[str, Any]:
    """Validate a public attestation without authenticating it or reading private inputs."""

    attestation_file = safe_input_path(root, attestation_path)
    attestation = _load_json_file(attestation_file, "public attestation")
    _require_public_fields(
        attestation,
        {"schema_version", "tool", "release", "commitment", "aggregates", "checks"},
        "attestation",
    )
    if attestation["schema_version"] != ATTESTATION_SCHEMA:
        raise fail("SS045", "public attestation has an unsupported schema")

    tool = _public_table(attestation["tool"], {"name", "version"}, "tool")
    if tool["name"] != "splitseal":
        raise fail("SS045", "public attestation tool.name must be splitseal")
    _public_token(tool["version"], "tool.version")

    release = _public_table(attestation["release"], {"name", "version"}, "release")
    release_name = _public_token(release["name"], "release.name")
    release_version = _public_token(release["version"], "release.version")

    commitment_data = _public_table(
        attestation["commitment"],
        {"algorithm", "value"},
        "commitment",
    )
    if commitment_data["algorithm"] != "hmac-sha256":
        raise fail("SS045", "public attestation commitment algorithm must be hmac-sha256")
    if not isinstance(commitment_data["value"], str) or not _SHA256_HEX.fullmatch(
        commitment_data["value"]
    ):
        raise fail("SS045", "public attestation commitment must be lowercase SHA-256 hex")

    aggregates = _public_table(
        attestation["aggregates"],
        {"record_count", "split_count", "split_counts"},
        "aggregates",
    )
    record_count = _public_count(aggregates["record_count"], "aggregates.record_count")
    split_count = _public_count(aggregates["split_count"], "aggregates.split_count")
    split_counts_raw = aggregates["split_counts"]
    if not isinstance(split_counts_raw, list):
        raise fail("SS045", "public attestation aggregates.split_counts must be an array")
    split_counts = [
        _public_count(value, f"aggregates.split_counts[{index}]")
        for index, value in enumerate(split_counts_raw)
    ]
    if split_count == 0 or len(split_counts) != split_count:
        raise fail("SS045", "public attestation split counts do not match split_count")
    if split_counts != sorted(split_counts):
        raise fail("SS045", "public attestation split_counts must be sorted")
    if sum(split_counts) != record_count:
        raise fail("SS045", "public attestation split counts do not sum to record_count")

    checks = _public_table(
        attestation["checks"],
        {"exact_cross_split_duplicates", "similarity"},
        "checks",
    )
    if checks["exact_cross_split_duplicates"] != "pass":
        raise fail("SS045", "public attestation exact duplicate check must be pass")
    similarity_status = checks["similarity"]
    if not isinstance(similarity_status, str) or similarity_status not in {"pass", "not_run"}:
        raise fail("SS045", "public attestation similarity check has an invalid status")

    return {
        "status": "pass",
        "validation": "structural",
        "authentication": "not_performed",
        "release": {"name": release_name, "version": release_version},
        "record_count": record_count,
        "split_count": split_count,
        "checks": {
            "schema": "pass",
            "canonical_encoding": "pass",
            "redaction_constraints": "pass",
            "keyed_authentication": "not_performed",
        },
    }


def _open_private_manifest(seal_file: Path, secret: bytes) -> dict[str, JSONValue]:
    container = _load_json_file(seal_file, "sealed manifest")
    return open_seal(container, secret)


def verify_release(  # noqa: PLR0913
    *,
    root: Path,
    seal_path: str | Path,
    attestation_path: str | Path,
    secret: bytes,
    config_path: str | Path | None = None,
    plugin_loader: PluginLoader = load_similarity_plugin,
) -> dict[str, Any]:
    """Authenticate a seal and optionally compare it with current dataset sources."""

    seal_file = safe_input_path(root, seal_path)
    attestation_file = safe_input_path(root, attestation_path)
    manifest = _open_private_manifest(seal_file, secret)
    attestation = _load_json_file(attestation_file, "public attestation")
    expected = _public_attestation(manifest, secret)
    if not hmac.compare_digest(
        canonicalize(_json_value(attestation)),
        canonicalize(_json_value(expected)),
    ):
        raise fail("SS050", "public attestation does not match the private manifest")

    source_check = "not_run"
    if config_path is not None:
        config_file = safe_input_path(root, config_path)
        current = _build_manifest(load_config(config_file), root, plugin_loader=plugin_loader)
        if canonicalize(_json_value(current)) != canonicalize(_json_value(manifest)):
            raise fail("SS051", "dataset sources do not match the frozen private manifest")
        source_check = "pass"

    _release, dataset, _splits = _manifest_parts(manifest)
    return {
        "status": "pass",
        "record_count": int(dataset["record_count"]),
        "split_count": int(dataset["split_count"]),
        "checks": {
            "seal_authentication": "pass",
            "attestation_commitment": "pass",
            "dataset_sources": source_check,
        },
    }


def _split_counters(splits: Sequence[Any]) -> dict[str, Counter[str]]:
    counters: dict[str, Counter[str]] = {}
    for split in splits:
        if not isinstance(split, dict):
            raise fail("SS043", "private manifest contains malformed split metadata")
        name = split.get("name")
        digests = split.get("record_digests")
        if (
            not isinstance(name, str)
            or not isinstance(digests, list)
            or not all(isinstance(item, str) for item in digests)
        ):
            raise fail("SS043", "private manifest contains malformed record digests")
        counters[name] = Counter(digests)
    return counters


def diff_releases(
    *,
    root: Path,
    old_seal_path: str | Path,
    new_seal_path: str | Path,
    old_secret: bytes,
    new_secret: bytes,
) -> dict[str, Any]:
    """Compare two private seals and return aggregate-only differences."""

    old_manifest = _open_private_manifest(safe_input_path(root, old_seal_path), old_secret)
    new_manifest = _open_private_manifest(safe_input_path(root, new_seal_path), new_secret)
    old_release, old_dataset, old_splits_raw = _manifest_parts(old_manifest)
    new_release, new_dataset, new_splits_raw = _manifest_parts(new_manifest)
    old_splits = _split_counters(old_splits_raw)
    new_splits = _split_counters(new_splits_raw)

    added = 0
    removed = 0
    for name in old_splits.keys() | new_splits.keys():
        old_counter = old_splits.get(name, Counter())
        new_counter = new_splits.get(name, Counter())
        added += sum((new_counter - old_counter).values())
        removed += sum((old_counter - new_counter).values())

    unchanged = canonicalize(_json_value(old_manifest)) == canonicalize(_json_value(new_manifest))
    return {
        "status": "pass" if unchanged else "changed",
        "old_release": {
            "name": str(old_release.get("name", "")),
            "version": str(old_release.get("version", "")),
        },
        "new_release": {
            "name": str(new_release.get("name", "")),
            "version": str(new_release.get("version", "")),
        },
        "changes": {
            "records_added": added,
            "records_removed": removed,
            "splits_added": len(new_splits.keys() - old_splits.keys()),
            "splits_removed": len(old_splits.keys() - new_splits.keys()),
            "old_record_count": int(old_dataset["record_count"]),
            "new_record_count": int(new_dataset["record_count"]),
        },
    }


__all__ = [
    "diff_releases",
    "freeze_release",
    "validate_public_attestation",
    "verify_release",
]
