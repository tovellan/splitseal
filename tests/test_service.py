from __future__ import annotations

import json
import stat
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

import splitseal.service as service_module
from splitseal.canonical import Record, canonicalize
from splitseal.errors import SplitSealError
from splitseal.plugins import SimilarityFinding
from splitseal.service import (
    diff_releases,
    freeze_release,
    validate_public_attestation,
    verify_release,
)

from .conftest import OTHER_SECRET, SECRET, write_config, write_jsonl


def freeze(project: Path, *, prefix: str = "release", secret: bytes = SECRET) -> dict[str, Any]:
    return freeze_release(
        root=project,
        config_path="splitseal.toml",
        seal_path=f"artifacts/{prefix}.sseal",
        attestation_path=f"artifacts/{prefix}.attestation.json",
        secret=secret,
    )


def test_freeze_and_verify_current_sources(project: Path) -> None:
    created = freeze(project)
    assert created == {
        "status": "created",
        "release": {"name": "synthetic-eval", "version": "1.0.0"},
        "record_count": 4,
        "split_count": 2,
    }
    verified = verify_release(
        root=project,
        seal_path="artifacts/release.sseal",
        attestation_path="artifacts/release.attestation.json",
        config_path="splitseal.toml",
        secret=SECRET,
    )
    assert verified["status"] == "pass"
    assert verified["checks"]["dataset_sources"] == "pass"
    mode = stat.S_IMODE((project / "artifacts" / "release.sseal").stat().st_mode)
    assert mode == 0o600


def test_public_and_private_outer_outputs_do_not_contain_records_or_membership(
    project: Path,
) -> None:
    freeze(project)
    attestation_bytes = (project / "artifacts" / "release.attestation.json").read_bytes()
    seal_bytes = (project / "artifacts" / "release.sseal").read_bytes()
    for forbidden in (
        b"private-901",
        b"Confidential synthetic gamma",
        b"private-evaluation",
        b"development",
        b"record_digests",
        b"content_digest",
    ):
        assert forbidden not in attestation_bytes
        assert forbidden not in seal_bytes
    attestation = json.loads(attestation_bytes)
    assert attestation["aggregates"] == {
        "record_count": 4,
        "split_count": 2,
        "split_counts": [2, 2],
    }


def test_same_sources_and_key_produce_same_attestation_but_random_seal(project: Path) -> None:
    freeze(project, prefix="first")
    freeze(project, prefix="second")
    first_attestation = (project / "artifacts" / "first.attestation.json").read_bytes()
    second_attestation = (project / "artifacts" / "second.attestation.json").read_bytes()
    assert first_attestation == second_attestation
    assert (project / "artifacts" / "first.sseal").read_bytes() != (
        project / "artifacts" / "second.sseal"
    ).read_bytes()


def test_validate_public_attestation_is_structural_only(project: Path) -> None:
    freeze(project)
    report = validate_public_attestation(
        root=project,
        attestation_path="artifacts/release.attestation.json",
    )
    assert report == {
        "status": "pass",
        "validation": "structural",
        "authentication": "not_performed",
        "release": {"name": "synthetic-eval", "version": "1.0.0"},
        "record_count": 4,
        "split_count": 2,
        "checks": {
            "schema": "pass",
            "canonical_encoding": "pass",
            "redaction_constraints": "pass",
            "keyed_authentication": "not_performed",
        },
    }


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda value: value.update({"record_digests": ["private"]}), "SS046"),
        (lambda value: value.pop("checks"), "SS045"),
        (lambda value: value.update({"schema_version": "unknown"}), "SS045"),
        (lambda value: value.update({"tool": []}), "SS045"),
        (lambda value: value["tool"].update({"name": "other"}), "SS045"),
        (lambda value: value["release"].update({"name": "has space"}), "SS045"),
        (lambda value: value["aggregates"].update({"record_count": True}), "SS045"),
        (lambda value: value["aggregates"].update({"split_counts": [3, 1]}), "SS045"),
        (lambda value: value["aggregates"].update({"split_counts": [1, 2]}), "SS045"),
        (lambda value: value["aggregates"].update({"split_count": 0}), "SS045"),
        (lambda value: value["commitment"].update({"algorithm": "sha256"}), "SS045"),
        (lambda value: value["commitment"].update({"value": "A" * 64}), "SS045"),
        (
            lambda value: value["checks"].update({"exact_cross_split_duplicates": "fail"}),
            "SS045",
        ),
        (lambda value: value["checks"].update({"similarity": "unknown"}), "SS045"),
    ],
)
def test_validate_public_attestation_rejects_unsafe_or_malformed_fields(
    project: Path,
    mutation: Any,
    code: str,
) -> None:
    freeze(project)
    path = project / "artifacts" / "release.attestation.json"
    value = json.loads(path.read_bytes())
    mutation(value)
    path.write_bytes(canonicalize(value) + b"\n")
    with pytest.raises(SplitSealError) as caught:
        validate_public_attestation(
            root=project, attestation_path="artifacts/release.attestation.json"
        )
    assert caught.value.code == code


def test_validate_public_attestation_rejects_noncanonical_json(project: Path) -> None:
    freeze(project)
    path = project / "artifacts" / "release.attestation.json"
    path.write_text(json.dumps(json.loads(path.read_bytes()), indent=2) + "\n", encoding="utf-8")
    with pytest.raises(SplitSealError) as caught:
        validate_public_attestation(
            root=project, attestation_path="artifacts/release.attestation.json"
        )
    assert caught.value.code == "SS044"


def test_duplicate_record_across_splits_blocks_outputs(project: Path) -> None:
    duplicate = '{"id":"dev-001","text":"Synthetic alpha","label":1}'
    write_jsonl(project / "data" / "private.jsonl", [duplicate])
    with pytest.raises(SplitSealError) as caught:
        freeze(project)
    assert caught.value.code == "SS030"
    assert not (project / "artifacts" / "release.sseal").exists()
    assert not (project / "artifacts" / "release.attestation.json").exists()


def test_duplicate_within_one_split_is_not_a_cross_split_failure(project: Path) -> None:
    record = '{"id":"dev-001","text":"Synthetic alpha","label":1}'
    write_jsonl(project / "data" / "development.jsonl", [record, record])
    assert freeze(project)["status"] == "created"


def test_verify_detects_attestation_and_source_tampering(project: Path) -> None:
    freeze(project)
    attestation_path = project / "artifacts" / "release.attestation.json"
    attestation = json.loads(attestation_path.read_bytes())
    attestation["aggregates"]["record_count"] = 900
    attestation_path.write_bytes(canonicalize(attestation) + b"\n")
    with pytest.raises(SplitSealError) as attestation_error:
        verify_release(
            root=project,
            seal_path="artifacts/release.sseal",
            attestation_path="artifacts/release.attestation.json",
            secret=SECRET,
        )
    assert attestation_error.value.code == "SS050"

    freeze_release(
        root=project,
        config_path="splitseal.toml",
        seal_path="artifacts/release.sseal",
        attestation_path="artifacts/release.attestation.json",
        secret=SECRET,
        force=True,
    )
    write_jsonl(
        project / "data" / "private.jsonl",
        ['{"id":"new","text":"changed","label":9}'],
    )
    with pytest.raises(SplitSealError) as source_error:
        verify_release(
            root=project,
            seal_path="artifacts/release.sseal",
            attestation_path="artifacts/release.attestation.json",
            config_path="splitseal.toml",
            secret=SECRET,
        )
    assert source_error.value.code == "SS051"


def test_verify_rejects_noncanonical_and_duplicate_key_artifacts(project: Path) -> None:
    freeze(project)
    attestation_path = project / "artifacts" / "release.attestation.json"
    attestation = json.loads(attestation_path.read_bytes())
    attestation_path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(SplitSealError) as noncanonical:
        verify_release(
            root=project,
            seal_path="artifacts/release.sseal",
            attestation_path="artifacts/release.attestation.json",
            secret=SECRET,
        )
    assert noncanonical.value.code == "SS044"

    attestation_path.write_text(
        '{"schema_version":"x","schema_version":"y"}\n',
        encoding="utf-8",
    )
    with pytest.raises(SplitSealError, match="duplicate") as duplicate:
        verify_release(
            root=project,
            seal_path="artifacts/release.sseal",
            attestation_path="artifacts/release.attestation.json",
            secret=SECRET,
        )
    assert duplicate.value.code == "SS044"


def test_freeze_refuses_overwrite_and_equal_output_paths(project: Path) -> None:
    freeze(project)
    with pytest.raises(SplitSealError) as overwrite:
        freeze(project)
    assert overwrite.value.code == "SS004"
    with pytest.raises(SplitSealError) as equal:
        freeze_release(
            root=project,
            config_path="splitseal.toml",
            seal_path="artifacts/same",
            attestation_path="artifacts/same",
            secret=SECRET,
        )
    assert equal.value.code == "SS004"


def test_initial_write_failure_removes_partial_output(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attestation_path = project / "artifacts" / "release.attestation.json"
    real_replace = service_module.os.replace
    failed = False

    def fail_attestation_once(source: str | Path, target: str | Path) -> None:
        nonlocal failed
        if not failed and Path(target) == attestation_path:
            failed = True
            raise OSError("synthetic attestation write failure")
        real_replace(source, target)

    monkeypatch.setattr(service_module.os, "replace", fail_attestation_once)
    with pytest.raises(OSError, match="synthetic attestation write failure"):
        freeze(project)

    assert not (project / "artifacts" / "release.sseal").exists()
    assert not attestation_path.exists()


def test_forced_write_failure_restores_previous_output_pair(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    freeze(project)
    seal_path = project / "artifacts" / "release.sseal"
    attestation_path = project / "artifacts" / "release.attestation.json"
    previous_seal = seal_path.read_bytes()
    previous_attestation = attestation_path.read_bytes()
    write_config(project, version="1.1.0")

    real_replace = service_module.os.replace
    failed = False

    def fail_attestation_once(source: str | Path, target: str | Path) -> None:
        nonlocal failed
        if not failed and Path(target) == attestation_path:
            failed = True
            raise OSError("synthetic attestation replacement failure")
        real_replace(source, target)

    monkeypatch.setattr(service_module.os, "replace", fail_attestation_once)
    with pytest.raises(OSError, match="synthetic attestation replacement failure"):
        freeze_release(
            root=project,
            config_path="splitseal.toml",
            seal_path="artifacts/release.sseal",
            attestation_path="artifacts/release.attestation.json",
            secret=SECRET,
            force=True,
        )

    assert seal_path.read_bytes() == previous_seal
    assert attestation_path.read_bytes() == previous_attestation
    assert not tuple((project / "artifacts").glob(".*.backup.*"))


def test_rollback_failure_preserves_recovery_backup(
    project: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    freeze(project)
    seal_path = project / "artifacts" / "release.sseal"
    attestation_path = project / "artifacts" / "release.attestation.json"
    previous_seal = seal_path.read_bytes()

    real_replace = service_module.os.replace
    write_failed = False

    def fail_write_and_rollback(source: str | Path, target: str | Path) -> None:
        nonlocal write_failed
        source_path = Path(source)
        target_path = Path(target)
        if not write_failed and target_path == attestation_path:
            write_failed = True
            raise OSError("synthetic attestation replacement failure")
        if write_failed and target_path == seal_path and ".backup." in source_path.name:
            raise OSError("synthetic rollback failure")
        real_replace(source, target)

    monkeypatch.setattr(service_module.os, "replace", fail_write_and_rollback)
    with pytest.raises(SplitSealError, match="release output rollback failed") as caught:
        freeze_release(
            root=project,
            config_path="splitseal.toml",
            seal_path="artifacts/release.sseal",
            attestation_path="artifacts/release.attestation.json",
            secret=SECRET,
            force=True,
        )

    assert caught.value.code == "SS005"
    backups = tuple((project / "artifacts").glob(".release.sseal.backup.*"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == previous_seal
    assert caught.value.details == {"recovery_files": [backups[0].name]}


class PassingPlugin:
    name = "synthetic-plugin"
    version = "1.2.3"

    def analyze(
        self,
        splits: Mapping[str, Sequence[Record]],
        settings: Mapping[str, Any],
    ) -> Iterable[SimilarityFinding]:
        assert len(splits) == 2
        assert settings == {"operating_point": "strict"}
        return []


class FindingPlugin(PassingPlugin):
    def analyze(
        self,
        splits: Mapping[str, Sequence[Record]],
        settings: Mapping[str, Any],
    ) -> Iterable[SimilarityFinding]:
        return [SimilarityFinding("development", 0, "private-evaluation", 0, 0.99)]


def test_similarity_plugin_pass_and_failure(project: Path) -> None:
    similarity = """
[[similarity]]
plugin = "synthetic-plugin"
[similarity.settings]
operating_point = "strict"
"""
    write_config(project, similarity=similarity)
    freeze_release(
        root=project,
        config_path="splitseal.toml",
        seal_path="artifacts/pass.sseal",
        attestation_path="artifacts/pass.json",
        secret=SECRET,
        plugin_loader=lambda _name: PassingPlugin(),
    )
    attestation = json.loads((project / "artifacts" / "pass.json").read_bytes())
    assert attestation["checks"]["similarity"] == "pass"
    assert b"synthetic-plugin" not in (project / "artifacts" / "pass.json").read_bytes()

    with pytest.raises(SplitSealError) as caught:
        freeze_release(
            root=project,
            config_path="splitseal.toml",
            seal_path="artifacts/fail.sseal",
            attestation_path="artifacts/fail.json",
            secret=SECRET,
            plugin_loader=lambda _name: FindingPlugin(),
        )
    assert caught.value.code == "SS062"


def test_similarity_plugin_exception_is_wrapped(project: Path) -> None:
    write_config(project, similarity='\n[[similarity]]\nplugin="broken"\n')

    class BrokenPlugin(PassingPlugin):
        def analyze(
            self,
            splits: Mapping[str, Sequence[Record]],
            settings: Mapping[str, Any],
        ) -> Iterable[SimilarityFinding]:
            raise RuntimeError("synthetic failure")

    with pytest.raises(SplitSealError) as caught:
        freeze_release(
            root=project,
            config_path="splitseal.toml",
            seal_path="artifacts/fail.sseal",
            attestation_path="artifacts/fail.json",
            secret=SECRET,
            plugin_loader=lambda _name: BrokenPlugin(),
        )
    assert caught.value.code == "SS061"


def test_similarity_plugin_loader_and_evidence_exceptions_are_wrapped(project: Path) -> None:
    write_config(project, similarity='\n[[similarity]]\nplugin="broken"\n')

    class BrokenVersionPlugin(PassingPlugin):
        @property
        def version(self) -> str:
            raise RuntimeError("synthetic version failure")

    def broken_loader(_name: str) -> PassingPlugin:
        raise RuntimeError("synthetic loader failure")

    for loader in (broken_loader, lambda _name: BrokenVersionPlugin()):
        with pytest.raises(SplitSealError) as caught:
            freeze_release(
                root=project,
                config_path="splitseal.toml",
                seal_path="artifacts/fail.sseal",
                attestation_path="artifacts/fail.json",
                secret=SECRET,
                plugin_loader=loader,
            )
        assert caught.value.code == "SS061"


def test_diff_reports_aggregate_changes_without_identifiers(project: Path) -> None:
    freeze(project, prefix="old", secret=SECRET)
    write_jsonl(
        project / "data" / "private.jsonl",
        [
            '{"id":"private-902","text":"Confidential synthetic delta","label":4}',
            '{"id":"private-903","text":"Synthetic replacement","label":5}',
        ],
    )
    write_config(project, version="1.1.0")
    freeze(project, prefix="new", secret=OTHER_SECRET)
    report = diff_releases(
        root=project,
        old_seal_path="artifacts/old.sseal",
        new_seal_path="artifacts/new.sseal",
        old_secret=SECRET,
        new_secret=OTHER_SECRET,
    )
    assert report["status"] == "changed"
    assert report["changes"]["records_added"] == 1
    assert report["changes"]["records_removed"] == 1
    serialized = json.dumps(report)
    assert "private-903" not in serialized
    assert "private-evaluation" not in serialized


def test_diff_of_same_manifest_passes(project: Path) -> None:
    freeze(project, prefix="one")
    freeze(project, prefix="two")
    report = diff_releases(
        root=project,
        old_seal_path="artifacts/one.sseal",
        new_seal_path="artifacts/two.sseal",
        old_secret=SECRET,
        new_secret=SECRET,
    )
    assert report["status"] == "pass"
    assert report["changes"]["records_added"] == 0
