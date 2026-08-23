from __future__ import annotations

import json
from pathlib import Path

import pytest

import splitseal.service as service_module
from splitseal.cli import main
from splitseal.errors import SplitSealError
from splitseal.plugins import load_similarity_plugin
from splitseal.reporting import render_report


def test_cli_keygen_freeze_verify_and_diff(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["keygen", "--root", str(project), "--output", "keys/generated.key"]) == 0
    key_report = json.loads(capsys.readouterr().out)
    assert key_report == {"key_file": "generated.key", "status": "created"}

    assert (
        main(
            [
                "freeze",
                "--root",
                str(project),
                "splitseal.toml",
                "--seal",
                "artifacts/cli.sseal",
                "--attestation",
                "artifacts/cli.json",
                "--key-file",
                "keys/generated.key",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "created"
    assert (
        main(
            [
                "verify",
                "--root",
                str(project),
                "--seal",
                "artifacts/cli.sseal",
                "--attestation",
                "artifacts/cli.json",
                "--key-file",
                "keys/generated.key",
                "--config",
                "splitseal.toml",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "pass"
    assert (
        main(
            [
                "diff",
                "--root",
                str(project),
                "--old-seal",
                "artifacts/cli.sseal",
                "--new-seal",
                "artifacts/cli.sseal",
                "--old-key-file",
                "keys/generated.key",
                "--new-key-file",
                "keys/generated.key",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "pass"


def test_cli_errors_are_machine_readable(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(
        [
            "verify",
            "--root",
            str(project),
            "--seal",
            "missing.sseal",
            "--attestation",
            "missing.json",
            "--key-file",
            "keys/release.key",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert json.loads(captured.err)["error"]["code"] == "SS001"


def test_cli_rollback_failure_is_machine_readable(
    project: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments = [
        "freeze",
        "--root",
        str(project),
        "splitseal.toml",
        "--seal",
        "artifacts/rollback.sseal",
        "--attestation",
        "artifacts/rollback.json",
        "--key-file",
        "keys/release.key",
    ]
    assert main(arguments) == 0
    capsys.readouterr()

    seal_path = project / "artifacts" / "rollback.sseal"
    attestation_path = project / "artifacts" / "rollback.json"
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
    exit_code = main([*arguments, "--force"])
    captured = capsys.readouterr()
    report = json.loads(captured.err)

    assert exit_code == 2
    assert captured.out == ""
    assert report["error"]["code"] == "SS005"
    assert len(report["error"]["details"]["recovery_files"]) == 1
    assert report["error"]["details"]["recovery_files"][0].startswith(".rollback.sseal.backup.")


def test_cli_sarif_is_valid_shape(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(
        [
            "keygen",
            "--root",
            str(project),
            "--output",
            "keys/sarif.key",
            "--format",
            "sarif",
        ]
    )
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["version"] == "2.1.0"
    assert report["runs"][0]["tool"]["driver"]["name"] == "SplitSeal"
    assert report["runs"][0]["results"] == []


def test_cli_validate_public_json_and_sarif_failure(
    project: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        main(
            [
                "freeze",
                "--root",
                str(project),
                "splitseal.toml",
                "--seal",
                "artifacts/public.sseal",
                "--attestation",
                "artifacts/public.json",
                "--key-file",
                "keys/release.key",
            ]
        )
        == 0
    )
    capsys.readouterr()
    arguments = [
        "validate-public",
        "--root",
        str(project),
        "--attestation",
        "artifacts/public.json",
    ]
    assert main(arguments) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["validation"] == "structural"
    assert report["authentication"] == "not_performed"

    path = project / "artifacts" / "public.json"
    value = json.loads(path.read_bytes())
    value["private_manifest"] = {"record_digests": []}
    path.write_bytes(service_module.canonicalize(value) + b"\n")
    assert main([*arguments, "--format", "sarif"]) == 2
    captured = capsys.readouterr()
    sarif = json.loads(captured.err)
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "SPLITSEAL_RESULT"
    embedded = result["properties"]["splitsealReport"]
    assert embedded["authentication"] == "not_performed"
    assert embedded["error"]["code"] == "SS046"


def test_render_report_marks_changed_result() -> None:
    report = json.loads(render_report({"status": "changed"}, "sarif"))
    assert report["runs"][0]["results"][0]["ruleId"] == "SPLITSEAL_RESULT"
    with pytest.raises(ValueError):
        render_report({"status": "pass"}, "xml")


def test_plugin_loader_rejects_missing_entry_point() -> None:
    with pytest.raises(SplitSealError) as caught:
        load_similarity_plugin("not-installed")
    assert caught.value.code == "SS060"


def test_plugin_loader_wraps_discovery_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_discovery(*, group: str) -> object:
        assert group == "splitseal.similarity"
        raise RuntimeError("synthetic discovery failure")

    monkeypatch.setattr("splitseal.plugins.entry_points", fail_discovery)
    with pytest.raises(SplitSealError) as caught:
        load_similarity_plugin("synthetic")
    assert caught.value.code == "SS060"


def test_plugin_loader_wraps_interface_property_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class BrokenPlugin:
        name = "synthetic"

        def analyze(self) -> None:
            return None

        @property
        def version(self) -> str:
            raise RuntimeError("synthetic version failure")

    class EntryPoint:
        name = "synthetic"

        def load(self) -> type[BrokenPlugin]:
            return BrokenPlugin

    monkeypatch.setattr("splitseal.plugins.entry_points", lambda **_kwargs: [EntryPoint()])
    with pytest.raises(SplitSealError) as caught:
        load_similarity_plugin("synthetic")
    assert caught.value.code == "SS060"


def test_plugin_loader_rejects_invalid_declared_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    def analyze(*_args: object) -> list[object]:
        return []

    class EntryPoint:
        name = "synthetic"

        def __init__(self, attributes: dict[str, object]) -> None:
            self.attributes = attributes

        def load(self) -> object:
            attributes = self.attributes

            class Plugin:
                pass

            for key, value in attributes.items():
                setattr(Plugin, key, value)
            return Plugin

    invalid_interfaces = [
        {"version": "1.0.0", "analyze": analyze},
        {"name": 1, "version": "1.0.0", "analyze": analyze},
        {"name": "", "version": "1.0.0", "analyze": analyze},
        {"name": "other", "version": "1.0.0", "analyze": analyze},
        {"name": "synthetic", "analyze": analyze},
        {"name": "synthetic", "version": 1, "analyze": analyze},
        {"name": "synthetic", "version": "", "analyze": analyze},
    ]
    for attributes in invalid_interfaces:
        monkeypatch.setattr(
            "splitseal.plugins.entry_points",
            lambda attributes=attributes, **_kwargs: [EntryPoint(attributes)],
        )
        with pytest.raises(SplitSealError) as caught:
            load_similarity_plugin("synthetic")
        assert caught.value.code == "SS060"


@pytest.mark.parametrize("attribute", ["name", "version"])
def test_plugin_loader_wraps_identity_property_failure(
    monkeypatch: pytest.MonkeyPatch,
    attribute: str,
) -> None:
    class BrokenPlugin:
        name = "synthetic"
        version = "1.0.0"

        def analyze(self) -> None:
            return None

        def __getattribute__(self, key: str) -> object:
            if key == attribute:
                raise RuntimeError(f"synthetic {key} failure")
            return super().__getattribute__(key)

    class EntryPoint:
        name = "synthetic"

        def load(self) -> type[BrokenPlugin]:
            return BrokenPlugin

    monkeypatch.setattr("splitseal.plugins.entry_points", lambda **_kwargs: [EntryPoint()])
    with pytest.raises(SplitSealError) as caught:
        load_similarity_plugin("synthetic")
    assert caught.value.code == "SS060"
