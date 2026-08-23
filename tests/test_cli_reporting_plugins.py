from __future__ import annotations

import json
from pathlib import Path

import pytest

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


def test_render_report_marks_changed_result() -> None:
    report = json.loads(render_report({"status": "changed"}, "sarif"))
    assert report["runs"][0]["results"][0]["ruleId"] == "SPLITSEAL_RESULT"
    with pytest.raises(ValueError):
        render_report({"status": "pass"}, "xml")


def test_plugin_loader_rejects_missing_entry_point() -> None:
    with pytest.raises(SplitSealError) as caught:
        load_similarity_plugin("not-installed")
    assert caught.value.code == "SS060"
