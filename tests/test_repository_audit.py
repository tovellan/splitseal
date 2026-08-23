from __future__ import annotations

from pathlib import Path

import pytest

from scripts.repository_audit import action_reference_violations

_FULL_SHA = "0123456789abcdef0123456789abcdef01234567"


@pytest.mark.parametrize(
    "reference",
    [
        f"actions/checkout@{_FULL_SHA}",
        f"github/codeql-action/analyze@{_FULL_SHA}",
        "./.github/actions/local-check",
    ],
)
def test_workflow_audit_accepts_commit_pins_and_local_actions(reference: str) -> None:
    workflow = f"steps:\n  - uses: {reference}\n"
    assert action_reference_violations(Path(".github/workflows/test.yml"), workflow) == []


@pytest.mark.parametrize(
    "reference",
    [
        "actions/checkout@v7",
        "actions/checkout@main",
        "actions/checkout@0123456",
        "docker://python:3.14",
        "${{ inputs.action }}",
    ],
)
def test_workflow_audit_rejects_mutable_or_dynamic_external_actions(reference: str) -> None:
    workflow = f"name: test\nsteps:\n  - uses: {reference}\n"
    assert action_reference_violations(Path(".github/workflows/test.yml"), workflow) == [
        ".github/workflows/test.yml:3: external action is not pinned to a full commit SHA"
    ]
