from __future__ import annotations

from pathlib import Path

import pytest

from scripts.repository_audit import action_reference_violations, contains_action_references

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


@pytest.mark.parametrize(
    ("workflow", "line"),
    [
        ("steps:\n  - uses : actions/checkout@main\n", 2),
        ('steps:\n  - "uses": actions/checkout@main\n', 2),
        ('steps: [{"uses": actions/checkout@main}]\n', 1),
        ("steps:\n  - {uses: actions/checkout@main}\n", 2),
    ],
)
def test_workflow_audit_rejects_yaml_formatting_bypasses(workflow: str, line: int) -> None:
    assert action_reference_violations(Path(".github/workflows/test.yaml"), workflow) == [
        f".github/workflows/test.yaml:{line}: external action is not pinned to a full commit SHA"
    ]


def test_workflow_audit_rejects_non_scalar_and_invalid_yaml_references() -> None:
    assert action_reference_violations(
        Path("nested/action.yml"),
        "runs:\n  steps:\n    - uses: [actions/checkout@main]\n",
    ) == ["nested/action.yml:3: action reference must be a scalar string"]
    assert action_reference_violations(
        Path(".github/workflows/test.yml"),
        "steps: [\n",
    ) == [".github/workflows/test.yml:2: action definition is not valid YAML"]


@pytest.mark.parametrize(
    "relative",
    [
        Path("action.yml"),
        Path("tools/private/action.yaml"),
        Path("vendor/deep/local/action.yml"),
        Path(".github/workflows/check.yaml"),
    ],
)
def test_action_audit_discovers_workflows_and_composite_actions_anywhere(relative: Path) -> None:
    assert contains_action_references(relative)


def test_action_audit_ignores_unrelated_yaml() -> None:
    assert not contains_action_references(Path("docs/example.yaml"))
