from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml


def _workflow_paths(workflow_root: Path) -> list[Path]:
    return sorted((*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml")))


def _workflows() -> list[tuple[Path, Mapping[str, Any]]]:
    workflow_root = Path(__file__).resolve().parents[1] / ".github" / "workflows"
    workflows: list[tuple[Path, Mapping[str, Any]]] = []
    for path in _workflow_paths(workflow_root):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(document, Mapping), path
        workflows.append((path, document))
    assert workflows
    return workflows


def _mapping(value: object, path: Path, context: str) -> Mapping[str, Any]:
    assert isinstance(value, Mapping), f"{path}: {context} must be a mapping"
    return value


def test_every_checkout_drops_persisted_credentials() -> None:
    checkout_steps = 0
    for path, workflow in _workflows():
        jobs = _mapping(workflow.get("jobs"), path, "jobs")
        for job_name, job_value in jobs.items():
            job = _mapping(job_value, path, f"job {job_name}")
            steps = job.get("steps")
            assert isinstance(steps, list), f"{path}: job {job_name} must define steps"
            for step_value in steps:
                step = _mapping(step_value, path, f"step in job {job_name}")
                reference = step.get("uses")
                if not isinstance(reference, str) or not reference.startswith("actions/checkout@"):
                    continue
                checkout_steps += 1
                settings = _mapping(step.get("with"), path, "checkout with")
                assert settings.get("persist-credentials") is False, path
    assert checkout_steps > 0


def test_every_workflow_has_concurrency_and_every_job_has_a_timeout() -> None:
    for path, workflow in _workflows():
        concurrency = _mapping(workflow.get("concurrency"), path, "concurrency")
        assert isinstance(concurrency.get("group"), str), path
        assert type(concurrency.get("cancel-in-progress")) is bool, path
        jobs = _mapping(workflow.get("jobs"), path, "jobs")
        assert jobs, path
        for job_name, job_value in jobs.items():
            job = _mapping(job_value, path, f"job {job_name}")
            timeout = job.get("timeout-minutes")
            assert type(timeout) is int and timeout > 0, f"{path}: job {job_name} needs a timeout"


def test_release_jobs_are_not_cancelled_after_publication() -> None:
    workflows = dict(_workflows())
    release_path = next(path for path in workflows if path.stem == "release-assets")
    concurrency = _mapping(workflows[release_path].get("concurrency"), release_path, "concurrency")
    assert concurrency.get("cancel-in-progress") is False
    group = concurrency.get("group")
    assert isinstance(group, str)
    assert "${{ inputs.release_tag }}" in group


def test_validation_workflows_use_per_ref_cancellation() -> None:
    for path, workflow in _workflows():
        if path.stem == "release-assets":
            continue
        concurrency = _mapping(workflow.get("concurrency"), path, "concurrency")
        assert concurrency.get("cancel-in-progress") is True, path
        group = concurrency.get("group")
        assert isinstance(group, str), path
        assert "${{ github.workflow }}" in group, path
        assert "${{ github.ref }}" in group, path


def test_workflow_discovery_includes_yml_and_yaml(tmp_path: Path) -> None:
    (tmp_path / "one.yml").write_text("name: one\n", encoding="utf-8")
    (tmp_path / "two.yaml").write_text("name: two\n", encoding="utf-8")
    (tmp_path / "ignored.txt").write_text("name: ignored\n", encoding="utf-8")
    assert [path.name for path in _workflow_paths(tmp_path)] == ["one.yml", "two.yaml"]
