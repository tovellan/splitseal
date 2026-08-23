from __future__ import annotations

import re
from pathlib import Path

_STEP_BOUNDARY = re.compile(r"(?=^      - name:|\Z)", re.MULTILINE)


def _workflows() -> list[tuple[Path, str]]:
    root = Path(__file__).resolve().parents[1]
    workflow_root = root / ".github" / "workflows"
    return [
        (path, path.read_text(encoding="utf-8")) for path in sorted(workflow_root.glob("*.yml"))
    ]


def test_every_checkout_drops_persisted_credentials() -> None:
    checkout_steps = 0
    for path, workflow in _workflows():
        for remainder in workflow.split("uses: actions/checkout@")[1:]:
            checkout_steps += 1
            step = _STEP_BOUNDARY.split(remainder, maxsplit=1)[0]
            assert "persist-credentials: false" in step, path
    assert checkout_steps == 5


def test_every_workflow_has_concurrency_and_every_job_has_a_timeout() -> None:
    timeout_count = 0
    for path, workflow in _workflows():
        assert "concurrency:" in workflow, path
        assert "cancel-in-progress:" in workflow, path
        job_count = len(re.findall(r"^  [a-z][a-z0-9_-]*:\n    name:", workflow, re.MULTILINE))
        workflow_timeouts = len(re.findall(r"^    timeout-minutes: ", workflow, re.MULTILINE))
        assert workflow_timeouts == job_count, path
        timeout_count += workflow_timeouts
    assert timeout_count == 5


def test_release_jobs_are_not_cancelled_after_publication() -> None:
    workflows = dict(_workflows())
    release_path = next(path for path in workflows if path.name == "release-assets.yml")
    assert "cancel-in-progress: false" in workflows[release_path]
