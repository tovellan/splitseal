from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

WORKFLOW_PATH = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release-assets.yml"


def _release_steps() -> list[Mapping[str, Any]]:
    document = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(document, Mapping)
    jobs = document.get("jobs")
    assert isinstance(jobs, Mapping)
    build = jobs.get("build")
    assert isinstance(build, Mapping)
    steps = build.get("steps")
    assert isinstance(steps, list)
    assert all(isinstance(step, Mapping) for step in steps)
    return steps


def _step(name: str) -> Mapping[str, Any]:
    return next(step for step in _release_steps() if step.get("name") == name)


def _run(name: str) -> str:
    command = _step(name).get("run")
    assert isinstance(command, str)
    return command


def _step_index(name: str) -> int:
    return next(index for index, step in enumerate(_release_steps()) if step.get("name") == name)


def test_release_preflight_precedes_verified_checkout() -> None:
    preflight = _run("Verify release tag targets protected main")
    assert "immutable-releases" in preflight
    assert "'.enabled'" in preflight
    assert "/git/ref/tags/$RELEASE_TAG" in preflight
    assert "/git/tags/$object_sha" in preflight
    assert ".tagger.name" in preflight
    assert ".tagger.email" in preflight
    assert "Tovellan Maintainers" in preflight
    assert "noreply@github.com" in preflight
    assert "/git/ref/heads/main" in preflight
    assert "/compare/$object_sha...$main_sha" in preflight
    assert '"$release_state" = "absent"' in preflight
    assert '"$comparison_status" != "ahead"' in preflight
    assert "target_sha=" in preflight
    assert "/releases?per_page=100" in preflight
    assert 'release_state="draft"' in preflight
    assert _step_index("Verify release tag targets protected main") < _step_index(
        "Check out release tag"
    )

    checkout = _step("Check out release tag")
    assert checkout.get("if") == "steps.verify-tag.outputs.release_state != 'published'"
    settings = checkout.get("with")
    assert isinstance(settings, Mapping)
    assert settings.get("persist-credentials") is False
    assert settings.get("ref") == "${{ steps.verify-tag.outputs.target_sha }}"


def test_release_publication_is_draft_first_and_resumable() -> None:
    create = _step("Create or resume draft release")
    attach = _step("Attach exact draft assets")
    publish = _step("Publish complete draft release")
    for step in (create, attach, publish):
        assert step.get("if") == "steps.verify-tag.outputs.release_state != 'published'"

    create_run = _run("Create or resume draft release")
    assert "--method POST" in create_run
    assert '"repos/$GITHUB_REPOSITORY/releases"' in create_run
    assert "-F draft=true" in create_run

    attach_run = _run("Attach exact draft assets")
    assert "/assets?per_page=100" in attach_run
    assert "'.state'" in attach_run
    assert "--method DELETE" in attach_run
    assert "gh release upload" in attach_run
    assert "cmp -s" in attach_run
    assert "--clobber" not in attach_run

    publish_run = _run("Publish complete draft release")
    assert "--method PATCH" in publish_run
    assert "-F draft=false" in publish_run
    assert "gh release create" not in WORKFLOW_PATH.read_text(encoding="utf-8")

    assert _step_index("Build distributions") < _step_index("Create or resume draft release")
    assert _step_index("Create or resume draft release") < _step_index("Attach exact draft assets")
    assert _step_index("Attach exact draft assets") < _step_index("Publish complete draft release")
    assert _step_index("Publish complete draft release") < _step_index(
        "Verify immutable release and automatic attestation"
    )


def test_release_closure_is_retryable_after_publication() -> None:
    verify = _run("Verify immutable release and automatic attestation")
    assert "for attempt in {1..40}" in verify
    assert "'.immutable'" in verify
    assert '"$state" = "true"' in verify
    assert "2>/dev/null" in verify
    assert 'gh release verify "$RELEASE_TAG" --format json' in verify
    assert "sleep 15" in verify
