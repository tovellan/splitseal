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
    assert ".message" in preflight
    assert '"SplitSeal $RELEASE_TAG"' in preflight
    assert "Tovellan Maintainers" in preflight
    assert "noreply@github.com" in preflight
    assert "/git/ref/heads/main" in preflight
    assert '"$GITHUB_REF" != "refs/tags/$RELEASE_TAG"' in preflight
    assert '"$GITHUB_SHA" != "$object_sha"' in preflight
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
    assert "if" not in checkout
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
    assert '-f name="SplitSeal $RELEASE_TAG"' in create_run
    assert '-f body="$release_notes"' in create_run
    assert '"repos/$GITHUB_REPOSITORY/releases/$RELEASE_ID"' in create_run
    assert "existing-draft.json" in create_run
    assert "scripts/validate_release_metadata.py" in create_run

    metadata_run = _run("Generate and validate public release notes")
    assert "/releases/generate-notes" in metadata_run
    assert "generated-release-notes.json" in metadata_run
    assert "scripts/validate_release_metadata.py" in metadata_run
    assert '--output "$RUNNER_TEMP/release-notes.json"' in metadata_run
    assert "--sanitize-generated" in metadata_run

    build_run = _run("Build distributions")
    assert "uv build" in build_run
    assert "rm -f dist/.gitignore" in build_run

    attach_run = _run("Attach exact draft assets")
    assert "/assets?per_page=100" in attach_run
    assert "'.state'" in attach_run
    assert "--method DELETE" in attach_run
    assert "gh release upload" in attach_run
    assert "cmp -s" in attach_run
    assert "--clobber" not in attach_run
    assert "scripts/validate_release_assets.py" in attach_run
    assert "draft-assets.json" in attach_run

    publish_run = _run("Publish complete draft release")
    assert "immutable-releases" in publish_run
    assert "'.enabled'" in publish_run
    assert "--method PATCH" in publish_run
    assert "-F draft=false" in publish_run
    assert "gh release create" not in WORKFLOW_PATH.read_text(encoding="utf-8")

    published_run = _run("Verify exact published assets")
    assert "scripts/validate_release_assets.py" in published_run
    assert "published-assets.json" in published_run
    assert "cmp -s" in published_run

    assert _step_index("Build distributions") < _step_index(
        "Generate and validate public release notes"
    )
    assert _step_index("Generate and validate public release notes") < _step_index(
        "Create or resume draft release"
    )
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
