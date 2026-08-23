from __future__ import annotations

import runpy
from collections.abc import Callable
from pathlib import Path
from typing import cast

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "validate_release_metadata.py"
SCRIPT = runpy.run_path(str(SCRIPT_PATH))
VALIDATE = cast(
    Callable[[object, object, object], list[str]],
    SCRIPT["validate_release_metadata"],
)
SANITIZE = cast(Callable[[object], object], SCRIPT["sanitize_generated_notes"])


def test_release_metadata_accepts_generic_generated_notes() -> None:
    assert (
        VALIDATE(
            "v0.3.0",
            "SplitSeal v0.3.0",
            "## Changes\n\n* Harden release publication ([#35](https://github.com/example/project/pull/35))",
        )
        == []
    )


def test_release_metadata_rejects_private_or_attributed_content() -> None:
    invalid_bodies = [
        "Internal " + "workflow handoff",
        "Independent " + "review handoff",
        "See codex/private-release-branch",
        "Assisted-by: release tool",
        "Co-authored-by: Contributor <contributor@example.com>",
        "Generated-by: release tool",
        "Built for a " + "founder audience",
        "Presented to " + "Y" + "C",
        "Apply " + "humanization wording",
        "Handled by " + "Mission" + " Control",
        "Opened from /" + "Users/example/project",
        "Opened from C:\\" + "Users\\example\\project",
        "Opened from /home/example/project",
        "Opened from /private/var/example",
        "Opened from file://local/project",
        "See " + "startup" + "-idea notes",
        "See tovellan-" + "codex worktree",
        "Contains personal account @example-user",
        "Contains a prohibited \u2014 character",
        "Contact person@example.com",
    ]
    for body in invalid_bodies:
        assert VALIDATE("v0.3.0", "SplitSeal v0.3.0", body)


def test_release_metadata_requires_exact_tag_name_and_nonempty_notes() -> None:
    assert VALIDATE("0.3.0", "SplitSeal 0.3.0", "notes") == ["invalid release tag"]
    assert VALIDATE("v0.3.0", "v0.3.0", "notes") == ["invalid release name"]
    assert VALIDATE("v0.3.0", "SplitSeal v0.3.0", "") == ["missing release notes"]


def test_generated_notes_remove_contributor_credits_and_sections() -> None:
    generated = """## Changes

* Harden release publication by @example-user in https://github.com/example/project/pull/35

## New Contributors
* @example-user made their first contribution in https://github.com/example/project/pull/35

**Full Changelog**: https://github.com/example/project/compare/v0.2.3...v0.3.0
"""
    sanitized = SANITIZE(generated)
    assert isinstance(sanitized, str)
    assert "@" not in sanitized
    assert "New Contributors" not in sanitized
    assert "[#35](https://github.com/example/project/pull/35)" in sanitized
    assert "Full Changelog" in sanitized
    assert VALIDATE("v0.3.0", "SplitSeal v0.3.0", sanitized) == []
