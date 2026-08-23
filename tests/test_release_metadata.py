from __future__ import annotations

import runpy
from collections.abc import Callable
from pathlib import Path
from typing import cast

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "validate_release_metadata.py"
VALIDATE = cast(
    Callable[[object, object, object], list[str]],
    runpy.run_path(str(SCRIPT_PATH))["validate_release_metadata"],
)


def test_release_metadata_accepts_generic_generated_notes() -> None:
    assert (
        VALIDATE(
            "v0.3.0",
            "SplitSeal v0.3.0",
            "## Changes\n\n* Harden release publication by @tovellan in #35",
        )
        == []
    )


def test_release_metadata_rejects_private_or_attributed_content() -> None:
    invalid_bodies = [
        "Internal " + "workflow handoff",
        "Independent " + "review handoff",
        "See codex/private-release-branch",
        "Co-authored-by: Contributor <contributor@example.com>",
        "Generated-by: release tool",
        "Contains a prohibited \u2014 character",
        "Contact person@example.com",
    ]
    for body in invalid_bodies:
        assert VALIDATE("v0.3.0", "SplitSeal v0.3.0", body)


def test_release_metadata_requires_exact_tag_name_and_nonempty_notes() -> None:
    assert VALIDATE("0.3.0", "SplitSeal 0.3.0", "notes") == ["invalid release tag"]
    assert VALIDATE("v0.3.0", "v0.3.0", "notes") == ["invalid release name"]
    assert VALIDATE("v0.3.0", "SplitSeal v0.3.0", "") == ["missing release notes"]
