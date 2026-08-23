#!/usr/bin/env python3
"""Validate public release names and generated notes before publication."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

TAG_PATTERN = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
EMAIL_PATTERN = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
TRAILER_PATTERN = re.compile(r"(?im)^\s*(?:co-authored-by|signed-off-by|generated-by):")
PRIVATE_REFERENCE_PATTERNS = (
    re.compile(r"(?i)\b(?:codex|dept)/[a-z0-9._/-]+"),
    re.compile(r"(?i)\binternal\s+workflow\b"),
    re.compile(r"(?i)\bindependent\s+review\b"),
)
PROHIBITED_CHARACTERS = {"\u2013", "\u2014"}


def validate_release_metadata(tag: object, name: object, body: object) -> list[str]:
    violations: list[str] = []
    if not isinstance(tag, str) or TAG_PATTERN.fullmatch(tag) is None:
        violations.append("invalid release tag")
        return violations
    if name != f"SplitSeal {tag}":
        violations.append("invalid release name")
    if not isinstance(body, str) or not body.strip():
        violations.append("missing release notes")
        return violations
    if any(character in body for character in PROHIBITED_CHARACTERS):
        violations.append("prohibited Unicode punctuation")
    if TRAILER_PATTERN.search(body):
        violations.append("prohibited attribution trailer")
    if any(pattern.search(body) for pattern in PRIVATE_REFERENCE_PATTERNS):
        violations.append("prohibited private workflow reference")
    unexpected_emails = {
        address.lower()
        for address in EMAIL_PATTERN.findall(body)
        if address.lower() != "noreply@github.com"
    }
    if unexpected_emails:
        violations.append("prohibited personal email address")
    return violations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--input", type=Path, required=True)
    arguments = parser.parse_args()
    document = json.loads(arguments.input.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        print("release metadata validation failed: invalid response")
        return 1
    violations = validate_release_metadata(
        arguments.tag,
        document.get("name"),
        document.get("body"),
    )
    if violations:
        print("release metadata validation failed: " + "; ".join(violations))
        return 1
    print("release metadata validation: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
