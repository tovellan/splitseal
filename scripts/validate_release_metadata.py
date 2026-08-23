#!/usr/bin/env python3
"""Validate public release names and generated notes before publication."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

TAG_PATTERN = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
EMAIL_PATTERN = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
HANDLE_PATTERN = re.compile(r"(?<![A-Za-z0-9_])@[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\b")
TRAILER_PATTERN = re.compile(r"(?im)^\s*[a-z][a-z0-9-]*-by:")
AUTHOR_CREDIT_PATTERN = re.compile(
    r"\s+by\s+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\s+in\s+"
    r"(?P<url>https://github\.com/[^/\s]+/[^/\s]+/pull/(?P<number>[0-9]+))\s*$"
)
PRIVATE_REFERENCE_PATTERNS = (
    re.compile(r"(?i)\b(?:codex|dept)/[a-z0-9._/-]+"),
    re.compile(r"(?i)\binternal\s+workflow\b"),
    re.compile(r"(?i)\bindependent\s+review\b"),
    re.compile(re.escape("Mission" + " Control"), re.IGNORECASE),
    re.compile(re.escape("startup" + "-idea"), re.IGNORECASE),
    re.compile(
        r"(?i)tovellan-(?:platform|bench|codex|design|trust|web|infra|handbook|"
        r"research|brand|sdk|gst-bench)\b"
    ),
    re.compile(re.escape("GST" + "-Bench"), re.IGNORECASE),
    re.compile("61f214" + "e7272095", re.IGNORECASE),
    re.compile("d57d6f" + "04a22e1e", re.IGNORECASE),
    re.compile(r"(?i)cosine\s*(?:>=|≥)\s*0\.88"),
)
PRODUCT_POSITIONING_PATTERNS = (
    re.compile(r"(?i)\bfounders?\b"),
    re.compile(r"(?i)(?<![a-z])yc(?![a-z])"),
    re.compile(r"(?i)\bhumani[sz](?:e[ds]?|ing|ation)\b"),
)
LOCAL_PATH_PATTERNS = (
    re.compile(re.escape("/" + "Users" + "/"), re.IGNORECASE),
    re.compile(r"(?i)/home/[A-Za-z0-9._-]+/"),
    re.compile(r"(?i)/private/var/"),
    re.compile(r"(?i)[A-Z]:\\Users\\"),
    re.compile(r"(?i)file://"),
)
PROHIBITED_CHARACTERS = {"\u2013", "\u2014"}


def sanitize_generated_notes(body: object) -> object:
    if not isinstance(body, str):
        return body
    sanitized: list[str] = []
    skipping_contributors = False
    for line in body.splitlines():
        if line.strip().casefold() == "## new contributors":
            skipping_contributors = True
            continue
        if skipping_contributors:
            if line.startswith(("## ", "**Full Changelog**")):
                skipping_contributors = False
            else:
                continue
        processed_line = AUTHOR_CREDIT_PATTERN.sub(r" ([#\g<number>](\g<url>))", line)
        sanitized.append(processed_line)
    return "\n".join(sanitized).strip() + "\n"


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
    if any(pattern.search(body) for pattern in PRODUCT_POSITIONING_PATTERNS):
        violations.append("prohibited product-positioning term")
    if any(pattern.search(body) for pattern in LOCAL_PATH_PATTERNS):
        violations.append("prohibited local path")
    if HANDLE_PATTERN.search(body):
        violations.append("prohibited personal account handle")
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
    parser.add_argument("--output", type=Path)
    parser.add_argument("--sanitize-generated", action="store_true")
    arguments = parser.parse_args()
    document = json.loads(arguments.input.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        print("release metadata validation failed: invalid response")
        return 1
    if arguments.sanitize_generated:
        document = {
            "name": f"SplitSeal {arguments.tag}",
            "body": sanitize_generated_notes(document.get("body")),
        }
    violations = validate_release_metadata(
        arguments.tag, document.get("name"), document.get("body")
    )
    if violations:
        print("release metadata validation failed: " + "; ".join(violations))
        return 1
    if arguments.output is not None:
        arguments.output.write_text(
            json.dumps(document, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    print("release metadata validation: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
