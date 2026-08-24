#!/usr/bin/env python3
"""Review tracked files for public-release boundary violations."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterator
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

MAX_TRACKED_BYTES = 1_000_000
BINARY_SUFFIXES = {
    ".7z",
    ".avi",
    ".bin",
    ".gif",
    ".gz",
    ".jpeg",
    ".jpg",
    ".key",
    ".mov",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".sseal",
    ".tar",
    ".wav",
    ".webm",
    ".zip",
}
_PINNED_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$")


def _forbidden_patterns() -> list[tuple[str, re.Pattern[str]]]:
    fragments = [
        ("absolute user path", r"/" + "Users" + r"/"),
        ("private checkout name", "startup" + "-idea"),
        ("private worktree name", r"tovellan-(?:" + "platform|bench|codex|design|trust|web" + r")"),
        ("private benchmark name", "GST" + r"[- ]" + "Bench"),
        ("private engine name", "Kas" + "auti"),
        ("private benchmark hash", "61f214" + "e7272095"),
        ("unreleased benchmark hash", "d57d6f" + "04a22e1e"),
        ("private operating point", r"cosine\s*(?:>=|≥)\s*0" + r"\.88"),
    ]
    return [(label, re.compile(pattern, re.IGNORECASE)) for label, pattern in fragments]


def tracked_files(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],  # noqa: S607
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [root / item.decode("utf-8") for item in result.stdout.split(b"\x00") if item]


def _uses_nodes(node: Node, seen: set[int] | None = None) -> Iterator[Node]:
    visited = seen if seen is not None else set()
    identity = id(node)
    if identity in visited:
        return
    visited.add(identity)

    if isinstance(node, MappingNode):
        for key, value in node.value:
            if isinstance(key, ScalarNode) and key.value == "uses":
                yield value
            yield from _uses_nodes(value, visited)
    elif isinstance(node, SequenceNode):
        for value in node.value:
            yield from _uses_nodes(value, visited)


def action_reference_violations(relative: Path, text: str) -> list[str]:
    """Return invalid YAML and mutable or unsupported external action references."""

    violations: list[str] = []
    try:
        document = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = mark.line + 1 if mark is not None else 1
        return [f"{relative}:{line}: action definition is not valid YAML"]
    if document is None:
        return violations

    for node in _uses_nodes(document):
        line = node.start_mark.line + 1
        if not isinstance(node, ScalarNode):
            violations.append(f"{relative}:{line}: action reference must be a scalar string")
            continue
        reference = node.value
        if reference.startswith("./"):
            continue
        if not _PINNED_ACTION.fullmatch(reference):
            violations.append(
                f"{relative}:{line}: external action is not pinned to a full commit SHA"
            )
    return violations


def contains_action_references(relative: Path) -> bool:
    if relative.suffix not in {".yml", ".yaml"}:
        return False
    if relative.parts[:2] == (".github", "workflows"):
        return True
    return relative.name in {"action.yml", "action.yaml"}


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    violations: list[str] = []
    for path in tracked_files(root):
        relative = path.relative_to(root)
        size = path.stat().st_size
        if size > MAX_TRACKED_BYTES:
            violations.append(f"{relative}: tracked file exceeds {MAX_TRACKED_BYTES} bytes")
        if path.suffix.lower() in BINARY_SUFFIXES:
            violations.append(f"{relative}: prohibited tracked binary or private-artifact suffix")
        data = path.read_bytes()
        if b"\x00" in data:
            violations.append(f"{relative}: unreviewed binary file")
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            violations.append(f"{relative}: tracked file is not UTF-8 text")
            continue
        for label, pattern in _forbidden_patterns():
            if pattern.search(text):
                violations.append(f"{relative}: contains {label}")
        if contains_action_references(relative):
            violations.extend(action_reference_violations(relative, text))
    if violations:
        print("\n".join(sorted(violations)))
        return 1
    print(f"repository audit: pass ({len(tracked_files(root))} tracked text files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
