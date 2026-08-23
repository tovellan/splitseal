#!/usr/bin/env python3
"""Reject prohibited Unicode dash characters in tracked text files."""

from __future__ import annotations

import subprocess
from pathlib import Path

PROHIBITED = {"\u2013": "U+2013", "\u2014": "U+2014"}


def tracked_files(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],  # noqa: S607
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [root / item.decode("utf-8") for item in result.stdout.split(b"\x00") if item]


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    violations: list[str] = []
    for path in tracked_files(root):
        data = path.read_bytes()
        if b"\x00" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            for character, name in PROHIBITED.items():
                if character in line:
                    violations.append(f"{path.relative_to(root)}:{line_number}: contains {name}")
    if violations:
        print("\n".join(violations))
        return 1
    print("text policy: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
