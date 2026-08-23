#!/usr/bin/env python3
"""Audit the locked runtime dependency set without auditing development tools."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path


def run(command: list[str], *, cwd: Path) -> None:
    subprocess.run(command, cwd=cwd, check=True)  # noqa: S603


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="splitseal-dependency-audit-") as directory:
        temporary = Path(directory)
        requirements = temporary / "requirements.txt"
        cache = temporary / "cache"
        run(
            [
                "uv",
                "--quiet",
                "export",
                "--frozen",
                "--no-dev",
                "--no-emit-project",
                "--format",
                "requirements-txt",
                "--output-file",
                str(requirements),
            ],
            cwd=root,
        )
        run(
            [
                "uv",
                "run",
                "pip-audit",
                "--require-hashes",
                "--disable-pip",
                "--cache-dir",
                str(cache),
                "-r",
                str(requirements),
            ],
            cwd=root,
        )
    print("runtime dependency audit: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
