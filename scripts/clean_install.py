#!/usr/bin/env python3
"""Build, install, and exercise the wheel in a clean virtual environment."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path


def run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=cwd, env=env, check=True)  # noqa: S603


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="splitseal-clean-install-") as directory:
        temporary = Path(directory)
        distribution = temporary / "dist"
        environment = temporary / "venv"
        run(["uv", "build", "--out-dir", str(distribution)], cwd=root)
        run(["uv", "venv", "--python", sys.executable, str(environment)], cwd=root)
        executable_dir = "Scripts" if os.name == "nt" else "bin"
        python = environment / executable_dir / ("python.exe" if os.name == "nt" else "python")
        wheel = next(distribution.glob("*.whl"))
        run(["uv", "pip", "install", "--python", str(python), str(wheel)], cwd=root)
        run([str(python), "-m", "splitseal", "--version"], cwd=temporary)
        run([str(python), str(root / "examples" / "synthetic" / "run.py")], cwd=temporary)
    print("clean installation: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
