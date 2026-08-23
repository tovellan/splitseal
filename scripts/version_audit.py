#!/usr/bin/env python3
"""Fail when release and compatibility versions drift across tracked surfaces."""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path


def _runtime_version(path: Path) -> str | None:
    module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    versions = [
        node.value.value
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        )
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    ]
    return versions[0] if len(versions) == 1 else None


def _locked_project_version(path: Path) -> str | None:
    with path.open("rb") as stream:
        document = tomllib.load(stream)
    packages = document.get("package")
    if not isinstance(packages, list):
        return None
    versions = [
        package.get("version")
        for package in packages
        if isinstance(package, dict) and package.get("name") == "splitseal"
    ]
    return versions[0] if len(versions) == 1 and isinstance(versions[0], str) else None


def version_violations(root: Path) -> list[str]:
    """Return every version surface that disagrees with project.version."""

    with (root / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream).get("project")
    if not isinstance(project, dict) or not isinstance(project.get("version"), str):
        return ["pyproject.toml: project.version is missing or invalid"]
    version = project["version"]
    release_match = re.fullmatch(r"(\d+)\.(\d+)(?:\.\d+.*)?", version)
    if release_match is None:
        return ["pyproject.toml: project.version does not identify a release line"]
    release_line = f"{release_match.group(1)}.{release_match.group(2)}"
    violations: list[str] = []

    runtime_version = _runtime_version(root / "src" / "splitseal" / "__init__.py")
    if runtime_version != version:
        violations.append(
            f"src/splitseal/__init__.py: __version__ is {runtime_version!r}, expected {version!r}"
        )

    locked_version = _locked_project_version(root / "uv.lock")
    if locked_version != version:
        violations.append(f"uv.lock: splitseal is {locked_version!r}, expected {version!r}")

    exact_checks = {
        "README.md": rf"splitseal\.git@v{re.escape(version)}(?:\"|\s)",
        "CHANGELOG.md": rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$",
        "SUPPORT.md": rf"Within the {re.escape(release_line)} release line",
        "docs/api.md": rf"The stable {re.escape(release_line)} API",
        "docs/manifest-format.md": rf"within a {re.escape(release_line)} release",
        "ROADMAP.md": rf"^## Delivered in {re.escape(release_line)}$",
    }
    for relative, pattern in exact_checks.items():
        text = (root / relative).read_text(encoding="utf-8")
        if re.search(pattern, text, re.MULTILINE) is None:
            violations.append(f"{relative}: does not declare release {version}")
    return violations


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    violations = version_violations(root)
    if violations:
        print("\n".join(violations))
        return 1
    print("version audit: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
