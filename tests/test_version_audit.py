from __future__ import annotations

from pathlib import Path

import pytest

from scripts.version_audit import version_violations


def _write_fixture(root: Path) -> None:
    files = {
        "pyproject.toml": '[project]\nname = "splitseal"\nversion = "1.2.3"\n',
        "uv.lock": (
            'version = 1\nrevision = 1\n[[package]]\nname = "splitseal"\nversion = "1.2.3"\n'
        ),
        "src/splitseal/__init__.py": '__version__ = "1.2.3"\n',
        "README.md": 'install "https://example.test/splitseal.git@v1.2.3"\n',
        "CHANGELOG.md": "## [1.2.3] - 2026-08-24\n",
        "SUPPORT.md": "Within the 1.2 release line, contracts are stable.\n",
        "docs/api.md": "The stable 1.2 API is exported.\n",
        "docs/manifest-format.md": "Fields may appear within a 1.2 release.\n",
        "ROADMAP.md": "## Delivered in 1.2\n",
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def test_current_repository_versions_are_consistent() -> None:
    root = Path(__file__).resolve().parents[1]
    assert version_violations(root) == []


@pytest.mark.parametrize(
    ("relative", "old", "new", "label"),
    [
        ("src/splitseal/__init__.py", "1.2.3", "1.2.2", "__version__"),
        ("uv.lock", "1.2.3", "1.2.2", "uv.lock"),
        ("README.md", "v1.2.3", "v1.2.2", "README.md"),
        ("CHANGELOG.md", "[1.2.3]", "[1.2.2]", "CHANGELOG.md"),
        ("SUPPORT.md", "1.2 release", "1.1 release", "SUPPORT.md"),
        ("docs/api.md", "1.2 API", "1.1 API", "docs/api.md"),
        ("docs/manifest-format.md", "1.2 release", "1.1 release", "docs/manifest-format.md"),
        ("ROADMAP.md", "Delivered in 1.2", "Delivered in 1.1", "ROADMAP.md"),
    ],
)
def test_version_audit_reports_each_drifted_surface(
    tmp_path: Path,
    relative: str,
    old: str,
    new: str,
    label: str,
) -> None:
    _write_fixture(tmp_path)
    path = tmp_path / relative
    path.write_text(path.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")
    violations = version_violations(tmp_path)
    assert len(violations) == 1
    assert label in violations[0]
