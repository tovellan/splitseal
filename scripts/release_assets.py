#!/usr/bin/env python3
"""Build a tag-matched release and emit a portable checksum manifest."""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Iterable
from pathlib import Path

_CHECKSUM_FILE = "SHA256SUMS"
_READ_SIZE = 64 * 1024


def project_identity(root: Path) -> tuple[str, str]:
    """Read and validate the package name and version from pyproject.toml."""

    with (root / "pyproject.toml").open("rb") as stream:
        document = tomllib.load(stream)
    project = document.get("project")
    if not isinstance(project, dict):
        raise ValueError("pyproject.toml is missing [project]")
    name = project.get("name")
    version = project.get("version")
    if not isinstance(name, str) or not name:
        raise ValueError("project.name must be a non-empty string")
    if not isinstance(version, str) or not version:
        raise ValueError("project.version must be a non-empty string")
    return name, version


def validate_release_tag(tag: str, version: str) -> None:
    """Require an exact v-prefixed match between the release tag and package version."""

    expected = f"v{version}"
    if tag != expected:
        raise ValueError(f"release tag {tag!r} does not match package version {expected!r}")


def expected_artifact_names(name: str, version: str) -> frozenset[str]:
    """Return the exact pure-Python wheel and source archive names."""

    wheel_name = re.sub(r"[-_.]+", "_", name).lower()
    source_name = re.sub(r"[-_.]+", "-", name).lower()
    return frozenset(
        {
            f"{wheel_name}-{version}-py3-none-any.whl",
            f"{source_name}-{version}.tar.gz",
        }
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_READ_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksum_manifest(output_dir: Path, expected_names: Iterable[str]) -> Path:
    """Validate the distribution set and write sorted SHA-256 checksums."""

    expected = frozenset(expected_names)
    actual = frozenset(path.name for path in output_dir.iterdir())
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise ValueError(
            f"release artifact set is invalid; missing={missing!r}, unexpected={unexpected!r}"
        )
    for name in expected:
        artifact = output_dir / name
        if artifact.is_symlink() or not artifact.is_file():
            raise ValueError(f"release artifact must be a regular non-symlink file: {name}")
    checksum_path = output_dir / _CHECKSUM_FILE
    content = "".join(f"{_sha256(output_dir / name)}  {name}\n" for name in sorted(expected))
    with checksum_path.open("x", encoding="ascii", newline="\n") as stream:
        stream.write(content)
    return checksum_path


def build_release_assets(*, root: Path, tag: str, output_dir: Path) -> Path:
    """Build a clean, version-matched distribution set and its checksums."""

    name, version = project_identity(root)
    validate_release_tag(tag, version)
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError("release output directory must be empty")
    output_dir.mkdir(parents=True, exist_ok=True)
    uv = shutil.which("uv")
    if uv is None:
        raise ValueError("uv executable was not found")
    subprocess.run(  # noqa: S603
        [uv, "build", "--out-dir", str(output_dir)],
        cwd=root,
        check=True,
    )
    (output_dir / ".gitignore").unlink(missing_ok=True)
    return write_checksum_manifest(output_dir, expected_artifact_names(name, version))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    try:
        checksum_path = build_release_assets(
            root=root,
            tag=args.tag,
            output_dir=args.output_dir.resolve(),
        )
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        sys.stderr.write(f"release asset build failed: {exc}\n")
        return 1
    sys.stdout.write(f"release assets: pass ({checksum_path})\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
