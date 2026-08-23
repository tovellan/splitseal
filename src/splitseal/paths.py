"""Repository-root path validation with Unicode and symlink controls."""

from __future__ import annotations

import os
import re
import unicodedata
from pathlib import Path, PurePosixPath

from splitseal.errors import fail

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


def repository_root(root: Path) -> Path:
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise fail("SS001", "repository root does not exist", path=str(root)) from exc
    if not resolved.is_dir():
        raise fail("SS001", "repository root is not a directory", path=str(root))
    return resolved


def _validate_relative(user_path: str | Path) -> PurePosixPath:
    raw = os.fspath(user_path)
    if not raw or "\x00" in raw:
        raise fail("SS001", "path is empty or contains a null byte")
    if unicodedata.normalize("NFC", raw) != raw:
        raise fail("SS002", "path must use Unicode NFC normalization", path=raw)
    if "\\" in raw:
        raise fail("SS001", "path must use forward slashes", path=raw)
    if _WINDOWS_DRIVE.match(raw):
        raise fail("SS001", "drive-qualified paths are not allowed", path=raw)
    if any(part in {"", ".", ".."} for part in raw.split("/")):
        raise fail("SS001", "path must be a normalized relative path", path=raw)
    relative = PurePosixPath(raw)
    if relative.is_absolute():
        raise fail("SS001", "path must be a normalized relative path", path=raw)
    return relative


def _assert_contained(root: Path, candidate: Path, *, user_path: str | Path) -> None:
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise fail(
            "SS003",
            "resolved path escapes the repository root",
            path=os.fspath(user_path),
        ) from exc


def safe_input_path(root: Path, user_path: str | Path) -> Path:
    resolved_root = repository_root(root)
    relative = _validate_relative(user_path)
    try:
        candidate = (resolved_root / Path(relative)).resolve(strict=True)
    except OSError as exc:
        raise fail("SS001", "input path does not exist", path=os.fspath(user_path)) from exc
    _assert_contained(resolved_root, candidate, user_path=user_path)
    if not candidate.is_file():
        raise fail("SS001", "input path is not a regular file", path=os.fspath(user_path))
    return candidate


def safe_output_path(root: Path, user_path: str | Path) -> Path:
    resolved_root = repository_root(root)
    relative = _validate_relative(user_path)
    candidate = resolved_root / Path(relative)
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as exc:
        raise fail(
            "SS001",
            "output parent directory does not exist",
            path=os.fspath(user_path),
        ) from exc
    _assert_contained(resolved_root, parent, user_path=user_path)
    if candidate.is_symlink():
        raise fail("SS003", "output path cannot be a symbolic link", path=os.fspath(user_path))
    if candidate.exists():
        resolved_candidate = candidate.resolve(strict=True)
        _assert_contained(resolved_root, resolved_candidate, user_path=user_path)
        if not resolved_candidate.is_file():
            raise fail("SS001", "output path is not a regular file", path=os.fspath(user_path))
    return candidate
