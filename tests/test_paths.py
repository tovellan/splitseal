from __future__ import annotations

import os
import unicodedata
from pathlib import Path

import pytest

from splitseal.errors import SplitSealError
from splitseal.paths import repository_root, safe_input_path, safe_output_path


def test_safe_paths_accept_contained_regular_files(tmp_path: Path) -> None:
    (tmp_path / "data").mkdir()
    source = tmp_path / "data" / "input.jsonl"
    source.write_text("{}\n", encoding="utf-8")
    assert safe_input_path(tmp_path, "data/input.jsonl") == source.resolve()
    assert safe_output_path(tmp_path, "data/output.json") == tmp_path / "data" / "output.json"


@pytest.mark.parametrize(
    "user_path",
    ["../outside", "/outside", "./file", "data/../file", "C:/outside", "data\\file"],
)
def test_paths_reject_traversal_and_non_portable_forms(tmp_path: Path, user_path: str) -> None:
    with pytest.raises(SplitSealError) as caught:
        safe_output_path(tmp_path, user_path)
    assert caught.value.code == "SS001"


def test_paths_reject_non_nfc_spelling(tmp_path: Path) -> None:
    decomposed = unicodedata.normalize("NFD", "café.json")
    assert decomposed != "café.json"
    with pytest.raises(SplitSealError) as caught:
        safe_output_path(tmp_path, decomposed)
    assert caught.value.code == "SS002"


def test_input_symlink_may_not_escape_root(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.txt"
    outside.write_text("private", encoding="utf-8")
    (tmp_path / "escape").symlink_to(outside)
    try:
        with pytest.raises(SplitSealError) as caught:
            safe_input_path(tmp_path, "escape")
        assert caught.value.code == "SS003"
    finally:
        outside.unlink()


def test_contained_input_symlink_is_allowed(tmp_path: Path) -> None:
    target = tmp_path / "target.jsonl"
    target.write_text("{}\n", encoding="utf-8")
    (tmp_path / "alias.jsonl").symlink_to(target)
    assert safe_input_path(tmp_path, "alias.jsonl") == target.resolve()


def test_output_symlink_is_rejected_even_when_target_is_contained(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    (tmp_path / "alias.json").symlink_to(target)
    with pytest.raises(SplitSealError) as caught:
        safe_output_path(tmp_path, "alias.json")
    assert caught.value.code == "SS003"


def test_paths_reject_missing_parent_and_non_file_input(tmp_path: Path) -> None:
    with pytest.raises(SplitSealError, match="parent"):
        safe_output_path(tmp_path, "missing/output.json")
    (tmp_path / "directory").mkdir()
    with pytest.raises(SplitSealError, match="regular"):
        safe_input_path(tmp_path, "directory")


def test_repository_root_must_exist_and_be_directory(tmp_path: Path) -> None:
    with pytest.raises(SplitSealError):
        repository_root(tmp_path / "missing")
    file_path = tmp_path / "file"
    file_path.write_text("x", encoding="utf-8")
    with pytest.raises(SplitSealError):
        repository_root(file_path)


def test_null_path_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(SplitSealError):
        safe_output_path(tmp_path, "bad\x00name")


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_symlinked_output_parent_may_not_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside-dir"
    outside.mkdir()
    (tmp_path / "escaped-dir").symlink_to(outside, target_is_directory=True)
    try:
        with pytest.raises(SplitSealError) as caught:
            safe_output_path(tmp_path, "escaped-dir/output.json")
        assert caught.value.code == "SS003"
    finally:
        (tmp_path / "escaped-dir").unlink()
        outside.rmdir()
