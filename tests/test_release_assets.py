from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from scripts.release_assets import (
    build_release_assets,
    expected_artifact_names,
    project_identity,
    validate_release_tag,
    write_checksum_manifest,
)


def test_repository_release_identity_matches_artifact_names() -> None:
    root = Path(__file__).resolve().parents[1]
    name, version = project_identity(root)
    validate_release_tag(f"v{version}", version)
    assert expected_artifact_names(name, version) == {
        f"splitseal-{version}-py3-none-any.whl",
        f"splitseal-{version}.tar.gz",
    }


def test_release_tag_must_match_exact_package_version() -> None:
    for tag in ("0.2.3", "v0.2.2", "v0.2.3-rc1", "refs/tags/v0.2.3"):
        with pytest.raises(ValueError, match="does not match package version"):
            validate_release_tag(tag, "0.2.3")


def test_checksum_manifest_is_complete_sorted_and_reproducible(tmp_path: Path) -> None:
    contents = {
        "splitseal-1.2.3-py3-none-any.whl": b"wheel bytes",
        "splitseal-1.2.3.tar.gz": b"source bytes",
    }
    for name, content in contents.items():
        (tmp_path / name).write_bytes(content)
    checksum_path = write_checksum_manifest(tmp_path, contents)
    expected = "".join(
        f"{hashlib.sha256(contents[name]).hexdigest()}  {name}\n" for name in sorted(contents)
    )
    assert checksum_path.read_text(encoding="ascii") == expected
    with pytest.raises(ValueError, match=r"unexpected=.*SHA256SUMS"):
        write_checksum_manifest(tmp_path, contents)


@pytest.mark.parametrize("extra_name", [None, "unexpected.zip"])
def test_checksum_manifest_rejects_incomplete_or_unexpected_sets(
    tmp_path: Path,
    extra_name: str | None,
) -> None:
    expected = expected_artifact_names("splitseal", "1.2.3")
    wheel = "splitseal-1.2.3-py3-none-any.whl"
    (tmp_path / wheel).write_bytes(b"wheel")
    if extra_name is not None:
        (tmp_path / extra_name).write_bytes(b"unexpected")
    with pytest.raises(ValueError, match="release artifact set is invalid"):
        write_checksum_manifest(tmp_path, expected)


def test_release_build_refuses_nonempty_output_before_invoking_builder(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    _name, version = project_identity(root)
    output = tmp_path / "dist"
    output.mkdir()
    sentinel = output / "do-not-overwrite"
    sentinel.write_bytes(b"existing")
    with pytest.raises(ValueError, match="output directory must be empty"):
        build_release_assets(root=root, tag=f"v{version}", output_dir=output)
    assert sentinel.read_bytes() == b"existing"


def test_release_workflow_pins_attestation_and_required_permissions() -> None:
    root = Path(__file__).resolve().parents[1]
    workflow = (root / ".github" / "workflows" / "release-assets.yml").read_text(encoding="utf-8")
    assert "actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d" in workflow
    assert "subject-checksums: dist/SHA256SUMS" in workflow
    for permission in (
        "artifact-metadata: write",
        "attestations: write",
        "contents: write",
        "id-token: write",
    ):
        assert permission in workflow
    assert "--clobber" not in workflow
