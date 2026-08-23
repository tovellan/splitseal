from __future__ import annotations

import hashlib
import runpy
from collections.abc import Callable
from pathlib import Path
from typing import cast

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "validate_release_assets.py"
VALIDATE = cast(
    Callable[[Path, object], list[str]],
    runpy.run_path(str(SCRIPT_PATH))["validate_release_assets"],
)


def _asset(name: str, content: bytes) -> dict[str, object]:
    return {
        "name": name,
        "digest": f"sha256:{hashlib.sha256(content).hexdigest()}",
        "state": "uploaded",
    }


def test_release_asset_inventory_requires_exact_names_and_digests(tmp_path: Path) -> None:
    wheel = b"wheel"
    source = b"source"
    (tmp_path / "package.whl").write_bytes(wheel)
    (tmp_path / "package.tar.gz").write_bytes(source)
    assert (
        VALIDATE(
            tmp_path,
            [_asset("package.whl", wheel), _asset("package.tar.gz", source)],
        )
        == []
    )


def test_release_asset_inventory_rejects_extra_missing_or_changed_assets(tmp_path: Path) -> None:
    wheel = b"wheel"
    (tmp_path / "package.whl").write_bytes(wheel)
    assert VALIDATE(tmp_path, [_asset("package.whl", wheel), _asset("extra.zip", b"extra")])
    assert VALIDATE(tmp_path, [])
    assert VALIDATE(tmp_path, [_asset("package.whl", b"changed")])


def test_release_asset_inventory_rejects_incomplete_or_ambiguous_entries(tmp_path: Path) -> None:
    wheel = b"wheel"
    (tmp_path / "package.whl").write_bytes(wheel)
    valid = _asset("package.whl", wheel)
    incomplete = {**valid, "state": "starter"}
    missing_digest = {"name": "package.whl", "state": "uploaded"}
    assert VALIDATE(tmp_path, [incomplete])
    assert VALIDATE(tmp_path, [missing_digest])
    assert VALIDATE(tmp_path, [valid, valid])
