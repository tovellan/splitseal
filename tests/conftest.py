from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pytest

SECRET = b"synthetic-release-key-material-32"
OTHER_SECRET = b"other-synthetic-key-material-32xx"


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (tmp_path / "data").mkdir()
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / "release.key").write_bytes(SECRET)
    write_jsonl(
        tmp_path / "data" / "development.jsonl",
        [
            '{"id":"dev-001","text":"Synthetic alpha","label":1}',
            '{"id":"dev-002","text":"Synthetic beta","label":2}',
        ],
    )
    write_jsonl(
        tmp_path / "data" / "private.jsonl",
        [
            '{"id":"private-901","text":"Confidential synthetic gamma","label":3}',
            '{"id":"private-902","text":"Confidential synthetic delta","label":4}',
        ],
    )
    write_config(tmp_path)
    return tmp_path


def write_jsonl(path: Path, records: Iterable[str]) -> None:
    path.write_text("\n".join(records) + "\n", encoding="utf-8")


def write_config(root: Path, *, version: str = "1.0.0", similarity: str = "") -> None:
    (root / "splitseal.toml").write_text(
        f'''schema_version = "splitseal.config.v1"

[release]
name = "synthetic-eval"
version = "{version}"

[[splits]]
name = "development"
path = "data/development.jsonl"
format = "jsonl"

[[splits]]
name = "private-evaluation"
path = "data/private.jsonl"
format = "jsonl"
{similarity}
''',
        encoding="utf-8",
    )
