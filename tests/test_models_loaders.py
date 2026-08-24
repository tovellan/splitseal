from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from splitseal.canonical import record_digest
from splitseal.errors import SplitSealError
from splitseal.loaders import iter_records, load_records
from splitseal.models import load_config, parse_config_bytes


def test_load_config_accepts_minimal_valid_document(project: Path) -> None:
    config = load_config(project / "splitseal.toml")
    assert config.release.name == "synthetic-eval"
    assert [split.name for split in config.splits] == ["development", "private-evaluation"]


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"schema_version = 'wrong'", "schema_version"),
        (b"\xff", "UTF-8"),
        (
            b'''schema_version="splitseal.config.v1"\n[release]\nname="x"\nversion="1"''',
            "splits",
        ),
    ],
)
def test_config_rejects_malformed_documents(content: bytes, message: str) -> None:
    with pytest.raises(SplitSealError, match=message) as caught:
        parse_config_bytes(content)
    assert caught.value.code == "SS010"


def test_config_rejects_duplicate_split_names_and_unknown_format() -> None:
    base = """schema_version="splitseal.config.v1"
[release]
name="x"
version="1"
[[splits]]
name="same"
path="one.jsonl"
format="jsonl"
"""
    with pytest.raises(SplitSealError, match="unique"):
        parse_config_bytes(
            (base + '[[splits]]\nname="same"\npath="two.csv"\nformat="csv"').encode()
        )
    with pytest.raises(SplitSealError, match="unsupported"):
        parse_config_bytes(base.replace('format="jsonl"', 'format="xml"').encode())


def test_config_rejects_malformed_similarity_settings() -> None:
    content = b"""schema_version="splitseal.config.v1"
[release]
name="x"
version="1"
[[splits]]
name="one"
path="one.jsonl"
format="jsonl"
[[similarity]]
plugin="p"
settings="bad"
"""
    with pytest.raises(SplitSealError, match="settings"):
        parse_config_bytes(content)


def test_jsonl_loader_rejects_duplicate_keys_blank_lines_and_scalars(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.jsonl"
    duplicate.write_text('{"id":"one","id":"two"}\n', encoding="utf-8")
    with pytest.raises(SplitSealError, match="duplicate"):
        load_records(duplicate, "jsonl")
    duplicate.write_text('{"id":"one"}\n\n', encoding="utf-8")
    with pytest.raises(SplitSealError, match="blank"):
        load_records(duplicate, "jsonl")
    duplicate.write_text('["not-object"]\n', encoding="utf-8")
    with pytest.raises(SplitSealError, match="object"):
        load_records(duplicate, "jsonl")


def test_jsonl_loader_rejects_empty_malformed_and_non_finite(tmp_path: Path) -> None:
    path = tmp_path / "input.jsonl"
    for content in ("", "{bad}\n", '{"value":NaN}\n'):
        path.write_text(content, encoding="utf-8")
        with pytest.raises(SplitSealError):
            load_records(path, "jsonl")


def test_csv_loader_maps_all_values_to_strings(tmp_path: Path) -> None:
    path = tmp_path / "input.csv"
    path.write_text("id,value\none,42\n", encoding="utf-8")
    assert load_records(path, "csv") == [{"id": "one", "value": "42"}]


def test_csv_loader_preserves_normalized_multiline_crlf_compatibility(tmp_path: Path) -> None:
    path = tmp_path / "input.csv"
    path.write_bytes(b'id,text\r\n1,"first\r\nline"\r\n')
    expected = {"id": "1", "text": "first\nline"}
    assert load_records(path, "csv") == [expected]
    assert list(iter_records(path, "csv")) == [expected]
    assert record_digest(load_records(path, "csv")[0]) == (
        "411170b180d64efcff74f35d2e94fd600af8502e35c71636cfa28208a8b8379a"
    )


@pytest.mark.parametrize(
    "content",
    [
        "id,id\none,two\n",
        "id,value,\none,two,three\n",
        "id,value\none\n",
        "id,value\none,two,three\n",
        "id,value\n",
    ],
)
def test_csv_loader_rejects_ambiguous_shapes(tmp_path: Path, content: str) -> None:
    path = tmp_path / "input.csv"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(SplitSealError):
        load_records(path, "csv")


def test_unknown_loader_format_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "input.txt"
    path.write_text("x", encoding="utf-8")
    with pytest.raises(SplitSealError, match="unsupported"):
        load_records(path, "unknown")


def test_parquet_loader_requires_optional_dependency(tmp_path: Path) -> None:
    if importlib.util.find_spec("pyarrow") is not None:
        pytest.skip("missing-dependency branch requires an environment without PyArrow")
    path = tmp_path / "input.parquet"
    path.write_bytes(b"synthetic")
    with pytest.raises(SplitSealError) as caught:
        load_records(path, "parquet")
    assert caught.value.code == "SS022"
