from __future__ import annotations

import json
import tempfile
import tracemalloc
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

import splitseal.service as service_module
from splitseal.canonical import canonicalize
from splitseal.loaders import iter_records, load_records
from splitseal.models import load_config
from splitseal.service import freeze_release, verify_release
from splitseal.streaming import build_streaming_manifest

from .conftest import SECRET, write_config, write_jsonl


def test_streaming_manifest_and_attestation_match_in_memory(project: Path) -> None:
    config = load_config(project / "splitseal.toml")
    expected_manifest = service_module._build_manifest(config, project)
    expected_attestation = service_module._public_attestation(expected_manifest, SECRET)
    with build_streaming_manifest(config, project) as streamed:
        assert streamed.path.read_bytes() == canonicalize(expected_manifest)
        assert streamed.record_count == 4
        assert streamed.split_counts == (2, 2)

    freeze_release(
        root=project,
        config_path="splitseal.toml",
        seal_path="artifacts/streamed.sseal",
        attestation_path="artifacts/streamed.json",
        secret=SECRET,
    )
    assert (project / "artifacts" / "streamed.json").read_bytes() == (
        canonicalize(expected_attestation) + b"\n"
    )
    assert (
        verify_release(
            root=project,
            seal_path="artifacts/streamed.sseal",
            attestation_path="artifacts/streamed.json",
            config_path="splitseal.toml",
            secret=SECRET,
        )["status"]
        == "pass"
    )


@settings(max_examples=20, deadline=None)
@given(
    development=st.lists(st.integers(min_value=0, max_value=10_000), min_size=1, max_size=12),
    private=st.lists(st.integers(min_value=0, max_value=10_000), min_size=1, max_size=12),
)
def test_streaming_manifest_property_matches_in_memory(
    development: list[int],
    private: list[int],
) -> None:
    with tempfile.TemporaryDirectory(prefix="splitseal-stream-property-") as directory:
        root = Path(directory)
        (root / "data").mkdir()
        write_jsonl(
            root / "data" / "development.jsonl",
            [
                json.dumps({"id": f"development-{index}", "value": value})
                for index, value in enumerate(development)
            ],
        )
        write_jsonl(
            root / "data" / "private.jsonl",
            [
                json.dumps({"id": f"private-{index}", "value": value})
                for index, value in enumerate(private)
            ],
        )
        write_config(root)
        config = load_config(root / "splitseal.toml")
        expected = canonicalize(service_module._build_manifest(config, root))
        with build_streaming_manifest(config, root) as streamed:
            assert streamed.path.read_bytes() == expected


def test_streaming_jsonl_preserves_unicode_splitlines(tmp_path: Path) -> None:
    path = tmp_path / "records.jsonl"
    path.write_text(
        '{"id":1}\r\n{"id":2}\u2028{"id":3}\x85{"id":4}\r{"id":5}\n',
        encoding="utf-8",
    )
    assert list(iter_records(path, "jsonl")) == [
        {"id": 1},
        {"id": 2},
        {"id": 3},
        {"id": 4},
        {"id": 5},
    ]
    assert list(iter_records(path, "jsonl")) == load_records(path, "jsonl")


def test_streaming_csv_matches_list_loader(tmp_path: Path) -> None:
    path = tmp_path / "records.csv"
    path.write_text('id,text\n1,"first\nline"\n2,second\n', encoding="utf-8")
    assert list(iter_records(path, "csv")) == load_records(path, "csv")
    assert next(iter_records(path, "csv"))["text"] == "first\nline"


def test_exact_only_freeze_has_bounded_python_peak(project: Path) -> None:
    payload = "x" * 4096
    records = [
        json.dumps({"id": f"large-{index:05d}", "payload": payload}) for index in range(1000)
    ]
    write_jsonl(project / "data" / "development.jsonl", records)
    write_jsonl(
        project / "data" / "private.jsonl",
        [json.dumps({"id": "private-only", "payload": payload})],
    )
    input_bytes = (project / "data" / "development.jsonl").stat().st_size
    tracemalloc.start()
    try:
        freeze_release(
            root=project,
            config_path="splitseal.toml",
            seal_path="artifacts/bounded.sseal",
            attestation_path="artifacts/bounded.json",
            secret=SECRET,
        )
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < input_bytes // 2
