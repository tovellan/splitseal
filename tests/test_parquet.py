from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path

import pytest

from splitseal.errors import SplitSealError
from splitseal.loaders import load_records

pytestmark = pytest.mark.parquet


@pytest.mark.skipif(importlib.util.find_spec("pyarrow") is None, reason="PyArrow is optional")
def test_parquet_rows_are_loaded_as_structured_records(tmp_path: Path) -> None:
    pa = importlib.import_module("pyarrow")
    pq = importlib.import_module("pyarrow.parquet")

    path = tmp_path / "input.parquet"
    pq.write_table(pa.table({"id": ["synthetic-1"], "score": [3]}), path)
    assert load_records(path, "parquet") == [{"id": "synthetic-1", "score": 3}]


@pytest.mark.skipif(importlib.util.find_spec("pyarrow") is None, reason="PyArrow is optional")
def test_parquet_preserves_domain_error_for_non_json_values(tmp_path: Path) -> None:
    pa = importlib.import_module("pyarrow")
    pq = importlib.import_module("pyarrow.parquet")

    path = tmp_path / "binary.parquet"
    pq.write_table(pa.table({"id": ["synthetic-1"], "payload": [b"not-json"]}), path)
    with pytest.raises(SplitSealError) as caught:
        load_records(path, "parquet")
    assert caught.value.code == "SS011"
