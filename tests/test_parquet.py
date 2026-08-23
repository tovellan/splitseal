from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path

import pytest

from splitseal.loaders import load_records

pytestmark = pytest.mark.parquet


@pytest.mark.skipif(importlib.util.find_spec("pyarrow") is None, reason="PyArrow is optional")
def test_parquet_rows_are_loaded_as_structured_records(tmp_path: Path) -> None:
    pa = importlib.import_module("pyarrow")
    pq = importlib.import_module("pyarrow.parquet")

    path = tmp_path / "input.parquet"
    pq.write_table(pa.table({"id": ["synthetic-1"], "score": [3]}), path)
    assert load_records(path, "parquet") == [{"id": "synthetic-1", "score": 3}]
