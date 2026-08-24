#!/usr/bin/env python3
"""Measure local synthetic exact-only freeze throughput and peak Python memory."""

from __future__ import annotations

import argparse
import json
import tempfile
import time
import tracemalloc
from pathlib import Path

from splitseal import freeze_release

_MINIMUM_RECORDS = 2


def _write_jsonl(path: Path, prefix: str, records: int, payload_bytes: int) -> None:
    payload = "x" * payload_bytes
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for index in range(records):
            stream.write(
                json.dumps(
                    {"id": f"{prefix}-{index:08d}", "payload": payload},
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--records", type=int, default=10_000)
    parser.add_argument("--payload-bytes", type=int, default=128)
    args = parser.parse_args()
    if args.records < _MINIMUM_RECORDS:
        parser.error("--records must be at least 2")
    if args.payload_bytes < 0:
        parser.error("--payload-bytes cannot be negative")

    with tempfile.TemporaryDirectory(prefix="splitseal-stream-benchmark-") as directory:
        root = Path(directory)
        (root / "data").mkdir()
        (root / "artifacts").mkdir()
        first_count = args.records // 2
        second_count = args.records - first_count
        _write_jsonl(root / "data" / "first.jsonl", "first", first_count, args.payload_bytes)
        _write_jsonl(root / "data" / "second.jsonl", "second", second_count, args.payload_bytes)
        (root / "splitseal.toml").write_text(
            """schema_version = "splitseal.config.v1"
[release]
name = "synthetic-stream-benchmark"
version = "1.0.0"
[[splits]]
name = "first"
path = "data/first.jsonl"
format = "jsonl"
[[splits]]
name = "second"
path = "data/second.jsonl"
format = "jsonl"
""",
            encoding="utf-8",
        )
        input_bytes = sum(path.stat().st_size for path in (root / "data").iterdir())
        tracemalloc.start()
        started = time.perf_counter()
        freeze_release(
            root=root,
            config_path="splitseal.toml",
            seal_path="artifacts/release.sseal",
            attestation_path="artifacts/release.attestation.json",
            secret=b"synthetic-benchmark-key-material",
        )
        elapsed = time.perf_counter() - started
        _current, peak_python_bytes = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        print(
            json.dumps(
                {
                    "input_bytes": input_bytes,
                    "payload_bytes": args.payload_bytes,
                    "peak_python_bytes": peak_python_bytes,
                    "records": args.records,
                    "records_per_second": args.records / elapsed,
                    "seconds": elapsed,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
