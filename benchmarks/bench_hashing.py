#!/usr/bin/env python3
"""Run a local synthetic canonical hashing throughput benchmark."""

from __future__ import annotations

import argparse
import time

from splitseal import record_digest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--records", type=int, default=10_000)
    args = parser.parse_args()
    if args.records <= 0:
        parser.error("--records must be positive")
    records = [
        {"id": f"synthetic-{index:08d}", "prompt": f"Synthetic prompt {index}", "label": index % 7}
        for index in range(args.records)
    ]
    started = time.perf_counter()
    for record in records:
        record_digest(record)
    elapsed = time.perf_counter() - started
    throughput = args.records / elapsed
    print(f"records={args.records} seconds={elapsed:.6f} records_per_second={throughput:.2f}")


if __name__ == "__main__":
    main()
