"""Deterministic JSON and SARIF 2.1.0 report rendering."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from splitseal import __version__


def json_report(report: Mapping[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def sarif_report(report: Mapping[str, Any]) -> str:
    status = report.get("status")
    results: list[dict[str, Any]] = []
    if status not in {"pass", "created"}:
        results.append(
            {
                "ruleId": "SPLITSEAL_RESULT",
                "level": "warning",
                "message": {"text": "SplitSeal reported release differences or a failed check."},
                "properties": {"splitsealReport": dict(report)},
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SplitSeal",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/tovellan/splitseal",
                        "rules": [
                            {
                                "id": "SPLITSEAL_RESULT",
                                "shortDescription": {"text": "SplitSeal release check"},
                            }
                        ],
                    }
                },
                "results": results,
                "properties": {"splitsealReport": dict(report)},
            }
        ],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def render_report(report: Mapping[str, Any], format_name: str) -> str:
    if format_name == "json":
        return json_report(report)
    if format_name == "sarif":
        return sarif_report(report)
    raise ValueError(f"unsupported report format: {format_name}")
