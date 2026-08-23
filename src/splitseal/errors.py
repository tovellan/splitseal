"""Stable error types used by the API and command line interface."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(eq=False)
class SplitSealError(Exception):
    """An expected failure with a machine-readable code."""

    code: str
    message: str
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "details": dict(self.details),
            }
        }


def fail(code: str, message: str, **details: Any) -> SplitSealError:
    return SplitSealError(code=code, message=message, details=details)
