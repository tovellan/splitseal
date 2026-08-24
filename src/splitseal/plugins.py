"""Trusted extension interface for optional similarity analysis."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from importlib.metadata import entry_points
from typing import Any, Protocol, cast

from splitseal.canonical import Record
from splitseal.errors import fail


@dataclass(frozen=True)
class SimilarityFinding:
    left_split: str
    left_index: int
    right_split: str
    right_index: int
    score: float


class SimilarityPlugin(Protocol):
    """Protocol implemented by trusted in-process similarity plugins."""

    name: str
    version: str

    def analyze(
        self,
        splits: Mapping[str, Sequence[Record]],
        settings: Mapping[str, Any],
    ) -> Iterable[SimilarityFinding]: ...


def load_similarity_plugin(name: str) -> SimilarityPlugin:
    try:
        matches = [
            entry for entry in entry_points(group="splitseal.similarity") if entry.name == name
        ]
    except Exception as exc:
        raise fail("SS060", "similarity plugins could not be discovered", plugin=name) from exc
    if len(matches) != 1:
        raise fail("SS060", "similarity plugin is not installed exactly once", plugin=name)
    try:
        plugin = matches[0].load()()
        analyze = plugin.analyze
        plugin_name = plugin.name
        version = plugin.version
    except Exception as exc:
        raise fail("SS060", "similarity plugin could not be loaded", plugin=name) from exc
    if (
        not callable(analyze)
        or not isinstance(plugin_name, str)
        or not plugin_name
        or plugin_name != name
        or not isinstance(version, str)
        or not version
    ):
        raise fail(
            "SS060",
            "similarity plugin does not implement the required interface",
            plugin=name,
        )
    return cast("SimilarityPlugin", plugin)
