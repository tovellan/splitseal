from __future__ import annotations

import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

from splitseal.canonical import (
    canonicalize,
    dataset_digest,
    ensure_record,
    record_digest,
    sequence_digest,
)
from splitseal.errors import SplitSealError


def test_canonicalization_is_independent_of_object_key_order() -> None:
    left = {"z": 1, "a": [True, None, "é"]}
    right = {"a": [True, None, "é"], "z": 1}
    assert canonicalize(left) == canonicalize(right)
    assert record_digest(left) == record_digest(right)


@given(
    st.dictionaries(
        keys=st.text(min_size=1, max_size=12),
        values=st.one_of(
            st.none(),
            st.booleans(),
            st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1),
            st.text(max_size=30),
        ),
        max_size=12,
    )
)
def test_canonical_output_is_deterministic_for_key_permutations(value: dict[str, object]) -> None:
    reversed_value = dict(reversed(list(value.items())))
    assert canonicalize(value) == canonicalize(reversed_value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf, 2**53, -(2**53)])
def test_canonicalization_rejects_non_interoperable_numbers(value: float | int) -> None:
    with pytest.raises(SplitSealError, match=r"canonical|interoperable") as caught:
        canonicalize({"value": value})
    assert caught.value.code == "SS011"


def test_canonicalization_rejects_non_string_keys_and_objects() -> None:
    with pytest.raises(SplitSealError) as key_error:
        canonicalize({1: "bad"})  # type: ignore[dict-item]
    assert key_error.value.code == "SS011"
    with pytest.raises(SplitSealError) as object_error:
        canonicalize({"bad": {1, 2}})  # type: ignore[dict-item]
    assert object_error.value.code == "SS011"


def test_canonicalization_rejects_excessive_nesting_with_stable_error() -> None:
    value: object = 0
    for _ in range(101):
        value = [value]

    with pytest.raises(SplitSealError) as caught:
        canonicalize(value)  # type: ignore[arg-type]

    assert caught.value.code == "SS011"
    assert caught.value.details["maximum_depth"] == 100

    empty_container: object = []
    for _ in range(100):
        empty_container = [empty_container]
    with pytest.raises(SplitSealError) as empty_caught:
        canonicalize(empty_container)  # type: ignore[arg-type]
    assert empty_caught.value.code == "SS011"
    assert empty_caught.value.details["maximum_depth"] == 100


def test_canonicalization_accepts_exact_nesting_limit() -> None:
    value: object = 0
    for _ in range(100):
        value = [value]
    canonicalize(value)  # type: ignore[arg-type]


def test_sequence_digest_is_order_sensitive() -> None:
    first = record_digest({"id": "one"})
    second = record_digest({"id": "two"})
    assert sequence_digest([first, second]) != sequence_digest([second, first])


@pytest.mark.parametrize("digest", ["not-hex", "ab"])
def test_sequence_digest_rejects_malformed_digest(digest: str) -> None:
    with pytest.raises(SplitSealError) as caught:
        sequence_digest([digest])
    assert caught.value.code == "SS012"


def test_dataset_digest_sorts_split_names_but_includes_counts() -> None:
    root = record_digest({"id": "one"})
    left = dataset_digest({"b": (1, root), "a": (1, root)})
    right = dataset_digest({"a": (1, root), "b": (1, root)})
    assert left == right
    assert left != dataset_digest({"a": (2, root), "b": (1, root)})


def test_dataset_digest_rejects_invalid_inputs() -> None:
    with pytest.raises(SplitSealError):
        dataset_digest({"a": (-1, "00" * 32)})
    with pytest.raises(SplitSealError):
        dataset_digest({"a": (1, "invalid")})
    with pytest.raises(SplitSealError):
        dataset_digest({"a": (1, "00")})


def test_ensure_record_rejects_non_object() -> None:
    with pytest.raises(SplitSealError) as caught:
        ensure_record(["not", "an", "object"], location="test")
    assert caught.value.code == "SS021"
