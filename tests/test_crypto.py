from __future__ import annotations

import json

import pytest

from splitseal.canonical import canonicalize
from splitseal.crypto import commitment, generate_secret, open_seal, seal_manifest, validate_secret
from splitseal.errors import SplitSealError

from .conftest import OTHER_SECRET, SECRET


def test_seal_round_trip_and_randomized_encryption() -> None:
    manifest = {"schema_version": "synthetic", "value": [1, 2, 3]}
    first = seal_manifest(manifest, SECRET)
    second = seal_manifest(manifest, SECRET)
    assert first != second
    assert open_seal(json.loads(first), SECRET) == manifest
    assert open_seal(json.loads(second), SECRET) == manifest


def test_commitment_is_deterministic_keyed_and_content_sensitive() -> None:
    payload = canonicalize({"value": 1})
    assert commitment(payload, SECRET) == commitment(payload, SECRET)
    assert commitment(payload, SECRET) != commitment(payload, OTHER_SECRET)
    assert commitment(payload, SECRET) != commitment(canonicalize({"value": 2}), SECRET)


def test_wrong_key_and_ciphertext_tampering_fail_authentication() -> None:
    seal = json.loads(seal_manifest({"value": "synthetic"}, SECRET))
    with pytest.raises(SplitSealError) as wrong_key:
        open_seal(seal, OTHER_SECRET)
    assert wrong_key.value.code == "SS042"
    ciphertext = seal["cipher"]["ciphertext"]
    seal["cipher"]["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
    with pytest.raises(SplitSealError) as tampered:
        open_seal(seal, SECRET)
    assert tampered.value.code == "SS042"


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value.update(schema_version="wrong"),
        lambda value: value.pop("kdf"),
        lambda value: value["kdf"].update(n=1),
        lambda value: value["cipher"].update(name="unknown"),
        lambda value: value["kdf"].update(salt="!"),
        lambda value: value["cipher"].update(nonce="AA"),
    ],
)
def test_malformed_seal_parameters_are_rejected(mutator: object) -> None:
    seal = json.loads(seal_manifest({"value": "synthetic"}, SECRET))
    mutator(seal)  # type: ignore[operator]
    with pytest.raises(SplitSealError) as caught:
        open_seal(seal, SECRET)
    assert caught.value.code == "SS040"


def test_noncanonical_plaintext_is_rejected_after_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The canonicality branch is exercised by replacing only the authenticated decryptor.
    class FakeAES:
        def __init__(self, _key: bytes) -> None:
            pass

        def decrypt(self, _nonce: bytes, _ciphertext: bytes, _aad: bytes) -> bytes:
            return b'{"z": 1, "a": 2}'

    seal = json.loads(seal_manifest({"value": "synthetic"}, SECRET))
    monkeypatch.setattr("splitseal.crypto.AESGCM", FakeAES)
    with pytest.raises(SplitSealError, match="canonically"):
        open_seal(seal, SECRET)


@pytest.mark.parametrize("depth", [101, 2_000])
def test_nested_decrypted_manifest_is_rejected_with_stable_error(
    monkeypatch: pytest.MonkeyPatch,
    depth: int,
) -> None:
    plaintext = b'{"value":' + b"[" * depth + b"0" + b"]" * depth + b"}"

    class FakeAES:
        def __init__(self, _key: bytes) -> None:
            pass

        def decrypt(self, _nonce: bytes, _ciphertext: bytes, _aad: bytes) -> bytes:
            return plaintext

    seal = json.loads(seal_manifest({"value": "synthetic"}, SECRET))
    monkeypatch.setattr("splitseal.crypto.AESGCM", FakeAES)
    with pytest.raises(SplitSealError) as caught:
        open_seal(seal, SECRET)
    assert caught.value.code == "SS040"


def test_key_material_has_a_minimum_length() -> None:
    with pytest.raises(SplitSealError) as caught:
        validate_secret(b"short")
    assert caught.value.code == "SS041"
    assert len(generate_secret()) == 32
