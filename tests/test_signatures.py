from __future__ import annotations

import base64
import hashlib
import json
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from splitseal.canonical import canonicalize
from splitseal.cli import main
from splitseal.errors import SplitSealError
from splitseal.service import freeze_release
from splitseal.signatures import (
    create_signing_material,
    sign_public_attestation,
    trust_store_bytes,
    verify_public_signature,
)

from .conftest import SECRET


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _material(seed_start: int) -> tuple[bytes, dict[str, str]]:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(seed_start, seed_start + 32)))
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_bytes, {
        "algorithm": "ed25519",
        "key_id": "ed25519-sha256:" + hashlib.sha256(public_bytes).hexdigest(),
        "public_key": _b64(public_bytes),
        "status": "active",
    }


def _freeze(project: Path, *, tool_version: str | None = None) -> Path:
    freeze_release(
        root=project,
        config_path="splitseal.toml",
        seal_path="artifacts/signature.sseal",
        attestation_path="artifacts/signature.attestation.json",
        secret=SECRET,
    )
    path = project / "artifacts" / "signature.attestation.json"
    if tool_version is not None:
        value = json.loads(path.read_bytes())
        value["tool"]["version"] = tool_version
        path.write_bytes(canonicalize(value) + b"\n")
    return path


def _write_material(project: Path, seed_start: int, name: str) -> dict[str, str]:
    private_bytes, entry = _material(seed_start)
    (project / "keys" / f"{name}.pem").write_bytes(private_bytes)
    return entry


def _sign(project: Path, name: str = "first") -> dict[str, Any]:
    return sign_public_attestation(
        root=project,
        attestation_path="artifacts/signature.attestation.json",
        private_key_path=f"keys/{name}.pem",
        signature_path=f"artifacts/{name}.signature.json",
    )


def _verify(project: Path, name: str = "first") -> dict[str, Any]:
    return verify_public_signature(
        root=project,
        attestation_path="artifacts/signature.attestation.json",
        signature_path=f"artifacts/{name}.signature.json",
        trust_store_path="keys/trust.json",
    )


def test_create_sign_verify_and_redaction_boundary(project: Path) -> None:
    _freeze(project)
    created = create_signing_material(
        root=project,
        private_key_path="keys/signing.pem",
        trust_store_path="keys/trust.json",
    )
    assert created["status"] == "created"
    assert created["algorithm"] == "ed25519"
    assert created["key_id"].startswith("ed25519-sha256:")
    assert stat.S_IMODE((project / "keys" / "signing.pem").stat().st_mode) == 0o600

    signed = sign_public_attestation(
        root=project,
        attestation_path="artifacts/signature.attestation.json",
        private_key_path="keys/signing.pem",
        signature_path="artifacts/signature.json",
    )
    verified = verify_public_signature(
        root=project,
        attestation_path="artifacts/signature.attestation.json",
        signature_path="artifacts/signature.json",
        trust_store_path="keys/trust.json",
    )
    assert signed["status"] == "created"
    assert verified["authentication"] == "pass"
    assert verified["key_status"] == "active"
    assert verified["checks"] == {
        "structural_validation": "pass",
        "attestation_digest": "pass",
        "signature_authentication": "pass",
        "key_status": "active",
    }
    public_outputs = (
        (project / "artifacts" / "signature.json").read_bytes()
        + (project / "keys" / "trust.json").read_bytes()
        + json.dumps(verified).encode()
    )
    for forbidden in (
        b"record_digests",
        b"content_digest",
        b"private-evaluation",
        b"development",
        b"private-901",
    ):
        assert forbidden not in public_outputs


def test_fixed_key_signature_is_deterministic_and_accepts_0_1_attestation(project: Path) -> None:
    _freeze(project, tool_version="0.1.0")
    entry = _write_material(project, 0, "first")
    (project / "keys" / "trust.json").write_bytes(trust_store_bytes([entry]))
    first = _sign(project)
    first_bytes = (project / "artifacts" / "first.signature.json").read_bytes()
    (project / "artifacts" / "first.signature.json").unlink()
    second = _sign(project)
    assert first == second
    assert first_bytes == (project / "artifacts" / "first.signature.json").read_bytes()
    assert _verify(project)["authentication"] == "pass"


def test_rotation_and_all_history_revocation(project: Path) -> None:
    _freeze(project)
    first_entry = _write_material(project, 0, "first")
    second_entry = _write_material(project, 32, "second")
    active_entries = sorted([first_entry, second_entry], key=lambda entry: entry["key_id"])
    (project / "keys" / "trust.json").write_bytes(trust_store_bytes(active_entries))
    _sign(project, "first")
    _sign(project, "second")
    assert _verify(project, "first")["authentication"] == "pass"
    assert _verify(project, "second")["authentication"] == "pass"

    revoked_entries = [dict(entry) for entry in active_entries]
    for entry in revoked_entries:
        if entry["key_id"] == first_entry["key_id"]:
            entry["status"] = "revoked"
    (project / "keys" / "trust.json").write_bytes(trust_store_bytes(revoked_entries))
    with pytest.raises(SplitSealError) as revoked:
        _verify(project, "first")
    assert revoked.value.code == "SS073"
    assert _verify(project, "second")["authentication"] == "pass"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"unknown": True}),
        lambda value: value.pop("algorithm"),
        lambda value: value.update({"schema_version": "unknown"}),
        lambda value: value.update({"algorithm": "rsa"}),
        lambda value: value.update({"algorithm": []}),
        lambda value: value.update({"key_id": 4}),
        lambda value: value.update({"key_id": {}}),
        lambda value: value.update({"attestation_sha256": []}),
        lambda value: value.update({"attestation_sha256": {}}),
        lambda value: value.update({"attestation_sha256": "0" * 63}),
        lambda value: value.update({"attestation_sha256": "A" * 64}),
        lambda value: value.update({"attestation_sha256": "g" * 64}),
        lambda value: value.update({"signature": "="}),
        lambda value: value.update({"signature": {}}),
        lambda value: value.update({"signature": _b64(b"short")}),
    ],
)
def test_malformed_signature_envelopes_fail_closed(
    project: Path,
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    _freeze(project)
    entry = _write_material(project, 0, "first")
    (project / "keys" / "trust.json").write_bytes(trust_store_bytes([entry]))
    _sign(project)
    path = project / "artifacts" / "first.signature.json"
    value = json.loads(path.read_bytes())
    mutation(value)
    path.write_bytes(canonicalize(value) + b"\n")
    with pytest.raises(SplitSealError) as caught:
        _verify(project)
    assert caught.value.code == "SS072"


def test_noncanonical_signature_and_cryptographic_mismatches(project: Path) -> None:
    _freeze(project)
    entry = _write_material(project, 0, "first")
    (project / "keys" / "trust.json").write_bytes(trust_store_bytes([entry]))
    _sign(project)
    path = project / "artifacts" / "first.signature.json"
    original = json.loads(path.read_bytes())
    correct_digest = original["attestation_sha256"]
    path.write_text(json.dumps(original, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(SplitSealError) as noncanonical:
        _verify(project)
    assert noncanonical.value.code == "SS044"

    original["attestation_sha256"] = "0" * 64
    path.write_bytes(canonicalize(original) + b"\n")
    with pytest.raises(SplitSealError) as digest:
        _verify(project)
    assert digest.value.code == "SS074"

    original["attestation_sha256"] = correct_digest
    original["signature"] = _b64(bytes(64))
    path.write_bytes(canonicalize(original) + b"\n")
    with pytest.raises(SplitSealError) as authentication:
        _verify(project)
    assert authentication.value.code == "SS074"


def test_modified_attestation_fails_signature_digest_check(project: Path) -> None:
    attestation_path = _freeze(project)
    entry = _write_material(project, 0, "first")
    (project / "keys" / "trust.json").write_bytes(trust_store_bytes([entry]))
    _sign(project)
    attestation = json.loads(attestation_path.read_bytes())
    attestation["release"]["version"] = "1.0.1"
    attestation_path.write_bytes(canonicalize(attestation) + b"\n")
    with pytest.raises(SplitSealError) as modified:
        _verify(project)
    assert modified.value.code == "SS074"


def test_unknown_key_and_malformed_private_key(project: Path) -> None:
    _freeze(project)
    _write_material(project, 0, "first")
    second_entry = _write_material(project, 32, "second")
    (project / "keys" / "trust.json").write_bytes(trust_store_bytes([second_entry]))
    _sign(project)
    with pytest.raises(SplitSealError) as unknown:
        _verify(project)
    assert unknown.value.code == "SS073"

    (project / "keys" / "first.pem").write_text("not a key", encoding="utf-8")
    (project / "artifacts" / "first.signature.json").unlink()
    with pytest.raises(SplitSealError) as malformed:
        _sign(project)
    assert malformed.value.code == "SS070"

    rsa_key = generate_private_key(public_exponent=65537, key_size=2048)
    (project / "keys" / "first.pem").write_bytes(
        rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    with pytest.raises(SplitSealError) as wrong_type:
        _sign(project)
    assert wrong_type.value.code == "SS070"


def test_trust_store_schema_and_entry_failures(project: Path) -> None:
    _freeze(project)
    first_entry = _write_material(project, 0, "first")
    second_entry = _write_material(project, 32, "second")
    _sign(project)
    valid = {
        "schema_version": "splitseal.trust-store.v1",
        "keys": sorted([first_entry, second_entry], key=lambda entry: entry["key_id"]),
    }
    mutations: list[Callable[[dict[str, Any]], None]] = [
        lambda value: value.update({"unknown": True}),
        lambda value: value.update({"schema_version": "unknown"}),
        lambda value: value.update({"keys": []}),
        lambda value: value.update({"keys": {}}),
        lambda value: value.update({"keys": [4]}),
        lambda value: value["keys"][0].update({"unknown": True}),
        lambda value: value["keys"][0].update({"algorithm": "rsa"}),
        lambda value: value["keys"][0].update({"algorithm": []}),
        lambda value: value["keys"][0].update({"key_id": "bad"}),
        lambda value: value["keys"][0].update({"key_id": {}}),
        lambda value: value["keys"][0].update({"status": "unknown"}),
        lambda value: value["keys"][0].update({"status": []}),
        lambda value: value["keys"][0].update({"status": {}}),
        lambda value: value["keys"][0].update({"public_key": "="}),
        lambda value: value["keys"][0].update({"public_key": {}}),
        lambda value: value["keys"][0].update({"public_key": _b64(b"short")}),
        lambda value: value["keys"][0].update({"public_key": _b64(bytes(32))}),
        lambda value: value.update({"keys": [value["keys"][0], value["keys"][0]]}),
        lambda value: value.update({"keys": list(reversed(value["keys"]))}),
    ]
    path = project / "keys" / "trust.json"
    for mutation in mutations:
        value = json.loads(json.dumps(valid))
        mutation(value)
        path.write_bytes(canonicalize(value) + b"\n")
        with pytest.raises(SplitSealError) as caught:
            _verify(project)
        assert caught.value.code == "SS071"


@pytest.mark.parametrize("status", [[], {}])
def test_trust_store_container_status_has_machine_cli_error(
    project: Path,
    capsys: pytest.CaptureFixture[str],
    status: object,
) -> None:
    _freeze(project)
    entry = _write_material(project, 0, "first")
    _sign(project)
    malformed_entry: dict[str, Any] = dict(entry)
    malformed_entry["status"] = status
    (project / "keys" / "trust.json").write_bytes(
        canonicalize({"schema_version": "splitseal.trust-store.v1", "keys": [malformed_entry]})
        + b"\n"
    )
    assert (
        main(
            [
                "verify-signature",
                "--root",
                str(project),
                "--attestation",
                "artifacts/signature.attestation.json",
                "--signature",
                "artifacts/first.signature.json",
                "--trust-store",
                "keys/trust.json",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "SS071"


def test_key_material_refuses_equal_paths_and_overwrite(project: Path) -> None:
    with pytest.raises(SplitSealError) as equal:
        create_signing_material(
            root=project,
            private_key_path="keys/same",
            trust_store_path="keys/same",
        )
    assert equal.value.code == "SS004"
    create_signing_material(
        root=project,
        private_key_path="keys/signing.pem",
        trust_store_path="keys/trust.json",
    )
    with pytest.raises(SplitSealError) as overwrite:
        create_signing_material(
            root=project,
            private_key_path="keys/signing.pem",
            trust_store_path="keys/trust.json",
        )
    assert overwrite.value.code == "SS004"


def test_signature_output_refuses_inputs_and_overwrite(project: Path) -> None:
    _freeze(project)
    _write_material(project, 0, "first")
    _sign(project)
    with pytest.raises(SplitSealError) as overwrite:
        _sign(project)
    assert overwrite.value.code == "SS004"
    with pytest.raises(SplitSealError) as attestation_collision:
        sign_public_attestation(
            root=project,
            attestation_path="artifacts/signature.attestation.json",
            private_key_path="keys/first.pem",
            signature_path="artifacts/signature.attestation.json",
            force=True,
        )
    assert attestation_collision.value.code == "SS004"
    with pytest.raises(SplitSealError) as key_collision:
        sign_public_attestation(
            root=project,
            attestation_path="artifacts/signature.attestation.json",
            private_key_path="keys/first.pem",
            signature_path="keys/first.pem",
            force=True,
        )
    assert key_collision.value.code == "SS004"


def test_signature_cli_workflow_and_machine_error(
    project: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _freeze(project)
    assert (
        main(
            [
                "signing-keygen",
                "--root",
                str(project),
                "--private-key",
                "keys/cli-signing.pem",
                "--trust-store",
                "keys/cli-trust.json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "created"
    assert (
        main(
            [
                "sign-public",
                "--root",
                str(project),
                "--attestation",
                "artifacts/signature.attestation.json",
                "--private-key",
                "keys/cli-signing.pem",
                "--signature",
                "artifacts/cli-signature.json",
            ]
        )
        == 0
    )
    capsys.readouterr()
    verify_args = [
        "verify-signature",
        "--root",
        str(project),
        "--attestation",
        "artifacts/signature.attestation.json",
        "--signature",
        "artifacts/cli-signature.json",
        "--trust-store",
        "keys/cli-trust.json",
        "--format",
        "sarif",
    ]
    assert main(verify_args) == 0
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["runs"][0]["properties"]["splitsealReport"]["authentication"] == "pass"

    signature_path = project / "artifacts" / "cli-signature.json"
    value = json.loads(signature_path.read_bytes())
    value["signature"] = _b64(bytes(64))
    signature_path.write_bytes(canonicalize(value) + b"\n")
    assert main(verify_args[:-2]) == 2
    error = json.loads(capsys.readouterr().err)
    assert error["error"]["code"] == "SS074"
