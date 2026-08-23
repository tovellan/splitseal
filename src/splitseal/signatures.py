"""Optional detached signatures for public attestations."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import splitseal.service as service_module
from splitseal.canonical import JSONValue, canonicalize
from splitseal.errors import fail
from splitseal.paths import safe_input_path, safe_output_path

TRUST_STORE_SCHEMA = "splitseal.trust-store.v1"
SIGNATURE_SCHEMA = "splitseal.detached-signature.v1"
SIGNATURE_ALGORITHM = "ed25519"
_KEY_ID_PREFIX = "ed25519-sha256:"
_KEY_ID = re.compile(r"^ed25519-sha256:[0-9a-f]{64}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE_DOMAIN = b"splitseal-attestation-signature-v1\x00"
_PRIVATE_KEY_MODE = 0o600
_PUBLIC_ARTIFACT_MODE = 0o644
_ED25519_PUBLIC_KEY_BYTES = 32
_ED25519_SIGNATURE_BYTES = 64


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: object, field: str, *, code: str) -> bytes:
    if not isinstance(value, str) or "=" in value:
        raise fail(code, "signature artifact field must be unpadded base64url", field=field)
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (TypeError, ValueError) as exc:
        raise fail(code, "signature artifact contains invalid base64url", field=field) from exc
    if _b64encode(decoded) != value:
        raise fail(code, "signature artifact contains noncanonical base64url", field=field)
    return decoded


def _public_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _key_id(public_key_bytes: bytes) -> str:
    return _KEY_ID_PREFIX + hashlib.sha256(public_key_bytes).hexdigest()


def _key_entry(public_key: Ed25519PublicKey, *, status: str = "active") -> dict[str, str]:
    public_key_bytes = _public_bytes(public_key)
    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": _key_id(public_key_bytes),
        "public_key": _b64encode(public_key_bytes),
        "status": status,
    }


def generate_signing_key() -> tuple[bytes, dict[str, str]]:
    """Generate an Ed25519 private key and its active public trust-store entry."""

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private_bytes, _key_entry(private_key.public_key())


def _load_private_key(data: bytes) -> Ed25519PrivateKey:
    try:
        private_key = serialization.load_pem_private_key(data, password=None)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise fail("SS070", "signing key is not valid unencrypted PKCS8 PEM") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise fail("SS070", "signing key must be an Ed25519 private key")
    return private_key


def _require_fields(
    value: Mapping[str, Any],
    expected: set[str],
    context: str,
    *,
    code: str,
) -> None:
    actual_keys = list(value)
    if not all(isinstance(key, str) for key in actual_keys):
        raise fail(code, "signature artifact field names must be strings", context=context)
    actual = set(actual_keys)
    extra = sorted(actual - expected)
    missing = sorted(expected - actual)
    if extra or missing:
        raise fail(
            code,
            "signature artifact fields do not match the schema",
            context=context,
            extra=extra,
            missing=missing,
        )


def trust_store_bytes(entries: Sequence[Mapping[str, Any]]) -> bytes:
    """Validate public key entries and encode one canonical v1 trust store."""

    parsed = _parse_trust_entries(list(entries))
    ordered_entries = [cast("JSONValue", parsed[key_id][1]) for key_id in sorted(parsed)]
    value: JSONValue = {"schema_version": TRUST_STORE_SCHEMA, "keys": ordered_entries}
    return canonicalize(value) + b"\n"


def _parse_trust_entries(
    entries: object,
) -> dict[str, tuple[Ed25519PublicKey, dict[str, str]]]:
    if not isinstance(entries, list) or not entries:
        raise fail("SS071", "trust store keys must be a non-empty array")
    parsed: dict[str, tuple[Ed25519PublicKey, dict[str, str]]] = {}
    ordered_ids: list[str] = []
    for index, raw_entry in enumerate(entries):
        if not isinstance(raw_entry, dict):
            raise fail("SS071", "trust store key entry must be an object", index=index)
        _require_fields(
            raw_entry,
            {"algorithm", "key_id", "public_key", "status"},
            f"keys[{index}]",
            code="SS071",
        )
        if raw_entry["algorithm"] != SIGNATURE_ALGORITHM:
            raise fail("SS071", "trust store key uses an unsupported algorithm", index=index)
        key_id = raw_entry["key_id"]
        if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
            raise fail("SS071", "trust store key_id is malformed", index=index)
        status = raw_entry["status"]
        if not isinstance(status, str) or status not in {"active", "revoked"}:
            raise fail("SS071", "trust store key status is invalid", key_id=key_id)
        public_bytes = _b64decode(raw_entry["public_key"], "public_key", code="SS071")
        if len(public_bytes) != _ED25519_PUBLIC_KEY_BYTES:
            raise fail("SS071", "trust store Ed25519 public key must contain 32 bytes")
        if _key_id(public_bytes) != key_id:
            raise fail("SS071", "trust store key_id does not match the public key")
        if key_id in parsed:
            raise fail("SS071", "trust store contains a duplicate key_id", key_id=key_id)
        try:
            public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        except ValueError as exc:
            raise fail("SS071", "trust store contains an invalid Ed25519 public key") from exc
        normalized = {
            "algorithm": SIGNATURE_ALGORITHM,
            "key_id": key_id,
            "public_key": _b64encode(public_bytes),
            "status": status,
        }
        parsed[key_id] = (public_key, normalized)
        ordered_ids.append(key_id)
    if ordered_ids != sorted(ordered_ids):
        raise fail("SS071", "trust store key entries must be sorted by key_id")
    return parsed


def _load_trust_store(path: Path) -> dict[str, tuple[Ed25519PublicKey, dict[str, str]]]:
    value = service_module._load_json_file(path, "signature trust store")
    _require_fields(value, {"schema_version", "keys"}, "trust_store", code="SS071")
    if value["schema_version"] != TRUST_STORE_SCHEMA:
        raise fail("SS071", "trust store has an unsupported schema")
    return _parse_trust_entries(value["keys"])


def _signature_message(attestation_bytes: bytes) -> bytes:
    return (
        _SIGNATURE_DOMAIN + len(attestation_bytes).to_bytes(8, byteorder="big") + attestation_bytes
    )


def _attestation_bytes(root: Path, attestation_path: str | Path) -> tuple[bytes, dict[str, Any]]:
    report = service_module.validate_public_attestation(
        root=root,
        attestation_path=attestation_path,
    )
    path = safe_input_path(root, attestation_path)
    value = service_module._load_json_file(path, "public attestation")
    return canonicalize(value), report


def _signature_envelope(value: Mapping[str, Any]) -> dict[str, str]:
    _require_fields(
        value,
        {"schema_version", "algorithm", "key_id", "attestation_sha256", "signature"},
        "signature",
        code="SS072",
    )
    if value["schema_version"] != SIGNATURE_SCHEMA:
        raise fail("SS072", "detached signature has an unsupported schema")
    if value["algorithm"] != SIGNATURE_ALGORITHM:
        raise fail("SS072", "detached signature uses an unsupported algorithm")
    key_id = value["key_id"]
    digest = value["attestation_sha256"]
    signature = value["signature"]
    if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
        raise fail("SS072", "detached signature key_id is malformed")
    if not isinstance(digest, str) or not _SHA256_HEX.fullmatch(digest):
        raise fail("SS072", "detached signature digest must be lowercase SHA-256 hex")
    signature_bytes = _b64decode(signature, "signature", code="SS072")
    if len(signature_bytes) != _ED25519_SIGNATURE_BYTES:
        raise fail("SS072", "detached Ed25519 signature must contain 64 bytes")
    return {
        "schema_version": SIGNATURE_SCHEMA,
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "attestation_sha256": digest,
        "signature": str(signature),
    }


def _atomic_write(target: Path, content: bytes, *, mode: int, force: bool) -> None:
    if target.exists() and not force:
        raise fail("SS004", "output already exists; pass --force to replace it", path=target.name)
    descriptor, raw_path = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary = Path(raw_path)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def create_signing_material(
    *,
    root: Path,
    private_key_path: str | Path,
    trust_store_path: str | Path,
    force: bool = False,
) -> dict[str, Any]:
    """Create one private Ed25519 key and a single-active-key trust store."""

    private_key_file = safe_output_path(root, private_key_path)
    trust_store_file = safe_output_path(root, trust_store_path)
    if private_key_file == trust_store_file:
        raise fail("SS004", "private key and trust store paths must differ")
    private_bytes, entry = generate_signing_key()
    trust_bytes = trust_store_bytes([entry])
    service_module._atomic_write_pair(
        (private_key_file, private_bytes, _PRIVATE_KEY_MODE),
        (trust_store_file, trust_bytes, _PUBLIC_ARTIFACT_MODE),
        force=force,
    )
    return {
        "status": "created",
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": entry["key_id"],
    }


def sign_public_attestation(
    *,
    root: Path,
    attestation_path: str | Path,
    private_key_path: str | Path,
    signature_path: str | Path,
    force: bool = False,
) -> dict[str, Any]:
    """Sign one structurally valid public attestation with a local Ed25519 key."""

    attestation_file = safe_input_path(root, attestation_path)
    private_key_file = safe_input_path(root, private_key_path)
    signature_file = safe_output_path(root, signature_path)
    if signature_file in {attestation_file, private_key_file}:
        raise fail("SS004", "signature output must differ from its input paths")
    attestation_bytes, _validation = _attestation_bytes(root, attestation_path)
    try:
        private_key = _load_private_key(private_key_file.read_bytes())
    except OSError as exc:
        raise fail("SS070", "signing key could not be read", path=private_key_file.name) from exc
    public_bytes = _public_bytes(private_key.public_key())
    digest = hashlib.sha256(attestation_bytes).hexdigest()
    envelope: JSONValue = {
        "schema_version": SIGNATURE_SCHEMA,
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": _key_id(public_bytes),
        "attestation_sha256": digest,
        "signature": _b64encode(private_key.sign(_signature_message(attestation_bytes))),
    }
    _atomic_write(
        signature_file,
        canonicalize(envelope) + b"\n",
        mode=_PUBLIC_ARTIFACT_MODE,
        force=force,
    )
    return {
        "status": "created",
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": _key_id(public_bytes),
        "attestation_sha256": digest,
    }


def verify_public_signature(
    *,
    root: Path,
    attestation_path: str | Path,
    signature_path: str | Path,
    trust_store_path: str | Path,
) -> dict[str, Any]:
    """Authenticate a public attestation against a caller-selected local trust store."""

    attestation_bytes, validation = _attestation_bytes(root, attestation_path)
    signature_file = safe_input_path(root, signature_path)
    trust_store_file = safe_input_path(root, trust_store_path)
    envelope = _signature_envelope(
        service_module._load_json_file(
            signature_file,
            "detached signature",
        )
    )
    trust_store = _load_trust_store(trust_store_file)
    key_id = envelope["key_id"]
    trusted = trust_store.get(key_id)
    if trusted is None:
        raise fail(
            "SS073", "detached signature key is not present in the trust store", key_id=key_id
        )
    public_key, entry = trusted
    if entry["status"] == "revoked":
        raise fail("SS073", "detached signature key is revoked", key_id=key_id)
    actual_digest = hashlib.sha256(attestation_bytes).hexdigest()
    if not hmac.compare_digest(actual_digest, envelope["attestation_sha256"]):
        raise fail("SS074", "detached signature attestation digest does not match")
    signature_bytes = _b64decode(envelope["signature"], "signature", code="SS072")
    try:
        public_key.verify(signature_bytes, _signature_message(attestation_bytes))
    except InvalidSignature as exc:
        raise fail("SS074", "detached signature authentication failed") from exc
    release = validation["release"]
    return {
        "status": "pass",
        "validation": "structural",
        "authentication": "pass",
        "key_status": "active",
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "release": release,
        "checks": {
            "structural_validation": "pass",
            "attestation_digest": "pass",
            "signature_authentication": "pass",
            "key_status": "active",
        },
    }


__all__ = [
    "create_signing_material",
    "generate_signing_key",
    "sign_public_attestation",
    "trust_store_bytes",
    "verify_public_signature",
]
