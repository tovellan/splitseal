"""Authenticated private-manifest sealing and keyed commitments."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from splitseal.canonical import JSONValue, canonicalize
from splitseal.errors import fail

SEAL_SCHEMA = "splitseal.seal.v1"
_AAD = SEAL_SCHEMA.encode("ascii")
_KDF_N = 2**15
_KDF_R = 8
_KDF_P = 1
_MINIMUM_SECRET_BYTES = 16
_SALT_BYTES = 16
_NONCE_BYTES = 12


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: object, field: str) -> bytes:
    if not isinstance(value, str):
        raise fail("SS040", "sealed manifest field must be a string", field=field)
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise fail("SS040", "sealed manifest contains invalid base64url", field=field) from exc


def validate_secret(secret: bytes) -> None:
    if not isinstance(secret, bytes):
        raise fail("SS041", "key material must be bytes")
    if len(secret) < _MINIMUM_SECRET_BYTES:
        raise fail("SS041", "key material must contain at least 16 bytes")


def generate_secret() -> bytes:
    return os.urandom(32)


def _encryption_key(secret: bytes, salt: bytes) -> bytes:
    validate_secret(secret)
    return Scrypt(salt=salt, length=32, n=_KDF_N, r=_KDF_R, p=_KDF_P).derive(secret)


def _commitment_key(secret: bytes) -> bytes:
    validate_secret(secret)
    return HKDF(
        algorithm=hashlib_to_cryptography_sha256(),
        length=32,
        salt=None,
        info=b"splitseal-public-commitment-v1",
    ).derive(secret)


def hashlib_to_cryptography_sha256() -> HashAlgorithm:
    return hashes.SHA256()


def commitment(manifest_bytes: bytes, secret: bytes) -> str:
    return hmac.new(_commitment_key(secret), manifest_bytes, hashlib.sha256).hexdigest()


def seal_manifest(manifest: JSONValue, secret: bytes) -> bytes:
    plaintext = canonicalize(manifest)
    salt = os.urandom(_SALT_BYTES)
    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(_encryption_key(secret, salt)).encrypt(nonce, plaintext, _AAD)
    container: JSONValue = {
        "schema_version": SEAL_SCHEMA,
        "kdf": {
            "name": "scrypt",
            "n": _KDF_N,
            "r": _KDF_R,
            "p": _KDF_P,
            "salt": _b64encode(salt),
        },
        "cipher": {
            "name": "aes-256-gcm",
            "nonce": _b64encode(nonce),
            "ciphertext": _b64encode(ciphertext),
        },
    }
    return canonicalize(container) + b"\n"


def open_seal(container: object, secret: bytes) -> dict[str, JSONValue]:
    if not isinstance(container, dict) or container.get("schema_version") != SEAL_SCHEMA:
        raise fail("SS040", "sealed manifest has an unsupported schema")
    kdf = container.get("kdf")
    cipher = container.get("cipher")
    if not isinstance(kdf, dict) or not isinstance(cipher, dict):
        raise fail("SS040", "sealed manifest is missing cryptographic parameters")
    expected_kdf = {"name": "scrypt", "n": _KDF_N, "r": _KDF_R, "p": _KDF_P}
    if any(kdf.get(key) != value for key, value in expected_kdf.items()):
        raise fail("SS040", "sealed manifest uses unsupported KDF parameters")
    if cipher.get("name") != "aes-256-gcm":
        raise fail("SS040", "sealed manifest uses an unsupported cipher")
    salt = _b64decode(kdf.get("salt"), "kdf.salt")
    nonce = _b64decode(cipher.get("nonce"), "cipher.nonce")
    ciphertext = _b64decode(cipher.get("ciphertext"), "cipher.ciphertext")
    if len(salt) != _SALT_BYTES or len(nonce) != _NONCE_BYTES:
        raise fail("SS040", "sealed manifest has invalid cryptographic parameter lengths")
    try:
        plaintext = AESGCM(_encryption_key(secret, salt)).decrypt(nonce, ciphertext, _AAD)
    except InvalidTag as exc:
        raise fail("SS042", "sealed manifest authentication failed") from exc
    try:
        manifest = json.loads(plaintext)
    except (UnicodeDecodeError, ValueError) as exc:
        raise fail("SS040", "decrypted manifest is not valid JSON") from exc
    if not isinstance(manifest, dict):
        raise fail("SS040", "decrypted manifest must be an object")
    if canonicalize(manifest) != plaintext:
        raise fail("SS040", "decrypted manifest is not canonically encoded")
    return manifest
