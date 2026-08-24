"""Authenticated private-manifest sealing and keyed commitments."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from splitseal.canonical import JSONValue, canonicalize
from splitseal.errors import SplitSealError, fail

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
    if not isinstance(value, str) or "=" in value:
        raise fail(
            "SS040",
            "sealed manifest field must be unpadded base64url",
            field=field,
        )
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise fail("SS040", "sealed manifest contains invalid base64url", field=field) from exc
    if _b64encode(decoded) != value:
        raise fail("SS040", "sealed manifest contains noncanonical base64url", field=field)
    return decoded


def _require_fields(value: dict[object, object], expected: set[str], context: str) -> None:
    if set(value) != expected:
        raise fail("SS040", "sealed manifest fields do not match the schema", context=context)


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


def commitment_file(manifest_path: Path, secret: bytes) -> str:
    """Commit to manifest bytes from disk without loading the manifest into memory."""

    digest = hmac.new(_commitment_key(secret), digestmod=hashlib.sha256)
    with manifest_path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _write_base64url(source: BinaryIO, destination: BinaryIO) -> None:
    carry = b""
    while chunk := source.read(64 * 1024):
        data = carry + chunk
        complete = len(data) // 3 * 3
        if complete:
            destination.write(base64.urlsafe_b64encode(data[:complete]))
        carry = data[complete:]
    if carry:
        destination.write(base64.urlsafe_b64encode(carry).rstrip(b"="))


def seal_manifest_file(manifest_path: Path, seal_path: Path, secret: bytes) -> None:
    """Encrypt canonical manifest bytes from disk into a canonical v1 seal."""

    salt = os.urandom(_SALT_BYTES)
    nonce = os.urandom(_NONCE_BYTES)
    descriptor, raw_cipher_path = tempfile.mkstemp(prefix=".splitseal-ciphertext-")
    os.close(descriptor)
    ciphertext_path = Path(raw_cipher_path)
    try:
        encryptor = Cipher(
            algorithms.AES(_encryption_key(secret, salt)),
            modes.GCM(nonce),
        ).encryptor()
        encryptor.authenticate_additional_data(_AAD)
        with manifest_path.open("rb") as manifest, ciphertext_path.open("wb") as ciphertext:
            while chunk := manifest.read(64 * 1024):
                ciphertext.write(encryptor.update(chunk))
            ciphertext.write(encryptor.finalize())
            ciphertext.write(encryptor.tag)
        kdf: JSONValue = {
            "name": "scrypt",
            "n": _KDF_N,
            "r": _KDF_R,
            "p": _KDF_P,
            "salt": _b64encode(salt),
        }
        with seal_path.open("wb") as seal, ciphertext_path.open("rb") as ciphertext:
            seal.write(b'{"cipher":{"ciphertext":"')
            _write_base64url(ciphertext, seal)
            seal.write(b'","name":"aes-256-gcm","nonce":')
            seal.write(canonicalize(_b64encode(nonce)))
            seal.write(b'},"kdf":')
            seal.write(canonicalize(kdf))
            seal.write(b',"schema_version":"splitseal.seal.v1"}\n')
            seal.flush()
            os.fsync(seal.fileno())
    finally:
        ciphertext_path.unlink(missing_ok=True)


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
    if not isinstance(container, dict):
        raise fail("SS040", "sealed manifest must be an object")
    _require_fields(container, {"schema_version", "kdf", "cipher"}, "seal")
    if container.get("schema_version") != SEAL_SCHEMA:
        raise fail("SS040", "sealed manifest has an unsupported schema")
    kdf = container.get("kdf")
    cipher = container.get("cipher")
    if not isinstance(kdf, dict) or not isinstance(cipher, dict):
        raise fail("SS040", "sealed manifest is missing cryptographic parameters")
    _require_fields(kdf, {"name", "n", "r", "p", "salt"}, "kdf")
    _require_fields(cipher, {"name", "nonce", "ciphertext"}, "cipher")
    expected_kdf_integers = {"n": _KDF_N, "r": _KDF_R, "p": _KDF_P}
    if kdf.get("name") != "scrypt" or any(
        type(kdf.get(key)) is not int or kdf.get(key) != value
        for key, value in expected_kdf_integers.items()
    ):
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
    except (RecursionError, UnicodeDecodeError, ValueError) as exc:
        raise fail("SS040", "decrypted manifest is not valid JSON") from exc
    if not isinstance(manifest, dict):
        raise fail("SS040", "decrypted manifest must be an object")
    try:
        canonical = canonicalize(manifest)
    except SplitSealError as exc:
        raise fail("SS040", "decrypted manifest contains invalid JSON values") from exc
    if canonical != plaintext:
        raise fail("SS040", "decrypted manifest is not canonically encoded")
    return manifest
