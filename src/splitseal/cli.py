"""SplitSeal command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from splitseal import __version__
from splitseal.crypto import generate_secret, validate_secret
from splitseal.errors import SplitSealError, fail
from splitseal.paths import safe_input_path, safe_output_path
from splitseal.reporting import render_report
from splitseal.service import (
    diff_releases,
    freeze_release,
    validate_public_attestation,
    verify_release,
)
from splitseal.signatures import (
    create_signing_material,
    sign_public_attestation,
    verify_public_signature,
)


def _parser() -> argparse.ArgumentParser:  # noqa: PLR0915
    parser = argparse.ArgumentParser(
        prog="splitseal",
        description=(
            "Freeze and verify evaluation dataset releases without exposing split membership."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)

    keygen = subcommands.add_parser("keygen", help="create a private 256-bit release key")
    _root_argument(keygen)
    keygen.add_argument("--output", required=True, help="relative key output path")
    keygen.add_argument("--force", action="store_true", help="replace an existing regular file")
    _format_argument(keygen)

    signing_keygen = subcommands.add_parser(
        "signing-keygen",
        help="create an Ed25519 signing key and local trust store",
    )
    _root_argument(signing_keygen)
    signing_keygen.add_argument("--private-key", required=True, help="relative private key path")
    signing_keygen.add_argument("--trust-store", required=True, help="relative trust store path")
    signing_keygen.add_argument(
        "--force",
        action="store_true",
        help="replace both existing output files",
    )
    _format_argument(signing_keygen)

    freeze = subcommands.add_parser("freeze", help="freeze dataset sources into release artifacts")
    _root_argument(freeze)
    freeze.add_argument("config", help="relative path to splitseal.toml")
    freeze.add_argument("--seal", required=True, help="relative private seal output path")
    freeze.add_argument(
        "--attestation",
        required=True,
        help="relative public attestation output path",
    )
    freeze.add_argument("--key-file", required=True, help="relative private key path")
    freeze.add_argument("--force", action="store_true", help="replace existing output files")
    _format_argument(freeze)

    verify = subcommands.add_parser("verify", help="verify frozen release artifacts")
    _root_argument(verify)
    verify.add_argument("--seal", required=True, help="relative private seal path")
    verify.add_argument("--attestation", required=True, help="relative public attestation path")
    verify.add_argument("--key-file", required=True, help="relative private key path")
    verify.add_argument(
        "--config",
        help="optional relative config path for verification against current sources",
    )
    _format_argument(verify)

    validate_public = subcommands.add_parser(
        "validate-public",
        help="validate public attestation structure without authentication",
    )
    _root_argument(validate_public)
    validate_public.add_argument(
        "--attestation",
        required=True,
        help="relative public attestation path",
    )
    _format_argument(validate_public)

    sign_public = subcommands.add_parser(
        "sign-public",
        help="sign a structurally valid public attestation",
    )
    _root_argument(sign_public)
    sign_public.add_argument("--attestation", required=True, help="relative attestation path")
    sign_public.add_argument("--private-key", required=True, help="relative signing key path")
    sign_public.add_argument("--signature", required=True, help="relative signature output path")
    sign_public.add_argument("--force", action="store_true", help="replace existing output file")
    _format_argument(sign_public)

    verify_signature = subcommands.add_parser(
        "verify-signature",
        help="authenticate a public attestation against a local trust store",
    )
    _root_argument(verify_signature)
    verify_signature.add_argument("--attestation", required=True, help="relative attestation path")
    verify_signature.add_argument("--signature", required=True, help="relative signature path")
    verify_signature.add_argument("--trust-store", required=True, help="relative trust store path")
    _format_argument(verify_signature)

    diff = subcommands.add_parser("diff", help="compare two private release seals")
    _root_argument(diff)
    diff.add_argument("--old-seal", required=True, help="relative old seal path")
    diff.add_argument("--new-seal", required=True, help="relative new seal path")
    diff.add_argument("--old-key-file", required=True, help="relative old private key path")
    diff.add_argument("--new-key-file", required=True, help="relative new private key path")
    _format_argument(diff)
    return parser


def _root_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--root",
        default=".",
        help="repository root used as the path containment boundary (default: current directory)",
    )


def _format_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=("json", "sarif"), default="json")


def _read_secret(root: Path, user_path: str) -> bytes:
    path = safe_input_path(root, user_path)
    try:
        secret = path.read_bytes()
    except OSError as exc:
        raise fail("SS041", "private key file could not be read", path=path.name) from exc
    validate_secret(secret)
    return secret


def _write_secret(root: Path, user_path: str, *, force: bool) -> None:
    target = safe_output_path(root, user_path)
    if target.exists() and not force:
        raise fail(
            "SS004",
            "key output already exists; pass --force to replace it",
            path=target.name,
        )
    descriptor, raw_temp = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary = Path(raw_temp)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(generate_secret())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def _execute(args: argparse.Namespace) -> dict[str, Any]:  # noqa: PLR0911
    root = Path(args.root)
    if args.command == "keygen":
        _write_secret(root, args.output, force=args.force)
        return {"status": "created", "key_file": Path(args.output).name}
    if args.command == "signing-keygen":
        return create_signing_material(
            root=root,
            private_key_path=args.private_key,
            trust_store_path=args.trust_store,
            force=args.force,
        )
    if args.command == "freeze":
        return freeze_release(
            root=root,
            config_path=args.config,
            seal_path=args.seal,
            attestation_path=args.attestation,
            secret=_read_secret(root, args.key_file),
            force=args.force,
        )
    if args.command == "verify":
        return verify_release(
            root=root,
            seal_path=args.seal,
            attestation_path=args.attestation,
            secret=_read_secret(root, args.key_file),
            config_path=args.config,
        )
    if args.command == "validate-public":
        return validate_public_attestation(
            root=root,
            attestation_path=args.attestation,
        )
    if args.command == "sign-public":
        return sign_public_attestation(
            root=root,
            attestation_path=args.attestation,
            private_key_path=args.private_key,
            signature_path=args.signature,
            force=args.force,
        )
    if args.command == "verify-signature":
        return verify_public_signature(
            root=root,
            attestation_path=args.attestation,
            signature_path=args.signature,
            trust_store_path=args.trust_store,
        )
    if args.command == "diff":
        return diff_releases(
            root=root,
            old_seal_path=args.old_seal,
            new_seal_path=args.new_seal,
            old_secret=_read_secret(root, args.old_key_file),
            new_secret=_read_secret(root, args.new_key_file),
        )
    raise fail("SS000", "unknown command")


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        report = _execute(args)
    except SplitSealError as exc:
        if args.command == "validate-public" and args.format == "sarif":
            failure = {
                "status": "failed",
                "validation": "structural",
                "authentication": "not_performed",
                **exc.to_dict(),
            }
            sys.stderr.write(render_report(failure, "sarif"))
            return 2
        sys.stderr.write(json.dumps(exc.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
        return 2
    sys.stdout.write(render_report(report, args.format))
    return 0 if report.get("status") in {"pass", "created"} else 1


__all__ = ["main"]
