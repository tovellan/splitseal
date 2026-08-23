"""Execute the documented SplitSeal workflow in a temporary repository root."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from splitseal import (
    create_signing_material,
    freeze_release,
    sign_public_attestation,
    validate_public_attestation,
    verify_public_signature,
    verify_release,
)
from splitseal.crypto import generate_secret


def main() -> None:
    example_root = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="splitseal-example-") as directory:
        root = Path(directory)
        shutil.copy2(example_root / "splitseal.toml", root / "splitseal.toml")
        shutil.copytree(example_root / "data", root / "data")
        (root / "artifacts").mkdir()
        (root / ".splitseal").mkdir()
        secret = generate_secret()
        created = freeze_release(
            root=root,
            config_path="splitseal.toml",
            seal_path="artifacts/release.sseal",
            attestation_path="artifacts/release.attestation.json",
            secret=secret,
        )
        public_validation = validate_public_attestation(
            root=root,
            attestation_path="artifacts/release.attestation.json",
        )
        signing_key = create_signing_material(
            root=root,
            private_key_path=".splitseal/signing.pem",
            trust_store_path="artifacts/signing-trust.json",
        )
        signature = sign_public_attestation(
            root=root,
            attestation_path="artifacts/release.attestation.json",
            private_key_path=".splitseal/signing.pem",
            signature_path="artifacts/release.signature.json",
        )
        signature_verification = verify_public_signature(
            root=root,
            attestation_path="artifacts/release.attestation.json",
            signature_path="artifacts/release.signature.json",
            trust_store_path="artifacts/signing-trust.json",
        )
        verified = verify_release(
            root=root,
            seal_path="artifacts/release.sseal",
            attestation_path="artifacts/release.attestation.json",
            config_path="splitseal.toml",
            secret=secret,
        )
        print(
            json.dumps(
                {
                    "freeze": created,
                    "public_validation": public_validation,
                    "signature": signature,
                    "signature_key": signing_key,
                    "signature_verification": signature_verification,
                    "verify": verified,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
