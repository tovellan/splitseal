"""Execute the documented SplitSeal workflow in a temporary repository root."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from splitseal import freeze_release, verify_release
from splitseal.crypto import generate_secret


def main() -> None:
    example_root = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="splitseal-example-") as directory:
        root = Path(directory)
        shutil.copy2(example_root / "splitseal.toml", root / "splitseal.toml")
        shutil.copytree(example_root / "data", root / "data")
        (root / "artifacts").mkdir()
        secret = generate_secret()
        created = freeze_release(
            root=root,
            config_path="splitseal.toml",
            seal_path="artifacts/release.sseal",
            attestation_path="artifacts/release.attestation.json",
            secret=secret,
        )
        verified = verify_release(
            root=root,
            seal_path="artifacts/release.sseal",
            attestation_path="artifacts/release.attestation.json",
            config_path="splitseal.toml",
            secret=secret,
        )
        print(json.dumps({"freeze": created, "verify": verified}, sort_keys=True))


if __name__ == "__main__":
    main()
