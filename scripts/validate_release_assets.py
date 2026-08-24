#!/usr/bin/env python3
"""Require an exact release-asset name and SHA-256 digest set."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_release_assets(local_dir: Path, inventory: object) -> list[str]:
    violations: list[str] = []
    if not isinstance(inventory, list) or not all(isinstance(item, dict) for item in inventory):
        return ["invalid remote asset inventory"]
    local = {
        path.name: f"sha256:{_sha256(path)}"
        for path in local_dir.iterdir()
        if path.is_file() and not path.is_symlink()
    }
    remote: dict[str, str] = {}
    for item in inventory:
        name = item.get("name")
        digest = item.get("digest")
        state = item.get("state")
        if not isinstance(name, str) or not name or name in remote:
            violations.append("invalid or duplicate remote asset name")
            continue
        if state != "uploaded":
            violations.append(f"remote asset is incomplete: {name}")
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            violations.append(f"remote asset is missing a SHA-256 digest: {name}")
            continue
        remote[name] = digest
    if set(local) != set(remote):
        violations.append("remote asset names do not match the verified build")
    violations.extend(
        f"remote asset digest does not match the verified build: {name}"
        for name in sorted(set(local) & set(remote))
        if local[name] != remote[name]
    )
    return violations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--local-dir", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    arguments = parser.parse_args()
    inventory = json.loads(arguments.inventory.read_text(encoding="utf-8"))
    violations = validate_release_assets(arguments.local_dir, inventory)
    if violations:
        print("release asset validation failed: " + "; ".join(violations))
        return 1
    print("release asset validation: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
