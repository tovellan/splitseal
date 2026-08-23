# SplitSeal

SplitSeal freezes versioned evaluation datasets without publishing record content,
identifiers, record digests, or split membership. It provides a Python API and command
line interface for JSONL, CSV, and optional Parquet inputs.

SplitSeal is intended for benchmark maintainers and evaluation teams that keep one or
more splits private. It is an integrity control, not a data store, access-control system,
or model evaluator.

## What it produces

`splitseal freeze` writes two files:

- A private seal encrypted with AES-256-GCM. It contains only record digests and release
  metadata, not raw records or identifiers.
- A public attestation containing the release name, release version, aggregate counts,
  check outcomes, and a keyed commitment to the private manifest.

The public attestation does not include unkeyed dataset hashes or per-record commitments.
That design prevents it from becoming a convenient oracle for testing whether a known
record belongs to a private split.

## Install

SplitSeal requires Python 3.11 or newer. The project is not published to a package
registry. Install a tagged source release from GitHub:

```console
python -m pip install "splitseal @ git+https://github.com/tovellan/splitseal.git@v0.3.0"
```

For Parquet input, add the optional dependency after cloning:

```console
python -m pip install ".[parquet]"
```

## Quick start

Create `splitseal.toml` next to your dataset files:

```toml
schema_version = "splitseal.config.v1"

[release]
name = "synthetic-eval"
version = "1.0.0"

[[splits]]
name = "development"
path = "data/development.jsonl"
format = "jsonl"

[[splits]]
name = "private-evaluation"
path = "data/private-evaluation.csv"
format = "csv"
```

Generate a release key. Keep this file private and out of Git:

```console
mkdir -p .splitseal artifacts
splitseal keygen --output .splitseal/release.key
```

Freeze the release:

```console
splitseal freeze splitseal.toml \
  --key-file .splitseal/release.key \
  --seal artifacts/synthetic-eval-1.0.0.sseal \
  --attestation artifacts/synthetic-eval-1.0.0.attestation.json
```

Verify the seal, attestation, and current source files:

```console
splitseal verify \
  --key-file .splitseal/release.key \
  --seal artifacts/synthetic-eval-1.0.0.sseal \
  --attestation artifacts/synthetic-eval-1.0.0.attestation.json \
  --config splitseal.toml
```

Validate only the public attestation's structure, canonical encoding, and redaction
constraints without a seal or key:

```console
splitseal validate-public \
  --attestation artifacts/synthetic-eval-1.0.0.attestation.json
```

This command reports `authentication` as `not_performed`. Structural validity is not
proof of authenticity, dataset origin, or possession of the private manifest.

Optionally create a local Ed25519 signing key and trust store, sign the public
attestation, and authenticate it without the symmetric release key or private seal:

```console
splitseal signing-keygen \
  --private-key .splitseal/signing.pem \
  --trust-store artifacts/signing-trust.json
splitseal sign-public \
  --attestation artifacts/synthetic-eval-1.0.0.attestation.json \
  --private-key .splitseal/signing.pem \
  --signature artifacts/synthetic-eval-1.0.0.signature.json
splitseal verify-signature \
  --attestation artifacts/synthetic-eval-1.0.0.attestation.json \
  --signature artifacts/synthetic-eval-1.0.0.signature.json \
  --trust-store artifacts/signing-trust.json
```

Trust-store provenance is the verifier's responsibility. A replaced trust store can
trust an attacker's key. Revoked keys fail every signature, including older signatures,
because version 1 makes no trusted-time claim.

All commands emit JSON. Pass `--format sarif` to produce SARIF 2.1.0 for CI systems.
Expected failures are JSON objects on standard error with stable `SS` error codes.

The complete synthetic example is in [`examples/synthetic`](examples/synthetic).

## Release properties

- Records use RFC 8785 JSON Canonicalization Scheme bytes.
- SHA-256 hashes use explicit domains and length framing.
- Record order affects a split digest. Split declaration order does not affect a dataset
  digest.
- Exact duplicate records across different splits block a freeze.
- Public split counts are sorted and do not carry split names.
- Private seals use scrypt key derivation and authenticated encryption with random salt
  and nonce values.
- Public attestations are deterministic for the same release, sources, tool version, and
  key. Private seal bytes are intentionally nondeterministic because nonce reuse is
  unsafe.
- Every input and output path is relative to a caller-selected repository root. Absolute
  paths, traversal, non-NFC path spellings, and escaping symlinks are rejected.

## Similarity plugins

Exact matching is built in. Approximate similarity is deliberately delegated to trusted
plugins because suitable methods and operating points vary by data and risk model.
SplitSeal does not define a default threshold. See [`docs/plugin-api.md`](docs/plugin-api.md).

Plugins run in the SplitSeal process and receive private records. Install only plugins
you trust with the full dataset.

## Security and limitations

SplitSeal does not hide aggregate counts or the public release name and version. It does
not provide timestamping, remote transparency, authorization, backup, secure deletion,
or protection after a private key, trust store, or source host is compromised. A keyed
attestation can be verified only by a holder of the release key and private seal.

Read [`docs/threat-model.md`](docs/threat-model.md) before adopting the tool. Report
security problems as described in [`SECURITY.md`](SECURITY.md).

## Development

```console
uv sync --extra dev
make check
```

The full release gate also builds distributions, installs the wheel in a clean virtual
environment, executes the example, audits dependencies, checks tracked files, and scans
Git history for secrets. See [`docs/release-process.md`](docs/release-process.md).

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
