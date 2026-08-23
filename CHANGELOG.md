# Changelog

All notable changes are recorded here. The format follows Keep a Changelog and the
project uses Semantic Versioning.

## [Unreleased]

### Changed

- Require an exact release-tag and package-version match before building release assets.
- Publish a sorted `SHA256SUMS` file with the wheel and source archive, and refuse stale
  output directories or release-asset overwrites.
- Record Sigstore-signed GitHub build-provenance attestations for the checksummed wheel
  and source archive.
- Scope checksum instructions to releases produced after the new workflow takes effect.
- Scope provenance instructions to releases produced after attestation takes effect.

## [0.2.3] - 2026-08-24

### Added

- Publish the accepted, design-only detached-signature contract for derived key identity,
  rotation, revocation, exact signed bytes, compatibility, and required test vectors.

## [0.2.2] - 2026-08-24

### Changed

- Exercise public-attestation validation, including its explicit no-authentication result,
  from the built wheel in the clean-install release gate.

## [0.2.1] - 2026-08-24

### Changed

- Document the exact public-attestation validation contract, failure codes, and explicit
  no-authentication boundary.
- Align API support and roadmap text with the 0.2 release line.

## [0.2.0] - 2026-08-24

### Added

- Validate public attestation schema, canonical encoding, field types, aggregate
  consistency, and redaction constraints without a private seal or release key.
- Report structural validation separately from keyed authentication in JSON and SARIF.

### Fixed

- Report the installed SplitSeal version in SARIF metadata.

## [0.1.1] - 2026-08-24

### Fixed

- Install private manifests and public attestations as an all-or-nothing artifact pair.
- Restore existing release artifacts after a partial write failure and retain recovery
  backups if rollback cannot complete.

## [0.1.0] - 2026-08-24

### Added

- RFC 8785 canonical serialization and domain-separated SHA-256 hashing.
- Strict JSONL and CSV readers, plus optional Parquet input.
- Encrypted private manifests and aggregate-only public attestations.
- Exact duplicate blocking across splits.
- Trusted similarity plugin protocol without a built-in operating point.
- Freeze, verify, key generation, and aggregate release diff commands.
- JSON and SARIF 2.1.0 reports.
- Repository-root containment, Unicode normalization, and symlink checks.

[Unreleased]: https://github.com/tovellan/splitseal/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/tovellan/splitseal/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/tovellan/splitseal/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/tovellan/splitseal/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/tovellan/splitseal/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/tovellan/splitseal/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/tovellan/splitseal/releases/tag/v0.1.0
