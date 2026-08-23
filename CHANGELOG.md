# Changelog

All notable changes are recorded here. The format follows Keep a Changelog and the
project uses Semantic Versioning.

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

[0.1.1]: https://github.com/tovellan/splitseal/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/tovellan/splitseal/releases/tag/v0.1.0
