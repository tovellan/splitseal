# Contributing

SplitSeal accepts focused bug fixes, security hardening, documentation improvements,
and changes supported by a concrete evaluation-release workflow.

## Development setup

1. Install Python 3.11 or newer and `uv`.
2. Run `uv sync --extra dev`.
3. Run `make check` before opening a pull request.

Tests must use synthetic records and identities. Never attach or commit private dataset
content, private manifests, release keys, production paths, or access tokens.

Changes to canonicalization, manifest schemas, cryptographic parameters, path handling,
or redaction rules require tests for backwards compatibility and adversarial inputs.
Schema changes must use a new schema identifier when an old reader could misinterpret
the result.

Pull requests should explain the problem, compatibility effect, security effect, and
validation performed. By contributing, you agree that your contribution is licensed
under Apache License 2.0.
