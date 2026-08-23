# Security policy

## Supported versions

The latest tagged minor release receives security fixes. Version 0.1 is an initial
release and may require a format migration for a severe design defect.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature for this repository. Do not open a
public issue for a suspected vulnerability and do not include private dataset records,
keys, or seals in a report. A maintainer will acknowledge a report within five business
days and will coordinate validation, remediation, and disclosure.

## Scope

Security-sensitive areas include canonicalization ambiguity, path escape, symlink races,
attestation disclosure, cross-split duplicate bypass, seal authentication, key handling,
and unsafe plugin behavior. The documented trust boundaries in
[`docs/threat-model.md`](docs/threat-model.md) are part of the security contract.

## Release publication

The release workflow requires the Git tag to match the package version exactly. It builds
into an empty directory and publishes a sorted `SHA256SUMS` alongside the wheel and source
archive. It uses `gh release create` to attach every asset while the release is still a
draft before publication. Checksums establish download integrity against the GitHub
release; they are not a publisher signature or an independent transparency log. Closure
requires the GitHub Releases API to report `immutable: true` and GitHub's automatic
release attestation to verify. Release v0.2.3 predates repository release immutability
and cannot be made immutable retroactively.

Before checkout, the workflow requires an annotated or signed version-tag object, resolves
it through the GitHub API, and requires the target commit to equal the current protected
`main` commit. It checks out that verified commit SHA. Active repository rules block
updates and deletions of `v*` tags without bypass actors.
