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
archive. It attaches every asset to a draft before publication. Checksums establish
download integrity against the GitHub release; they are not a publisher signature or an
independent transparency log. Closure requires the GitHub Releases API to report
`immutable: true` and GitHub's automatic release attestation to verify. The GitHub Releases
API reports `immutable: false` for release v0.2.3.

Before checkout, the workflow requires an annotated or signed version-tag object, resolves
it through the GitHub API, and requires a new release target to equal the current protected
`main` commit. Every tag object must use the generic maintainer name and email documented
in the release process plus its exact public annotation. Generated release notes pass a
public-metadata check before draft creation. The workflow also requires repository release
immutability before checkout and again immediately before publication, then checks out the
verified commit SHA. A partial draft rerun
accepts a tag that remains in protected `main` history, verifies existing asset bytes, and
resumes missing uploads without overwriting conflicts. A published-release rerun performs
a protected-tag rebuild and requires exact remote names, SHA-256 digests, and bytes without
uploading or republishing. Active repository rules block updates and deletions of `v*` tags
without bypass actors. The workflow must itself run from that exact protected tag revision,
and the repository's server-side Actions policy requires immutable action SHA pins.
