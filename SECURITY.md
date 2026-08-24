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
unsafe plugin behavior, and CI dependency substitution. External GitHub Action references
are release-gated to full commit SHAs. The documented trust boundaries in
[`docs/threat-model.md`](docs/threat-model.md) are part of the security contract.

CI jobs receive read-only repository contents by default and checkout removes persisted
credentials after initial fetch. Jobs have explicit timeouts, and superseded validation
runs are cancelled per ref. Published-release jobs are serialized per tag but never
cancelled by a later run.

## Release publication

The release workflow accepts an existing version tag, builds the distributions, and uses
`gh release create` to attach every asset while the release is still a draft before
publication. Closure requires the GitHub Releases API to report `immutable: true` and
GitHub's automatic release attestation to verify. The GitHub Releases API reports
`immutable: false` for release v0.2.3.

Organization policy enforces immutable releases for this repository. The release job does
not receive an organization Administration token and cannot weaken that prerequisite.
Before checkout, the workflow requires an annotated or signed version-tag object, resolves
it through the GitHub API, and requires a new release target to equal the current protected
`main` commit. Every tag object must use the generic maintainer name and email documented
in the release process plus its exact public annotation. Generated release notes remove
contributor credits and pass the complete public-text policy before draft creation. The
workflow does not print removed account metadata and checks out only the verified commit
SHA. A partial draft rerun
accepts a tag that remains in protected `main` history, verifies existing asset bytes, and
resumes missing uploads without overwriting conflicts. A published-release rerun performs
a protected-tag rebuild and requires exact remote names, SHA-256 digests, and bytes without
uploading or republishing. The build tool is version-pinned, but the hosted runner and
Python minor runtime are not hermetic. A later byte mismatch therefore fails closed as an
integrity error; this check is not a guarantee of indefinite byte-for-byte reproducibility.
Active repository rules block updates and deletions of `v*` tags without bypass actors.
The workflow must itself run from that exact protected tag revision, and the repository's
server-side Actions policy requires immutable action SHA pins.
