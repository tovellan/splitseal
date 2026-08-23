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

The release workflow accepts an existing version tag, builds the distributions, and uses
`gh release create` to attach every asset while the release is still a draft before
publication. Closure requires the GitHub Releases API to report `immutable: true` and
GitHub's automatic release attestation to verify. The GitHub Releases API reports
`immutable: false` for release v0.2.3.

Before checkout, the workflow requires an annotated or signed version-tag object, resolves
it through the GitHub API, and requires the target commit to equal the current protected
`main` commit. Every tag object must use the generic maintainer name and email documented
in the release process. The workflow also requires repository release immutability to be
enabled before checkout, then checks out the verified commit SHA. Active repository rules
block updates and deletions of `v*` tags without bypass actors.
