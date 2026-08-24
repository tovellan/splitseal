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
