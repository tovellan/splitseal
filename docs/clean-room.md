# Clean-room research record

Date: 2026-08-24

SplitSeal was designed as an independent implementation from public specifications and
public product documentation. Its source was not derived from another benchmark or
private dataset system. All repository fixtures are synthetic.

## Primary sources reviewed

- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) defines a canonical JSON byte
  representation suitable for hashing. SplitSeal uses it for structured records and
  artifact metadata.
- [DVC data versioning](https://dvc.org/doc/user-guide/project-structure/dvc-files)
  tracks data artifacts through hash-bearing pointer files and remote storage. SplitSeal
  does not provide storage or pipeline management.
- [DataLad](https://www.datalad.org/) combines Git and git-annex for distributed dataset
  storage, retrieval, and provenance. SplitSeal does not replace those logistics.
- [Hugging Face Datasets fingerprints](https://huggingface.co/docs/datasets/en/about_cache)
  identify cached dataset state and transforms. SplitSeal instead creates a release
  control that separates private evidence from a redacted public statement.
- [in-toto](https://in-toto.readthedocs.io/en/stable/) defines software supply-chain
  evidence and verification. SplitSeal does not model a general supply chain.
- [The Update Framework specification](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md)
  demonstrates versioned, canonical metadata for secure update systems. SplitSeal does
  not implement TUF roles, delegation, or update delivery.
- [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)
  defines the machine-readable static-analysis report used by the CI output mode.
- [Python pathlib documentation](https://docs.python.org/3.13/library/pathlib.html)
  documents resolving paths before ancestry checks to eliminate parent components and
  resolve symlinks.

## Differentiation decision

A general data versioning tool would duplicate maintained projects. SplitSeal is
therefore limited to a missing release-control boundary for private evaluation splits:

- canonical content evidence inside an authenticated private seal;
- no raw content, identifiers, record digests, split names, or unkeyed dataset hashes in
  the public attestation;
- aggregate counts and deterministic check outcomes for public release notes;
- local verification against current sources by a key holder;
- exact cross-split duplicate blocking and an explicit trusted extension point for
  similarity analysis.

This scope is useful alongside Git, DVC, DataLad, object storage, or a dataset hub. It is
not a replacement for them.

## Dependency licenses

Runtime dependencies are RFC8785 under Apache-2.0 and cryptography under dual Apache-2.0
or BSD-3-Clause terms. The optional PyArrow dependency is Apache-2.0.
The PyYAML development dependency is MIT licensed and parses workflow policy tests.
Development dependencies are not bundled in the wheel. The release gate records an
installed dependency audit and wheel-content review.
