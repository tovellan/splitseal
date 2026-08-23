# Threat model

## Assets

- Private evaluation records and identifiers.
- The association between a record and a split.
- Release keys and encrypted private seals.
- Optional signing private keys and verifier-selected trust stores.
- Integrity of release metadata and source files.

## Trusted components

The host operating system, Python runtime, SplitSeal installation, release key holder,
and configured similarity plugins are trusted. A plugin runs in-process and receives all
records. A malicious plugin can read or transmit the dataset.

## Attacker capabilities

The design considers an attacker who can read the public repository and attestation,
supply malformed dataset files or paths to a CI invocation, compare multiple public
attestations, and modify stored seal bytes. The attacker does not possess the release
key and does not control the trusted host while a freeze runs.

## Controls

- Public output omits records, identifiers, record hashes, split names, source paths, and
  unkeyed content commitments.
- The public commitment is HMAC-SHA256 under a key derived separately from the encryption
  key. It does not support offline membership tests without key material.
- The private manifest is encrypted and authenticated with AES-256-GCM. A random scrypt
  salt and AES-GCM nonce are generated for every seal.
- Source and artifact paths must remain beneath an explicit root after symlink resolution.
  Non-NFC path spellings and traversal forms are rejected.
- Exact canonical duplicates across splits stop a release.
- Private output files are created with owner-only permissions on platforms that support
  POSIX modes.
- Optional Ed25519 signatures authenticate only canonical public-attestation bytes against
  an explicit local trust store. Derived key identifiers do not assert publisher identity.

## Out of scope

- A compromised host, Python interpreter, package dependency, or plugin.
- Replacement or untrusted provenance of the caller-selected signature trust store.
- Disclosure through source file names chosen by a caller outside public artifacts.
- Aggregate-count inference that is inherent in publishing counts.
- Key recovery from weak user-supplied key material. `splitseal keygen` is recommended.
- Hardware-backed keys, remote signing, transparency, timestamping, backup, authorization,
  and secure deletion.
- Filesystem time-of-check to time-of-use attacks by another process with write access to
  the repository during a command.
- Proving that a dataset is scientifically valid or that a similarity method is suitable.

Operate SplitSeal on a controlled host, keep keys outside version control, restrict plugin
installation, and retain private seals in access-controlled storage.
