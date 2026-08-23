# Python API

The stable 0.2 API is exported from `splitseal`.

## Canonicalization

```python
from splitseal import canonicalize, record_digest

record = {"prompt": "Synthetic question", "expected": 4}
encoded = canonicalize(record)
digest = record_digest(record)
```

`canonicalize` accepts JSON-compatible values in the RFC 8785 interoperable domain.
It rejects non-string object keys, non-finite floats, unsupported objects, and integers
outside the exactly interoperable range.

`dataset_digest` accepts string split names paired with a non-negative 64-bit record
count and exactly 64 lowercase or uppercase hexadecimal SHA-256 characters.
`sequence_digest` applies the same exact grammar to each record digest from a one-pass
iterable. Text and byte containers are not treated as iterables of digests. Whitespace is
not accepted. Invalid runtime types, encodings, lengths, and count ranges fail with
`SS012`.

## Release operations

```python
from pathlib import Path

from splitseal import freeze_release, validate_public_attestation, verify_release

secret = Path(".splitseal/release.key").read_bytes()
freeze_release(
    root=Path.cwd(),
    config_path="splitseal.toml",
    seal_path="artifacts/release.sseal",
    attestation_path="artifacts/release.attestation.json",
    secret=secret,
)
verify_release(
    root=Path.cwd(),
    seal_path="artifacts/release.sseal",
    attestation_path="artifacts/release.attestation.json",
    config_path="splitseal.toml",
    secret=secret,
)
validate_public_attestation(
    root=Path.cwd(),
    attestation_path="artifacts/release.attestation.json",
)
```

`validate_public_attestation` accepts only a public attestation path. It validates the
schema, RFC 8785 encoding, field types, aggregate consistency, and redaction constraints.
It does not authenticate the commitment or establish provenance, and its report always
marks keyed authentication as `not_performed`.

Paths are always relative to `root`. Expected failures raise `SplitSealError` with stable
`code`, `message`, and `details` fields. Details are intended for local diagnostics and
may include a caller-supplied file name. Do not publish raw local error logs without
review.
