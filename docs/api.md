# Python API

The stable 0.1 API is exported from `splitseal`.

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

## Release operations

```python
from pathlib import Path

from splitseal import freeze_release, verify_release

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
```

Paths are always relative to `root`. Expected failures raise `SplitSealError` with stable
`code`, `message`, and `details` fields. Details are intended for local diagnostics and
may include a caller-supplied file name. Do not publish raw local error logs without
review.
