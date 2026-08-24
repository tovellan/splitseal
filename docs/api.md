# Python API

The stable 0.4 API is exported from `splitseal`.

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

## Detached signatures

```python
from splitseal import (
    create_signing_material,
    sign_public_attestation,
    verify_public_signature,
)

create_signing_material(
    root=Path.cwd(),
    private_key_path=".splitseal/signing.pem",
    trust_store_path="artifacts/signing-trust.json",
)
sign_public_attestation(
    root=Path.cwd(),
    attestation_path="artifacts/release.attestation.json",
    private_key_path=".splitseal/signing.pem",
    signature_path="artifacts/release.signature.json",
)
verify_public_signature(
    root=Path.cwd(),
    attestation_path="artifacts/release.attestation.json",
    signature_path="artifacts/release.signature.json",
    trust_store_path="artifacts/signing-trust.json",
)
```

The verifier accepts no private seal or symmetric release key. Authentication is relative
to the caller-selected trust store. `generate_signing_key` and `trust_store_bytes` support
local rotation workflows that need to assemble multiple sorted active or revoked entries.

Paths are always relative to `root`. Expected failures raise `SplitSealError` with stable
`code`, `message`, and `details` fields. Details are intended for local diagnostics and
may include a caller-supplied file name. Do not publish raw local error logs without
review.

Exact-only `freeze_release` calls use bounded-memory disk spooling automatically.
Configurations containing a similarity plugin retain the in-memory plugin path. Both
paths produce identical canonical private-manifest bytes for the same inputs.
