# Detached signature design

Status: implemented in the 0.3 release line.

This contract defines the trust boundary required by issue 9 before a wire format is
implemented. Detached signatures will remain optional, local-first, and independent of
the symmetric release key and private seal.

## Security boundary

Signing authenticates only the exact canonical bytes of an already public attestation.
It never reads a private seal, release key, source record, record digest, split name, or
source path. Verification establishes that a non-revoked trusted signing key signed those
public bytes. It does not establish dataset quality, timestamping, transparency, or
control of the private manifest.

Trust is relative to the caller-selected trust store. Its provenance and integrity are
an out-of-band caller responsibility. An attacker who can replace that store can trust a
new key and defeat signature authentication. A key identifier identifies only public-key
bytes, not a publisher or legal identity.

## Key identity

Version 1 uses Ed25519. A key identifier is derived, never chosen:

```text
ed25519-sha256:<64 lowercase hexadecimal characters>
```

The hexadecimal suffix is SHA-256 over the 32 raw Ed25519 public-key bytes. Verifiers
recompute it and reject mismatches. Private keys use PKCS8 PEM and owner-only permissions.
Private key bytes never appear in a signature or trust store.

## Rotation and revocation

Trust is an explicit local RFC 8785 canonical-JSON document with one trailing LF. It
contains exactly `schema_version` and `keys`; `schema_version` is
`splitseal.trust-store.v1`, and `keys` is an array. Each key entry contains exactly
`algorithm`, `key_id`, `public_key`, and `status`. `public_key` is unpadded base64url;
`status` is `active` or `revoked`. Entries are unique and sorted by `key_id`. Unknown or
duplicate fields, duplicate key identifiers, unsorted entries, noncanonical encoding,
unsupported schemas, malformed keys, and key-identifier mismatches fail closed.

Rotation adds the successor as active before publishers begin using it. The predecessor
may remain active so historical signatures continue to verify. Revocation changes its
status to revoked; a revoked key fails verification for every signature, including an
older signature. Version 1 has no trusted time source and therefore does not claim that a
signature predates revocation. Time-scoped or delegated trust requires a new schema.

## Detached signature format

The canonical JSON envelope uses schema `splitseal.detached-signature.v1` and contains
exactly these fields:

- `schema_version`: `splitseal.detached-signature.v1`;
- `algorithm`: `ed25519`;
- `key_id`: the derived key identifier;
- `attestation_sha256`: a 64-character lowercase hexadecimal JSON string encoding the
  SHA-256 digest of the canonical attestation bytes;
- `signature`: the 64 Ed25519 signature bytes as unpadded base64url.

The attestation bytes are RFC 8785 canonical JSON without the artifact's trailing LF.
The signed message is the following unambiguous byte sequence:

```text
UTF8("splitseal-attestation-signature-v1") || 0x00 ||
UINT64_BE(length(attestation_bytes)) || attestation_bytes
```

The detached envelope is itself RFC 8785 canonical JSON with one trailing LF. Unknown
fields, duplicate keys, noncanonical encoding, an unknown schema, or a key identifier
mismatch fail closed.

## Command behavior

The signing command structurally validates the public attestation before signing and
writes its detached envelope atomically. The verification command accepts only an
attestation, detached signature, and trust store. It distinguishes
`structural_validation`, `signature_authentication`, and `key_status` in JSON and SARIF.
Malformed keys or envelopes, unknown keys, revoked keys, digest mismatches, and invalid
signatures require stable machine-readable errors.

Existing `splitseal.public-attestation.v1` files, including those produced by 0.1, remain
unchanged and can be signed. Existing seals and symmetric-key verification are unaffected.

## Test-vector coverage

The deterministic public vectors cover active-key success, rotation with two active keys,
revocation failure, wrong-key failure, malformed base64url,
noncanonical and unknown-field envelopes, `attestation_sha256` values with the wrong JSON
type, length, case, or encoding, digest mismatches, unknown or duplicate trust-store
fields, duplicate or unsorted key entries, malformed public keys, trust-store key-identifier
mismatches, modified attestations, and confirmation that neither the envelope nor reports
introduce membership-sensitive fields.
