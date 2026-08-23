# Artifact formats

All artifacts are UTF-8 JSON encoded with RFC 8785 canonicalization and one trailing LF.
Readers reject unsupported schema identifiers.

## Private seal

Schema: `splitseal.seal.v1`

The outer object contains fixed scrypt parameters, a random salt, an AES-256-GCM nonce,
and ciphertext. Binary fields use unpadded base64url. The schema identifier is authenticated
as additional data.

The encrypted `splitseal.private-manifest.v1` object contains:

- tool and release versions;
- canonicalization and digest profile identifiers;
- split names, formats, ordered record digests, split digests, and counts;
- one dataset digest;
- exact-duplicate and similarity-plugin outcomes.

It contains no raw record or identifier value and no source path. The record digests and
split names remain sensitive because they can enable membership testing or reveal release
structure. Keep the seal private even though it is encrypted.

## Public attestation

Schema: `splitseal.public-attestation.v1`

The object contains the tool version, public release name and version, HMAC commitment,
total record and split counts, a sorted list of per-split counts without names, and check
outcomes. It contains no record digest, dataset digest, split name, source path, plugin
setting, or plugin operating point.

The keyed commitment is stable for the same private manifest and release key. A public
reader without the key can inspect aggregate claims but cannot authenticate them.

The `validate-public` command and `validate_public_attestation` Python API enforce the
following exact v1 shape:

- `tool` contains only `name` and `version`, with `name` equal to `splitseal`;
- `release` contains only the public `name` and `version` tokens;
- `commitment` contains only the `hmac-sha256` algorithm and 64-character lowercase
  hexadecimal value;
- `aggregates` contains only non-negative `record_count`, positive `split_count`, and a
  sorted `split_counts` array whose length and sum match those totals;
- `checks` contains only a passing exact-duplicate result and a similarity result of
  `pass` or `not_run`.

Unknown fields fail with `SS046`; malformed or missing schema fields fail with `SS045`;
invalid, duplicate-key, or noncanonical JSON fails with `SS044`. Validation reports
`authentication` and `keyed_authentication` as `not_performed`. It accepts no seal or key,
and it does not prove authenticity or provenance.

## Compatibility

New optional report fields may appear within a 0.2 release. Artifact interpretation does
not change without a new schema identifier. Attestation validation fails closed on unknown
fields as well as an unknown schema so disclosure constraints remain explicit.
