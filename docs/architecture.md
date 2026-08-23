# Architecture

SplitSeal has four layers.

1. Strict loaders map JSONL, CSV, or optional Parquet rows to JSON objects. Duplicate
   JSON keys, duplicate CSV headers, non-finite numbers, empty inputs, and ambiguous rows
   are rejected.
2. Canonicalization converts each record to RFC 8785 bytes. Domain-separated SHA-256
   functions hash records, ordered split sequences, and the sorted set of named splits.
3. Release control blocks exact duplicates across different splits and runs configured
   similarity plugins. The resulting private manifest contains hashes and counts, never
   source records or identifiers.
4. Cryptographic output encrypts the private manifest with AES-256-GCM. A separately
   derived HMAC-SHA256 key commits to the canonical manifest in an aggregate-only public
   attestation.

## Data flow

```text
config + source files + private key
              |
       strict root-contained load
              |
     canonical record hashing
              |
  duplicate and optional plugin checks
              |
       private hash manifest
          /               \
  AES-GCM encryption   keyed commitment + aggregates
          |               |
     private .sseal    public attestation
```

Verification decrypts and authenticates the seal, recreates the public attestation, and
uses a constant-time HMAC comparison through the standard library. With `--config`, it
also reloads current sources and requires byte-identical canonical private metadata.

Optional detached signing validates the public attestation, signs domain-separated bytes
with Ed25519, and writes a separate public envelope. Verification uses only the public
attestation, detached envelope, and caller-selected local trust store. It does not touch
the private seal or symmetric release key.

Release diffing decrypts both seals, compares multisets of record digests within split
boundaries, and reports only aggregate additions, removals, and split-count changes.

## Determinism boundary

Canonical record bytes, every content digest, the private manifest plaintext, the public
attestation, JSON reports, and SARIF reports are deterministic for fixed inputs, tool
version, plugin versions, plugin outcomes, and release key.

Private seal bytes are intentionally nondeterministic. AES-GCM requires a unique nonce
for each encryption under a key. SplitSeal also uses a new scrypt salt for each seal.
Verification treats the decrypted canonical manifest as the stable release evidence.
