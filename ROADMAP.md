# Roadmap

The roadmap is ordered by dependency and user evidence, not by a promised date.

## Delivered in 0.2

- Public-attestation schema validation without an authenticity claim.

## Next candidates

- Detached signatures for public attestations. The key identity, rotation, revocation,
  and wire contract are accepted in `docs/detached-signature-design.md`; implementation
  and test vectors remain pending.
- Streaming manifest construction for datasets that do not use similarity plugins.
- Additional independently maintained similarity plugin examples.

## Later investigations

- Transparency-log integration without introducing a mandatory hosted service.
- Standard provenance envelopes that preserve the no-membership-oracle design.
- Additional structured formats when their canonical type mapping is unambiguous.

SplitSeal will not add model scoring, benchmark task construction, remote dataset
storage, or a universal similarity threshold.
