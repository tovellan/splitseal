# Streaming exact-only freezes

SplitSeal 0.4 uses a disk-spooled streaming path whenever a configuration has no
similarity plugin. Configurations with a trusted similarity plugin retain the original
in-memory path because the plugin protocol receives complete split record sequences.

## Compatibility

The streaming path preserves record order, strict JSONL, CSV, and Parquet decoding,
record digests, exact cross-split duplicate blocking, split roots, dataset roots, private
manifest schema, canonical manifest bytes, public attestation bytes, and error codes.
Tests compare streaming output with the in-memory builder over generated inputs. Private
seal bytes remain intentionally nondeterministic because every seal uses a new salt and
nonce.

## Memory and disk bound

The exact-only path retains one decoded JSONL or CSV record at a time. Parquet retains at
most one 1,024-row decoded batch. Python-side working memory is bounded by the largest
decoded record or Parquet batch, 64 KiB I/O buffers, split metadata, and a 2 MiB SQLite
page cache. The fixed scrypt parameters also require native memory independently of input
size. Verification remains an in-memory operation in 0.4.

Temporary disk use is linear in record count. It includes a SQLite exact-digest index,
ordered hexadecimal digest spools, the canonical private manifest, and encrypted
ciphertext staging. Digest spools and the private manifest live in an owner-only temporary
directory; ciphertext and output staging files are created with mode 0600. Successful and
failed operations remove their temporary files.

## Local benchmark

Run the synthetic benchmark with caller-selected input size:

```console
uv run python benchmarks/bench_streaming.py --records 10000 --payload-bytes 128
```

The command reports measured input bytes, elapsed seconds, records per second, and peak
Python bytes for that invocation. These local measurements are not published performance
claims and vary by host, filesystem, Python version, and cryptographic backend.
