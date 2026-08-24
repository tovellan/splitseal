"""SplitSeal public API."""

__version__ = "0.4.0"

from splitseal.canonical import canonicalize, dataset_digest, record_digest
from splitseal.errors import SplitSealError
from splitseal.service import (
    diff_releases,
    freeze_release,
    validate_public_attestation,
    verify_release,
)
from splitseal.signatures import (
    create_signing_material,
    generate_signing_key,
    sign_public_attestation,
    trust_store_bytes,
    verify_public_signature,
)

__all__ = [
    "SplitSealError",
    "canonicalize",
    "create_signing_material",
    "dataset_digest",
    "diff_releases",
    "freeze_release",
    "generate_signing_key",
    "record_digest",
    "sign_public_attestation",
    "trust_store_bytes",
    "validate_public_attestation",
    "verify_public_signature",
    "verify_release",
]
