"""SplitSeal public API."""

__version__ = "0.2.1"

from splitseal.canonical import canonicalize, dataset_digest, record_digest
from splitseal.errors import SplitSealError
from splitseal.service import (
    diff_releases,
    freeze_release,
    validate_public_attestation,
    verify_release,
)

__all__ = [
    "SplitSealError",
    "canonicalize",
    "dataset_digest",
    "diff_releases",
    "freeze_release",
    "record_digest",
    "validate_public_attestation",
    "verify_release",
]
