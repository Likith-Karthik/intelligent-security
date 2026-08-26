"""Default policy for bounded, non-destructive reconnaissance."""

from intelligent_security.domain import ReconPolicy


def default_recon_policy() -> ReconPolicy:
    """Return a fresh immutable-in-practice policy object for the POC."""
    return ReconPolicy()
