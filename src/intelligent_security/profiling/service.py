from datetime import datetime, timezone

from intelligent_security.domain import Audit, TargetProfile
from intelligent_security.policy.scope import _normalize_network_asset, _normalize_url


class TargetProfilingError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _authentication_status(audit: Audit) -> str:
    return "credential_reference_available" if audit.credential_references else "unknown"


def profile_target(audit: Audit) -> TargetProfile:
    """Build a deterministic profile from already authorized target metadata.

    This first profiler deliberately performs no DNS, HTTP, port, or repository
    access. Active discovery will be added later as an explicitly approved
    capability, not as a side effect of profiling.
    """
    target_type = audit.target.target_type
    identifier = audit.target.identifier
    profiled_at = datetime.now(timezone.utc)

    if target_type in {"web_application", "api", "llm_application"}:
        canonical_identifier, _ = _normalize_url(identifier)
        return TargetProfile(
            profile_version="1",
            profile_method="declared_metadata",
            target_type=target_type,
            canonical_identifier=canonical_identifier,
            interfaces=[canonical_identifier],
            technologies=[],
            source_available=False,
            authentication=_authentication_status(audit),
            confidence=0.75,
            profiled_at=profiled_at,
        )

    if target_type == "source_repository":
        canonical_identifier, _ = _normalize_url(identifier)
        return TargetProfile(
            profile_version="1",
            profile_method="declared_metadata",
            target_type=target_type,
            canonical_identifier=canonical_identifier,
            interfaces=[canonical_identifier],
            technologies=[],
            source_available=True,
            authentication=_authentication_status(audit),
            confidence=0.75,
            profiled_at=profiled_at,
        )

    if target_type == "network_host":
        canonical_identifier = _normalize_network_asset(identifier)
        return TargetProfile(
            profile_version="1",
            profile_method="declared_metadata",
            target_type=target_type,
            canonical_identifier=canonical_identifier,
            interfaces=["network://{}".format(canonical_identifier)],
            technologies=[],
            source_available=False,
            authentication=_authentication_status(audit),
            confidence=0.75,
            profiled_at=profiled_at,
        )

    raise TargetProfilingError(
        "unsupported_target_type", "Unsupported target type: {}".format(target_type)
    )
