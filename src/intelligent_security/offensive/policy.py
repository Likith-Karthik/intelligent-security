from intelligent_security.domain import Audit, OffensiveState


OFFENSIVE_DISABLED_REASON = (
    "Offensive actions are disabled in this POC. No offensive adapter or approved capability set is configured."
)


def disabled_status(audit: Audit) -> dict:
    """Return the only currently permitted offensive-policy outcome.

    This function intentionally has no feature flag, runtime lookup, model call, or
    plugin resolution path. Future enablement must replace this policy explicitly.
    """
    return {
        "audit_id": str(audit.id),
        "state": OffensiveState.OFFENSIVE_DISABLED.value,
        "enabled": False,
        "reason": OFFENSIVE_DISABLED_REASON,
        "request_count": len(audit.offensive_requests),
        "permission_grant_count": len(audit.offensive_permission_grants),
        "plan_count": len(audit.offensive_plans),
    }
