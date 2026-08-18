import ipaddress
from datetime import datetime, timezone
from typing import List, Tuple
from urllib.parse import urlparse, urlunparse

from intelligent_security.domain import Audit, ScopePolicy


class ScopeValidationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _normalize_host(value: str) -> str:
    host = value.strip().rstrip(".").lower()
    if not host or any(character.isspace() for character in host):
        raise ScopeValidationError(
            "invalid_asset",
            "Asset must be a non-empty hostname, IP address, CIDR, or HTTPS URL.",
        )
    return host


def _normalize_url(value: str) -> Tuple[str, str]:
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ScopeValidationError(
            "invalid_target", "Web, API, and LLM targets must use an HTTP or HTTPS URL."
        )
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ScopeValidationError(
            "invalid_target",
            "Target URLs may not contain credentials, query parameters, or fragments.",
        )
    host = _normalize_host(parsed.hostname)
    port = parsed.port
    netloc = host if port is None else "{}:{}".format(host, port)
    path = parsed.path.rstrip("/") or "/"
    return urlunparse((parsed.scheme.lower(), netloc, path, "", "", "")), host


def _normalize_network_asset(value: str) -> str:
    candidate = value.strip()
    try:
        return str(ipaddress.ip_network(candidate, strict=False))
    except ValueError:
        return _normalize_host(candidate)


def _target_matches_scope(audit: Audit, authorized_assets: List[str]) -> bool:
    target_type = audit.target.target_type
    identifier = audit.target.identifier

    if target_type in {"web_application", "api", "llm_application"}:
        _, target_host = _normalize_url(identifier)
        return target_host in authorized_assets

    if target_type == "source_repository":
        target_url, _ = _normalize_url(identifier)
        normalized_repositories = [_normalize_url(asset)[0] for asset in authorized_assets]
        return target_url in normalized_repositories

    if target_type == "network_host":
        target = _normalize_network_asset(identifier)
        try:
            target_address = ipaddress.ip_address(target)
        except ValueError:
            return target in authorized_assets
        for asset in authorized_assets:
            try:
                if target_address in ipaddress.ip_network(asset, strict=False):
                    return True
            except ValueError:
                if str(target_address) == asset:
                    return True
        return False

    raise ScopeValidationError(
        "unsupported_target_type", "Unsupported target type: {}".format(target_type)
    )


def validate_scope(audit: Audit) -> ScopePolicy:
    now = datetime.now(timezone.utc)
    valid_until = audit.authorization.valid_until
    if valid_until.tzinfo is None:
        valid_until = valid_until.replace(tzinfo=timezone.utc)
    if valid_until <= now:
        raise ScopeValidationError("authorization_expired", "Authorization has expired.")

    normalizer = _normalize_network_asset
    if audit.target.target_type == "source_repository":
        normalizer = lambda asset: _normalize_url(asset)[0]
    authorized_assets = sorted({normalizer(asset) for asset in audit.scope.authorized_assets})
    excluded_assets = sorted({normalizer(asset) for asset in audit.scope.excluded_assets})
    if set(authorized_assets).intersection(excluded_assets):
        raise ScopeValidationError(
            "conflicting_scope", "An asset cannot be both authorized and excluded."
        )

    if not _target_matches_scope(audit, authorized_assets):
        raise ScopeValidationError(
            "target_out_of_scope", "The target identifier is not contained in the authorized scope."
        )

    allowed_operations = set(audit.authorization.allowed_operations)
    prohibited_operations = set(audit.scope.prohibited_operations)
    if not allowed_operations.difference(prohibited_operations):
        raise ScopeValidationError(
            "no_permitted_operations",
            "Authorization does not permit any operation after scope restrictions are applied.",
        )

    filesystem_boundaries = []
    if audit.target.target_type == "source_repository":
        filesystem_boundaries = [_normalize_url(audit.target.identifier)[0]]

    network_allowlist = authorized_assets if audit.target.target_type != "source_repository" else []
    return ScopePolicy(
        authorized_assets=authorized_assets,
        excluded_assets=excluded_assets,
        network_allowlist=network_allowlist,
        filesystem_boundaries=filesystem_boundaries,
        allowed_operations=sorted(
            allowed_operations.difference(prohibited_operations), key=lambda item: item.value
        ),
        prohibited_operations=sorted(prohibited_operations, key=lambda item: item.value),
        authorization_id=audit.authorization.authorization_id,
        valid_until=valid_until,
    )
