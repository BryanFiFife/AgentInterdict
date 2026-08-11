from __future__ import annotations

EXTERNAL_SOURCES = {"web", "email", "document", "api", "tool", "unknown_external"}
HUMAN_SOURCES = {"human", "human_verified"}
SYSTEM_SOURCES = {"system_config"}

AUTHORITY_ORDER = {"untrusted": 0, "observed": 1, "verified": 2, "authoritative": 3}


def base_authority(source_type: str, explicit_human_authorization: bool = False) -> str:
    if source_type == "human_verified" and explicit_human_authorization:
        return "authoritative"
    if source_type in HUMAN_SOURCES:
        return "verified"
    if source_type in SYSTEM_SOURCES:
        return "authoritative"
    if source_type in EXTERNAL_SOURCES:
        return "untrusted"
    return "observed"


def inherited_authority(parent_authorities: list[str], requested: str | None = None) -> str:
    """Derived content can never outrank its least-trusted parent.

    This makes source authority non-malleable through summarisation/rewrites.
    """
    if not parent_authorities:
        return "untrusted"
    floor = min(parent_authorities, key=lambda x: AUTHORITY_ORDER.get(x, 0))
    # Model/tool-generated derivations are transformations, not fresh human authorization.
    # Even a derivation of exclusively authoritative parents is capped at verified.
    if AUTHORITY_ORDER.get(floor, 0) > AUTHORITY_ORDER["verified"]:
        floor = "verified"
    if requested is None:
        return floor
    requested = requested if requested in AUTHORITY_ORDER else "untrusted"
    return requested if AUTHORITY_ORDER[requested] <= AUTHORITY_ORDER[floor] else floor


def decision_for(score: int, authority: str) -> str:
    if score >= 70:
        return "quarantined"
    if score >= 35:
        return "review"
    # Low-risk external memories may be stored, but remain non-authoritative.
    return "allowed"


def safe_for_action(authority: str, status: str) -> bool:
    return status == "allowed" and authority == "authoritative"
