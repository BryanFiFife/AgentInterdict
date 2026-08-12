from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from .config import DEFAULT_MAX_CONTENT, DEFAULT_MAX_METADATA_BYTES, DEFAULT_MAX_PARENTS

SourceType = Literal["human","human_verified","system_config","web","email","document","api","tool","unknown_external","derived"]
_NAMESPACE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ACTOR = re.compile(r"^[^\x00-\x1f\x7f]{1,160}$")
_SAFE_ID = re.compile(r"^[^\x00-\x1f\x7f]{8,200}$")
_SAFE_URI = re.compile(r"^[^\x00-\x1f\x7f]{1,4096}$")


def _validate_metadata_shape(value: dict[str, Any]) -> None:
    """Bound metadata depth/node count without recursive traversal."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > 4096:
            raise ValueError("metadata contains too many nested values")
        if depth > 24:
            raise ValueError("metadata nesting exceeds 24 levels")
        if isinstance(current, dict):
            for key, child in current.items():
                if not isinstance(key, str):
                    raise ValueError("metadata object keys must be strings")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
        elif current is None or isinstance(current, (str, int, float, bool)):
            continue
        else:
            raise ValueError("metadata must contain JSON-compatible values only")


def _normalise_time(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("expires_at must be an ISO-8601 timestamp") from exc
    if dt.tzinfo is None:
        raise ValueError("expires_at must include an explicit timezone or UTC offset")
    normalized = dt.astimezone(timezone.utc)
    if normalized <= datetime.now(timezone.utc):
        raise ValueError("expires_at must be in the future")
    return normalized.isoformat()


class IngestRequest(BaseModel):
    content: str = Field(min_length=1, max_length=DEFAULT_MAX_CONTENT)
    source_type: SourceType
    source_uri: str | None = Field(default=None, max_length=4096)
    namespace: str = "default"
    created_by: str = "agent"
    metadata: dict[str, Any] = Field(default_factory=dict)
    parent_ids: list[int] = Field(default_factory=list, max_length=DEFAULT_MAX_PARENTS)
    explicit_human_authorization: bool = False
    expires_at: str | None = None
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=200)

    @field_validator("namespace")
    @classmethod
    def valid_namespace(cls, value: str) -> str:
        value = value.strip()
        if not _NAMESPACE.fullmatch(value):
            raise ValueError("namespace must be 1-128 safe characters: letters, numbers, . _ : -")
        return value

    @field_validator("created_by")
    @classmethod
    def valid_actor(cls, value: str) -> str:
        value = value.strip()
        if not _ACTOR.fullmatch(value):
            raise ValueError("created_by contains invalid control characters or is too long")
        return value

    @field_validator("expires_at")
    @classmethod
    def valid_expiry(cls, value: str | None) -> str | None:
        return _normalise_time(value)

    @field_validator("source_uri")
    @classmethod
    def valid_source_uri(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value or not _SAFE_URI.fullmatch(value):
            raise ValueError("source_uri contains invalid control characters or is empty")
        return value

    @field_validator("idempotency_key")
    @classmethod
    def valid_idempotency_key(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SAFE_ID.fullmatch(value):
            raise ValueError("idempotency_key contains invalid control characters")
        return value

    @field_validator("parent_ids")
    @classmethod
    def valid_parents(cls, value: list[int]) -> list[int]:
        if any(x <= 0 for x in value):
            raise ValueError("parent_ids must contain positive memory IDs")
        if len(set(value)) != len(value):
            raise ValueError("parent_ids must not contain duplicates")
        return value

    @field_validator("metadata")
    @classmethod
    def bounded_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_metadata_shape(value)
        try:
            encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("metadata must be JSON-serializable and contain no NaN/Infinity") from exc
        if len(encoded.encode("utf-8")) > DEFAULT_MAX_METADATA_BYTES:
            raise ValueError(f"metadata exceeds {DEFAULT_MAX_METADATA_BYTES} bytes")
        return value

    @model_validator(mode="after")
    def semantic_rules(self):
        if self.source_type == "derived" and not self.parent_ids:
            raise ValueError("derived memories require at least one parent_id")
        if self.source_type != "derived" and self.parent_ids:
            # Parent lineage is allowed only for derived content to prevent accidental authority semantics.
            raise ValueError("parent_ids are only valid when source_type='derived'")
        if self.explicit_human_authorization and self.source_type != "human_verified":
            raise ValueError("explicit_human_authorization requires source_type='human_verified'")
        if self.explicit_human_authorization:
            scopes = self.metadata.get("authorization_scope")
            if not isinstance(scopes, list) or not scopes:
                raise ValueError("explicit_human_authorization requires metadata.authorization_scope with at least one action scope")
            if len(scopes) > 8 or any(not isinstance(x, str) for x in scopes):
                raise ValueError("metadata.authorization_scope must contain 1-8 strings")
            for scope in scopes:
                canonical = " ".join(scope.strip().split())
                if len(canonical) < 8 or len(canonical) > 240 or len(canonical.split()) < 2:
                    raise ValueError("each authorization scope must be 8-240 characters and contain at least two words")
                if any(ord(ch) < 32 or ord(ch) == 127 for ch in canonical):
                    raise ValueError("authorization scopes cannot contain control characters")
        return self


class SearchRequest(BaseModel):
    query: str = Field(default="", max_length=4000)
    namespace: str = "default"
    limit: int = Field(default=10, ge=1, le=50)
    include_review: bool = False

    @field_validator("namespace")
    @classmethod
    def valid_namespace(cls, value: str) -> str:
        value = value.strip()
        if not _NAMESPACE.fullmatch(value):
            raise ValueError("invalid namespace")
        return value


class ReviewRequest(BaseModel):
    action: Literal["allow","quarantine"]
    actor: str = Field(default="reviewer", min_length=1, max_length=160)
    reason: str = Field(default="", max_length=4000)

    @field_validator("actor")
    @classmethod
    def valid_actor(cls, value: str) -> str:
        value = value.strip()
        if not _ACTOR.fullmatch(value):
            raise ValueError("actor contains invalid control characters or is too long")
        return value


class PromoteRequest(BaseModel):
    target_authority: Literal["untrusted","observed","verified","authoritative"]
    actor: str = Field(default="reviewer", min_length=1, max_length=160)
    reason: str = Field(default="", max_length=4000)

    @field_validator("actor")
    @classmethod
    def valid_actor(cls, value: str) -> str:
        value = value.strip()
        if not _ACTOR.fullmatch(value):
            raise ValueError("actor contains invalid control characters or is too long")
        return value


class ReviseRequest(BaseModel):
    content: str = Field(min_length=1, max_length=DEFAULT_MAX_CONTENT)
    actor: str = Field(default="reviewer", min_length=1, max_length=160)
    reason: str = Field(default="", max_length=4000)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=200)

    @field_validator("actor")
    @classmethod
    def valid_actor(cls, value: str) -> str:
        value = value.strip()
        if not _ACTOR.fullmatch(value):
            raise ValueError("actor contains invalid control characters or is too long")
        return value

    @field_validator("idempotency_key")
    @classmethod
    def valid_idempotency_key(cls, value: str | None) -> str | None:
        if value is not None and not _SAFE_ID.fullmatch(value):
            raise ValueError("idempotency_key contains invalid control characters")
        return value

class ScanRequest(BaseModel):
    content: str = Field(min_length=1, max_length=DEFAULT_MAX_CONTENT)
    source_type: SourceType = "unknown_external"


class CodeChangeRequest(BaseModel):
    """Optional code-change review gate.

    Scans a code diff (or a code-change description) with the same engine used
    for memory content, and writes a signed, tamper-evident evidence record of
    the verdict. This is an OPTIONAL layer: it reuses the existing scanning and
    audit infrastructure to govern AI-generated code changes, without changing
    any existing enforcement behavior.
    """
    diff: str = Field(min_length=1, max_length=DEFAULT_MAX_CONTENT)
    repo: str = Field(default="", max_length=4096)
    branch: str = Field(default="", max_length=4096)
    actor: str = Field(default="agent", min_length=1, max_length=160)
    namespace: str = "default"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("namespace")
    @classmethod
    def valid_code_namespace(cls, value: str) -> str:
        value = value.strip()
        if not _NAMESPACE.fullmatch(value):
            raise ValueError("invalid namespace")
        return value

    @field_validator("actor")
    @classmethod
    def valid_code_actor(cls, value: str) -> str:
        value = value.strip()
        if not _ACTOR.fullmatch(value):
            raise ValueError("actor contains invalid control characters or is too long")
        return value

    @field_validator("metadata")
    @classmethod
    def bounded_code_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_metadata_shape(value)
        try:
            encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("metadata must be JSON-serializable and contain no NaN/Infinity") from exc
        if len(encoded.encode("utf-8")) > DEFAULT_MAX_METADATA_BYTES:
            raise ValueError(f"metadata exceeds {DEFAULT_MAX_METADATA_BYTES} bytes")
        return value


class ActionCheckRequest(BaseModel):
    action: str = Field(min_length=1, max_length=4000)
    action_risk: Literal["low", "medium", "high", "critical"] = "medium"
    namespace: str = "default"
    context_memory_ids: list[int] = Field(default_factory=list, max_length=DEFAULT_MAX_PARENTS)
    authorization_memory_ids: list[int] = Field(default_factory=list, max_length=16)
    actor: str = Field(default="agent", min_length=1, max_length=160)

    @field_validator("namespace")
    @classmethod
    def valid_action_namespace(cls, value: str) -> str:
        value = value.strip()
        if not _NAMESPACE.fullmatch(value):
            raise ValueError("invalid namespace")
        return value

    @field_validator("actor")
    @classmethod
    def valid_action_actor(cls, value: str) -> str:
        value = value.strip()
        if not _ACTOR.fullmatch(value):
            raise ValueError("actor contains invalid control characters or is too long")
        return value

    @field_validator("context_memory_ids", "authorization_memory_ids")
    @classmethod
    def valid_action_ids(cls, value: list[int]) -> list[int]:
        if any(x <= 0 for x in value):
            raise ValueError("memory IDs must be positive")
        if len(set(value)) != len(value):
            raise ValueError("memory IDs must not contain duplicates")
        return value

    @model_validator(mode="after")
    def no_overlap(self):
        overlap = set(self.context_memory_ids) & set(self.authorization_memory_ids)
        if overlap:
            raise ValueError("context and authorization memory IDs must not overlap")
        return self


class RuntimeModeRequest(BaseModel):
    mode: Literal["normal", "read_only", "lockdown"]
    actor: str = Field(default="dashboard", min_length=1, max_length=160)
    reason: str = Field(default="", max_length=4000)

    @field_validator("actor")
    @classmethod
    def valid_mode_actor(cls, value: str) -> str:
        value = value.strip()
        if not _ACTOR.fullmatch(value):
            raise ValueError("actor contains invalid control characters or is too long")
        return value
