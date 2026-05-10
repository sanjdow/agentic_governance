# Shared data models — the contract between L1-L4.

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator




class SensitivityLevel(str, Enum):
    # ordered low → high
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    SECRET = "secret"

    @classmethod
    def _order(cls) -> list["SensitivityLevel"]:
        return [cls.PUBLIC, cls.INTERNAL, cls.CONFIDENTIAL, cls.RESTRICTED, cls.SECRET]

    def _rank(self) -> int:
        return self._order().index(self)

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, SensitivityLevel):
            return NotImplemented
        return self._rank() >= other._rank()

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, SensitivityLevel):
            return NotImplemented
        return self._rank() > other._rank()

    def __le__(self, other: object) -> bool:
        if not isinstance(other, SensitivityLevel):
            return NotImplemented
        return self._rank() <= other._rank()

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SensitivityLevel):
            return NotImplemented
        return self._rank() < other._rank()


class AccessRight(str, Enum):
    READ = "read"
    WRITE = "write"
    AGGREGATE = "aggregate"
    EXPORT = "export"
    ADMIN = "admin"


class AgentStatus(str, Enum):
    ELIGIBLE = "eligible"
    INELIGIBLE = "ineligible"
    BLOCKED = "blocked"


class InjectionRisk(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"




# Reject identifiers containing characters that could break SQL filter templates
# or log injection. Allowed: alphanumeric, underscore, hyphen, dot.
_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_\-\.]{1,128}$")


def _validate_safe_identifier(value: str, field_name: str) -> str:
    if not _SAFE_IDENTIFIER_RE.match(value):
        raise ValueError(
            f"Field '{field_name}' must match {_SAFE_IDENTIFIER_RE.pattern} "
            f"(got: {value!r}). Identifiers used in SQL filter templates and "
            "audit logs must be safe characters only."
        )
    return value




class UserContext(BaseModel):
    user_id: str
    roles: list[str] = Field(default_factory=list)
    brand_scope: list[str] = Field(default_factory=list)   # e.g. ["brand_b", "brand_a"]
    clearance_level: SensitivityLevel = SensitivityLevel.INTERNAL
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_user_id(self) -> "UserContext":
        _validate_safe_identifier(self.user_id, "user_id")
        for brand in self.brand_scope:
            _validate_safe_identifier(brand, "brand_scope")
        return self


class AgentContext(BaseModel):
    agent_id: str
    agent_type: str                          # e.g. "retrieval", "summarisation", "output"
    max_sensitivity: SensitivityLevel = SensitivityLevel.INTERNAL
    allowed_rights: list[AccessRight] = Field(default_factory=list)
    allowed_sources: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_agent_id(self) -> "AgentContext":
        _validate_safe_identifier(self.agent_id, "agent_id")
        return self


class SessionContext(BaseModel):
    session_id: str = Field(default_factory=lambda: str(uuid4()))
    user: UserContext
    request_intent: str                      # Natural language intent
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)




class DataAsset(BaseModel):
    asset_id: str
    name: str
    source: str                              # e.g. "snowflake", "postgres", "delta_lake"
    table: Optional[str] = None
    columns: list[str] = Field(default_factory=list)
    sensitivity: SensitivityLevel = SensitivityLevel.INTERNAL
    required_rights: list[AccessRight] = Field(default_factory=list)
    brand_tags: list[str] = Field(default_factory=list)
    row_filter_template: Optional[str] = None   # SQL WHERE clause template
    pii_columns: list[str] = Field(default_factory=list)
    consent_required: bool = False
    owner: Optional[str] = None
    tags: dict[str, str] = Field(default_factory=dict)


class PolicyVersion(BaseModel):
    version_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    checksum: str = ""




class SignedAccessToken(BaseModel):
    """
    RS256-signed JWT binding a specific query to a user/agent/session.
    Single-use, short-lived, non-delegable. Issued by PolicyResolver only.
    """
    token_id: str = Field(default_factory=lambda: str(uuid4()))
    query_hash: str                          # SHA-256 of canonicalized authorised query
    query_preview: str                       # First 120 chars for logging (not for execution)
    user_id: str
    agent_id: str
    session_id: str
    catalog_policy_version: str
    issued_at: datetime
    expires_at: datetime
    allowed_filters: dict[str, Any] = Field(default_factory=dict)  # Push-down filter map
    token: str = ""                          # Signed JWT — set after signing
    asset_ids: list[str] = Field(default_factory=list)

    @classmethod
    def canonicalize_query(cls, query: str) -> str:
        # collapse whitespace — same query different formatting = same hash
        # intentionally not lowercased, SQL identifiers can be case-sensitive
        return re.sub(r"\s+", " ", query.strip())

    @classmethod
    def hash_query(cls, query: str) -> str:
        canonical = cls.canonicalize_query(query)
        return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at

    def matches_query(self, candidate_query: str) -> bool:
        return self.query_hash == self.hash_query(candidate_query)




class ClassifiedChunk(BaseModel):
    text: str
    sensitivity: SensitivityLevel
    pii_detected: bool = False
    brand_tags: list[str] = Field(default_factory=list)
    redacted: bool = False


class GovernedContext(BaseModel):
    """
    The output of the context governance layer.
    Passed between agents instead of raw context.
    """
    original_agent_id: str
    receiving_agent_id: str
    chunks: list[ClassifiedChunk] = Field(default_factory=list)
    redaction_count: int = 0
    max_sensitivity_passed: SensitivityLevel = SensitivityLevel.PUBLIC
    governance_applied_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def safe_text(self) -> str:
        # placeholder instead of empty string so the receiving agent knows
        # content was withheld rather than simply not retrieved
        parts = []
        for c in self.chunks:
            if c.redacted:
                parts.append("[redacted: content above receiving agent's clearance]")
            else:
                parts.append(c.text)
        return "\n".join(parts)




class InjectionAssessment(BaseModel):
    risk_level: InjectionRisk
    confidence: float = Field(ge=0.0, le=1.0)
    triggered_patterns: list[str] = Field(default_factory=list)
    explanation: str = ""
    should_block: bool = False

    @model_validator(mode="after")
    def _auto_block_on_high_risk(self) -> "InjectionAssessment":
        # After all fields populated: force should_block on HIGH/CRITICAL.
        # We use object.__setattr__ to bypass any pydantic immutability guards,
        # since this is a post-construction normalization rather than mutation.
        if self.risk_level in (InjectionRisk.HIGH, InjectionRisk.CRITICAL) and not self.should_block:
            object.__setattr__(self, "should_block", True)
        return self




class MCPToolCall(BaseModel):
    # proof=None means ungoverned call — rejected by MCPGovernanceServer by default
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    proof: Optional[SignedAccessToken] = None   # None = naive / ungoverned call

    def is_governed(self) -> bool:
        return self.proof is not None and bool(self.proof.token)


class MCPToolResult(BaseModel):
    success: bool
    data: Any = None
    error: Optional[str] = None
    filters_applied: dict[str, Any] = Field(default_factory=dict)
    token_id: Optional[str] = None
    governed: bool = False
