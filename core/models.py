"""
core/models.py
--------------
Shared data models used across all framework modules.
These form the contract between layers L1–L4.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class SensitivityLevel(str, Enum):
    """Data classification sensitivity levels, ordered low → high."""
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
    """Access rights for data assets."""
    READ = "read"
    WRITE = "write"
    AGGREGATE = "aggregate"
    EXPORT = "export"
    ADMIN = "admin"


class AgentStatus(str, Enum):
    """Agent eligibility status determined by the orchestrator."""
    ELIGIBLE = "eligible"
    INELIGIBLE = "ineligible"
    BLOCKED = "blocked"


class InjectionRisk(str, Enum):
    """Risk level returned by prompt injection detector."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ─────────────────────────────────────────────────────────────────────────────
# Identity validation helpers
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# Identity & Session
# ─────────────────────────────────────────────────────────────────────────────

class UserContext(BaseModel):
    """Represents the authenticated user invoking the agent system."""
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
    """Represents an AI agent within the orchestration graph."""
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
    """Binds a user, session, and request together."""
    session_id: str = Field(default_factory=lambda: str(uuid4()))
    user: UserContext
    request_intent: str                      # Natural language intent
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Catalog Types
# ─────────────────────────────────────────────────────────────────────────────

class DataAsset(BaseModel):
    """A governed data asset registered in the catalog."""
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
    """Tracks the current policy version for proof binding."""
    version_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    checksum: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Signed Access Token
# ─────────────────────────────────────────────────────────────────────────────

class SignedAccessToken(BaseModel):
    """
    The core artifact of the data access governance model.

    A cryptographically signed, short-lived, operation-scoped, non-delegable proof
    that a specific query has been validated against catalog policies for a
    specific user/agent/session context.

    Properties:
    - Signature:      Issued by Policy Resolver — no agent can self-issue
    - Query binding:  SHA-256 hash of the canonicalized authorised query embedded
    - Context binding: user_id + agent_id + session_id + timestamp
    - Short-lived:    Expiry in seconds to minutes
    - Non-delegable:  Cannot be passed from one agent to another
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
        """
        Canonicalize a query for hashing.

        Normalizes whitespace (collapses runs of whitespace to single spaces,
        strips leading/trailing whitespace) so that semantically identical
        queries with different formatting produce the same hash.

        Does NOT lower-case — SQL identifiers in quoted form are case-sensitive.
        """
        return re.sub(r"\s+", " ", query.strip())

    @classmethod
    def hash_query(cls, query: str) -> str:
        """Compute the canonical query hash."""
        canonical = cls.canonicalize_query(query)
        return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at

    def matches_query(self, candidate_query: str) -> bool:
        """Verify the submitted query matches the proof's binding."""
        return self.query_hash == self.hash_query(candidate_query)


# ─────────────────────────────────────────────────────────────────────────────
# Context Governance
# ─────────────────────────────────────────────────────────────────────────────

class ClassifiedChunk(BaseModel):
    """A content chunk with its detected sensitivity classification."""
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
        """
        Returns the chunks as a string, with redacted chunks replaced by a placeholder.

        Using a placeholder rather than empty string preserves the signal that content
        was removed — receiving agents can decide how to handle the absence rather than
        being silently misled into thinking nothing was retrieved.
        """
        parts = []
        for c in self.chunks:
            if c.redacted:
                parts.append("[redacted: content above receiving agent's clearance]")
            else:
                parts.append(c.text)
        return "\n".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# Injection Detection
# ─────────────────────────────────────────────────────────────────────────────

class InjectionAssessment(BaseModel):
    """Result of prompt injection analysis."""
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


# ─────────────────────────────────────────────────────────────────────────────
# MCP Tool Call
# ─────────────────────────────────────────────────────────────────────────────

class MCPToolCall(BaseModel):
    """
    Extended MCP tool call with a mandatory proof field.
    This is the proposed MCP protocol extension from the governance thesis.
    """
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    proof: Optional[SignedAccessToken] = None   # None = naive / ungoverned call

    def is_governed(self) -> bool:
        return self.proof is not None and bool(self.proof.token)


class MCPToolResult(BaseModel):
    """Result returned by the MCP governance server."""
    success: bool
    data: Any = None
    error: Optional[str] = None
    filters_applied: dict[str, Any] = Field(default_factory=dict)
    token_id: Optional[str] = None
    governed: bool = False
