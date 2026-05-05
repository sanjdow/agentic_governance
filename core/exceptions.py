"""
core/exceptions.py
------------------
Framework-wide exception hierarchy.
"""


class AgenticGovernanceError(Exception):
    """Base exception for all framework errors."""


# ── Authorization ─────────────────────────────────────────────────────────────

class ProofVerificationError(AgenticGovernanceError):
    """Raised when an Authorized Query Proof fails verification."""


class ProofExpiredError(ProofVerificationError):
    """Raised when an Authorized Query Proof has expired."""


class ProofQueryMismatchError(ProofVerificationError):
    """Raised when the submitted query does not match the proof's query hash."""


class ProofDelegationError(ProofVerificationError):
    """Raised when a proof is used by an agent other than the one it was issued for."""


class ProofRevocationError(ProofVerificationError):
    """Raised when a proof has been explicitly revoked (e.g. mid-session policy change)."""


class UnauthorizedQueryError(AgenticGovernanceError):
    """Raised when the Policy Resolver denies a query."""


# ── Catalog ───────────────────────────────────────────────────────────────────

class AssetNotFoundError(AgenticGovernanceError):
    """Raised when a data asset is not registered in the catalog."""


class PolicyResolutionError(AgenticGovernanceError):
    """Raised when catalog policy cannot be resolved for a given context."""


class ConsentBlockedError(AgenticGovernanceError):
    """Raised when a query touches personal data without required consent."""


# ── Orchestrator ──────────────────────────────────────────────────────────────

class AgentIneligibleError(AgenticGovernanceError):
    """Raised when an agent is blocked before invocation by the orchestrator."""


class AgentIdentityAmbiguityError(AgenticGovernanceError):
    """Raised when agent identity cannot be resolved in a delegation chain."""


# ── Context Governance ────────────────────────────────────────────────────────

class ContextRedactionError(AgenticGovernanceError):
    """Raised when context cannot be safely passed to a receiving agent."""


class ContextSensitivityViolation(AgenticGovernanceError):
    """Raised when context contains data above the receiving agent's clearance."""


# ── Injection Detection ───────────────────────────────────────────────────────

class PromptInjectionBlockedError(AgenticGovernanceError):
    """Raised when a prompt injection attempt is detected and blocked."""


# ── Cache ─────────────────────────────────────────────────────────────────────

class CacheKeyPolicyViolation(AgenticGovernanceError):
    """Raised when a cache key would create a cross-identity data leak."""


class CachePolicyVersionMismatch(AgenticGovernanceError):
    """Raised when cached data was stored under a different policy version."""
