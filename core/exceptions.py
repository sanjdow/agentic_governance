class AgenticGovernanceError(Exception):
    pass




class TokenVerificationError(AgenticGovernanceError):
    pass


class TokenExpiredError(TokenVerificationError):
    pass


class TokenQueryMismatchError(TokenVerificationError):
    pass


class TokenDelegationError(TokenVerificationError):
    pass


class TokenRevocationError(TokenVerificationError):
    pass


class QueryAccessDeniedError(AgenticGovernanceError):
    pass




class AssetNotFoundError(AgenticGovernanceError):
    pass


class PolicyResolutionError(AgenticGovernanceError):
    pass


class ConsentBlockedError(AgenticGovernanceError):
    pass




class AgentIneligibleError(AgenticGovernanceError):
    pass


class AgentIdentityAmbiguityError(AgenticGovernanceError):
    pass




class ContextRedactionError(AgenticGovernanceError):
    pass


class ContextSensitivityViolation(AgenticGovernanceError):
    pass




class PromptInjectionBlockedError(AgenticGovernanceError):
    pass




class CacheKeyPolicyViolation(AgenticGovernanceError):
    pass


class CachePolicyVersionMismatch(AgenticGovernanceError):
    pass
