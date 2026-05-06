"""
auth/entra_integration.py
--------------------------
High-level integration: Entra ID authentication → governance framework.

This is the entry point for the auth module. It ties together:
  - EntraTokenValidator (validates the JWT)
  - EntraClaimMapper    (translates claims to UserContext)
  - PolicyResolver      (issues Authorized Query Proofs with Entra OID embedded)

The resulting SessionContext carries the Entra OID as the user_id throughout
the governance chain — ensuring that even when downstream components only see
the Authorized Query Proof (not the original Bearer token), the identity anchor
is preserved and tamper-evident.

Key architectural point:
  Entra ID tells us WHO the user is.
  The Authorized Query Proof tells us WHAT they are permitted to query.
  These are different questions — this module bridges them.

Usage (production):
    config = EntraConfig.from_env()
    gateway = EntraAuthGateway(config, catalog)

    # In your FastAPI/MCP HTTP handler:
    session = gateway.authenticate_request(
        authorization_header=request.headers.get("Authorization"),
        request_intent="Retrieve Audi quality defect rates",
    )
    # session.user is a fully-mapped UserContext backed by Entra identity
    # session.user.user_id is the Entra OID

Usage (testing):
    config = EntraConfig.for_testing()
    gateway = EntraAuthGateway.for_testing(config, catalog)
    factory = gateway.token_factory  # pre-wired test factory

    token = factory.make_user_token(oid="audi-analyst-oid", groups=["Audi-Analysts"], roles=["DataAnalyst"])
    session = gateway.authenticate_request(f"Bearer {token}", "Fetch defect rates")
"""

from __future__ import annotations

import logging
from typing import Optional

from auth.claim_mapper import EntraClaimMapper
from auth.entra_config import EntraConfig
from auth.token_factory import EntraTokenFactory
from auth.token_validator import EntraTokenClaims, EntraTokenValidationError, EntraTokenValidator
from catalog.catalog import DataCatalog
from core.models import SessionContext, UserContext

logger = logging.getLogger(__name__)


class EntraAuthGateway:
    """
    Entra ID authentication gateway for the governance framework.

    Validates incoming Bearer tokens, maps claims to UserContext,
    and creates SessionContext objects for use in the governance chain.
    """

    def __init__(
        self,
        config: EntraConfig,
        catalog: DataCatalog,
        validator: Optional[EntraTokenValidator] = None,
        mapper: Optional[EntraClaimMapper] = None,
    ) -> None:
        self._config = config
        self._catalog = catalog
        self._validator = validator or EntraTokenValidator(config)
        self._mapper = mapper or EntraClaimMapper(config)
        self._token_factory: Optional[EntraTokenFactory] = None

    @property
    def token_factory(self) -> Optional[EntraTokenFactory]:
        """Test token factory (only set in test mode)."""
        return self._token_factory

    # ── Public interface ──────────────────────────────────────────────────────

    def authenticate_request(
        self,
        authorization_header: str,
        request_intent: str,
        override_brand_scope: Optional[list[str]] = None,
    ) -> SessionContext:
        """
        Authenticate an incoming request and return a governance SessionContext.

        Args:
            authorization_header: HTTP Authorization header value
                                  ('Bearer <token>' or raw token)
            request_intent:       Natural language description of what the
                                  user wants to do — used in audit logs
            override_brand_scope: Explicit brand scope to use instead of
                                  deriving from Entra groups. Useful when
                                  the application has a brand picker UI.

        Returns:
            SessionContext with a UserContext backed by Entra identity.
            The UserContext.user_id is the Entra OID.

        Raises:
            EntraTokenValidationError — if the token is invalid/expired/wrong tenant
            ValueError — if the token is app-only (no user identity)
        """
        claims = self._validator.validate_from_header(authorization_header)
        user_ctx = self._mapper.to_user_context(claims, override_brand_scope)

        session = SessionContext(
            user=user_ctx,
            request_intent=request_intent,
            metadata={
                "auth_source": "entra_id",
                "upn":         claims.upn,
                "entra_oid":   claims.oid,
                "app_id":      claims.app_id,
            },
        )

        logger.info(
            "Session established: oid=%s upn=%s brand_scope=%s clearance=%s session=%s",
            user_ctx.user_id, claims.upn,
            user_ctx.brand_scope, user_ctx.clearance_level,
            session.session_id[:8],
        )
        return session

    def authenticate_obo_request(
        self,
        obo_authorization_header: str,
        original_session: Optional[SessionContext],
        request_intent: str,
    ) -> SessionContext:
        """
        Authenticate an OBO (On-Behalf-Of) downstream request.

        Validates the OBO token, then applies OBO constraints — reducing the
        UserContext to the minimum safely inferred from the OBO token, which
        lacks app role claims.

        Args:
            obo_authorization_header: Authorization header for the OBO token
            original_session:         The originating user's full session (optional)
            request_intent:           What the downstream agent is doing

        Returns:
            A degraded SessionContext reflecting OBO context loss.
            The UserContext.metadata["obo_degraded"] will be True.
        """
        from core.models import SensitivityLevel as _SL
        claims = self._validator.validate_from_header(obo_authorization_header)

        base_user_ctx = UserContext(
            user_id=claims.oid or claims.subject,
            roles=[],
            brand_scope=[],
            clearance_level=_SL.INTERNAL,
            metadata={"upn": claims.upn, "entra_oid": claims.oid},
        )

        degraded_ctx = self._mapper.apply_obo_constraints(base_user_ctx)

        session = SessionContext(
            user=degraded_ctx,
            request_intent=request_intent,
            metadata={
                "auth_source":         "entra_id_obo",
                "obo_degraded":        True,
                "original_session_id": original_session.session_id if original_session else None,
                "original_user_id":    original_session.user.user_id if original_session else None,
            },
        )

        logger.warning(
            "OBO session established with degraded context: oid=%s — "
            "brand_scope=[] clearance=INTERNAL. "
            "Use original session's Authorized Query Proof for full access.",
            degraded_ctx.user_id,
        )
        return session

    def get_claims(self, authorization_header: str) -> EntraTokenClaims:
        """
        Validate a token and return raw claims without creating a session.
        Useful for inspection, logging, or custom mapping logic.
        """
        return self._validator.validate_from_header(authorization_header)

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def for_testing(
        cls,
        config: Optional[EntraConfig] = None,
        catalog: Optional[DataCatalog] = None,
    ) -> "EntraAuthGateway":
        """
        Create a test gateway with a pre-wired token factory.

        Returns a gateway that accepts self-signed test tokens with no
        Azure credentials. The gateway.token_factory attribute provides
        the matching factory for generating tokens in tests.
        """
        from catalog.catalog import build_demo_catalog

        cfg = config or EntraConfig.for_testing()
        cat = catalog or build_demo_catalog()

        factory = EntraTokenFactory(cfg)
        validator = EntraTokenValidator(cfg)
        validator.set_test_keypair(factory.public_key_pem)

        gateway = cls(config=cfg, catalog=cat, validator=validator)
        gateway._token_factory = factory
        return gateway
