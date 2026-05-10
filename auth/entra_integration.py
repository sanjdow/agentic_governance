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
        # OBO loses app roles — context will be degraded (brand_scope=[], clearance=INTERNAL)
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
            "Use original session's Signed Access Token for full access.",
            degraded_ctx.user_id,
        )
        return session

    def get_claims(self, authorization_header: str) -> EntraTokenClaims:

        return self._validator.validate_from_header(authorization_header)

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def for_testing(
        cls,
        config: Optional[EntraConfig] = None,
        catalog: Optional[DataCatalog] = None,
    ) -> "EntraAuthGateway":

        from catalog.catalog import build_demo_catalog

        cfg = config or EntraConfig.for_testing()
        cat = catalog or build_demo_catalog()

        factory = EntraTokenFactory(cfg)
        validator = EntraTokenValidator(cfg)
        validator.set_test_keypair(factory.public_key_pem)

        gateway = cls(config=cfg, catalog=cat, validator=validator)
        gateway._token_factory = factory
        return gateway
