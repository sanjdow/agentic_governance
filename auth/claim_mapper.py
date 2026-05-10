from __future__ import annotations

import logging
from typing import Optional

from auth.entra_config import EntraConfig
from auth.token_validator import EntraTokenClaims
from core.models import SensitivityLevel, UserContext

logger = logging.getLogger(__name__)


class EntraClaimMapper:

    def __init__(self, config: EntraConfig) -> None:
        self._config = config

    # ── Primary mapping ───────────────────────────────────────────────────────

    def to_user_context(
        self,
        claims: EntraTokenClaims,
        override_brand_scope: Optional[list[str]] = None,
    ) -> UserContext:

        if claims.is_app_only:
            raise ValueError("app-only token has no user identity — use map_to_agent_principal()")

        # user_id: use OID as the canonical, immutable identifier.
        # UPN can change (username renames); OID never does.
        user_id = claims.oid or claims.subject
        if not user_id:
            raise ValueError("no oid/sub claim in token")

        # Brand scope: derive from group memberships
        if override_brand_scope is not None:
            brand_scope = override_brand_scope
        else:
            brand_scope = self._resolve_brand_scope(claims)

        # Clearance level: derive from app roles
        clearance_level = self._resolve_clearance_level(claims)

        # Roles: pass through Entra app roles as-is for downstream use
        roles = list(claims.roles)

        user_ctx = UserContext(
            user_id=user_id,
            roles=roles,
            brand_scope=brand_scope,
            clearance_level=clearance_level,
            metadata={
                "upn":       claims.upn,
                "name":      claims.name,
                "tenant_id": claims.tenant_id,
                "app_id":    claims.app_id,
                "entra_groups": claims.groups,
                "source":    "entra_id",
            },
        )

        logger.debug(
            "Entra claim mapped: oid=%s upn=%s → brand_scope=%s clearance=%s",
            user_id, claims.upn, brand_scope, clearance_level,
        )
        return user_ctx

    def map_to_agent_principal(self, claims: EntraTokenClaims) -> dict:
        # app-only token — no UserContext possible, return raw metadata
        return {
            "service_principal_oid": claims.oid,
            "app_id": claims.app_id,
            "tenant_id": claims.tenant_id,
            "roles": claims.roles,
            "source": "entra_id_managed_identity",
        }

    # ── OBO degradation ───────────────────────────────────────────────────────

    def apply_obo_constraints(self, user_ctx: UserContext) -> UserContext:
        """
        Model the policy context loss that occurs in an OBO delegation chain.

        When an orchestrator uses On-Behalf-Of to call a downstream agent on
        behalf of a user, Entra propagates OID and UPN — but app role assignments
        (which drive clearance_level) come from the app registration, not the
        user token. In OBO chains, roles are typically NOT included.

        This method produces a degraded UserContext representing what can be
        safely inferred from an OBO token alone, without app role claims:

          - brand_scope:     reduced to empty (cannot be inferred without groups)
          - clearance_level: reduced to INTERNAL (the safe default)
          - roles:           cleared

        The receiving agent must re-request a fresh Signed Access Token
        under the degraded context rather than inheriting the original context.
        This makes the OBO identity loss EXPLICIT in the governance model.

        This is exactly the gap that embedding the Entra OID in the Authorized
        Query Proof addresses: the proof carries the original user context forward
        as a signed, tamper-evident artifact, even when OBO loses the app roles.
        """
        logger.warning(
            "OBO constraint applied for user=%s — brand_scope cleared, "
            "clearance reduced to INTERNAL. Original context: brand=%s clearance=%s. "
            "Re-establish full context via Policy Resolver.",
            user_ctx.user_id, user_ctx.brand_scope, user_ctx.clearance_level,
        )
        return UserContext(
            user_id=user_ctx.user_id,
            roles=[],                              # Roles NOT propagated via OBO
            brand_scope=[],                        # Cannot be inferred from OBO token
            clearance_level=SensitivityLevel.INTERNAL,  # Safe default
            metadata={
                **user_ctx.metadata,
                "obo_degraded": True,
                "original_clearance": user_ctx.clearance_level.value,
                "original_brand_scope": user_ctx.brand_scope,
                "degradation_reason": (
                    "OBO delegation loses app role assignments. "
                    "Brand scope and clearance must be re-established via "
                    "the Policy Resolver with a fresh Signed Access Token."
                ),
            },
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    def _resolve_brand_scope(self, claims: EntraTokenClaims) -> list[str]:

        if claims.has_groups_overage:
            logger.warning(
                "Groups overage for oid=%s — groups not in token. "
                "Brand scope cannot be resolved without a Graph API call. "
                "Returning empty brand scope (fail-closed). "
                "Configure graph_client in EntraClaimMapper for full group resolution.",
                claims.oid,
            )
            return []

        brand_scope: set[str] = set()
        user_groups = set(claims.groups)  # group OIDs

        for group_key, brands in self._config.brand_group_map.items():
            if group_key in user_groups:
                brand_scope.update(brands)

        if not brand_scope and claims.groups:
            logger.debug(
                "No brand_group_map matches for oid=%s groups=%s. "
                "Add group OIDs or display names to ENTRA_BRAND_GROUP_MAP.",
                claims.oid, claims.groups,
            )

        return sorted(brand_scope)

    def _resolve_clearance_level(self, claims: EntraTokenClaims) -> SensitivityLevel:
        # no match = INTERNAL (minimum) — fail closed
        level = SensitivityLevel.INTERNAL  # Default — minimum access

        for role in claims.roles:
            mapped = self._config.clearance_role_map.get(role)
            if mapped:
                try:
                    candidate = SensitivityLevel(mapped)
                    if candidate > level:
                        level = candidate
                except ValueError:
                    logger.warning(
                        "clearance_role_map value '%s' for role '%s' is not "
                        "a valid SensitivityLevel. Valid values: %s",
                        mapped, role, [e.value for e in SensitivityLevel],
                    )

        return level
