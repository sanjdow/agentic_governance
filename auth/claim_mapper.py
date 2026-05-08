"""
auth/claim_mapper.py
--------------------
Maps validated Entra ID token claims to the framework's UserContext.

This is the translation layer between Microsoft's identity model and
the governance framework's policy model. It answers:

  "Given what Entra ID tells us about this user, what brand_scope and
   clearance_level should the governance framework apply?"

The mapping is driven by two tables in EntraConfig:
  - brand_group_map:   group display-name or OID  → brand_scope values
  - clearance_role_map: app role value             → SensitivityLevel string

Why this layer exists
---------------------
Entra ID knows about principals, group memberships, and app roles.
It knows nothing about data mesh brand scopes, data mesh sensitivity levels,
or the distinction between being ALLOWED to authenticate vs. being
AUTHORIZED to execute a specific query against a specific data asset.

This mapper is the bridge — it converts Entra's identity facts into
governance-framework policy facts. The resulting UserContext is then
the root of every trust decision in L2 (eligibility), L3 (proof),
and L4 (enforcement).

OBO delegation gap
-------------------
When an agent uses OBO to call a downstream service on behalf of a user,
Entra propagates the user's OID and UPN but does NOT propagate:
  - App role assignments (roles come from the app registration, not the user)
  - Custom group-to-brand mappings
  - Session-scoped policy context

The `apply_obo_constraints()` method explicitly models this degradation,
reducing the UserContext to the minimum that can be safely inferred
from OBO claims alone — forcing the caller to re-establish full policy
context via the Policy Resolver rather than silently inheriting it.
"""

from __future__ import annotations

import logging
from typing import Optional

from auth.entra_config import EntraConfig
from auth.token_validator import EntraTokenClaims
from core.models import SensitivityLevel, UserContext

logger = logging.getLogger(__name__)


class EntraClaimMapper:
    """
    Maps EntraTokenClaims → UserContext.

    Instantiate once and reuse across requests.
    """

    def __init__(self, config: EntraConfig) -> None:
        self._config = config

    # ── Primary mapping ───────────────────────────────────────────────────────

    def to_user_context(
        self,
        claims: EntraTokenClaims,
        override_brand_scope: Optional[list[str]] = None,
    ) -> UserContext:
        """
        Map validated Entra token claims to a UserContext.

        Args:
            claims:               Validated token claims from EntraTokenValidator
            override_brand_scope: If provided, use this brand scope instead of
                                  deriving it from group claims. Useful when the
                                  caller has additional context (e.g. a UI picker).

        Returns:
            UserContext ready for use in the governance framework.

        Raises:
            ValueError — if the token is app-only (no user identity) and cannot
                         be mapped to a user context.
        """
        if claims.is_app_only:
            raise ValueError(
                "Cannot map an app-only (Managed Identity / client credentials) token "
                "to a UserContext. App-only tokens have no user identity. "
                "Use map_to_agent_principal() instead, or require OBO delegation "
                "to carry the user's identity forward."
            )

        # user_id: use OID as the canonical, immutable identifier.
        # UPN can change (username renames); OID never does.
        user_id = claims.oid or claims.subject
        if not user_id:
            raise ValueError("Token has no 'oid' or 'sub' claim — cannot establish user identity.")

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
        """
        Map an app-only token to an agent principal dict.

        Used when an LLM agent authenticates using Managed Identity or
        client credentials (no user context). Returns raw metadata only —
        this does NOT produce a UserContext because there is no user.

        The caller must explicitly construct an AgentContext with appropriate
        permission ceilings based on the service principal's role.
        """
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
        """
        Derive brand_scope from Entra group memberships.

        Walks the user's group list (OIDs or display names) against the
        brand_group_map in config. Returns the union of all matched brands,
        deduplicated and sorted.

        If the user has groups overage (>200 groups), groups are absent
        from the token — warn and return empty (fail-closed). Production
        systems should fetch groups via Microsoft Graph in this case.
        """
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
        """
        Derive clearance_level from Entra app roles.

        Applies the highest sensitivity level matched across all assigned roles.
        Defaults to INTERNAL if no roles match (fail-closed: no app role
        assignment means minimum access, not maximum).
        """
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
