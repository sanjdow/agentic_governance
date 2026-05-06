"""
auth/token_validator.py
-----------------------
Microsoft Entra ID JWT token validator.

Validates Bearer tokens issued by Entra ID (Azure AD) and extracts
the identity claims needed to construct a UserContext for the governance
framework.

Validation steps (per Microsoft's best practices):
  1. Fetch the JWKS from the tenant's OIDC metadata endpoint
  2. Verify the RS256 signature using the matching public key
  3. Validate standard claims: iss, aud, exp, nbf, tid
  4. Extract identity claims: oid (Object ID), upn, groups, roles

Caching:
  JWKS keys are cached in memory with a 24-hour TTL. This avoids a
  network call on every token validation while still rotating on key
  rollover (when a kid mismatch forces a cache refresh).

Test mode:
  When validate_tenant=False (EntraConfig.for_testing()), the validator
  accepts self-signed tokens without calling Microsoft endpoints. This
  allows full unit testing without Azure credentials.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional
from urllib.request import urlopen
import json

import jwt
from jwt import PyJWKClient, PyJWKClientError

from auth.entra_config import EntraConfig
from core.exceptions import AgenticGovernanceError

logger = logging.getLogger(__name__)


class EntraTokenValidationError(AgenticGovernanceError):
    """Raised when an Entra ID token fails validation."""


class EntraTokenClaims:
    """
    Typed wrapper around validated Entra ID token claims.

    Provides safe access to standard and custom claims with
    sensible defaults when claims are absent.
    """

    def __init__(self, raw_claims: dict[str, Any]) -> None:
        self._claims = raw_claims

    # ── Standard claims ───────────────────────────────────────────────────────

    @property
    def oid(self) -> str:
        """Object ID — the immutable, canonical identity anchor in Entra."""
        return self._claims.get("oid", "")

    @property
    def upn(self) -> str:
        """User Principal Name — the login name (email format)."""
        return self._claims.get("upn", self._claims.get("preferred_username", ""))

    @property
    def name(self) -> str:
        """Display name."""
        return self._claims.get("name", "")

    @property
    def tenant_id(self) -> str:
        """Tenant (directory) ID from the 'tid' claim."""
        return self._claims.get("tid", "")

    @property
    def subject(self) -> str:
        """Subject identifier — stable per user per application."""
        return self._claims.get("sub", "")

    # ── Group and role claims ─────────────────────────────────────────────────

    @property
    def groups(self) -> list[str]:
        """
        Group OIDs the user is a member of.

        Note: Entra only includes groups in the token if the app manifest
        has 'groupMembershipClaims' set to 'SecurityGroup' or 'All'.
        If groups exceed 200, Entra omits them from the token and sets a
        _claim_names overage indicator — handle via Graph API in that case.
        """
        return self._claims.get("groups", [])

    @property
    def roles(self) -> list[str]:
        """
        App roles assigned to the user/principal.
        These are the values defined in the app manifest's 'appRoles' array.
        """
        return self._claims.get("roles", [])

    @property
    def scp(self) -> list[str]:
        """Scopes in delegated-permission tokens."""
        raw = self._claims.get("scp", "")
        return raw.split() if isinstance(raw, str) else raw

    @property
    def has_groups_overage(self) -> bool:
        """
        True if Entra truncated group claims due to the 200-group limit.
        When True, groups must be fetched via Microsoft Graph API.
        """
        return "_claim_names" in self._claims and "groups" in self._claims.get("_claim_names", {})

    # ── Application-context claims ────────────────────────────────────────────

    @property
    def app_id(self) -> str:
        """Client application ID that requested the token (azp / appid)."""
        return self._claims.get("azp", self._claims.get("appid", ""))

    @property
    def is_app_only(self) -> bool:
        """
        True if this is an application (Managed Identity / client credentials)
        token with no user context.

        In app-only tokens, there is no 'upn' or 'oid' representing a human.
        The identity is the service principal. This is the scenario where
        user identity is LOST in agent-to-agent delegation via Managed Identity.
        """
        return "oid" not in self._claims or self._claims.get("idtyp") == "app"

    def raw(self) -> dict[str, Any]:
        return dict(self._claims)

    def __repr__(self) -> str:
        return f"EntraTokenClaims(oid={self.oid!r}, upn={self.upn!r}, roles={self.roles})"


class EntraTokenValidator:
    """
    Validates Entra ID JWT tokens and returns typed claims.

    Usage:
        config = EntraConfig.from_env()
        validator = EntraTokenValidator(config)

        # Validate a Bearer token from an HTTP Authorization header
        claims = validator.validate("eyJ0eXAiOiJKV1Q...")

    Test mode (no Azure credentials needed):
        config = EntraConfig.for_testing()
        validator = EntraTokenValidator(config)
        # Accepts tokens signed with a test key pair
    """

    _JWKS_CACHE_TTL = 86_400   # 24 hours

    def __init__(self, config: EntraConfig) -> None:
        self._config = config
        self._jwks_client: Optional[PyJWKClient] = None
        self._jwks_cached_at: float = 0.0
        self._test_public_key: Optional[str] = None  # set in test mode

    # ── Public interface ──────────────────────────────────────────────────────

    def validate(self, token: str) -> EntraTokenClaims:
        """
        Validate an Entra ID JWT and return its claims.

        Raises:
            EntraTokenValidationError — for any validation failure:
                invalid signature, expired token, wrong audience, wrong tenant
        """
        if self._config.validate_tenant:
            return self._validate_production(token)
        else:
            return self._validate_test(token)

    def validate_from_header(self, authorization_header: str) -> EntraTokenClaims:
        """
        Extract and validate a Bearer token from an HTTP Authorization header.
        Accepts 'Bearer <token>' or raw '<token>'.
        """
        token = authorization_header.strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        return self.validate(token)

    # ── Production validation ─────────────────────────────────────────────────

    def _validate_production(self, token: str) -> EntraTokenClaims:
        """Full validation against Microsoft's JWKS."""
        # Refresh JWKS client if stale
        if time.time() - self._jwks_cached_at > self._JWKS_CACHE_TTL:
            self._refresh_jwks()

        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
        except PyJWKClientError as e:
            # kid mismatch — Microsoft may have rotated keys; force refresh once
            logger.info("JWKS kid mismatch, refreshing key set: %s", e)
            self._refresh_jwks()
            try:
                signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            except PyJWKClientError as e2:
                raise EntraTokenValidationError(
                    f"Token signing key not found in tenant JWKS: {e2}"
                )

        try:
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._config.audience,
                options={
                    "require": ["exp", "iat", "iss", "aud"],
                    "verify_exp": True,
                    "verify_iat": True,
                    "leeway": self._config.clock_skew_seconds,
                },
            )
        except jwt.ExpiredSignatureError:
            raise EntraTokenValidationError("Token has expired.")
        except jwt.InvalidAudienceError:
            raise EntraTokenValidationError(
                f"Token audience does not match expected '{self._config.audience}'."
            )
        except jwt.InvalidIssuerError:
            raise EntraTokenValidationError(
                f"Token issuer is not trusted for tenant '{self._config.tenant_id}'."
            )
        except jwt.InvalidTokenError as e:
            raise EntraTokenValidationError(f"Token validation failed: {e}")

        # Validate tenant claim to prevent cross-tenant token use
        if claims.get("tid") != self._config.tenant_id:
            raise EntraTokenValidationError(
                f"Token tenant '{claims.get('tid')}' does not match "
                f"expected tenant '{self._config.tenant_id}'. "
                "Cross-tenant token use is not permitted."
            )

        logger.debug(
            "Token validated: oid=%s upn=%s roles=%s groups=%d",
            claims.get("oid"), claims.get("upn"), claims.get("roles"),
            len(claims.get("groups", [])),
        )
        return EntraTokenClaims(claims)

    def _refresh_jwks(self) -> None:
        """Fetch and cache the tenant's JWKS."""
        try:
            with urlopen(self._config.oidc_metadata_url, timeout=10) as resp:
                metadata = json.loads(resp.read())
            jwks_uri = metadata["jwks_uri"]
        except Exception as e:
            raise EntraTokenValidationError(
                f"Failed to fetch OIDC metadata from {self._config.oidc_metadata_url}: {e}"
            )

        self._jwks_client = PyJWKClient(jwks_uri, cache_jwk_set=True, lifespan=self._JWKS_CACHE_TTL)
        self._jwks_cached_at = time.time()
        logger.info("JWKS refreshed from %s", jwks_uri)

    # ── Test-mode validation ──────────────────────────────────────────────────

    def _validate_test(self, token: str) -> EntraTokenClaims:
        """
        Validate a self-signed test token without calling Microsoft endpoints.
        Used in unit tests and local development with mock tokens.
        """
        if self._test_public_key is None:
            raise EntraTokenValidationError(
                "No test public key configured. Call set_test_keypair() first, "
                "or use EntraTokenFactory to generate test tokens."
            )
        try:
            claims = jwt.decode(
                token,
                self._test_public_key,
                algorithms=["RS256"],
                audience=self._config.audience,
                options={"leeway": self._config.clock_skew_seconds},
            )
        except jwt.InvalidTokenError as e:
            raise EntraTokenValidationError(f"Test token validation failed: {e}")
        return EntraTokenClaims(claims)

    def set_test_keypair(self, public_key_pem: str) -> None:
        """Register the public key for test-mode token validation."""
        self._test_public_key = public_key_pem
