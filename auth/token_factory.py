"""
auth/token_factory.py
---------------------
Test token factory: generates realistic Entra ID-style JWTs for testing.

This module exists so the test suite can exercise the full token validation
and claim-mapping pipeline without requiring real Azure credentials or a
live Entra ID tenant.

Generated tokens are signed with an ephemeral RSA key pair created at
factory construction time. The factory exposes the public key so tests
can configure the validator to accept these tokens.

Usage in tests:
    factory = EntraTokenFactory(config)
    validator = EntraTokenValidator(config)
    validator.set_test_keypair(factory.public_key_pem)

    token = factory.make_user_token(
        oid="test-oid-audi-analyst",
        upn="analyst@audi.example.com",
        groups=["Audi-Analysts"],
        roles=["DataAnalyst"],
    )
    claims = validator.validate(token)

IMPORTANT: These tokens are for testing only. Never use in production.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from auth.entra_config import EntraConfig


class EntraTokenFactory:
    """
    Generates Entra ID-style JWTs signed with an ephemeral test key pair.
    """

    def __init__(self, config: EntraConfig) -> None:
        self._config = config
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self._public_key = self._private_key.public_key()

    @property
    def public_key_pem(self) -> str:
        """PEM-encoded public key to register with EntraTokenValidator."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    @property
    def private_key_pem(self) -> str:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

    def make_user_token(
        self,
        oid: str,
        upn: str,
        name: str = "Test User",
        groups: Optional[list[str]] = None,
        roles: Optional[list[str]] = None,
        scp: str = "user_impersonation",
        ttl_seconds: int = 3600,
        extra_claims: Optional[dict[str, Any]] = None,
    ) -> str:
        """
        Generate a delegated-permission user token (simulates interactive login).

        Args:
            oid:      Object ID — the canonical Entra identity anchor
            upn:      User Principal Name (email-format login)
            name:     Display name
            groups:   Group OIDs or display names the user belongs to
            roles:    App role values assigned to the user
            scp:      Delegated permission scopes
            ttl_seconds: Token lifetime in seconds
        """
        now = datetime.now(timezone.utc)
        payload = {
            # Standard claims
            "jti":  str(uuid4()),
            "iss":  f"https://login.microsoftonline.com/{self._config.tenant_id}/v2.0",
            "aud":  self._config.audience,
            "iat":  int(now.timestamp()),
            "nbf":  int(now.timestamp()),
            "exp":  int((now + timedelta(seconds=ttl_seconds)).timestamp()),
            # Identity claims
            "oid":  oid,
            "sub":  oid,    # In real tokens sub ≠ oid, but close enough for tests
            "tid":  self._config.tenant_id,
            "upn":  upn,
            "preferred_username": upn,
            "name": name,
            # Group and role claims
            "groups": groups or [],
            "roles":  roles or [],
            "scp":    scp,
            # App context
            "azp":  self._config.client_id,
            "ver":  "2.0",
        }
        if extra_claims:
            payload.update(extra_claims)

        return jwt.encode(payload, self.private_key_pem, algorithm="RS256")

    def make_app_token(
        self,
        app_id: str,
        service_name: str = "test-agent-service",
        roles: Optional[list[str]] = None,
        ttl_seconds: int = 3600,
    ) -> str:
        """
        Generate an app-only (Managed Identity / client credentials) token.

        This simulates the token an LLM agent receives when calling downstream
        services using its Managed Identity — critically, with NO user context.
        This is the "agent vs user identity" gap demonstrated in the presentation.
        """
        now = datetime.now(timezone.utc)
        payload = {
            "jti":   str(uuid4()),
            "iss":   f"https://login.microsoftonline.com/{self._config.tenant_id}/v2.0",
            "aud":   self._config.audience,
            "iat":   int(now.timestamp()),
            "nbf":   int(now.timestamp()),
            "exp":   int((now + timedelta(seconds=ttl_seconds)).timestamp()),
            # App-only identity — no oid/upn for the human user
            "oid":   app_id,
            "sub":   app_id,
            "tid":   self._config.tenant_id,
            "appid": app_id,
            "azp":   app_id,
            "idtyp": "app",   # Signals this is an app-only token
            "roles": roles or [],
            "ver":   "2.0",
        }
        return jwt.encode(payload, self.private_key_pem, algorithm="RS256")

    def make_obo_token(
        self,
        original_claims: dict[str, Any],
        downstream_scope: str,
        ttl_seconds: int = 3600,
    ) -> str:
        """
        Simulate an OBO (On-Behalf-Of) token for a downstream service call.

        OBO preserves: oid, sub, upn, tid
        OBO loses:     roles (from app registration, not propagated)
                       groups (may be absent depending on downstream app config)
                       Custom claims

        This models exactly the policy context loss described in the Spectrum
        and Entra ID slides — and why embedding context in the Authorized
        Query Proof is necessary.
        """
        now = datetime.now(timezone.utc)
        return jwt.encode(
            {
                "jti":  str(uuid4()),
                "iss":  f"https://login.microsoftonline.com/{self._config.tenant_id}/v2.0",
                "aud":  self._config.audience,
                "iat":  int(now.timestamp()),
                "nbf":  int(now.timestamp()),
                "exp":  int((now + timedelta(seconds=ttl_seconds)).timestamp()),
                # Preserved from original user context
                "oid":  original_claims.get("oid", ""),
                "sub":  original_claims.get("sub", ""),
                "upn":  original_claims.get("upn", ""),
                "name": original_claims.get("name", ""),
                "tid":  self._config.tenant_id,
                # Propagated scope
                "scp":  downstream_scope,
                # OMITTED: roles, groups — this is the OBO context loss
                "ver":  "2.0",
                "_obo": True,   # Custom marker for test assertions
            },
            self.private_key_pem,
            algorithm="RS256",
        )
