from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from auth.entra_config import EntraConfig


class EntraTokenFactory:

    def __init__(self, config: EntraConfig) -> None:
        self._config = config
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self._public_key = self._private_key.public_key()

    @property
    def public_key_pem(self) -> str:
    
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
        # simulates Managed Identity — no user context, just the service principal
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
        # OBO preserves oid/upn but loses roles and groups — that's the whole problem
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
