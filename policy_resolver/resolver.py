

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from catalog.catalog import DataCatalog
from core.exceptions import (
    TokenDelegationError,
    TokenExpiredError,
    TokenQueryMismatchError,
    TokenRevocationError,
    TokenVerificationError,
    QueryAccessDeniedError,
)
from core.models import (
    AccessRight,
    AgentContext,
    SignedAccessToken,
    SessionContext,
    UserContext,
)

logger = logging.getLogger(__name__)


class PolicyResolver:
    # private key never leaves this class — use KMS in production

    DEFAULT_PROOF_TTL_SECONDS = 120

    def __init__(
        self,
        catalog: DataCatalog,
        proof_ttl_seconds: int = DEFAULT_PROOF_TTL_SECONDS,
    ) -> None:
        self._catalog = catalog
        self._proof_ttl = proof_ttl_seconds
        self._private_key, self._public_key = self._generate_keypair()
        self._revoked_proofs: set[str] = set()
        self._revoked_sessions: set[str] = set()
        self._proof_session_index: dict[str, str] = {}
        logger.info("PolicyResolver initialized with %ds proof TTL", proof_ttl_seconds)


    def _generate_keypair(self) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        return private_key, private_key.public_key()

    @property
    def public_key_pem(self) -> str:
    
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()


    def request_token(
        self,
        session: SessionContext,
        agent: AgentContext,
        query: str,
        asset_ids: list[str],
        required_right: AccessRight = AccessRight.READ,
    ) -> SignedAccessToken:

        user = session.user

        all_filters: dict[str, str] = {}
        all_masked_columns: list[str] = []

        for asset_id in asset_ids:
            asset = self._catalog.get_asset(asset_id)

            allowed, reason = self._catalog.resolve_access(
                user=user,
                agent=agent,
                asset_id=asset_id,
                required_right=required_right,
            )
            if not allowed:
                logger.warning(
                    "Access denied for user=%s agent=%s asset=%s: %s",
                    user.user_id, agent.agent_id, asset_id, reason,
                )
                raise QueryAccessDeniedError(
                    f"Query denied for asset '{asset_id}': {reason}"
                )

            filters = self._catalog.derive_row_filters(user, asset)
            all_filters.update(filters)
            masked = self._catalog.derive_column_mask(user, asset)
            all_masked_columns.extend(masked)

            logger.debug(
                "Access granted user=%s asset=%s filters=%s",
                user.user_id, asset_id, filters,
            )

        policy_version = self._catalog.get_policy_version()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=self._proof_ttl)

        proof = SignedAccessToken(
            query_hash=SignedAccessToken.hash_query(query),
            query_preview=query[:120],
            user_id=user.user_id,
            agent_id=agent.agent_id,
            session_id=session.session_id,
            catalog_policy_version=policy_version.version_id,
            issued_at=now,
            expires_at=expires_at,
            allowed_filters={**all_filters, "masked_columns": all_masked_columns},
            asset_ids=asset_ids,
        )
        proof.token = self._sign_proof(proof)
        self._proof_session_index[proof.token_id] = session.session_id

        logger.info(
            "Proof issued token_id=%s user=%s agent=%s assets=%s ttl=%ds",
            proof.token_id, user.user_id, agent.agent_id, asset_ids, self._proof_ttl,
        )
        return proof

    def _sign_proof(self, proof: SignedAccessToken) -> str:
    
        private_key_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        payload = {
            "jti": proof.token_id,
            "sub": proof.user_id,
            "agent_id": proof.agent_id,
            "session_id": proof.session_id,
            "query_hash": proof.query_hash,
            "policy_version": proof.catalog_policy_version,
            "allowed_filters": proof.allowed_filters,
            "asset_ids": proof.asset_ids,
            "iat": int(proof.issued_at.timestamp()),
            "exp": int(proof.expires_at.timestamp()),
            "iss": "agentic-governance/policy-resolver",
        }
        return jwt.encode(payload, private_key_pem, algorithm="RS256")


    def verify_token(
        self,
        token: str,
        submitted_query: str,
        claiming_agent_id: str,
    ) -> SignedAccessToken:
        # raises TokenVerificationError subclasses — catch base class if you don't care why
        public_key_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        try:
            payload = jwt.decode(
                token,
                public_key_pem,
                algorithms=["RS256"],
                options={"require": ["jti", "sub", "agent_id", "query_hash", "exp"]},
            )
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError("Proof has expired.")
        except jwt.InvalidTokenError as e:
            raise TokenVerificationError(f"invalid token: {e}")

        token_id = payload["jti"]
        session_id = payload["session_id"]

        if token_id in self._revoked_proofs:
            raise TokenRevocationError(f"Proof '{token_id}' has been revoked.")

        if session_id in self._revoked_sessions:
            raise TokenRevocationError(f"session {session_id!r} revoked")

        if payload["agent_id"] != claiming_agent_id:
            raise TokenDelegationError(f"token issued for {payload['agent_id']!r}, not {claiming_agent_id!r}")

        expected_hash = SignedAccessToken.hash_query(submitted_query)
        if payload["query_hash"] != expected_hash:
            raise TokenQueryMismatchError("query hash mismatch")

        return SignedAccessToken(
            token_id=token_id,
            query_hash=payload["query_hash"],
            query_preview="",
            user_id=payload["sub"],
            agent_id=payload["agent_id"],
            session_id=payload["session_id"],
            catalog_policy_version=payload["policy_version"],
            issued_at=datetime.fromtimestamp(payload["iat"], tz=timezone.utc),
            expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
            allowed_filters=payload.get("allowed_filters", {}),
            asset_ids=payload.get("asset_ids", []),
            token=token,
        )


    def revoke_token(self, token_id: str) -> None:
        # TODO: write to distributed revocation store in production
        self._revoked_proofs.add(token_id)
        logger.warning("Proof revoked: token_id=%s", token_id)

    def revoke_session_tokens(self, session_id: str) -> None:

        self._revoked_sessions.add(session_id)
        logger.warning("All proofs revoked for session=%s", session_id)
