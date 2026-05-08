"""
policy_resolver/resolver.py
---------------------------
L3 — Policy Resolver: Issues Signed Access Tokens.

This is the architectural heart of the data access governance model.

An agent expresses intent. The Policy Resolver:
  1. Looks up the data assets touched by the query
  2. Validates the query against catalog-derived access rights
  3. Derives row/column filters from catalog policy
  4. Issues an Signed Access Token: a cryptographically signed,
     short-lived document binding the specific query to the user identity,
     agent identity, session, and policy version at the time of issuance.

The query hash is binding — any modification is detected. Each token is single-use.
No agent can self-issue a proof.
"""

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
    """
    Issues and validates Signed Access Tokens.

    Uses RS256 asymmetric signing — the private key stays in the resolver,
    the public key is distributed to MCP enforcement servers.

    In production, the private key should be stored in a HSM or secrets manager
    (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault).
    """

    DEFAULT_PROOF_TTL_SECONDS = 120   # 2 minutes — short-lived by design

    def __init__(
        self,
        catalog: DataCatalog,
        proof_ttl_seconds: int = DEFAULT_PROOF_TTL_SECONDS,
    ) -> None:
        self._catalog = catalog
        self._proof_ttl = proof_ttl_seconds
        self._private_key, self._public_key = self._generate_keypair()
        # Direct revocation: set of revoked token_ids
        self._revoked_proofs: set[str] = set()
        # Session-level revocation: if a session_id is here, all proofs
        # issued under that session are considered revoked
        self._revoked_sessions: set[str] = set()
        # Track issued token_id → session_id so revoke_session_tokens can act
        self._proof_session_index: dict[str, str] = {}
        logger.info("PolicyResolver initialized with %ds proof TTL", proof_ttl_seconds)

    # ── Key Management ────────────────────────────────────────────────────────

    def _generate_keypair(self) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate an in-process RSA keypair. Replace with HSM in production."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        return private_key, private_key.public_key()

    @property
    def public_key_pem(self) -> str:
        """PEM-encoded public key for distribution to MCP enforcement servers."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    # ── Proof Issuance ────────────────────────────────────────────────────────

    def request_token(
        self,
        session: SessionContext,
        agent: AgentContext,
        query: str,
        asset_ids: list[str],
        required_right: AccessRight = AccessRight.READ,
    ) -> SignedAccessToken:
        """
        Core method: validate a query and issue an Signed Access Token.

        Steps:
          1. Resolve access for each asset against catalog policy
          2. Derive row/column filters
          3. Issue and sign the proof JWT

        Raises:
          QueryAccessDeniedError — if any asset access is denied
          ConsentBlockedError    — if PII consent is missing
          AssetNotFoundError     — if an asset_id is not in the catalog
        """
        user = session.user

        all_filters: dict[str, str] = {}
        all_masked_columns: list[str] = []

        for asset_id in asset_ids:
            asset = self._catalog.get_asset(asset_id)

            # Policy decision: does this user+agent have access?
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

            # Derive filters — these will be embedded in the proof
            filters = self._catalog.derive_row_filters(user, asset)
            all_filters.update(filters)
            masked = self._catalog.derive_column_mask(user, asset)
            all_masked_columns.extend(masked)

            logger.debug(
                "Access granted user=%s asset=%s filters=%s",
                user.user_id, asset_id, filters,
            )

        # Build and sign the proof
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
        """Sign the proof as a JWT using RS256."""
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

    # ── Proof Verification ────────────────────────────────────────────────────

    def verify_token(
        self,
        token: str,
        submitted_query: str,
        claiming_agent_id: str,
    ) -> SignedAccessToken:
        """
        Verify a proof token.

        Called by the MCP enforcement server before executing any query.

        Checks:
          1. JWT signature validity   → TokenVerificationError
          2. Expiry                   → TokenExpiredError
          3. Direct/session revocation → TokenRevocationError
          4. Agent identity (non-delegable) → TokenDelegationError
          5. Query hash match          → TokenQueryMismatchError

        All five exceptions inherit from TokenVerificationError, so callers
        that don't care about the specific reason can catch the base class.
        """
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
            raise TokenVerificationError(f"Proof signature invalid: {e}")

        token_id = payload["jti"]
        session_id = payload["session_id"]

        # Direct proof revocation
        if token_id in self._revoked_proofs:
            raise TokenRevocationError(f"Proof '{token_id}' has been revoked.")

        # Session-level revocation (e.g. mid-session policy change)
        if session_id in self._revoked_sessions:
            raise TokenRevocationError(
                f"Session '{session_id}' has been revoked — "
                "all proofs from this session are invalid. "
                "A new session must be established."
            )

        # Non-delegable: the agent using the proof must be the one it was issued for
        if payload["agent_id"] != claiming_agent_id:
            raise TokenDelegationError(
                f"Proof was issued for agent '{payload['agent_id']}', "
                f"not '{claiming_agent_id}'. Proofs are non-delegable."
            )

        # Query hash binding
        expected_hash = SignedAccessToken.hash_query(submitted_query)
        if payload["query_hash"] != expected_hash:
            raise TokenQueryMismatchError(
                "Submitted query does not match the proof's query hash. "
                "Query substitution detected."
            )

        # Reconstruct proof object for downstream use
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

    # ── Revocation ────────────────────────────────────────────────────────────

    def revoke_token(self, token_id: str) -> None:
        """
        Explicitly revoke a single proof.

        In production this should write to a distributed revocation store
        (Redis, DynamoDB) that all MCP servers can query.
        """
        self._revoked_proofs.add(token_id)
        logger.warning("Proof revoked: token_id=%s", token_id)

    def revoke_session_tokens(self, session_id: str) -> None:
        """
        Mark all proofs for a session as revoked.

        Used on policy updates that should invalidate any in-flight
        agent activity in the affected session. Subsequent verification
        of any proof issued under this session will fail.
        """
        self._revoked_sessions.add(session_id)
        logger.warning("All proofs revoked for session=%s", session_id)
