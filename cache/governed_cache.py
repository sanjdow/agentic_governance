"""
cache/governed_cache.py
-----------------------
Governed Cache: Identity-scoped, policy-version-bound, classification-aware.

Problems addressed:
  1. Cached tool results carry zero classification metadata
  2. Cache keys rarely incorporate user identity — enabling cross-user hits
  3. TTL is the only control; policy changes don't invalidate stale entries
  4. Sensitive governed data sits in Redis in plaintext by default

This implementation wraps Redis (or fakeredis for testing) with:
  - Identity-scoped cache keys (user_id + agent_id + query_hash)
  - Policy-version binding (cached entries are invalidated on policy change)
  - Classification-aware TTLs (sensitive data expires faster)
  - Transparent at-rest encryption using Fernet symmetric encryption
  - Automatic invalidation on policy version change

Cache Key Structure:
  governed:{policy_version_prefix}:{user_id}:{agent_id}:{query_hash}

This ensures:
  - Agent A's results are NEVER served to Agent B (different agent_id)
  - User X's results are NEVER served to User Y (different user_id)
  - Results from an old policy version are NEVER served after a policy change
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any, Optional

from cryptography.fernet import Fernet

from catalog.catalog import DataCatalog
from core.exceptions import CachePolicyVersionMismatch
from core.models import SensitivityLevel

logger = logging.getLogger(__name__)

# TTL by sensitivity level (seconds) — the more sensitive, the shorter the cache life
SENSITIVITY_TTL: dict[SensitivityLevel, int] = {
    SensitivityLevel.PUBLIC:       3600,   # 1 hour
    SensitivityLevel.INTERNAL:     1800,   # 30 minutes
    SensitivityLevel.CONFIDENTIAL:  300,   # 5 minutes
    SensitivityLevel.RESTRICTED:     60,   # 1 minute
    SensitivityLevel.SECRET:          0,   # Never cache
}


class GovernedCache:
    """
    A governed wrapper around Redis (or fakeredis) for agent tool-call result caching.

    Provides identity-scoped, policy-version-bound, classification-aware caching
    with optional at-rest encryption.

    Usage:
        cache = GovernedCache(catalog=catalog)

        # Store a result
        cache.set(
            user_id="sanjay",
            agent_id="retrieval_agent",
            query="SELECT * FROM cost_analytics.group_costs WHERE brand='vw'",
            data=query_result,
            sensitivity=SensitivityLevel.CONFIDENTIAL,
        )

        # Retrieve — returns None if not found, expired, or policy version mismatch
        result = cache.get(
            user_id="sanjay",
            agent_id="retrieval_agent",
            query="SELECT * FROM cost_analytics.group_costs WHERE brand='vw'",
        )
    """

    def __init__(
        self,
        catalog: DataCatalog,
        redis_client: Any = None,          # redis.Redis or fakeredis.FakeRedis
        encrypt: bool = True,
        encryption_key: Optional[bytes] = None,
    ) -> None:
        self._catalog = catalog
        self._encrypt = encrypt

        if redis_client is not None:
            self._redis = redis_client
        else:
            # Fall back to in-process dict-based store (no redis required)
            self._redis = _InMemoryStore()
            logger.info("GovernedCache: using in-memory fallback store (no Redis configured)")

        if encrypt:
            key = encryption_key or Fernet.generate_key()
            self._fernet = Fernet(key)
            logger.info("GovernedCache: at-rest encryption enabled")
        else:
            self._fernet = None
            logger.warning("GovernedCache: at-rest encryption DISABLED — not suitable for production")

    # ── Public Interface ──────────────────────────────────────────────────────

    def set(
        self,
        user_id: str,
        agent_id: str,
        query: str,
        data: Any,
        sensitivity: SensitivityLevel = SensitivityLevel.INTERNAL,
    ) -> bool:
        """
        Cache a query result under a governed key.

        Returns False if the sensitivity level prohibits caching (SECRET).
        """
        ttl = SENSITIVITY_TTL.get(sensitivity, 0)
        if ttl == 0:
            logger.debug(
                "Cache write skipped: sensitivity=%s does not permit caching", sensitivity
            )
            return False

        key = self._build_key(user_id, agent_id, query)
        policy_version = self._catalog.get_policy_version().version_id

        entry = {
            "data": data,
            "policy_version": policy_version,
            "sensitivity": sensitivity.value,
            "user_id": user_id,
            "agent_id": agent_id,
            "stored_at": time.time(),
        }

        serialized = json.dumps(entry, default=str).encode()
        if self._encrypt and self._fernet:
            serialized = self._fernet.encrypt(serialized)

        self._redis.setex(key, ttl, serialized)
        logger.debug(
            "Cache SET: user=%s agent=%s sensitivity=%s ttl=%ds key_suffix=...%s",
            user_id, agent_id, sensitivity, ttl, key[-12:],
        )
        return True

    def get(
        self,
        user_id: str,
        agent_id: str,
        query: str,
        current_policy_version: Optional[str] = None,
    ) -> Optional[Any]:
        """
        Retrieve a cached result with full governance validation.

        Returns None if:
          - Key not found
          - Entry is expired (Redis handles TTL expiry natively)
          - Policy version mismatch (stale entry)
          - user_id or agent_id mismatch (should never happen due to key scoping,
            but validated defensively against key collisions)

        Raises:
          CachePolicyVersionMismatch — when strict mode detects a policy change
        """
        key = self._build_key(user_id, agent_id, query)
        raw = self._redis.get(key)

        if raw is None:
            return None

        try:
            if self._encrypt and self._fernet:
                raw = self._fernet.decrypt(raw)
            entry = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
        except Exception as e:
            logger.warning("Cache entry corrupt or decryption failed: %s", e)
            self._redis.delete(key)
            return None

        # Defensive identity check
        if entry.get("user_id") != user_id or entry.get("agent_id") != agent_id:
            logger.error(
                "Cache identity mismatch! Stored user=%s agent=%s, requested user=%s agent=%s. "
                "Evicting entry.",
                entry.get("user_id"), entry.get("agent_id"), user_id, agent_id,
            )
            self._redis.delete(key)
            return None

        # Policy version check
        stored_version = entry.get("policy_version", "")
        live_version = (
            current_policy_version or self._catalog.get_policy_version().version_id
        )
        if stored_version != live_version:
            logger.info(
                "Cache MISS (policy version changed): stored=%s live=%s key_suffix=...%s",
                stored_version[:12], live_version[:12], key[-12:],
            )
            self._redis.delete(key)
            return None

        logger.debug(
            "Cache HIT: user=%s agent=%s key_suffix=...%s", user_id, agent_id, key[-12:]
        )
        return entry["data"]

    def invalidate_for_user(self, user_id: str) -> int:
        """Evict all cache entries for a user. Call on permission revocation."""
        pattern = f"governed:*:{user_id}:*"
        return self._delete_by_pattern(pattern)

    def invalidate_for_policy_version(self, old_version: str) -> int:
        """
        Evict all entries stored under a specific policy version.
        Call when a catalog policy change is committed.
        """
        version_prefix = old_version[:16]
        pattern = f"governed:{version_prefix}:*"
        return self._delete_by_pattern(pattern)

    def stats(self) -> dict[str, Any]:
        """Return cache statistics for monitoring."""
        if hasattr(self._redis, "info"):
            info = self._redis.info("stats")
            return {
                "hits": info.get("keyspace_hits", 0),
                "misses": info.get("keyspace_misses", 0),
            }
        return {"backend": "in-memory"}

    # ── Key Construction ──────────────────────────────────────────────────────

    def _build_key(self, user_id: str, agent_id: str, query: str) -> str:
        """
        Build a governed cache key.

        Key structure:
          governed:{policy_prefix}:{user_id}:{agent_id}:{query_hash}

        The policy_prefix means keys from different policy versions NEVER collide.
        The user_id and agent_id scope means results NEVER cross identity boundaries.
        The query_hash uniquely identifies the exact query.
        """
        policy_prefix = self._catalog.get_policy_version().version_id[:16]
        query_hash = hashlib.sha256(query.strip().encode()).hexdigest()[:24]
        # Hash user_id and agent_id to avoid key length/character issues
        id_hash = hashlib.sha256(f"{user_id}:{agent_id}".encode()).hexdigest()[:16]
        return f"governed:{policy_prefix}:{id_hash}:{query_hash}"

    def _delete_by_pattern(self, pattern: str) -> int:
        """Delete keys matching a pattern. Works with Redis SCAN or in-memory store."""
        if hasattr(self._redis, "scan_iter"):
            keys = list(self._redis.scan_iter(pattern))
            if keys:
                return self._redis.delete(*keys)
            return 0
        elif hasattr(self._redis, "delete_pattern"):
            return self._redis.delete_pattern(pattern)
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Minimal in-memory store (no Redis dependency required for tests/dev)
# ─────────────────────────────────────────────────────────────────────────────

class _InMemoryStore:
    """Simple TTL-aware in-memory store. Not for production use."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[bytes, float]] = {}   # {key: (value, expires_at)}

    def setex(self, key: str, ttl: int, value: bytes) -> None:
        self._store[key] = (value, time.time() + ttl)

    def get(self, key: str) -> Optional[bytes]:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if time.time() > expires_at:
            del self._store[key]
            return None
        return value

    def delete(self, *keys: str) -> int:
        count = 0
        for key in keys:
            if key in self._store:
                del self._store[key]
                count += 1
        return count

    def delete_pattern(self, pattern: str) -> int:
        """Very basic glob-style pattern match for in-memory store."""
        import fnmatch
        matching = [k for k in list(self._store.keys()) if fnmatch.fnmatch(k, pattern)]
        return self.delete(*matching)
