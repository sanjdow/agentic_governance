"""
mcp_server/governance_server.py
--------------------------------
L4 — MCP Governance Server: Access Enforcer — it never decides policy.

The MCP server does NOT evaluate whether a query is permissible.
That decision has already been made and encoded in the Signed Access Token.

The MCP server:
  1. Verifies the proof's JWT signature
  2. Checks proof expiry
  3. Validates the submitted query matches the proof's query hash
  4. Verifies the claiming agent matches the proof's agent binding
  5. Routes to one of two execution paths:
       a. Filter push-down: translate policy semantics into WHERE clauses
       b. Authorized query pass-through: execute the pre-validated query unchanged

Policy logic does NOT live here. It never should.

This implements the proposed MCP protocol extension:
  {
    "tool": "query_datasource",
    "arguments": { "source": "...", "query": "..." },
    "proof": {
      "token": "<signed JWT>",
      "issued_by": "policy-resolver.internal",
      "query_hash": "sha256:...",
      "expires_at": "..."
    }
  }
"""

from __future__ import annotations

import copy
import logging
import re
from datetime import datetime, timezone
from typing import Any, Optional

from core.exceptions import (
    TokenVerificationError,
    QueryAccessDeniedError,
)
from core.models import (
    SignedAccessToken,
    MCPToolCall,
    MCPToolResult,
)
from policy_resolver.resolver import PolicyResolver

logger = logging.getLogger(__name__)


class MCPGovernanceServer:
    """
    MCP-style governance server acting as a pure Access Enforcer.

    In production this would be a FastAPI/ASGI service. Here it is implemented
    as an in-process class so it can be used directly in tests and examples
    without network overhead.

    Swap the `_execute_*` methods for real database connectors in production.
    """

    def __init__(
        self,
        policy_resolver: PolicyResolver,
        require_sat: bool = True,
        max_replay_cache_size: int = 100_000,
    ) -> None:
        self._resolver = policy_resolver
        self._require_sat = require_sat
        self._max_replay_cache_size = max_replay_cache_size
        # Replay protection: maps token_id → expiry timestamp.
        # Entries are evicted when:
        #   (a) the token_id's expiry has passed (proof can no longer be verified anyway)
        #   (b) the cache exceeds max_replay_cache_size (oldest entries evicted)
        # In production this should be a distributed store (Redis with TTLs).
        self._used_token_ids: dict[str, datetime] = {}
        logger.info(
            "MCPGovernanceServer initialized (require_sat=%s, replay_cache_size=%d)",
            require_sat, max_replay_cache_size,
        )

    def _record_proof_use(self, token_id: str, expires_at: datetime) -> None:
        """Record a proof as used, evicting expired or oldest entries."""
        now = datetime.now(timezone.utc)

        # Evict expired entries (proofs past their expiry can't be reverified anyway)
        expired = [pid for pid, exp in self._used_token_ids.items() if exp <= now]
        for pid in expired:
            del self._used_token_ids[pid]

        # If still over the limit, evict the oldest entries (FIFO by insertion)
        if len(self._used_token_ids) >= self._max_replay_cache_size:
            # dict preserves insertion order in Python 3.7+
            to_remove = len(self._used_token_ids) - self._max_replay_cache_size + 1
            for pid in list(self._used_token_ids.keys())[:to_remove]:
                del self._used_token_ids[pid]

        self._used_token_ids[token_id] = expires_at

    # ── Main Dispatch ─────────────────────────────────────────────────────────

    def handle_tool_call(self, call: MCPToolCall) -> MCPToolResult:
        """
        Handle an MCP tool call.

        If the call carries a valid proof → verify and execute.
        If require_sat=True and no proof → reject.
        If require_sat=False and no proof → execute with warning (dev mode only).
        """
        if not call.is_governed():
            if self._require_sat:
                return MCPToolResult(
                    success=False,
                    error=(
                        "Ungoverned call rejected. All tool calls must carry "
                        "a valid Signed Access Token. "
                        "Use the Policy Resolver to obtain one."
                    ),
                    governed=False,
                )
            logger.warning(
                "⚠  UNGOVERNED call to tool '%s' — proof enforcement disabled (dev mode)",
                call.tool,
            )
            return self._execute_ungoverned(call)

        return self._execute_governed(call)

    # ── Governed Execution Path ───────────────────────────────────────────────

    def _execute_governed(self, call: MCPToolCall) -> MCPToolResult:
        """Verify proof, then execute with filter push-down or pass-through."""
        proof = call.proof
        query = call.arguments.get("query", "")
        agent_id = call.arguments.get("agent_id", "")

        # Step 1: Verify the proof
        try:
            verified_sat = self._resolver.verify_token(
                token=proof.token,
                submitted_query=query,
                claiming_agent_id=agent_id,
            )
        except TokenVerificationError as e:
            logger.error("Proof verification failed: %s", e)
            return MCPToolResult(
                success=False,
                error=f"Proof verification failed: {e}",
                governed=True,
            )

        # Step 2: Replay protection — a proof can only be used once
        if verified_sat.token_id in self._used_token_ids:
            return MCPToolResult(
                success=False,
                error=f"Proof '{verified_sat.token_id}' has already been used. "
                      "Proofs are single-use.",
                governed=True,
            )
        self._record_proof_use(verified_sat.token_id, verified_sat.expires_at)

        # Step 3: Determine execution path
        # IMPORTANT: copy filters so we don't mutate the proof's allowed_filters dict.
        # The pop() of "masked_columns" below would otherwise persist on the proof
        # object and confuse any subsequent inspection.
        filters = copy.deepcopy(verified_sat.allowed_filters)
        masked_columns = filters.pop("masked_columns", [])

        if filters:
            # Filter push-down path: translate catalog policy semantics into SQL WHERE
            result = self._execute_with_filter_pushdown(
                call=call,
                query=query,
                row_filters=filters,
                masked_columns=masked_columns,
                proof=verified_sat,
            )
        else:
            # Pass-through path: query already validated, no additional filters needed
            result = self._execute_passthrough(
                call=call,
                query=query,
                masked_columns=masked_columns,
                proof=verified_sat,
            )

        result.token_id = verified_sat.token_id
        result.governed = True
        return result

    def _execute_with_filter_pushdown(
        self,
        call: MCPToolCall,
        query: str,
        row_filters: dict[str, str],
        masked_columns: list[str],
        proof: SignedAccessToken,
    ) -> MCPToolResult:
        """
        Filter push-down path.

        Translates catalog-derived policy semantics into SQL WHERE clauses
        and injects them into the query before execution.

        This is analogous to:
          - Unity Catalog row-level security
          - Starburst/Trino row filters
          - Apache Ranger policy push-down
        """
        governed_query = self._inject_where_clauses(query, row_filters)
        logger.info(
            "Filter push-down applied: sat=%s filters=%s",
            proof.token_id, row_filters,
        )

        # Execute against the (simulated) data source
        raw_result = self._simulate_query_execution(
            source=call.arguments.get("source", "unknown"),
            query=governed_query,
        )

        # Apply column masking
        if masked_columns and isinstance(raw_result, list):
            raw_result = self._mask_columns(raw_result, masked_columns)

        return MCPToolResult(
            success=True,
            data=raw_result,
            filters_applied={**row_filters, "masked_columns": masked_columns},
        )

    def _execute_passthrough(
        self,
        call: MCPToolCall,
        query: str,
        masked_columns: list[str],
        proof: SignedAccessToken,
    ) -> MCPToolResult:
        """
        Pass-through path.

        The query has already been validated by the Policy Resolver.
        Execute it unchanged.
        """
        logger.info("Pass-through execution: sat=%s", proof.token_id)
        raw_result = self._simulate_query_execution(
            source=call.arguments.get("source", "unknown"),
            query=query,
        )
        if masked_columns and isinstance(raw_result, list):
            raw_result = self._mask_columns(raw_result, masked_columns)

        return MCPToolResult(
            success=True,
            data=raw_result,
            filters_applied={"masked_columns": masked_columns},
        )

    # ── Ungoverned Path (dev/testing only) ────────────────────────────────────

    def _execute_ungoverned(self, call: MCPToolCall) -> MCPToolResult:
        query = call.arguments.get("query", "")
        raw_result = self._simulate_query_execution(
            source=call.arguments.get("source", "unknown"),
            query=query,
        )
        return MCPToolResult(success=True, data=raw_result, governed=False)

    # ── SQL Filter Injection ──────────────────────────────────────────────────

    @staticmethod
    def _inject_where_clauses(query: str, filters: dict[str, str]) -> str:
        """
        Inject catalog-derived row filters into a SQL query.

        ⚠  IMPORTANT: This is a reference implementation suitable for simple
        SELECT queries. It uses string manipulation rather than AST parsing
        and will not handle all of:
          - Subqueries (the WHERE keyword in a subquery may be matched first)
          - CTEs (WITH ... AS clauses)
          - UNION queries (only the first SELECT receives the filter)
          - Complex CASE/WHEN expressions

        Production deployments MUST replace this with a proper SQL AST parser
        (sqlglot is recommended) that:
          1. Parses the query into an AST
          2. Walks each SELECT subtree
          3. Augments the WHERE clause of every relevant SELECT with the filters
          4. Re-serializes the modified AST

        See: https://github.com/tobymao/sqlglot

        For demonstration purposes the simple string injection below is
        sufficient — but DO NOT deploy this implementation against untrusted
        queries in production.
        """
        if not filters:
            return query

        combined_filter = " AND ".join(f"({v})" for v in filters.values())

        # Use a case-insensitive regex to find the first WHERE that's a SQL keyword
        # (i.e. preceded by whitespace and not part of a column/string literal).
        # This is still imperfect but safer than naive string indexing.
        where_match = re.search(r"\bWHERE\b", query, re.IGNORECASE)

        if where_match:
            # Insert filter as additional AND condition right after WHERE keyword
            insert_pos = where_match.end()
            return (
                query[:insert_pos]
                + f" ({combined_filter}) AND "
                + query[insert_pos:].lstrip()
            )

        # No WHERE clause — insert one before any trailing clauses
        # We need to find the earliest of these keywords (ignoring case, word-boundary)
        trailing_keywords = ["GROUP BY", "HAVING", "ORDER BY", "LIMIT", "OFFSET"]
        earliest_pos = len(query)
        for kw in trailing_keywords:
            m = re.search(rf"\b{kw}\b", query, re.IGNORECASE)
            if m and m.start() < earliest_pos:
                earliest_pos = m.start()

        if earliest_pos < len(query):
            return query[:earliest_pos].rstrip() + f" WHERE {combined_filter} " + query[earliest_pos:]
        else:
            return query.rstrip() + f" WHERE {combined_filter}"

    @staticmethod
    def _mask_columns(
        rows: list[dict[str, Any]], masked_columns: list[str]
    ) -> list[dict[str, Any]]:
        """Remove masked columns from result rows."""
        return [
            {k: v for k, v in row.items() if k not in masked_columns}
            for row in rows
        ]

    # ── Simulated Data Source ─────────────────────────────────────────────────

    @staticmethod
    def _simulate_query_execution(source: str, query: str) -> list[dict[str, Any]]:
        """
        Simulated query execution for demo purposes.

        Replace with real connectors:
          - delta_lake  → Delta Sharing / Spark
          - snowflake   → snowflake-connector-python
          - postgres    → psycopg2 / asyncpg
        """
        query_lower = query.lower()

        if "cost_analytics" in query_lower or "group_costs" in query_lower:
            return [
                {"brand": "brand_a", "cost_center": "R&D", "amount": 1200000, "currency": "EUR", "fiscal_year": 2025},
                {"brand": "brand_a", "cost_center": "Manufacturing", "amount": 3400000, "currency": "EUR", "fiscal_year": 2025},
            ]
        elif "quality" in query_lower or "defect" in query_lower:
            return [
                {"model": "A4", "defect_code": "E-001", "rate": 0.02, "region": "DE", "quarter": "Q1"},
                {"model": "Q5", "defect_code": "E-003", "rate": 0.01, "region": "DE", "quarter": "Q1"},
            ]
        elif "employees" in query_lower or "hr" in query_lower:
            return [
                {"employee_id": "E001", "name": "Alex Smith", "department": "Engineering",
                 "email": "a.schmidt@example.com", "salary": 85000, "birth_date": "1990-01-15"},
            ]
        elif "telemetry" in query_lower:
            return [
                {"vin": "VEH-001", "timestamp": "2025-01-01T10:00:00Z",
                 "speed": 120, "location_lat": 52.52, "location_lon": 13.40, "brand": "brand_a"},
            ]
        elif "parts" in query_lower:
            return [
                {"part_id": "P001", "description": "Brake Pad Set", "price": 49.99, "supplier": "Bosch"},
                {"part_id": "P002", "description": "Air Filter", "price": 12.50, "supplier": "Mann"},
            ]
        else:
            return [{"result": f"Query executed on {source}", "rows": 0}]
