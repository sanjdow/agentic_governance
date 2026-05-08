"""
examples/demo_entra_auth.py
----------------------------
Entra ID authentication use case — end-to-end demo.

Demonstrates:
  1. Entra Bearer token validation (test mode, no Azure credentials needed)
  2. Claim → UserContext mapping (groups → brand_scope, roles → clearance)
  3. Full governance chain: auth → eligibility → proof → MCP enforcement
  4. App-only (Managed Identity) token rejection — no user context
  5. OBO delegation and explicit policy context loss
  6. The proof as a remedy: Entra OID embedded in the signed JWT

Run:
  python examples/demo_entra_auth.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import logging

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

from auth.entra_config import EntraConfig
from auth.entra_integration import EntraAuthGateway
from catalog.catalog import build_demo_catalog
from orchestrator.eligibility import AgentEligibilityResolver
from policy_resolver.resolver import PolicyResolver
from mcp_server.governance_server import MCPGovernanceServer
from core.models import (
    AgentContext, AccessRight, SensitivityLevel, MCPToolCall,
)
from core.exceptions import AgentIneligibleError, QueryAccessDeniedError


def sep(title: str) -> None:
    print(f"\n{'─' * 65}")
    print(f"  {title}")
    print("─" * 65)


def main() -> None:

    # ── Setup ─────────────────────────────────────────────────────────────────
    sep("SETUP")

    catalog = build_demo_catalog()
    gateway = EntraAuthGateway.for_testing(catalog=catalog)
    factory = gateway.token_factory

    resolver = PolicyResolver(catalog, proof_ttl_seconds=120)
    elig = AgentEligibilityResolver(catalog)
    mcp = MCPGovernanceServer(resolver, require_sat=True)

    # Define agents
    retrieval_agent = AgentContext(
        agent_id="retrieval_agent",
        agent_type="retrieval",
        max_sensitivity=SensitivityLevel.CONFIDENTIAL,
        allowed_rights=[AccessRight.READ],
        allowed_sources=["snowflake", "delta_lake"],
    )
    elig.register_agent(retrieval_agent)
    print("  ✓ Framework components initialized (Entra test mode)")

    # ─────────────────────────────────────────────────────────────────────────
    # Scenario 1: Normal user login — division analyst
    # ─────────────────────────────────────────────────────────────────────────
    sep("SCENARIO 1: DIVISION ANALYST — INTERACTIVE LOGIN TOKEN")

    # Simulate what Entra issues after a user logs in interactively.
    # The token contains the user's OID, UPN, groups, and app roles.
    primary_token = factory.make_user_token(
        oid="a1b2c3d4-0001-0002-0003-primary00001",
        upn="analyst@division-a.example.com",
        name="Alex Smith",
        groups=["Division-A-Analysts"],      # Maps to brand_scope=["brand_b"] via config
        roles=["DataAnalyst"],         # Maps to clearance=CONFIDENTIAL via config
    )

    session = gateway.authenticate_request(
        authorization_header=f"Bearer {primary_token}",
        request_intent="Retrieve division quality defect rates for Q1 reporting",
    )
    user = session.user
    print(f"  Token validated:   {user.metadata.get('upn')}")
    print(f"  Entra OID:         {user.user_id}")
    print(f"  Brand scope:       {user.brand_scope}   ← derived from 'Division-A-Analysts' group")
    print(f"  Clearance:         {user.clearance_level}  ← derived from 'DataAnalyst' role")
    print(f"  Roles:             {user.roles}")

    # Full governance chain
    print("\n  Running governance chain...")
    decision = elig.gate("retrieval_agent", session, ["division_quality_metrics"])
    print(f"  L2 Eligibility:    ✓ ELIGIBLE ({decision.reason[:50]})")

    query = "SELECT model, defect_code, rate FROM quality.division_defect_rates WHERE quarter='Q1'"
    proof = resolver.request_token(
        session=session,
        agent=retrieval_agent,
        query=query,
        asset_ids=["division_quality_metrics"],
    )
    print(f"  L3 Proof issued:   token_id={proof.token_id[:16]}...")
    print(f"  Proof user_id:     {proof.user_id}  (Entra OID — immutable anchor)")
    print(f"  Proof query_hash:  {proof.query_hash[:40]}...")

    result = mcp.handle_tool_call(MCPToolCall(
        tool="query_datasource",
        arguments={"source": "snowflake", "query": query, "agent_id": "retrieval_agent"},
        proof=proof,
    ))
    print(f"  L4 MCP result:     success={result.success}, governed={result.governed}, rows={len(result.data or [])}")

    # ─────────────────────────────────────────────────────────────────────────
    # Scenario 2: Corp Group-level user — broader brand scope
    # ─────────────────────────────────────────────────────────────────────────
    sep("SCENARIO 2: CORP GROUP USER — BROADER BRAND ACCESS")

    vw_token = factory.make_user_token(
        oid="b2c3d4e5-0001-0002-0003-corpgroup0001",
        upn="architect@corp-group.example.com",
        name="Jordan Lee",
        groups=["Corp-Group-All"],      # Maps to all brands
        roles=["DataSteward"],         # Also maps to CONFIDENTIAL
    )
    vw_session = gateway.authenticate_request(
        f"Bearer {vw_token}", "Review cross-brand cost analytics"
    )
    print(f"  User:          {vw_session.user.metadata.get('upn')}")
    print(f"  Brand scope:   {vw_session.user.brand_scope}  ← full Corp Group access")
    print(f"  Clearance:     {vw_session.user.clearance_level}")

    vw_proof = resolver.request_token(
        session=vw_session,
        agent=retrieval_agent,
        query="SELECT brand, amount, cost_center FROM cost_analytics.group_costs",
        asset_ids=["corp_cost_data"],
    )
    print(f"  Proof issued:  brand filters derived = {vw_proof.allowed_filters.get('brand_filter', 'none')}")

    # ─────────────────────────────────────────────────────────────────────────
    # Scenario 3: App-only token (Managed Identity) — identity gap
    # ─────────────────────────────────────────────────────────────────────────
    sep("SCENARIO 3: MANAGED IDENTITY TOKEN — THE IDENTITY GAP")
    print("  An LLM agent calls using its Managed Identity (no user context).")

    agent_token = factory.make_app_token(
        app_id="agent-service-principal-oid-001",
        service_name="retrieval-agent-service",
        roles=["DataReader"],
    )

    print("\n  Attempting to map app-only token to UserContext:")
    try:
        gateway.authenticate_request(
            f"Bearer {agent_token}",
            "Agent autonomous retrieval",
        )
    except ValueError as e:
        print(f"  ✗ BLOCKED: {e}")
        print("  → This is correct. The agent's Managed Identity is not a user.")
        print("    The invoking user's identity is completely absent from this token.")
        print("    RBAC on the MCP server sees a valid service principal — not the user.")

    # Inspect the app-only claims directly
    claims = gateway.get_claims(f"Bearer {agent_token}")
    agent_principal = gateway._mapper.map_to_agent_principal(claims)
    print(f"\n  Raw app-only principal: {json.dumps(agent_principal, indent=4)}")
    print("  → No upn, no groups, no brand_scope. User is invisible to the data source.")

    # ─────────────────────────────────────────────────────────────────────────
    # Scenario 4: OBO delegation — policy context loss
    # ─────────────────────────────────────────────────────────────────────────
    sep("SCENARIO 4: OBO DELEGATION — EXPLICIT POLICY CONTEXT LOSS")
    print("  Orchestrator uses OBO to call downstream agent on behalf of Alex.")

    # Alex's original token (from Scenario 1)
    original_claims = {
        "oid": "a1b2c3d4-0001-0002-0003-primary00001",
        "sub": "a1b2c3d4-0001-0002-0003-primary00001",
        "upn": "analyst@division-a.example.com",
        "name": "Alex Smith",
        "roles": ["DataAnalyst"],
        "groups": ["Division-A-Analysts"],
    }

    # OBO token — propagates identity but loses roles and groups
    obo_token = factory.make_obo_token(
        original_claims=original_claims,
        downstream_scope="api://downstream-agent/.default",
    )

    obo_session = gateway.authenticate_obo_request(
        obo_authorization_header=f"Bearer {obo_token}",
        original_session=session,
        request_intent="Downstream summarisation agent",
    )

    obo_user = obo_session.user
    print(f"\n  OBO user_id:      {obo_user.user_id}  (OID preserved ✓)")
    print(f"  OBO brand_scope:  {obo_user.brand_scope}     ← LOST via OBO — was ['brand_b']")
    print(f"  OBO clearance:    {obo_user.clearance_level}      ← LOST via OBO — was confidential")
    print(f"  OBO roles:        {obo_user.roles}                 ← LOST via OBO — was ['DataAnalyst']")
    print(f"  obo_degraded:     {obo_user.metadata.get('obo_degraded')}")

    print("\n  Attempting proof request with degraded OBO context:")
    try:
        resolver.request_token(
            session=obo_session,
            agent=retrieval_agent,
            query="SELECT model, rate FROM quality.division_defect_rates",
            asset_ids=["division_quality_metrics"],
        )
    except QueryAccessDeniedError as e:
        print(f"  ✗ DENIED: {e}")
        print("  → OBO context degradation is enforced — degraded session cannot")
        print("    request proofs for brand-restricted assets.")

    # ─────────────────────────────────────────────────────────────────────────
    # Scenario 5: The proof as remedy — Entra OID in the proof
    # ─────────────────────────────────────────────────────────────────────────
    sep("SCENARIO 5: THE REMEDY — ENTRA OID EMBEDDED IN THE PROOF")
    print("  Alex's original proof carries the Entra OID as a tamper-evident anchor.")
    print("  Even when downstream agents receive only the proof (not the Bearer token),")
    print("  the identity is preserved and verifiable.\n")

    import jwt as pyjwt
    # Decode the proof JWT (without verification — just to inspect payload)
    proof_payload = pyjwt.decode(
        proof.token,
        options={"verify_signature": False},
        algorithms=["RS256"],
    )
    print("  Proof JWT payload (decoded):")
    display_fields = ["sub", "agent_id", "session_id", "query_hash",
                      "policy_version", "exp"]
    for field in display_fields:
        if field in proof_payload:
            val = str(proof_payload[field])
            print(f"    {field:<22} {val[:60]}")

    print(f"\n  proof['sub'] == Entra OID: {proof_payload['sub'] == user.user_id}")
    print("  → The Entra OID is bound to the query hash in a signed, non-delegable proof.")
    print("    The MCP server can verify BOTH identity AND query compliance from")
    print("    a single artifact — without seeing the original Bearer token.")

    # ─────────────────────────────────────────────────────────────────────────
    # Summary
    # ─────────────────────────────────────────────────────────────────────────
    sep("SUMMARY")
    print("""
  Scenario  Description                               Outcome
  ────────────────────────────────────────────────────────────────
  1         division analyst — interactive login           ✓ Full access, brand-filtered proof
  2         Corp Group architect — broader scope         ✓ Multi-brand proof with all filters
  3         Managed Identity (app-only)                ✗ Blocked — no user identity in token
  4         OBO delegation downstream                  ✗ Degraded — brand/clearance lost
  5         Proof as remedy (OID embedded in JWT)      ✓ Identity + operation-scoped, tamper-evident
  """)


if __name__ == "__main__":
    main()
