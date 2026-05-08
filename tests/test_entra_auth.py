"""
tests/test_entra_auth.py
------------------------
Tests for the Entra ID authentication use case.

All tests run without Azure credentials using the test token factory.
The full token validation → claim mapping → UserContext → governance chain
is exercised end-to-end.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import time

from auth.entra_config import EntraConfig
from auth.entra_integration import EntraAuthGateway
from auth.token_validator import EntraTokenValidationError
from catalog.catalog import build_demo_catalog
from core.models import SensitivityLevel, AgentContext, AccessRight, MCPToolCall
from core.exceptions import QueryAccessDeniedError, AgentIneligibleError
from orchestrator.eligibility import AgentEligibilityResolver
from policy_resolver.resolver import PolicyResolver
from mcp_server.governance_server import MCPGovernanceServer


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def catalog():
    return build_demo_catalog()


@pytest.fixture(scope="module")
def gateway(catalog):
    return EntraAuthGateway.for_testing(catalog=catalog)


@pytest.fixture(scope="module")
def factory(gateway):
    return gateway.token_factory


@pytest.fixture(scope="module")
def resolver(catalog):
    return PolicyResolver(catalog, proof_ttl_seconds=60)


@pytest.fixture(scope="module")
def mcp(resolver):
    return MCPGovernanceServer(resolver, require_sat=True)


@pytest.fixture(scope="module")
def retrieval_agent():
    return AgentContext(
        agent_id="retrieval_agent",
        agent_type="retrieval",
        max_sensitivity=SensitivityLevel.CONFIDENTIAL,
        allowed_rights=[AccessRight.READ],
        allowed_sources=["snowflake", "delta_lake"],
    )


@pytest.fixture
def primary_session(gateway, factory):
    token = factory.make_user_token(
        oid="primary-oid-001",
        upn="analyst@division-a.example.com",
        groups=["Division-A-Analysts"],
        roles=["DataAnalyst"],
    )
    return gateway.authenticate_request(f"Bearer {token}", "Test request")


@pytest.fixture
def group_session(gateway, factory):
    token = factory.make_user_token(
        oid="group-oid-001",
        upn="architect@corp-group.example.com",
        groups=["Corp-Group-All"],
        roles=["DataSteward"],
    )
    return gateway.authenticate_request(f"Bearer {token}", "Corp group request")


# ─────────────────────────────────────────────────────────────────────────────
# Token Validation Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestTokenValidation:

    def test_valid_user_token_is_accepted(self, gateway, factory):
        token = factory.make_user_token(oid="test-oid", upn="user@example.com")
        claims = gateway.get_claims(f"Bearer {token}")
        assert claims.oid == "test-oid"
        assert claims.upn == "user@example.com"

    def test_bearer_prefix_is_stripped(self, gateway, factory):
        token = factory.make_user_token(oid="test-oid", upn="u@example.com")
        claims_with = gateway.get_claims(f"Bearer {token}")
        claims_without = gateway.get_claims(token)
        assert claims_with.oid == claims_without.oid

    def test_expired_token_is_rejected(self, gateway, factory):
        token = factory.make_user_token(
            oid="test-oid", upn="u@example.com",
            ttl_seconds=-10,  # already expired
        )
        with pytest.raises(EntraTokenValidationError, match="[Ee]xpir"):
            gateway.get_claims(f"Bearer {token}")

    def test_tampered_token_is_rejected(self, gateway, factory):
        token = factory.make_user_token(oid="test-oid", upn="u@example.com")
        # Tamper with the payload segment (middle segment)
        parts = token.split(".")
        parts[1] = parts[1][:-4] + "XXXX"
        tampered = ".".join(parts)
        with pytest.raises(EntraTokenValidationError):
            gateway.get_claims(f"Bearer {tampered}")

    def test_wrong_audience_is_rejected(self):
        """Token issued for a different app should be rejected."""
        wrong_config = EntraConfig.for_testing(client_id="wrong-client-id")
        from auth.token_factory import EntraTokenFactory
        from auth.token_validator import EntraTokenValidator
        factory = EntraTokenFactory(wrong_config)
        validator = EntraTokenValidator(EntraConfig.for_testing())
        validator.set_test_keypair(factory.public_key_pem)

        token = factory.make_user_token(oid="o", upn="u@example.com")
        # The token's aud is "wrong-client-id", but validator expects "test-client-id"
        with pytest.raises(EntraTokenValidationError):
            validator.validate(token)

    def test_app_only_token_claims_detected(self, gateway, factory):
        token = factory.make_app_token(app_id="service-principal-001")
        claims = gateway.get_claims(f"Bearer {token}")
        assert claims.is_app_only is True

    def test_user_token_is_not_app_only(self, gateway, factory):
        token = factory.make_user_token(oid="oid", upn="u@example.com")
        claims = gateway.get_claims(f"Bearer {token}")
        assert claims.is_app_only is False


# ─────────────────────────────────────────────────────────────────────────────
# Claim Mapping Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestClaimMapping:

    def test_div_analyst_gets_correct_brand_scope(self, primary_session):
        assert primary_session.user.brand_scope == ["brand_b"]

    def test_vw_group_gets_full_brand_scope(self, group_session):
        assert set(group_session.user.brand_scope) == {"brand_a", "brand_b", "brand_c", "brand_d", "brand_e"}

    def test_data_analyst_role_maps_to_confidential(self, primary_session):
        assert primary_session.user.clearance_level == SensitivityLevel.CONFIDENTIAL

    def test_data_reader_role_maps_to_internal(self, gateway, factory):
        token = factory.make_user_token(
            oid="reader-oid", upn="reader@example.com",
            groups=["Division-A-Analysts"], roles=["DataReader"],
        )
        session = gateway.authenticate_request(f"Bearer {token}", "Read")
        assert session.user.clearance_level == SensitivityLevel.INTERNAL

    def test_no_role_defaults_to_internal_clearance(self, gateway, factory):
        token = factory.make_user_token(oid="norole-oid", upn="u@example.com", groups=["Division-A-Analysts"])
        session = gateway.authenticate_request(f"Bearer {token}", "No role")
        assert session.user.clearance_level == SensitivityLevel.INTERNAL

    def test_multiple_roles_highest_wins(self, gateway, factory):
        """User with both DataReader and DataAdmin should get RESTRICTED clearance."""
        token = factory.make_user_token(
            oid="multi-role-oid", upn="admin@example.com",
            groups=["Corp-Group-All"],
            roles=["DataReader", "DataAdmin"],   # Admin maps to RESTRICTED
        )
        session = gateway.authenticate_request(f"Bearer {token}", "Multi role")
        assert session.user.clearance_level == SensitivityLevel.RESTRICTED

    def test_unknown_group_yields_empty_brand_scope(self, gateway, factory):
        """Groups not in brand_group_map should produce no brand scope — fail-closed."""
        token = factory.make_user_token(
            oid="unknown-group-oid", upn="u@example.com",
            groups=["Unknown-Group-Not-In-Config"],
            roles=["DataAnalyst"],
        )
        session = gateway.authenticate_request(f"Bearer {token}", "Unknown group")
        assert session.user.brand_scope == []

    def test_app_only_token_cannot_create_user_context(self, gateway, factory):
        token = factory.make_app_token(app_id="agent-sp-001")
        with pytest.raises(ValueError, match="app-only"):
            gateway.authenticate_request(f"Bearer {token}", "App-only attempt")

    def test_entra_oid_is_the_user_id(self, factory, gateway):
        """user_id must be the Entra OID — immutable, not the UPN which can change."""
        oid = "specific-oid-12345"
        token = factory.make_user_token(oid=oid, upn="could-change@example.com")
        session = gateway.authenticate_request(f"Bearer {token}", "OID check")
        assert session.user.user_id == oid


# ─────────────────────────────────────────────────────────────────────────────
# OBO Delegation Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestOBODelegation:

    def test_obo_token_preserves_oid(self, gateway, factory):
        original = {"oid": "original-oid", "sub": "original-oid", "upn": "u@example.com"}
        obo_token = factory.make_obo_token(original, "api://downstream/.default")
        obo_session = gateway.authenticate_obo_request(
            f"Bearer {obo_token}",
            original_session=None,
            request_intent="OBO call",
        )
        assert obo_session.user.user_id == "original-oid"

    def test_obo_token_loses_brand_scope(self, gateway, factory):
        original = {"oid": "o", "sub": "o", "upn": "u@example.com",
                    "roles": ["DataAnalyst"], "groups": ["Division-A-Analysts"]}
        obo_token = factory.make_obo_token(original, "api://downstream/.default")
        obo_session = gateway.authenticate_obo_request(
            f"Bearer {obo_token}", None, "OBO"
        )
        assert obo_session.user.brand_scope == []

    def test_obo_token_loses_clearance(self, gateway, factory):
        original = {"oid": "o", "sub": "o", "upn": "u@example.com",
                    "roles": ["DataAdmin"]}
        obo_token = factory.make_obo_token(original, "api://downstream/.default")
        obo_session = gateway.authenticate_obo_request(
            f"Bearer {obo_token}", None, "OBO clearance test"
        )
        assert obo_session.user.clearance_level == SensitivityLevel.INTERNAL

    def test_obo_session_is_marked_degraded(self, gateway, factory):
        original = {"oid": "o", "sub": "o", "upn": "u@example.com"}
        obo_token = factory.make_obo_token(original, "api://downstream/.default")
        obo_session = gateway.authenticate_obo_request(
            f"Bearer {obo_token}", None, "OBO degraded flag"
        )
        assert obo_session.user.metadata.get("obo_degraded") is True

    def test_obo_session_cannot_access_brand_restricted_asset(
        self, gateway, factory, catalog, resolver, retrieval_agent
    ):
        """Degraded OBO session must not be able to request proofs for brand-tagged assets."""
        original = {"oid": "o", "sub": "o", "upn": "u@example.com",
                    "roles": ["DataAnalyst"], "groups": ["Division-A-Analysts"]}
        obo_token = factory.make_obo_token(original, "api://downstream/.default")
        obo_session = gateway.authenticate_obo_request(
            f"Bearer {obo_token}", None, "OBO brand access attempt"
        )
        with pytest.raises(QueryAccessDeniedError):
            resolver.request_token(
                session=obo_session,
                agent=retrieval_agent,
                query="SELECT model FROM quality.division_defect_rates",
                asset_ids=["division_quality_metrics"],
            )


# ─────────────────────────────────────────────────────────────────────────────
# Full Governance Chain Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestEntraGovernanceChain:

    QUERY = "SELECT model, defect_code, rate FROM quality.division_defect_rates"

    def test_div_analyst_full_chain(self, primary_session, retrieval_agent, resolver, mcp):
        """Full chain: Entra auth → eligibility → proof → MCP."""
        elig = AgentEligibilityResolver(build_demo_catalog())
        elig.register_agent(retrieval_agent)

        decision = elig.gate("retrieval_agent", primary_session, ["division_quality_metrics"])
        from core.models import AgentStatus
        assert decision.status == AgentStatus.ELIGIBLE

        proof = resolver.request_token(
            session=primary_session,
            agent=retrieval_agent,
            query=self.QUERY,
            asset_ids=["division_quality_metrics"],
        )
        # The proof user_id must be the Entra OID
        assert proof.user_id == primary_session.user.user_id
        assert proof.user_id == "primary-oid-001"

        result = mcp.handle_tool_call(MCPToolCall(
            tool="query_datasource",
            arguments={"source": "snowflake", "query": self.QUERY,
                       "agent_id": "retrieval_agent"},
            proof=proof,
        ))
        assert result.success is True
        assert result.governed is True

    def test_proof_user_id_is_entra_oid(self, primary_session, retrieval_agent, resolver):
        """The OID embedded in the proof must equal the Entra OID — the user_id itself."""
        proof = resolver.request_token(
            session=primary_session,
            agent=retrieval_agent,
            query=self.QUERY,
            asset_ids=["division_quality_metrics"],
        )
        # user_id IS the OID — that's the whole point of using OID not UPN
        assert proof.user_id == primary_session.user.user_id
        assert proof.user_id == "primary-oid-001"

    def test_vw_user_sees_brand_filters_for_all_vw_brands(
        self, group_session, retrieval_agent, resolver
    ):
        """Corp Group user should get brand filters covering all brands in their scope."""
        proof = resolver.request_token(
            session=group_session,
            agent=retrieval_agent,
            query="SELECT brand, amount FROM cost_analytics.group_costs",
            asset_ids=["corp_cost_data"],
        )
        brand_filter = proof.allowed_filters.get("brand_filter", "")
        # All brands in Corp-Group-All scope should appear in the filter
        for brand in group_session.user.brand_scope:
            assert brand in brand_filter

    def test_user_without_brand_scope_denied_brand_asset(
        self, gateway, factory, resolver, retrieval_agent
    ):
        """User with no group membership gets no brand scope and cannot access brand-tagged assets."""
        token = factory.make_user_token(
            oid="no-brand-oid", upn="u@example.com",
            groups=[],   # No group membership → no brand scope
            roles=["DataAnalyst"],
        )
        session = gateway.authenticate_request(f"Bearer {token}", "No brand")
        assert session.user.brand_scope == []

        with pytest.raises(QueryAccessDeniedError):
            resolver.request_token(
                session=session,
                agent=retrieval_agent,
                query=self.QUERY,
                asset_ids=["division_quality_metrics"],
            )

    def test_override_brand_scope_is_respected(self, gateway, factory, resolver, retrieval_agent):
        """Application can override brand scope for explicit picker scenarios."""
        token = factory.make_user_token(
            oid="multi-brand-oid", upn="u@example.com",
            groups=["Corp-Group-All"],
            roles=["DataAnalyst"],
        )
        # App explicitly constrains to brand_b only (e.g. the user picked one brand in the UI)
        session = gateway.authenticate_request(
            f"Bearer {token}", "brand_b-scoped request",
            override_brand_scope=["brand_b"],
        )
        assert session.user.brand_scope == ["brand_b"]
        # Can still access brand_b data
        proof = resolver.request_token(
            session=session,
            agent=retrieval_agent,
            query=self.QUERY,
            asset_ids=["division_quality_metrics"],
        )
        assert proof.user_id == "multi-brand-oid"
