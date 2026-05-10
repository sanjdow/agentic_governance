from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

from catalog.catalog import DataCatalog
from core.exceptions import AgentIneligibleError
from core.models import (
    AccessRight,
    AgentContext,
    AgentStatus,
    SessionContext,
    SensitivityLevel,
)

logger = logging.getLogger(__name__)


@dataclass
class EligibilityDecision:
    """The result of an agent eligibility check."""
    agent_id: str
    status: AgentStatus
    reason: str
    allowed_asset_ids: list[str] = field(default_factory=list)
    applied_filters: dict[str, dict[str, str]] = field(default_factory=dict)


class AgentEligibilityResolver:
    """
    Resolves agent eligibility before any agent is invoked.

    This is the L2 enforcement point. The orchestrator calls
    `check_eligibility()` for each candidate agent before dispatching.
    Agents that fail the check are never started.
    """

    def __init__(self, catalog: DataCatalog) -> None:
        self._catalog = catalog
        self._registered_agents: dict[str, AgentContext] = {}

    def register_agent(self, agent: AgentContext) -> None:
        """Register an agent definition with the orchestrator."""
        self._registered_agents[agent.agent_id] = agent
        logger.debug("Agent registered: %s", agent.agent_id)

    def check_eligibility(
        self,
        agent_id: str,
        session: SessionContext,
        requested_asset_ids: list[str],
        required_right: AccessRight = AccessRight.READ,
    ) -> EligibilityDecision:
        """
        Perform a full eligibility check for an agent against the current session.

        This checks:
          1. Agent is registered
          2. Agent's max_sensitivity >= each asset's sensitivity
          3. User clearance covers the agent's max_sensitivity
          4. User+agent has the required right on each asset
          5. Brand scope intersection for all brand-tagged assets

        Returns an EligibilityDecision. Does NOT raise — callers decide
        whether to block or proceed.
        """
        if agent_id not in self._registered_agents:
            return EligibilityDecision(
                agent_id=agent_id,
                status=AgentStatus.BLOCKED,
                reason=f"Agent '{agent_id}' is not registered with the orchestrator.",
            )

        agent = self._registered_agents[agent_id]
        user = session.user
        allowed_assets: list[str] = []
        applied_filters: dict[str, dict[str, str]] = {}
        denial_reasons: list[str] = []

        # User clearance ceiling check
        if user.clearance_level < agent.max_sensitivity:
            return EligibilityDecision(
                agent_id=agent_id,
                status=AgentStatus.INELIGIBLE,
                reason=(
                    f"User '{user.user_id}' clearance ({user.clearance_level}) "
                    f"is below agent '{agent_id}' max sensitivity ({agent.max_sensitivity}). "
                    "Refusing to run agent under elevated identity."
                ),
            )

        for asset_id in requested_asset_ids:
            try:
                asset = self._catalog.get_asset(asset_id)
                allowed, reason = self._catalog.resolve_access(
                    user=user,
                    agent=agent,
                    asset_id=asset_id,
                    required_right=required_right,
                )
                if allowed:
                    allowed_assets.append(asset_id)
                    filters = self._catalog.derive_row_filters(user, asset)
                    if filters:
                        applied_filters[asset_id] = filters
                else:
                    denial_reasons.append(f"{asset_id}: {reason}")
            except Exception as exc:
                denial_reasons.append(f"{asset_id}: {exc}")

        if denial_reasons and not allowed_assets:
            return EligibilityDecision(
                agent_id=agent_id,
                status=AgentStatus.INELIGIBLE,
                reason=f"All requested assets denied: {'; '.join(denial_reasons)}",
            )

        if denial_reasons and allowed_assets:
            # Partial eligibility — agent can run but only against allowed assets
            logger.warning(
                "Agent %s partially eligible. Denied assets: %s",
                agent_id, denial_reasons,
            )

        return EligibilityDecision(
            agent_id=agent_id,
            status=AgentStatus.ELIGIBLE,
            reason="All checks passed." if not denial_reasons else f"Partial: {denial_reasons}",
            allowed_asset_ids=allowed_assets,
            applied_filters=applied_filters,
        )

    def gate(
        self,
        agent_id: str,
        session: SessionContext,
        requested_asset_ids: list[str],
        required_right: AccessRight = AccessRight.READ,
    ) -> EligibilityDecision:
        """
        Gate call: check eligibility and raise AgentIneligibleError if blocked.
        Use this in the orchestration graph node before dispatching an agent.
        """
        decision = self.check_eligibility(
            agent_id=agent_id,
            session=session,
            requested_asset_ids=requested_asset_ids,
            required_right=required_right,
        )
        if decision.status in (AgentStatus.INELIGIBLE, AgentStatus.BLOCKED):
            logger.error(
                "Agent BLOCKED before invocation: agent=%s reason=%s",
                agent_id, decision.reason,
            )
            raise AgentIneligibleError(
                f"Agent '{agent_id}' is not eligible for this session: {decision.reason}"
            )
        return decision

    def list_eligible_agents(
        self,
        session: SessionContext,
        requested_asset_ids: list[str],
        required_right: AccessRight = AccessRight.READ,
    ) -> list[EligibilityDecision]:
        """
        Evaluate all registered agents and return only eligible ones.
        The orchestrator uses this to build the callable agent pool.
        """
        decisions = []
        for agent_id in self._registered_agents:
            d = self.check_eligibility(
                agent_id=agent_id,
                session=session,
                requested_asset_ids=requested_asset_ids,
                required_right=required_right,
            )
            if d.status == AgentStatus.ELIGIBLE:
                decisions.append(d)
            else:
                logger.info(
                    "Agent excluded from pool: %s — %s", agent_id, d.reason
                )
        return decisions
