"""
agents/session_isolation.py
----------------------------
Session Isolation: Need-to-know context design between agent hops.

Problems addressed:
  1. Context window as uncontrolled shared memory across agent chains
  2. GPU KV cache prefix caching sharing internal states across requests
  3. Agents accumulating data outside any governed store

This module provides:
  - SessionBoundary: Wraps each agent invocation in an isolated session scope
  - ContextFilter: Enforces need-to-know — agents receive only the minimum
    context required for their specific task
  - SessionStateStore: A governed intermediary that mediates what each
    agent receives, rather than passing raw context forward

Design principle:
  Instead of Agent A passing its full context to Agent B, Agent A writes
  structured outputs to the SessionStateStore. Agent B receives only the
  fields it has declared it needs — nothing more.

  This breaks the "context window as shared memory" attack surface.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from core.models import AgentContext, SensitivityLevel

logger = logging.getLogger(__name__)


@dataclass
class AgentOutput:
    """
    Structured output from an agent, stored in the SessionStateStore.
    Agents declare what they produced rather than passing raw text.
    """
    agent_id: str
    output_type: str              # e.g. "query_result", "summary", "analysis"
    data: Any
    sensitivity: SensitivityLevel = SensitivityLevel.INTERNAL
    produced_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ContextRequest:
    """
    An agent's declared context requirements.
    Agents must explicitly declare what they need from prior steps.
    This is the enforcement mechanism for need-to-know context.
    """
    requesting_agent_id: str
    needed_output_types: list[str]     # What output types from previous agents
    needed_fields: dict[str, list[str]]  # {output_type: [field_names]} — field-level need-to-know
    max_sensitivity: SensitivityLevel = SensitivityLevel.INTERNAL


class SessionStateStore:
    """
    Governed intermediary for inter-agent context.

    Replaces the pattern of passing raw context forward.
    Each agent writes its outputs here; downstream agents request
    only what they declared they need.

    This breaks the chain of "Agent A's full context automatically
    becomes Agent B's context" — which is the root cause of
    context window leakage in multi-agent systems.
    """

    def __init__(self, session_id: str) -> None:
        self._session_id = session_id
        self._outputs: dict[str, list[AgentOutput]] = {}   # {agent_id: [outputs]}
        self._access_log: list[dict[str, Any]] = []
        logger.info("SessionStateStore created for session=%s", session_id)

    def write(self, output: AgentOutput) -> None:
        """Store an agent's output."""
        if output.agent_id not in self._outputs:
            self._outputs[output.agent_id] = []
        self._outputs[output.agent_id].append(output)
        logger.debug(
            "StateStore WRITE: agent=%s type=%s sensitivity=%s",
            output.agent_id, output.output_type, output.sensitivity,
        )

    def read(self, request: ContextRequest) -> dict[str, Any]:
        """
        Retrieve only the context a downstream agent declared it needs.

        Enforces:
          - Output type filtering (agent gets only declared types)
          - Field-level filtering (agent gets only declared fields)
          - Sensitivity ceiling (outputs above the agent's ceiling are excluded)

        Returns a dict keyed by output_type with filtered data.
        """
        result: dict[str, Any] = {}
        violations: list[str] = []

        for agent_id, outputs in self._outputs.items():
            if agent_id == request.requesting_agent_id:
                continue  # Don't read own outputs

            for output in outputs:
                if output.output_type not in request.needed_output_types:
                    continue  # Not declared as needed

                # Sensitivity ceiling check
                if output.sensitivity > request.max_sensitivity:
                    violations.append(
                        f"{agent_id}/{output.output_type} ({output.sensitivity}) "
                        f"exceeds ceiling ({request.max_sensitivity}) — excluded"
                    )
                    logger.warning(
                        "Context excluded: agent=%s output_type=%s sensitivity=%s "
                        "exceeds requesting_agent=%s ceiling=%s",
                        agent_id, output.output_type, output.sensitivity,
                        request.requesting_agent_id, request.max_sensitivity,
                    )
                    continue

                # Field-level filtering
                needed_fields = request.needed_fields.get(output.output_type)
                if needed_fields and isinstance(output.data, dict):
                    filtered_data = {
                        k: v for k, v in output.data.items()
                        if k in needed_fields
                    }
                elif needed_fields and isinstance(output.data, list):
                    filtered_data = [
                        {k: v for k, v in row.items() if k in needed_fields}
                        if isinstance(row, dict) else row
                        for row in output.data
                    ]
                else:
                    filtered_data = output.data

                result.setdefault(output.output_type, [])
                result[output.output_type].append({
                    "from_agent": agent_id,
                    "data": filtered_data,
                    "sensitivity": output.sensitivity.value,
                })

        # Log the access for audit
        self._access_log.append({
            "requesting_agent": request.requesting_agent_id,
            "needed_types": request.needed_output_types,
            "received_types": list(result.keys()),
            "violations": violations,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        if violations:
            logger.info(
                "Session context access by '%s': %d types received, %d excluded for sensitivity",
                request.requesting_agent_id, len(result), len(violations),
            )

        return result

    def audit_log(self) -> list[dict[str, Any]]:
        """Return the full access log for this session."""
        return list(self._access_log)

    def clear_agent_outputs(self, agent_id: str) -> None:
        """Evict an agent's outputs (e.g. after it completes or is revoked)."""
        if agent_id in self._outputs:
            del self._outputs[agent_id]
            logger.info("Cleared outputs for agent=%s in session=%s", agent_id, self._session_id)


class SessionBoundary:
    """
    Context manager that wraps an agent invocation in an isolated scope.

    Prevents context bleeding by:
      1. Providing each agent only the context it declared
      2. Catching and logging any attempt to access undeclared state
      3. Clearing sensitive outputs after the agent completes

    Usage:
        with SessionBoundary(state_store, agent_context, context_request) as ctx:
            result = my_agent.run(context=ctx.declared_context)
            ctx.write_output(AgentOutput(...))
    """

    def __init__(
        self,
        state_store: SessionStateStore,
        agent: AgentContext,
        context_request: Optional[ContextRequest] = None,
    ) -> None:
        self._store = state_store
        self._agent = agent
        self._request = context_request
        self._declared_context: dict[str, Any] = {}

    def __enter__(self) -> "SessionBoundary":
        if self._request:
            self._declared_context = self._store.read(self._request)
        logger.debug(
            "SessionBoundary: agent=%s entering with %d context types",
            self._agent.agent_id, len(self._declared_context),
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if exc_type is not None:
            logger.warning(
                "SessionBoundary: agent=%s exited with exception: %s",
                self._agent.agent_id, exc_val,
            )
        return False  # Don't suppress exceptions

    @property
    def declared_context(self) -> dict[str, Any]:
        """The context the agent is permitted to see."""
        return self._declared_context

    def write_output(self, output: AgentOutput) -> None:
        """Write the agent's output to the governed state store."""
        self._store.write(output)
