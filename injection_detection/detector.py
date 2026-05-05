"""
injection_detection/detector.py
--------------------------------
Prompt Injection Detector: Multi-layer defence before tool dispatch.

Problem addressed:
  Malicious instructions embedded in data the agent reads — a document,
  a database field, a web page — redirect the agent's behaviour.
  The agent then makes tool calls under its own permitted identity.
  RBAC sees a legitimate principal. The governance layer is completely blind.

This detector intercepts content before it reaches the agent's reasoning loop,
classifying it as safe or injected across multiple detection layers:

  Layer 1: Heuristic pattern matching (zero latency, high recall)
  Layer 2: Instruction boundary analysis (detects role/context switches)
  Layer 3: Suspicious command detection (tool-call redirection patterns)

In production, augment with:
  Layer 4: LLM-based semantic classifier (higher precision, ~100ms latency)
  Layer 5: Embedding similarity against known injection templates

References:
  - OWASP LLM Top 10: LLM01 Prompt Injection
  - Greshake et al. 2023: "Not What You've Signed Up For: Compromising
    Real-World LLM-Integrated Applications with Indirect Prompt Injection"
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from core.exceptions import PromptInjectionBlockedError
from core.models import InjectionAssessment, InjectionRisk

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Detection Pattern Libraries
# ─────────────────────────────────────────────────────────────────────────────

# Layer 1: Direct injection attempts — high confidence patterns
CRITICAL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ignore_previous",     re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE)),
    ("disregard_system",    re.compile(r"disregard\s+(your\s+)?(system\s+prompt|instructions?|guidelines?)", re.IGNORECASE)),
    ("new_instructions",    re.compile(r"(your\s+new|actual|real)\s+instructions?\s+(are|is|follow)", re.IGNORECASE)),
    ("jailbreak_dan",       re.compile(r"\bDAN\b|\bdo\s+anything\s+now\b", re.IGNORECASE)),
    ("pretend_no_rules",    re.compile(r"pretend\s+(you\s+have\s+no|there\s+are\s+no)\s+(rules?|restrictions?|limits?|guidelines?)", re.IGNORECASE)),
    ("as_root_admin",       re.compile(r"(as\s+(root|admin|superuser)|sudo\s+mode|developer\s+mode)", re.IGNORECASE)),
    ("override_safety",     re.compile(r"override\s+(safety|security|policy|governance)\s+(filter|check|control|measure)", re.IGNORECASE)),
    ("system_prompt_leak",  re.compile(r"(print|show|reveal|output|display)\s+(your\s+)?(system\s+prompt|instructions?|context)", re.IGNORECASE)),
    ("token_injection",     re.compile(r"<\|?(system|user|assistant|im_start|im_end)\|?>", re.IGNORECASE)),
    ("role_switch",         re.compile(r"\[\s*(SYSTEM|INST|SYS)\s*\]", re.IGNORECASE)),
]

# Layer 2: Instruction boundary analysis — medium confidence
BOUNDARY_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("you_are_now",         re.compile(r"you\s+are\s+now\s+(a\s+|an\s+)?(?!helpful|an? AI|an? assistant)", re.IGNORECASE)),
    ("forget_training",     re.compile(r"forget\s+(everything|all|your\s+training|what\s+you('ve|\s+have)\s+learned)", re.IGNORECASE)),
    ("act_as",              re.compile(r"act\s+as\s+(if\s+you\s+are|a\s+)?(?!helpful|an? AI)", re.IGNORECASE)),
    ("from_now_on",         re.compile(r"from\s+now\s+on\s+(you\s+(will|must|should|shall)|always)", re.IGNORECASE)),
    ("new_persona",         re.compile(r"your\s+(new\s+)?(name|persona|role|identity)\s+is", re.IGNORECASE)),
    ("hidden_instruction",  re.compile(r"(<!--|/\*|#\s*HIDDEN|<!--\s*instruction)", re.IGNORECASE)),
]

# Layer 3: Tool-call redirection — agent-specific injection attempts
TOOL_REDIRECT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("call_tool",           re.compile(r"call\s+the\s+(tool|function|api|endpoint)\s+", re.IGNORECASE)),
    ("exfil_to_url",        re.compile(r"(send|post|upload|exfiltrate)\s+(this|the|all)?\s*(data|information|context|results?)\s+to\s+(https?://|www\.)", re.IGNORECASE)),
    ("write_to_db",         re.compile(r"(insert|update|delete|drop|truncate)\s+(into|from|table)", re.IGNORECASE)),
    ("email_data",          re.compile(r"(email|send)\s+.{0,30}(to|at)\s+\S+@\S+", re.IGNORECASE)),
    ("execute_code",        re.compile(r"(exec|execute|run|eval)\s+(this\s+)?(code|script|command|sql)", re.IGNORECASE)),
    ("read_credentials",    re.compile(r"(read|access|retrieve)\s+(the\s+)?(api\s+key|secret|password|credential|token)\s+from", re.IGNORECASE)),
    ("bypass_auth",         re.compile(r"(bypass|skip|ignore)\s+(auth(entication|orisation)?|login|verification|the\s+proof)", re.IGNORECASE)),
]

# Context boundary markers — often used to smuggle instructions
DELIMITER_INJECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("triple_backtick",     re.compile(r"```\s*(system|instructions?|prompt)\s*\n", re.IGNORECASE)),
    ("xml_injection",       re.compile(r"<(system|instructions?|prompt|context)>", re.IGNORECASE)),
    ("json_injection",      re.compile(r'"(system|instructions?|role)"\s*:\s*"(system|override|jailbreak)"', re.IGNORECASE)),
]


# ─────────────────────────────────────────────────────────────────────────────
# Detector
# ─────────────────────────────────────────────────────────────────────────────

class PromptInjectionDetector:
    """
    Multi-layer prompt injection detector.

    Screens content before it is included in an agent's context window
    or before the agent's output is treated as a tool-call instruction.

    Typical usage:
        detector = PromptInjectionDetector()

        # Before adding retrieved content to agent context:
        assessment = detector.assess(retrieved_document_text)
        if assessment.should_block:
            raise PromptInjectionBlockedError(assessment.explanation)

        # Before executing an agent's stated tool call intent:
        assessment = detector.assess_tool_intent(agent_reasoning_text)
        if assessment.should_block:
            raise PromptInjectionBlockedError(assessment.explanation)
    """

    # Risk thresholds
    CRITICAL_THRESHOLD = 1     # Any critical pattern → CRITICAL risk
    HIGH_THRESHOLD = 2         # 2+ boundary/tool patterns → HIGH risk
    MEDIUM_THRESHOLD = 1       # 1 boundary/tool pattern → MEDIUM risk

    def __init__(self, block_on: InjectionRisk = InjectionRisk.HIGH) -> None:
        """
        Args:
            block_on: Minimum risk level that triggers should_block=True.
                      Default: HIGH (CRITICAL and HIGH are blocked).
        """
        self._block_on = block_on
        self._risk_order = [
            InjectionRisk.NONE,
            InjectionRisk.LOW,
            InjectionRisk.MEDIUM,
            InjectionRisk.HIGH,
            InjectionRisk.CRITICAL,
        ]

    def assess(self, content: str) -> InjectionAssessment:
        """
        Assess content for prompt injection risk.

        Args:
            content: Any text to be included in an agent's context —
                     retrieved documents, database values, web pages, etc.

        Returns:
            InjectionAssessment with risk level, confidence, and explanation.
        """
        triggered: list[str] = []
        risk_level = InjectionRisk.NONE
        confidence = 0.0

        # Layer 1: Critical patterns (highest confidence)
        for name, pattern in CRITICAL_PATTERNS:
            if pattern.search(content):
                triggered.append(f"critical:{name}")
                risk_level = InjectionRisk.CRITICAL
                confidence = max(confidence, 0.95)

        # Layer 2: Boundary patterns
        boundary_hits = 0
        for name, pattern in BOUNDARY_PATTERNS:
            if pattern.search(content):
                triggered.append(f"boundary:{name}")
                boundary_hits += 1

        if boundary_hits >= self.HIGH_THRESHOLD:
            risk_level = self._max_risk(risk_level, InjectionRisk.HIGH)
            confidence = max(confidence, 0.80)
        elif boundary_hits >= self.MEDIUM_THRESHOLD:
            risk_level = self._max_risk(risk_level, InjectionRisk.MEDIUM)
            confidence = max(confidence, 0.60)

        # Layer 3: Tool redirect patterns
        tool_hits = 0
        for name, pattern in TOOL_REDIRECT_PATTERNS:
            if pattern.search(content):
                triggered.append(f"tool_redirect:{name}")
                tool_hits += 1

        if tool_hits >= 2:
            risk_level = self._max_risk(risk_level, InjectionRisk.HIGH)
            confidence = max(confidence, 0.75)
        elif tool_hits == 1:
            risk_level = self._max_risk(risk_level, InjectionRisk.MEDIUM)
            confidence = max(confidence, 0.55)

        # Layer 4: Delimiter injection
        for name, pattern in DELIMITER_INJECTION_PATTERNS:
            if pattern.search(content):
                triggered.append(f"delimiter:{name}")
                risk_level = self._max_risk(risk_level, InjectionRisk.HIGH)
                confidence = max(confidence, 0.85)

        # Adjust confidence if no patterns triggered
        if not triggered:
            confidence = 0.95  # High confidence it's clean

        should_block = self._risk_order.index(risk_level) >= self._risk_order.index(self._block_on)

        explanation = self._build_explanation(risk_level, triggered)

        if risk_level != InjectionRisk.NONE:
            logger.warning(
                "Injection risk detected: level=%s confidence=%.2f patterns=%s",
                risk_level, confidence, triggered,
            )

        return InjectionAssessment(
            risk_level=risk_level,
            confidence=confidence,
            triggered_patterns=triggered,
            explanation=explanation,
            should_block=should_block,
        )

    def assess_and_raise(self, content: str, context: str = "") -> None:
        """
        Assess content and raise PromptInjectionBlockedError if blocked.
        Convenience method for inline use.
        """
        assessment = self.assess(content)
        if assessment.should_block:
            raise PromptInjectionBlockedError(
                f"Prompt injection detected{' in ' + context if context else ''}: "
                f"{assessment.explanation} "
                f"(risk={assessment.risk_level}, confidence={assessment.confidence:.0%})"
            )

    def scan_retrieved_data(self, data: list[dict]) -> dict[str, InjectionAssessment]:
        """
        Scan all string fields in retrieved data rows.
        Returns a dict of {field_path: assessment} for any flagged fields.

        Use this before injecting database results into an agent's context.
        """
        flagged: dict[str, InjectionAssessment] = {}
        for i, row in enumerate(data):
            for key, value in row.items():
                if isinstance(value, str) and len(value) > 10:
                    assessment = self.assess(value)
                    if assessment.risk_level != InjectionRisk.NONE:
                        flagged[f"row[{i}].{key}"] = assessment
        return flagged

    def _max_risk(self, current: InjectionRisk, candidate: InjectionRisk) -> InjectionRisk:
        """Return the higher of two risk levels."""
        if self._risk_order.index(candidate) > self._risk_order.index(current):
            return candidate
        return current

    @staticmethod
    def _build_explanation(risk: InjectionRisk, patterns: list[str]) -> str:
        if not patterns:
            return "No injection patterns detected."
        pattern_summary = ", ".join(patterns[:5])
        if len(patterns) > 5:
            pattern_summary += f" (+{len(patterns) - 5} more)"
        return (
            f"Injection risk {risk}: detected patterns [{pattern_summary}]. "
            "This content may attempt to redirect agent behaviour."
        )
