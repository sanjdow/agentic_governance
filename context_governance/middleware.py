"""
context_governance/middleware.py
---------------------------------
Context Governance Middleware: Inter-agent context classification and scrubbing.

Problem addressed:
  Data retrieved under a governed, policy-compliant query immediately enters the
  agent's context window — and exits the governance perimeter. When Agent A passes
  context to Agent B, sensitive data travels forward in plaintext. Agent B never
  made a governed call to retrieve it. Agent C may write, email, or surface it
  through a path no individual policy rule blocked.

This middleware intercepts the output of each agent before it is passed to the
next, classifies its content against the catalog, and redacts or blocks content
that exceeds the receiving agent's sensitivity ceiling.

Architecture note:
  This is the "context governance layer" identified as unsolved in the vendor
  analysis. This implementation provides the core classification and redaction
  logic. In production it requires a fast classification model (sub-50ms) to
  be viable in real-time agent chains. Consider a fine-tuned NER model or
  a distilled classifier rather than a full LLM for this hop.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from catalog.catalog import DataCatalog
from core.exceptions import ContextSensitivityViolation
from core.models import (
    AgentContext,
    ClassifiedChunk,
    GovernedContext,
    SensitivityLevel,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Heuristic Classifiers
# ─────────────────────────────────────────────────────────────────────────────

# Patterns that indicate PII or sensitive data in text.
# These are tuned for precision over recall — false positives here cause
# legitimate content to be redacted between agents, which degrades the
# user experience. Production deployments should augment with a fine-tuned
# NER model rather than rely on regex precision alone.
PII_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("email",        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("iban",         re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b")),
    ("salary",       re.compile(r"\b(salary|gehalt|salaire|salario)\b", re.IGNORECASE)),
    ("birth_date",   re.compile(r"\b(19|20)\d{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])\b")),
    # Phone: requires either an explicit international '+' prefix with separators,
    # or a structured local format with two separators. This rejects bare integer
    # strings (version numbers, IDs, order numbers) while accepting real phones.
    ("phone",        re.compile(
        r"(?:"
        r"\+\d{1,3}[\s\-]\d{2,5}[\s\-]\d{3,10}"   # +49 30 12345678  /  +1-415-555-1234
        r"|"
        r"\b\d{3}[\s\-]\d{3,4}[\s\-]\d{4}\b"       # 555-123-4567
        r")"
    )),
    # VIN: exactly 17 chars, but must contain at least one digit AND at least one letter
    # (a 17-char hash or word would otherwise match). We post-filter in detect_pii.
    ("vin",          re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")),
    # GPS coordinates: latitude must be -90..90, longitude -180..180, with 4+ decimals.
    # The previous broad pattern flagged any number with 4+ decimals (e.g. statistical rates).
    ("coordinates",  re.compile(
        r"\b-?(?:90(?:\.0{4,})?|[1-8]?\d\.\d{4,})"           # lat
        r"\s*[,;]\s*"                                          # separator
        r"-?(?:180(?:\.0{4,})?|(?:1[0-7]\d|\d{1,2})\.\d{4,})\b"  # lon
    )),
    ("ssn",          re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]

# Keywords that indicate higher sensitivity levels
CONFIDENTIAL_KEYWORDS = frozenset([
    "cost", "budget", "revenue", "profit", "loss", "cost_center", "fiscal",
    "defect_rate", "quality_metric", "supplier_contract", "bid", "tender",
    "internal only", "vertraulich", "confidentiel",
])

RESTRICTED_KEYWORDS = frozenset([
    "salary", "gehalt", "personnel", "hr record", "employee_id", "birth_date",
    "medical", "health", "performance_review", "termination", "legal",
])


def heuristic_classify(text: str) -> SensitivityLevel:
    """
    Classify a text chunk's sensitivity level using heuristic rules.

    Returns the HIGHEST sensitivity level matched across all detection signals,
    not the first match. This prevents the order-dependence bug where a
    CONFIDENTIAL keyword match would short-circuit before a RESTRICTED PII
    pattern was checked.

    In production, replace with a fine-tuned NER/classifier model
    for higher accuracy. This heuristic approach is deterministic
    and has zero latency overhead.
    """
    text_lower = text.lower()
    detected = SensitivityLevel.INTERNAL  # Default baseline (not PUBLIC — assume internal until proven public)

    # PII patterns: SSN, salary, birth_date → RESTRICTED
    # Other PII (email, phone, IBAN, VIN, coordinates) → CONFIDENTIAL
    for name, pattern in PII_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        # VIN post-filter: bare 17-char alphanumeric tokens are not VINs.
        if name == "vin":
            matched = match.group(0)
            if not (any(c.isdigit() for c in matched) and any(c.isalpha() for c in matched)):
                continue
        if name in ("salary", "birth_date", "ssn"):
            if SensitivityLevel.RESTRICTED > detected:
                detected = SensitivityLevel.RESTRICTED
        else:
            if SensitivityLevel.CONFIDENTIAL > detected:
                detected = SensitivityLevel.CONFIDENTIAL

    # RESTRICTED keywords (HR, medical, personnel, etc.)
    if any(kw in text_lower for kw in RESTRICTED_KEYWORDS):
        if SensitivityLevel.RESTRICTED > detected:
            detected = SensitivityLevel.RESTRICTED

    # CONFIDENTIAL keywords (financial, business-sensitive)
    if any(kw in text_lower for kw in CONFIDENTIAL_KEYWORDS):
        if SensitivityLevel.CONFIDENTIAL > detected:
            detected = SensitivityLevel.CONFIDENTIAL

    # Currency amounts suggest financial confidentiality
    if re.search(r"\b\d{4,}\s*(EUR|USD|GBP|€|\$|£)\b", text, re.IGNORECASE):
        if SensitivityLevel.CONFIDENTIAL > detected:
            detected = SensitivityLevel.CONFIDENTIAL

    return detected


def detect_pii(text: str) -> bool:
    """Return True if any PII pattern is detected in the text."""
    for name, pattern in PII_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        # VIN post-filter: must contain at least one digit AND one letter.
        # A bare 17-char alphanumeric token (e.g. a hash slug) is not a VIN.
        if name == "vin":
            matched_text = match.group(0)
            has_digit = any(c.isdigit() for c in matched_text)
            has_alpha = any(c.isalpha() for c in matched_text)
            if not (has_digit and has_alpha):
                continue
        return True
    return False


def detect_brand_tags(text: str, known_brands: list[str]) -> list[str]:
    """Detect which brand names appear in the text."""
    text_lower = text.lower()
    return [b for b in known_brands if b.lower() in text_lower]


def redact_pii(text: str) -> str:
    """Replace PII matches with [REDACTED] placeholders."""
    for name, pattern in PII_PATTERNS:
        text = pattern.sub(f"[REDACTED:{name.upper()}]", text)
    return text


# ─────────────────────────────────────────────────────────────────────────────
# Context Governance Middleware
# ─────────────────────────────────────────────────────────────────────────────

class ContextGovernanceMiddleware:
    """
    Intercepts inter-agent context and applies need-to-know enforcement.

    Usage in a LangGraph orchestration graph:

        # Instead of passing raw output directly:
        raw_output = agent_a.run(...)

        # Pass through governance middleware:
        governed = middleware.govern(
            content=raw_output,
            source_agent=agent_a_context,
            receiving_agent=agent_b_context,
        )
        agent_b.run(context=governed.safe_text)

    Modes:
      REDACT  — Remove sensitive content, pass safe remainder (default)
      BLOCK   — Raise ContextSensitivityViolation if any sensitive content detected
      AUDIT   — Pass everything but log all sensitivity violations (dev/testing)
    """

    KNOWN_BRANDS = ["vw", "audi", "porsche", "skoda", "seat", "volkswagen"]
    CHUNK_SIZE = 500   # characters per classification chunk

    def __init__(
        self,
        catalog: DataCatalog,
        mode: str = "REDACT",
        chunk_size: int = CHUNK_SIZE,
    ) -> None:
        assert mode in ("REDACT", "BLOCK", "AUDIT"), f"Unknown mode: {mode}"
        self._catalog = catalog
        self._mode = mode
        self._chunk_size = chunk_size
        logger.info("ContextGovernanceMiddleware initialized in %s mode", mode)

    def govern(
        self,
        content: str | dict | list,
        source_agent: AgentContext,
        receiving_agent: AgentContext,
    ) -> GovernedContext:
        """
        Classify and filter content before it passes from source to receiving agent.

        Args:
            content:          The raw output from the source agent
            source_agent:     The agent that produced the content
            receiving_agent:  The agent that will receive the content

        Returns:
            GovernedContext with redacted chunks and governance metadata

        Raises:
            ContextSensitivityViolation — in BLOCK mode when sensitive content detected
        """
        # Normalise content to string
        if isinstance(content, (dict, list)):
            import json
            text = json.dumps(content, default=str)
        else:
            text = str(content)

        # Split into classifiable chunks
        raw_chunks = self._split_into_chunks(text)
        classified_chunks: list[ClassifiedChunk] = []
        redaction_count = 0
        max_sensitivity = SensitivityLevel.PUBLIC

        for chunk_text in raw_chunks:
            sensitivity = heuristic_classify(chunk_text)
            pii = detect_pii(chunk_text)
            brand_tags = detect_brand_tags(chunk_text, self.KNOWN_BRANDS)

            # Update max sensitivity seen
            if sensitivity > max_sensitivity:
                max_sensitivity = sensitivity

            # Determine if this chunk exceeds the receiving agent's ceiling
            exceeds_ceiling = sensitivity > receiving_agent.max_sensitivity

            if exceeds_ceiling:
                if self._mode == "BLOCK":
                    raise ContextSensitivityViolation(
                        f"Context from agent '{source_agent.agent_id}' contains "
                        f"{sensitivity} content which exceeds receiving agent "
                        f"'{receiving_agent.agent_id}' ceiling "
                        f"({receiving_agent.max_sensitivity}). Blocking entire transfer."
                    )
                elif self._mode == "REDACT":
                    if pii:
                        safe_text = redact_pii(chunk_text)
                        # Re-classify after PII redaction to see if sensitivity drops
                        post_redact_sensitivity = heuristic_classify(safe_text)
                        still_exceeds = post_redact_sensitivity > receiving_agent.max_sensitivity
                        classified_chunks.append(ClassifiedChunk(
                            text=safe_text if not still_exceeds else "[REDACTED: ABOVE CLEARANCE]",
                            sensitivity=sensitivity,
                            pii_detected=True,
                            brand_tags=brand_tags,
                            redacted=still_exceeds,
                        ))
                        # Count as a redaction event if PII was found and removed,
                        # regardless of whether post-redaction sensitivity still exceeds
                        # the ceiling. PII removal itself is a governance action.
                        redaction_count += 1
                    else:
                        # No PII to redact — the whole chunk exceeds clearance
                        classified_chunks.append(ClassifiedChunk(
                            text="[REDACTED: ABOVE CLEARANCE]",
                            sensitivity=sensitivity,
                            pii_detected=False,
                            brand_tags=brand_tags,
                            redacted=True,
                        ))
                        redaction_count += 1
                    logger.debug(
                        "Chunk governed: source=%s receiving=%s sensitivity=%s pii=%s",
                        source_agent.agent_id, receiving_agent.agent_id, sensitivity, pii,
                    )
                else:  # AUDIT
                    logger.warning(
                        "⚠  AUDIT: Context sensitivity violation: source=%s receiving=%s "
                        "chunk_sensitivity=%s receiving_ceiling=%s",
                        source_agent.agent_id, receiving_agent.agent_id,
                        sensitivity, receiving_agent.max_sensitivity,
                    )
                    classified_chunks.append(ClassifiedChunk(
                        text=chunk_text,
                        sensitivity=sensitivity,
                        pii_detected=pii,
                        brand_tags=brand_tags,
                        redacted=False,
                    ))
            else:
                classified_chunks.append(ClassifiedChunk(
                    text=chunk_text,
                    sensitivity=sensitivity,
                    pii_detected=pii,
                    brand_tags=brand_tags,
                    redacted=False,
                ))

        governed = GovernedContext(
            original_agent_id=source_agent.agent_id,
            receiving_agent_id=receiving_agent.agent_id,
            chunks=classified_chunks,
            redaction_count=redaction_count,
            max_sensitivity_passed=max_sensitivity,
        )

        if redaction_count > 0:
            logger.info(
                "Context governed: source=%s→receiving=%s redacted=%d/%d chunks max_sensitivity=%s",
                source_agent.agent_id, receiving_agent.agent_id,
                redaction_count, len(classified_chunks), max_sensitivity,
            )

        return governed

    def govern_structured(
        self,
        rows: list[dict],
        source_agent: AgentContext,
        receiving_agent: AgentContext,
        masked_columns: list[str] | None = None,
    ) -> list[dict]:
        """
        Govern structured data (list of dicts / query results).

        Applies column-level masking and row-level PII scrubbing.
        More efficient than text-based governance for tabular results.
        """
        if masked_columns is None:
            masked_columns = []

        result = []
        for row in rows:
            governed_row = {}
            for key, value in row.items():
                # Column mask check
                if key in masked_columns:
                    governed_row[key] = "[MASKED]"
                    continue

                # Sensitivity check on the value
                str_val = str(value)
                sensitivity = heuristic_classify(str_val)
                if sensitivity > receiving_agent.max_sensitivity:
                    if detect_pii(str_val):
                        governed_row[key] = "[REDACTED:PII]"
                    else:
                        governed_row[key] = "[REDACTED:ABOVE_CLEARANCE]"
                else:
                    governed_row[key] = value

            result.append(governed_row)

        return result

    def _split_into_chunks(self, text: str) -> list[str]:
        """
        Split text into chunks for classification.

        Uses overlapping windows to prevent PII patterns from being split
        across chunk boundaries. Without overlap, an SSN like '123-45-6789'
        could land as '123-45' in chunk N and '-6789' in chunk N+1, evading
        detection entirely.

        Overlap size is sized to fit the longest PII pattern we detect
        (IBAN ≈ 34 characters, VIN = 17). 64 characters is generous and
        the duplicate scanning cost is negligible for short overlaps.

        If chunk_size is too small to support the overlap meaningfully, the
        method falls back to a single chunk per call (since the overlap would
        consume the whole window and no progress could be made).
        """
        if not text:
            return []

        OVERLAP = 64
        # If chunk_size is too small for overlap, just emit non-overlapping chunks
        # (this is a degenerate config — production should use chunk_size >= 256).
        step = max(self._chunk_size - OVERLAP, 1)
        if self._chunk_size <= OVERLAP:
            step = self._chunk_size  # fall back to non-overlapping

        if len(text) <= self._chunk_size:
            return [text]

        chunks: list[str] = []
        i = 0
        while i < len(text):
            end = min(i + self._chunk_size, len(text))
            chunks.append(text[i:end])
            if end >= len(text):
                break
            i += step
        return chunks
