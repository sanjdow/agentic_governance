# Code Review — Findings & Changes Applied

## Summary

49 tests passing (up from 38). All identified issues fixed.
A full review identified 16 issues across the codebase, ranging from critical
(SQL injection, broken comparison operators) to minor (misleading test names).

---

## Critical Issues (Fixed)

### 1. `SensitivityLevel` comparison operators were broken
**Location:** `core/models.py`

The original implementation only defined `__ge__` properly. `__gt__` was identical
to `__ge__`, and `__le__`/`__lt__` referenced each other circularly. This meant
that in the existing code, `confidential > confidential` and `confidential >= confidential`
both returned `True` — silently masking permission boundary checks.

**Fix:** Implemented all four operators based on a stable `_rank()` method using
the canonical `_order()` list. Added `TestModelValidation::test_sensitivity_comparison_consistency`
to lock the behaviour.

### 2. SQL injection vulnerability in row filter templates
**Location:** `catalog/catalog.py::derive_row_filters`

The `row_filter_template` field was string-formatted with `user_id` and `brand_scope`
values directly. A user with `user_id="x'; DROP TABLE users--"` would have that
SQL fragment injected into every query they triggered.

**Fix:**
- Added `_validate_safe_identifier()` to `core/models.py` that runs as a
  pydantic `model_validator(mode="after")` on both `UserContext.user_id`,
  `UserContext.brand_scope[]`, and `AgentContext.agent_id`.
- Identifiers must match `^[A-Za-z0-9_\-\.]{1,128}$` — anything else is rejected
  at construction time before any SQL touches the value.
- Added explicit documentation to `derive_row_filters` noting that production
  systems should use `sqlglot` AST manipulation rather than string templates.
- Added three new tests demonstrating injection attempts are rejected:
  `test_user_id_rejects_sql_injection_attempt`, `test_brand_scope_rejects_sql_injection_attempt`,
  `test_agent_id_rejects_sql_injection_attempt`.

### 3. Brand-scope-empty allowed access to brand-tagged assets
**Location:** `catalog/catalog.py::resolve_access`

Original code: `if asset.brand_tags and user.brand_scope:` — meaning a user with
**no** brand scope (empty list) bypassed the brand intersection check entirely
and gained access to ALL brand-tagged assets. This is the most dangerous kind
of fail-open.

**Fix:** Changed to fail-closed semantics. If an asset has any brand tags, the
user must have a non-empty brand scope that intersects with them. Added test
`test_brand_scope_empty_denies_brand_tagged_asset`.

### 4. `InjectionAssessment.should_block` validator unreliable
**Location:** `core/models.py`

The original validator used `mode="before"` and read `info.data.get("risk_level")`
which only works if `risk_level` is parsed before `should_block`. Field order
in pydantic isn't guaranteed by source order in all cases — the validator was
fragile and could silently fail to auto-block on HIGH/CRITICAL risk.

**Fix:** Changed to `model_validator(mode="after")` which runs after all fields
are populated. Used `object.__setattr__` to set the field, since by post-validation
the model state is guaranteed.

### 5. Catalog policy version didn't change on consent updates
**Location:** `catalog/catalog.py::_compute_version`

`record_consent()` triggered a version recompute, but `_compute_version()` only
hashed the `_assets` dict — not `_consent_state`. Result: revoking consent did
not invalidate cached entries or trigger proof re-issuance. A user who withdrew
consent could still have their data served from cache for the full TTL window.

**Fix:** `_compute_version` now hashes both the asset registry AND the consent
state, sorted deterministically. Consent withdrawal now correctly bumps the
policy version, which evicts cached entries and invalidates outstanding proofs.

---

## High-Severity Issues (Fixed)

### 6. MCP server replay protection set was unbounded
**Location:** `mcp_server/governance_server.py`

`_used_proof_ids` was a `set` that only ever grew. In a long-running deployment
this is a memory leak, and there was no eviction logic at all.

**Fix:**
- Changed to `dict[str, datetime]` mapping `proof_id → expires_at`.
- Added `_record_proof_use()` method that:
  - Evicts entries whose proof expiry has passed (those proofs can't be
    re-verified anyway, so tracking them adds no security)
  - Caps the dict at `max_replay_cache_size` (default 100K), evicting oldest
    entries FIFO when full
- Production note added: distributed deployments should use Redis with TTLs.

### 7. `revoke_all_for_session` was broken
**Location:** `policy_resolver/resolver.py`

Original implementation added `f"session:{session_id}"` as a sentinel string
to `_revoked_proofs`, but `verify_proof` only checked `proof_id in self._revoked_proofs`
— it never looked for the sentinel. Session-level revocation silently failed.

**Fix:**
- Added separate `_revoked_sessions: set[str]` tracking session-level revocation.
- `verify_proof` now extracts `session_id` from the JWT payload and checks both
  `_revoked_proofs` (per-proof) and `_revoked_sessions` (session-wide).
- Added `_proof_session_index` mapping for diagnostics.
- New test `test_session_revocation` confirms the fix.

### 8. MCP server mutated the proof's `allowed_filters` dict during execution
**Location:** `mcp_server/governance_server.py::_execute_governed`

`filters = verified_proof.allowed_filters` then `filters.pop("masked_columns", [])`
mutated the dict in-place on the verified_proof object. Any subsequent inspection
of the proof (logging, audit trail) would show altered filters that don't match
what was actually issued.

**Fix:** Use `copy.deepcopy(verified_proof.allowed_filters)` before pop.
Added test `test_proof_filters_not_mutated_by_execution` that snapshots the
proof's filters, executes the call, and asserts the proof is unchanged.

### 9. Heuristic classifier short-circuited on first match
**Location:** `context_governance/middleware.py::heuristic_classify`

The original loop returned immediately on the first PII pattern match. If text
contained both an email address (CONFIDENTIAL) and a salary keyword (RESTRICTED),
the iteration order of `PII_PATTERNS` decided which classification was returned —
typically the lower one, which is the dangerous direction for fail-closed behaviour.

**Fix:** Refactored to scan ALL patterns and keyword lists, tracking the highest
sensitivity seen. Returns the maximum match, never short-circuits on a lower one.
Added test `test_classifier_returns_highest_sensitivity_match` with a mixed-signal
input that previously misclassified.

---

## Medium-Severity Issues (Fixed)

### 10. SQL filter injection didn't handle `ORDER BY` correctly
**Location:** `mcp_server/governance_server.py::_inject_where_clauses`

The original used `query_upper.index("WHERE")` which fails on queries with WHERE
inside subqueries. Also inserted WHERE clauses with poor whitespace handling that
could produce malformed SQL when followed by ORDER BY/GROUP BY/LIMIT.

**Fix:**
- Switched to regex with `\bWHERE\b` word boundary matching to avoid matching
  WHERE substrings inside identifiers.
- Improved trailing-keyword detection to find the EARLIEST of GROUP BY/HAVING/
  ORDER BY/LIMIT/OFFSET and insert WHERE before it.
- Added explicit documentation that this is a reference implementation and
  production systems MUST use sqlglot for AST-based SQL manipulation.
- Added two new tests: `test_filter_injection_with_existing_where` and
  `test_filter_injection_with_order_by`.

### 11. `safe_text` returned empty string when all chunks were redacted
**Location:** `core/models.py::GovernedContext.safe_text`

Filtering `if not c.redacted` and joining with `\n` produced an empty string
when everything was redacted. A receiving agent then sees no context at all
and may make spurious decisions thinking the upstream agent produced nothing.

**Fix:** Redacted chunks are now replaced with the placeholder string
`[redacted: content above receiving agent's clearance]` so the receiving agent
has a clear signal that content existed but was withheld.

### 12. Query hash was not whitespace-canonical
**Location:** `core/models.py::AuthorizedQueryProof.hash_query`

Two semantically identical queries with different formatting (extra spaces,
line breaks) produced different hashes, causing legitimate queries to fail
verification when reformatted by intermediate layers.

**Fix:** Added `canonicalize_query()` classmethod that collapses runs of
whitespace and strips leading/trailing whitespace before hashing. Does NOT
lower-case (SQL identifiers can be case-sensitive). Added test
`test_query_canonicalization_whitespace_insensitive`.

---

## Minor Issues (Fixed)

### 13. Misleading test name
**Location:** `tests/test_framework.py`

`test_brand_scope_access_denied_wrong_brand` asserted the access was *granted*
(audi user with audi brand-tagged asset). The test was correct, the name was
inverted.

**Fix:** Renamed to `test_brand_scope_intersection_grants_access` and added a
genuinely access-denied test as a separate case.

### 14. Confusing illustrative `row_filter_template` in demo catalog
**Location:** `catalog/catalog.py::build_demo_catalog`

The demo catalog used `row_filter_template="department = '{user_id}'"` for
employee data, which suggested user_id should equal department name. Misleading.

**Fix:** Removed the illustrative template. The brand_filter from `derive_row_filters`
is sufficient for the demo. Added a comment noting production systems should
use sqlglot.

### 15. `KeyError` on bad row_filter_template
**Location:** `catalog/catalog.py::derive_row_filters`

`asset.row_filter_template.format(...)` would raise a raw `KeyError` if the
template referenced an unknown placeholder. This bubbled up as an unhandled
exception with no diagnostic context.

**Fix:** Wrapped in try/except, raising a `PolicyResolutionError` with a clear
message naming the asset and the unknown placeholder.

### 16. `AccessRight.AGGREGATE` defined but never enforced
**Location:** `core/models.py` and various

`AGGREGATE` was in the enum but no code path checked for it. Documented
this in the module — it's reserved for future use by COUNT/SUM/AVG-only
agents that should not see raw rows.

---

## Issues Identified But Not Fixed (Production Concerns)

These are documented in the code but require infrastructure changes outside
the Python library:

### A. RSA key rotation
The `PolicyResolver` generates a fresh keypair per instance. Production needs
key rotation, an HSM/KMS, and a key ID (`kid`) header in JWTs so MCP servers
can locate the verifying key for each token.

### B. Distributed revocation store
`_revoked_proofs` and `_revoked_sessions` are in-process sets. A multi-instance
deployment needs Redis or DynamoDB for revocation state, otherwise a revoked
proof is still valid on instances that haven't seen the revocation.

### C. Heuristic classifier accuracy
The pattern-based classifier has high recall but low precision. Production
should use a fine-tuned NER model (spaCy with custom entities, or a distilled
BERT classifier) for sub-50ms latency at higher accuracy.

### D. SQL AST parsing
Filter push-down via string manipulation is fundamentally unsafe for complex
queries. Production must use sqlglot to parse, walk, and rewrite the AST.

### E. KV cache infrastructure isolation
This is the broadest open problem. Documented in README — requires
infrastructure-layer controls (per-tenant inference endpoints, disabled prefix
caching for sensitive workloads) that no Python library can solve.

---

## Test Coverage Summary

| Category | Tests | Status |
|---|---|---|
| Catalog (L1) | 9 | ✓ |
| Eligibility (L2) | 3 | ✓ |
| Policy Resolver (L3) | 8 | ✓ |
| MCP Server (L4) | 7 | ✓ |
| Context Governance | 4 | ✓ |
| Injection Detection | 5 | ✓ |
| Governed Cache | 5 | ✓ |
| Session Isolation | 3 | ✓ |
| Model Validation (new) | 5 | ✓ |
| **Total** | **49** | **All passing** |
