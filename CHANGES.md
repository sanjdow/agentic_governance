# Changelog

## [Unreleased]

### Added
- Entra ID authentication module (`auth/`) — JWKS-based JWT validation, group→scope
  and role→clearance mapping, OBO degradation modelling via `apply_obo_constraints()`
- `EntraAuthGateway.for_testing()` — self-signed test token factory so the full
  auth pipeline runs without Azure credentials
- `revoke_session_tokens()` on PolicyResolver — session-wide revocation now actually
  works (was silently a no-op before, see fixes below)
- Overlapping chunk windows in context governance classifier to prevent PII detection
  being defeated by chunk boundaries
- `canonicalize_query()` on SignedAccessToken — whitespace-normalises before hashing
  so reformatted-but-identical queries don't fail verification
- 26 new tests covering Entra auth flows, OBO degradation, SQL injection guards,
  session revocation, and classifier edge cases

### Fixed
- **`SensitivityLevel` comparisons were wrong.** `__gt__` and `__ge__` returned the
  same result, so `CONFIDENTIAL > CONFIDENTIAL` was `True`. Clearance ceiling checks
  were silently passing when they shouldn't. Rewrote all four operators using `_rank()`.
- **SQL injection through `user_id` and `brand_scope`.** These were string-formatted
  directly into row filter templates. Added `_validate_safe_identifier()` on
  `UserContext` and `AgentContext` — rejects anything outside `[A-Za-z0-9_\-\.]`.
- **Empty brand scope granted access to brand-tagged assets.** The condition
  `if asset.brand_tags and user.brand_scope:` silently skipped the intersection
  check when a user had no brand scope at all, giving them access to everything.
  Changed to fail-closed: brand-tagged asset + no brand scope = denied.
- `InjectionAssessment.should_block` didn't reliably auto-set on HIGH/CRITICAL.
  Was using `mode="before"` which ran before `risk_level` was guaranteed to be
  populated. Moved to `model_validator(mode="after")`.
- Consent withdrawal didn't bump the policy version. `_compute_version()` only
  hashed `_assets`, not `_consent_state`. A user revoking consent could still be
  served cached data for the full TTL window. Version checksum now covers both.
- Replay protection set grew without bound. `_used_token_ids` was a bare `set`
  with no eviction. Replaced with `dict[str, datetime]` keyed by expiry; entries
  evicted on expiry or when the dict exceeds `max_replay_cache_size`.
- Session revocation was a no-op. `revoke_session_tokens()` added a sentinel
  string to `_revoked_tokens` but `verify_token()` never checked for it. Added
  `_revoked_sessions: set[str]` and the corresponding check in verify.
- MCP server mutated the token's `allowed_filters` in place. `filters.pop()`
  was called directly on `verified_sat.allowed_filters`, corrupting the object for
  anything inspecting it afterwards (logging, audit). Fixed with `copy.deepcopy()`.
- Heuristic classifier returned first PII match, not highest. Text containing
  both an email (CONFIDENTIAL) and a salary field (RESTRICTED) would return
  whichever pattern matched first. Refactored to scan all patterns and return max.
- SQL filter injection broke on subqueries and `ORDER BY`. `str.index("WHERE")`
  found the first occurrence regardless of context. Switched to `\bWHERE\b` regex
  and reworked the trailing-keyword insertion logic.
- `safe_text` returned empty string when everything was redacted. A downstream
  agent receiving empty context had no way to know content existed but was withheld.
  Redacted chunks now replaced with `[redacted: content above receiving agent's clearance]`.
- `KeyError` on malformed row filter templates. Bare `str.format()` raised
  `KeyError` when a template referenced an unknown placeholder. Wrapped in
  try/except and reraised as `PolicyResolutionError` with the asset ID and key name.

### Changed
- Renamed coined terms throughout to avoid overlap with third-party terminology:
  `AuthorizedQueryProof` → `SignedAccessToken`, `ProofVerificationError` →
  `TokenVerificationError`, `request_proof` → `request_token`, etc.
- Framework name: `Agentic Governance Framework` → `Agent Data Access Governance Framework`
- `_compute_version()` now includes consent state in its checksum
- Demo catalog row filter templates removed — were misleading about how `user_id`
  maps to SQL predicates

### Known limitations (not fixed — need infrastructure)
- RSA keypair is generated per-instance. Production needs KMS + `kid` header in JWTs.
- Revocation state is in-process. Multi-instance deployments need Redis or DynamoDB.
- Context classifier is pattern-based (high recall, low precision). A fine-tuned NER
  model would be better but that's a separate project.
- SQL filter push-down uses string manipulation, not AST. Safe for simple SELECTs,
  not for CTEs or subqueries. Use sqlglot in production.
- GPU KV cache isolation is an infrastructure problem this library can't solve.


## [0.1.0] — 2026-04-03

Initial implementation.

- Four-layer governance model: data catalog (L1), agent eligibility (L2),
  policy resolver (L3), MCP enforcement (L4)
- `SignedAccessToken` — RS256-signed JWT bound to query hash, user, agent, session,
  and catalog policy version. Single-use, 120s TTL, non-delegable.
- `DataCatalog` with sensitivity classifications, access rights, PII column lists,
  consent state, and deterministic policy versioning
- `AgentEligibilityResolver` — blocks ineligible agents before invocation
- `MCPGovernanceServer` — pure enforcement: verifies token, applies row filters,
  masks columns. Never decides policy.
- `ContextGovernanceMiddleware` — heuristic PII classifier, redacts inter-agent
  context above receiving agent's clearance ceiling
- `InjectionDetector` — 4-layer prompt injection detection before tool dispatch
- `GovernedCache` — identity-scoped Redis wrapper with Fernet encryption and
  policy-version-bound TTLs
- `SessionStateStore` — need-to-know context isolation between agent hops
- 54 tests
