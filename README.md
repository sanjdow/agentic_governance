# Agent Data Access Governance Framework

A Python reference implementation addressing the core identity and data security gaps
in LLM agentic systems — specifically the failure modes of RBAC/PBAC when AI agents
enter the data stack.

---

## The Problems This Repo Addresses

| # | Problem | Module |
|---|---------|--------|
| 1 | Tokens prove identity, not query compliance | `policy_resolver/` |
| 2 | RBAC/PBAC cannot govern non-deterministic queries | `orchestrator/` |
| 3 | Agents can chain calls to aggregate beyond permission | `orchestrator/eligibility.py` |
| 4 | Prompt injection hijacks governed tool calls | `injection_detection/` |
| 5 | Context leaks across agent chains | `context_governance/` |
| 6 | Redis cache carries no classification metadata | `cache/` |
| 7 | KV cache / session isolation at inference layer | `agents/session_isolation.py` |
| 8 | MCP server acts as decision point, not enforcement point | `mcp_server/` |
| 9 | Entra ID proves who is calling, not what they may query | `auth/` |
| 10 | OBO delegation silently drops brand scope and clearance | `auth/claim_mapper.py` |

---


---

## Standing on Established Foundations

The architectural patterns in this framework are grounded in two decades of prior art
in access control, data governance, and zero-trust security. The contribution here is
not the invention of these patterns — it is their application and extension to the
specific failure modes introduced by non-deterministic LLM query generation inside
agentic systems.

### Prior art this work builds on

**XACML (OASIS, 2003)**
XACML formalized the Policy Decision Point / Policy Enforcement Point / Policy
Information Point / Policy Administration Point split over twenty years ago.
The decision-vs-enforcement separation at the core of this framework is XACML's
foundational principle. Apache Ranger, Open Policy Agent, and every modern data
governance platform implement this pattern.

**Apache Ranger**
Ranger Admin is the decision point; Ranger plugins are enforcement points — the
exact PDP/PEP split applied at the data source layer. Catalog-driven row and column
filtering is Ranger's core pattern, predating this work entirely.

**Open Policy Agent (OPA)**
OPA externalizes policy decisions from enforcement, with policy-as-code pulled from
a central store. Standard in Kubernetes, service mesh, and data platforms since 2016.
The orchestrator's eligibility gating follows the same decision-before-invocation
principle.

**Catalog as governance authority**
Databricks Unity Catalog, Snowflake Horizon, Microsoft Purview, Collibra, Immuta,
Privacera, and AWS Lake Formation all implement catalog-as-source-of-truth with
policy decisions separated from enforcement. This is the dominant paradigm in
enterprise data governance.

**Signed authorization context**
Macaroons (Google, 2014), SPIFFE/SPIRE workload identity, GCP signed URLs, AWS STS
session tokens, and Zanzibar consistency tokens all implement the pattern of carrying
pre-validated authorization in a signed artifact across service hops. This is
foundational zero-trust architecture.

**Short-lived credentials**
AWS STS temporary credentials, OAuth 2.0 access tokens with short TTLs, and SPIRE
SVID rotation all establish the principle that credentials should be ephemeral and
scoped. The 120-second token TTL here follows the same principle.

---

## Original Contributions

What this framework adds — specifically for LLM agentic systems — beyond the
established patterns above:

**Query-hash binding**
Existing signed credential systems scope tokens to a resource, a session, or an
identity. They do not bind to the exact query string. LLM agents generate queries
non-deterministically — the same prompt can produce a different, more permissive
query on each invocation. Binding the SHA-256 hash of the canonicalized query into
the signed token closes this gap: any deviation from the authorized query is detected
at enforcement time.

**Single-use, non-delegable, per-query tokens**
Standard session tokens are reusable, delegable, and scoped to a resource not a
query. Here each token is issued for one specific data operation, is single-use
(replay protection at the enforcer), non-delegable (agent ID bound in the payload),
and expires in seconds — a tighter scope than any of the prior art systems above.

**MCP as enforcement substrate**
The Model Context Protocol is the emerging standard for how LLM agents call tools
and data sources. This framework applies the PDP/PEP split specifically to MCP tool
calls — treating the MCP server as a pure enforcement point that verifies a signed
token before executing any data operation.

**Ten LLM-specific failure modes**
The failure mode taxonomy addresses risks that do not exist in traditional API
governance: cross-call aggregation (agent correlates results across permitted calls
in its context window), context leakage between agent hops, prompt injection via
retrieved data hijacking tool calls, GPU KV cache cross-tenant contamination, and
OBO delegation silently dropping policy context in multi-agent chains. These are
LLM-native attack surfaces with no equivalent in the XACML / Ranger / OPA threat
model.

**Entra ID OBO degradation modelling**
On-Behalf-Of delegation in Microsoft Entra ID silently strips app role assignments,
losing data scope and clearance level in agent chains. This is modelled explicitly
via `apply_obo_constraints()`, which degrades the UserContext rather than silently
inheriting stale context — and embeds the original Entra OID in the signed token to
preserve identity across hops.

## Architecture

### High-Level Flow

```
┌──────────────────────────────────────────────────────────────┐
│         Entra ID Auth  →  User Session                       │
│  OID · UPN · group→brand · role→clearance · OBO constraints  │
└──────────────────────────┬───────────────────────────────────┘
                           │ session context
                           ▼
┌──────────────────────────────────────────────────────────────┐
│            L1 — Data Catalog  (policy source of truth)       │
│  classifications · sensitivity · ACLs · consent · versioning │
└──────────────────────────┬───────────────────────────────────┘
                           │ policy propagation
                           ▼
┌──────────────────────────────────────────────────────────────┐
│         L2 — Orchestrator  (agent eligibility gating)        │
│  resolves eligible agents · blocks non-eligible before       │
│  invocation · brand + clearance + source allowlist checks    │
└──────┬────────────────────────────────────┬──────────────────┘
       │                                    │
       │ input content                      │ eligible agents only
       ▼                                    ▼
┌─────────────────┐            ┌────────────────────────────────┐
│ Injection        │            │  L3 — Policy Resolver          │
│ Detector         │            │  catalog lookup → validate     │
│                  │            │  query → issue signed proof    │
│ heuristic        │            │  (RS256 JWT)                   │
│ boundary         │            └───────────────┬────────────────┘
│ tool-redirect    │                            │
│ delimiter scans  │                            │ Signed Access Token
│                  │                            │  · query_hash (sha256)
│ → BLOCKED        │                            │  · user_id + agent_id
└─────────────────┘                            │  · session_id
                                               │  · catalog_policy_version
                                               │  · issued_at / expires_at
                                               │  · allowed_filters
                                               │  · signature
                                               │  (non-delegable · single-use
                                               │   · operation-scoped)
                                               ▼
┌──────────────────────────────────────────────────────────────┐
│       L4 — MCP Governance Server  (enforcement-only)         │
│  verify signature · check expiry · replay protection         │
│  → filter push-down (SQL WHERE)                              │
│  → OR authorised query pass-through                          │
│  never makes a policy decision                               │
└──────────┬──────────────────────────────────────────────────┘
           │
    ┌──────┼──────────────┐
    ▼      ▼              ▼
Delta    Snowflake    Postgres / APIs
Lake     column       filter
row-lvl  masking      push-down

── Cross-cutting controls ────────────────────────────────────────
│  Context Governance   │  Governed Cache    │  Session Isolation │
│  Classifies inter-    │  Identity-scoped   │  Need-to-know      │
│  agent context ·      │  Redis keys ·      │  context · agents  │
│  redacts above        │  policy-version    │  declare fields    │
│  clearance ceiling    │  TTLs · encrypted  │  they need         │
─────────────────────────────────────────────────────────────────
```

### Trust Model Inversion

Traditional agentic systems are **reactive**: a token grants entry, and any subsequent
query is presumed acceptable unless the receiving system detects a violation. Policy
logic must therefore be replicated across every system that can receive a query.

This framework is **proactive**: no query reaches a data source unless it arrives with
a signed attestation that it has already been found compliant. The query *is* the proof.
The MCP server does not need to understand policy semantics — it only verifies a signature.

---

## Architecture Flow — Step by Step

### Step 0: Entra ID authentication (new)
Before any governance layer runs, an incoming Bearer token is validated against Microsoft
Entra ID. The `auth/` module handles this in three steps:

1. **Token validation** — the JWT signature is verified against the tenant's JWKS; audience,
   expiry, and tenant claims are checked.
2. **Claim mapping** — the validated claims are translated into a `UserContext`:
   - `oid` (Object ID) becomes `user_id` — the immutable, canonical identity anchor
   - Group memberships map to `brand_scope` via `brand_group_map` in config
   - App roles map to `clearance_level` via `clearance_role_map` in config
3. **OBO constraint modelling** — if the request arrives via an On-Behalf-Of delegation
   chain, `apply_obo_constraints()` explicitly degrades the context (clearing `brand_scope`,
   reducing `clearance_level` to `INTERNAL`) to model the policy information lost in OBO.

App-only tokens (Managed Identity / client credentials) are rejected at this layer — they
carry no user identity and cannot produce a valid `UserContext`.

### Step 1: User session is established
A `UserContext` is created carrying the user's identity, roles, brand scope (e.g. `["brand_b"]`),
and clearance level. When using Entra ID authentication, this is produced by the `auth/`
module automatically. The `user_id` is always the Entra OID — not the UPN, which can change.
This context is the root of every trust decision downstream. Nothing in the framework grants
more access than what the user's session context permits.

### Step 2: L1 — Data Catalog (policy source of truth)
The catalog is the single authoritative source for all governance rules. It holds:

- **Sensitivity classifications** per asset (`PUBLIC` → `SECRET`)
- **Access rights** required to query each asset (`READ`, `AGGREGATE`, `EXPORT`, ...)
- **Brand tags** enabling brand-scoped row-level isolation (e.g. division analysts only see division rows)
- **PII column lists** for column masking at the enforcement layer
- **Consent state** per data subject (GDPR / CCPA)
- **Policy version** — a checksum of current catalog state, embedded in every proof

No downstream component (orchestrator, MCP server, cache) holds its own copy of policy
logic. Any policy change propagates outward from the catalog. The catalog exposes
a runtime-queryable API so the Policy Resolver can resolve rules in the request path.

### Step 3: L2 — Orchestrator (agent eligibility gating)
Before any agent is invoked, the orchestrator resolves which agents are eligible given
the current user context, session, and request classification — as derived from catalog
policies. Non-eligible agents are **never activated**.

This is not filtering after the fact; it is **exclusion before invocation**.

Key checks performed per agent:
- User clearance level must meet or exceed the agent's `max_sensitivity` ceiling
- Agent must have the required access right (`READ`, `AGGREGATE`, etc.)
- Agent's `allowed_sources` must include the target data source
- Brand scope intersection must be non-empty for brand-tagged assets

An agent with `max_sensitivity = RESTRICTED` is completely blocked from a session where
the user holds only `CONFIDENTIAL` clearance — even if the agent would technically have
access to the data. This prevents the common attack of running agents under elevated
identity relative to the invoking user.

### Step 4: Injection detector (cross-cutting — before tool dispatch)
Before retrieved content (documents, database rows, web pages) is injected into any
agent's context, the injection detector screens it across four layers:

- **Layer 1 — Critical patterns**: direct instruction override attempts (`ignore all previous instructions`, DAN, `disregard your system prompt`)
- **Layer 2 — Boundary analysis**: role-switch attempts (`you are now`, `from now on you will`, `forget your training`)
- **Layer 3 — Tool redirect**: attempts to redirect tool calls to exfiltrate data (`send all data to https://...`, `execute this SQL`)
- **Layer 4 — Delimiter injection**: attempts to smuggle instructions through format delimiters (XML, JSON, triple-backtick system blocks)

Content flagged as `HIGH` or `CRITICAL` risk is blocked before it reaches the agent.
This addresses the prompt injection attack surface where a malicious database field
hijacks the agent's tool calls while presenting a legitimate identity to RBAC.

### Step 5: L3 — Policy Resolver (Signed Access Token)
The Policy Resolver is the architectural heart of the framework. An eligible agent
expresses intent (a query). The resolver:

1. Looks up every data asset the query touches in the catalog
2. Validates user + agent access rights against catalog policy for each asset
3. Derives catalog-driven row filters and column masks
4. Issues an **Signed Access Token** — a cryptographically signed JWT

The proof has five critical properties:

| Property | Mechanism |
|----------|-----------|
| **Query-bound** | SHA-256 hash of the exact query embedded in the proof. The query hash is binding — any modification is detected at the MCP layer. |
| **Non-delegable** | `agent_id` embedded in the proof. A different agent presenting the same proof is rejected. |
| **Single-use** | The MCP server tracks used `token_id` values. Replay attacks are blocked. |
| **Short-lived** | Default TTL of 120 seconds. No refresh mechanism. |
| **Policy-versioned** | `catalog_policy_version` embedded. Proofs issued under superseded policy versions are detectable. |

No agent can self-issue a proof. The private signing key lives only in the Policy Resolver.
The public key is distributed to MCP servers for verification.

### Step 6: L4 — MCP Governance Server (enforcement point)
The MCP server is a **pure Access Enforcer** — it never makes a policy decision.

On receiving a tool call with a proof:

1. Verify the JWT signature against the Policy Resolver's public key
2. Check proof expiry
3. Verify `agent_id` in proof matches the claiming agent (non-delegable)
4. Verify the submitted query hash matches the proof's `query_hash` (operation-scoped)
5. Check the `token_id` has not been used before (replay protection)
6. Route to one of two execution paths:
   - **Filter push-down**: translate catalog-derived row filters into SQL `WHERE` clauses injected into the query before execution (equivalent to Unity Catalog RLS or Starburst row filters)
   - **Pass-through**: execute the pre-validated query unchanged (when no additional filters are needed)

Calls arriving without a proof are rejected outright (`require_sat=True` by default).

### Step 7: Cross-cutting — Context Governance
Between agent hops, the context governance middleware intercepts each agent's output
before it is passed to the next agent, classifies its content sensitivity heuristically,
and redacts or blocks content that exceeds the receiving agent's sensitivity ceiling.

This addresses the core **context window leakage** problem: data retrieved under a
governed query immediately exits the governance perimeter the moment it enters the
agent's context. A retrieval agent permitted to see `CONFIDENTIAL` data passes its
output to a summarisation agent with an `INTERNAL` ceiling — the middleware redacts
PII fields, financial figures, and brand-restricted content before the summarisation
agent sees anything.

The middleware operates in three modes:
- `REDACT` — remove sensitive chunks, pass safe remainder (default)
- `BLOCK` — raise an exception if any sensitive content is detected
- `AUDIT` — pass everything but log all violations (for testing)

### Step 8: Cross-cutting — Session Isolation
Rather than passing raw context forward between agents, each agent writes structured
outputs to a `SessionStateStore`. Downstream agents declare via a `ContextRequest`
exactly which output types and field names they need.

The state store mediates access, enforcing:
- **Output type filtering** — agents only receive declared output types
- **Field-level filtering** — agents only receive declared fields within those outputs
- **Sensitivity ceiling** — outputs above the receiving agent's ceiling are excluded entirely

This breaks the "context window as shared memory" pattern where Agent A's full context
automatically becomes Agent B's context.

### Step 9: Cross-cutting — Governed Cache
The Redis cache wrapper enforces identity-scoped, policy-version-bound caching:

- **Identity-scoped keys**: the cache key incorporates `user_id + agent_id + query_hash`.
  Agent A's results are never served to Agent B. User X's results are never served to User Y.
- **Policy-version binding**: the current catalog policy version is embedded in the key
  prefix. When policy changes, cached entries under the old version are automatically
  treated as misses and evicted.
- **Classification-aware TTLs**: `PUBLIC` data may cache for 1 hour; `CONFIDENTIAL` for
  5 minutes; `RESTRICTED` for 60 seconds; `SECRET` is never cached.
- **At-rest encryption**: Fernet symmetric encryption is applied before writing to Redis.
  Sensitive governed data does not sit in plaintext.

---

## Environment Setup

### Prerequisites

| Requirement | Minimum | Recommended | Notes |
|-------------|---------|-------------|-------|
| Python | 3.10 | 3.12 | Type annotations use `X \| Y` syntax (3.10+) |
| pip | 22.0 | 24.0 | Needed for `pyjwt[crypto]` extras resolution |
| Git | any | — | To clone/version the repo |
| Redis | — | 7.x | Optional — framework falls back to in-memory cache |

The framework runs entirely in-process for development and testing — no database,
no network services, and no Redis instance are required to get started.

---

### Step 1 — Clone or extract the repo

If you received the tarball:
```bash
tar -xzf agentic_governance_repo.tar.gz
cd agentic_governance
```

If cloning from version control:
```bash
git clone <repo-url>
cd agentic_governance
```

---

### Step 2 — Create a virtual environment

Using a virtual environment isolates the framework's dependencies from your
system Python and from other projects.

**macOS / Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (Command Prompt):**
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

You should see `(.venv)` at the start of your prompt once activated.

---

### Step 3 — Install dependencies

The repo ships with both a `requirements.txt` and a `pyproject.toml`. Use
whichever fits your workflow.

**Option A — requirements.txt (simplest):**
```bash
pip install -r requirements.txt
```

**Option B — editable install via pyproject.toml (recommended if you plan to modify the code):**
```bash
pip install -e ".[test]"
```

This installs the framework as an editable package so imports resolve correctly
from any working directory. The `[test]` extra adds pytest and coverage tools.

Either option installs these core packages:
- `pyjwt[crypto]` — RS256 JWT signing and verification for Signed Access Tokens
- `cryptography` — Fernet symmetric encryption for the governed cache
- `pydantic` — typed models and identifier validation throughout the framework

**Optional extras (via pyproject.toml):**
```bash
pip install -e ".[redis]"   # real Redis backend for the governed cache
pip install -e ".[sql]"     # sqlglot for AST-based SQL filter push-down
pip install -e ".[http]"    # FastAPI + uvicorn to run the MCP server over HTTP
pip install -e ".[all]"     # everything above
```

---

### Step 4 — Verify the installation

Run the test suite. All 54 tests should pass with no warnings:
```bash
pytest tests/ -v
```

Expected output:
```
============================= test session starts ==============================
...
80 passed in 2.6s
```

If you see import errors, confirm you are in the repo root directory and the
virtual environment is activated (`which python` should point inside `.venv`).

---

### Step 5 — Run the demos

**Core governance demo** (all 11 controls):
```bash
python examples/full_scenario.py
```

**Entra ID authentication demo** (token validation, claim mapping, OBO, Managed Identity):
```bash
python examples/demo_entra_auth.py
```

The core demo runs an end-to-end governed workflow demonstrating:

```
─────────────────────────────────────────────────────────────────
  1. INITIALIZING FRAMEWORK COMPONENTS
─────────────────────────────────────────────────────────────────
  ✓ Catalog loaded: 5 assets registered
  ✓ Policy Resolver initialized (120s proof TTL)
  ...
─────────────────────────────────────────────────────────────────
  10. SUMMARY
─────────────────────────────────────────────────────────────────
  L1  Data Catalog              ✓  Policy source of truth
  L2  Agent Eligibility         ✓  group agent blocked for division user
  L3  Policy Resolver           ✓  Signed proof issued (RS256 JWT)
  L3  Proof — Non-delegable     ✓  Delegation attempt rejected
  L3  Proof — Query-bound       ✓  Query substitution rejected
  L4  MCP Governance Server     ✓  Ungoverned call rejected
  L4  MCP Filter Push-down      ✓  Brand filters applied
      Injection Detection       ✓  Malicious field flagged
      Context Governance        ✓  PII redacted between agents
      Session Isolation         ✓  Need-to-know context declared
      Governed Cache            ✓  Identity-scoped, encrypted
```

---

### Optional: Run with a real Redis instance

By default the governed cache uses an in-memory fallback. To connect to Redis,
pass a `redis.Redis` client when constructing `GovernedCache`:

```python
import redis
from cache.governed_cache import GovernedCache
from catalog.catalog import build_demo_catalog

catalog = build_demo_catalog()
redis_client = redis.Redis(host="localhost", port=6379, db=0)
cache = GovernedCache(catalog=catalog, redis_client=redis_client, encrypt=True)
```

**Starting a local Redis instance with Docker:**
```bash
docker run -d --name redis-gov -p 6379:6379 redis:7-alpine
```

**Stopping it:**
```bash
docker stop redis-gov && docker rm redis-gov
```

---

### Optional: Run tests with coverage

```bash
pytest tests/ -v --cov=. --cov-report=term-missing
```

---

### Project structure at a glance

```
agentic_governance/
├── core/                   # Shared models, exceptions, type definitions
├── auth/                   # Entra ID authentication, claim mapping, OBO modelling
├── catalog/                # L1 — data catalog (in-memory stub)
├── policy_resolver/        # L3 — RS256-signed Signed Access Token issuance
├── orchestrator/           # L2 — agent eligibility gating before invocation
├── mcp_server/             # L4 — proof enforcement, filter push-down
├── context_governance/     # Inter-agent context classification and redaction
├── injection_detection/    # Prompt injection detection before tool dispatch
├── cache/                  # Governed Redis cache with identity-scoped keys
├── agents/                 # Session isolation, need-to-know context design
├── examples/               # End-to-end demos (full_scenario, demo_entra_auth)
├── tests/                  # 80 pytest tests covering all modules
├── requirements.txt        # Dependencies (core + optional)
├── CHANGES.md              # Code review findings and applied fixes
└── README.md               # This file
```

---

### Troubleshooting

**`ModuleNotFoundError: No module named 'core'`**
You are not running from the repo root. All modules use relative imports
(`from core.models import ...`) which resolve from the working directory.
```bash
cd agentic_governance   # make sure you are here
python examples/full_scenario.py
```

**`ImportError: cannot import name 'RSAPrivateKey'`**
The `cryptography` package is not installed or the wrong version is installed.
```bash
pip install --upgrade "cryptography>=41.0.0"
```

**`jwt.exceptions.MissingRequiredClaimError`**
Usually caused by running tests against a stale `.pyc` cache. Clear and retry:
```bash
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; pytest tests/ -v
```

**Tests fail with `ValidationError` on `UserContext`**
Identifier validation rejects characters outside `[A-Za-z0-9_\-\.]`. Check
that any custom `user_id` or `brand_scope` values in your test fixtures
only use permitted characters.

**`ValueError: ENTRA_TENANT_ID environment variable is required`**
Set the required Entra environment variables before running production code:
```bash
export ENTRA_TENANT_ID="your-tenant-id"
export ENTRA_CLIENT_ID="your-app-registration-client-id"
export ENTRA_AUDIENCE="api://your-client-id"
```
For development and tests, no variables are needed — use `EntraConfig.for_testing()`
and `EntraAuthGateway.for_testing()` which run entirely without Azure credentials.

**`EntraTokenValidationError: Failed to fetch OIDC metadata`**
The validator cannot reach `login.microsoftonline.com`. Check network connectivity
and proxy settings. In air-gapped environments, pre-seed the JWKS by calling
`validator._jwks_client` with a local JWKS endpoint.

**`EntraTokenValidationError: Token tenant '...' does not match`**
A token from a different Azure tenant was presented. This is blocked by design.
If multi-tenant support is required, set `validate_tenant=False` and implement
your own tenant allowlist check after validation.

**`ValueError: Cannot map an app-only token to a UserContext`**
An LLM agent called using Managed Identity (no user context). Either require the
agent to use OBO delegation (carrying the invoking user's identity), or use
`map_to_agent_principal()` and construct an `AgentContext` explicitly.

**Redis connection refused**
The framework automatically falls back to in-memory cache — you will see:
```
GovernedCache: using in-memory fallback store (no Redis configured)
```
This is expected behaviour when no Redis client is passed. To use Redis,
see the optional Redis section above.

---

## Entra ID Configuration

For production use, set these environment variables before starting the application.
For development and testing, none of these are required — the test mode factory
generates valid tokens without Azure credentials.

```bash
# Required
export ENTRA_TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   # Azure tenant (directory) ID
export ENTRA_CLIENT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   # App registration client ID
export ENTRA_AUDIENCE="api://your-client-id"                     # Expected token audience

# Optional — confidential-client flows only
export ENTRA_CLIENT_SECRET="your-client-secret"

# Group → brand scope mapping (JSON)
# Key: Entra group OID or display name  Value: list of brand_scope values
export ENTRA_BRAND_GROUP_MAP='{"aabb-ccdd-div-a-group-oid": ["brand_b"], "eeff-0011-corp-all-oid": ["brand_a","brand_b","brand_c","brand_d","brand_e"]}'

# App role → clearance level mapping (JSON)
# Key: Entra app role value  Value: SensitivityLevel string
export ENTRA_CLEARANCE_ROLE_MAP='{"DataReader": "internal", "DataAnalyst": "confidential", "DataSteward": "confidential", "DataAdmin": "restricted"}'

# OBO downstream scope (optional)
export ENTRA_OBO_SCOPE="api://downstream-service/.default"
```

**Finding these values in Azure Portal:**
- `ENTRA_TENANT_ID`: Azure Portal → Entra ID → Overview → Tenant ID
- `ENTRA_CLIENT_ID`: Azure Portal → Entra ID → App registrations → your app → Application (client) ID
- Group OIDs: Azure Portal → Entra ID → Groups → your group → Object ID

**App manifest configuration required for group claims:**

Add this to your app registration manifest in Azure Portal so Entra includes group OIDs in tokens:
```json
"groupMembershipClaims": "SecurityGroup"
```

Without this, `claims.groups` will be empty and `brand_scope` will always be `[]`.

---

## Quick Start

For those who want to get running immediately (Python 3.10+, pip 22+):

```bash
# 1. Extract and enter the repo
tar -xzf agentic_governance_repo.tar.gz && cd agentic_governance

# 2. Create and activate a virtual environment
python3 -m venv .venv && source .venv/bin/activate   # macOS/Linux
# .venv\Scripts\activate.bat                          # Windows CMD

# 3a. Install via requirements.txt (simple)
pip install -r requirements.txt

# 3b. OR install as editable package (recommended if modifying the code)
# pip install -e ".[test]"

# 4. Verify — all 80 tests should pass
pytest tests/ -v

# 5. Run the full governance demo
python examples/full_scenario.py
```

---

## Module Overview

### `auth/`
Microsoft Entra ID authentication integration. Validates Bearer tokens against the
tenant's JWKS, maps claims to `UserContext` via configurable group → brand and
role → clearance tables, and explicitly models OBO delegation context loss.
Includes a test token factory so the full auth pipeline can be exercised without
Azure credentials.

Four files:
- `entra_config.py` — configuration and policy mapping tables (from env or code)
- `token_validator.py` — JWT validation with JWKS caching and test-mode support
- `claim_mapper.py` — claim → `UserContext` translation and `apply_obo_constraints()`
- `entra_integration.py` — high-level gateway: `authenticate_request()`, `authenticate_obo_request()`

### `catalog/`
In-memory data catalog stub implementing the policy source of truth.
Provides runtime-queryable APIs for classifications, sensitivity levels,
access rights, consent state, and policy versioning.

### `policy_resolver/`
Issues **Signed Access Tokens** — cryptographically signed JWTs binding
a specific query hash to user identity, agent identity, session, and catalog
policy version. Short-lived, non-delegable, non-reusable.

### `orchestrator/`
Multi-agent orchestrator with catalog-policy-driven agent eligibility gating.
Non-eligible agents are excluded before invocation, not filtered after.

### `mcp_server/`
MCP-style tool server that acts as a pure **Access Enforcer**.
Verifies proof signature and expiry, then either executes pre-validated
queries or applies filter push-down from catalog policy semantics.

### `cache/`
Governed Redis cache wrapper with identity-scoped keys, policy-version
binding, classification-aware TTLs, and at-rest encryption. Falls back
to an in-memory implementation when Redis is unavailable.

### `context_governance/`
Inter-agent context middleware that intercepts agent outputs, classifies
content against the catalog, and redacts or blocks content exceeding
the receiving agent's permission level.

### `injection_detection/`
Multi-layer prompt injection detector combining heuristic pattern matching,
instruction boundary analysis, tool-redirect detection, and delimiter scanning.

### `agents/`
Session isolation utilities enforcing need-to-know context design between
agent hops. Each agent receives only the minimum context required.

---

## Security Model

This framework inverts the trust model:

- **Reactive (today):** Token grants entry → query presumed acceptable → violations detected downstream
- **Proactive (this framework):** No query reaches a data source without a signed, operation-scoped proof of prior authorization

The MCP server never makes policy decisions. It only enforces proofs already
issued by the Policy Resolver.

---

## What Each Component Addresses

| Problem | Module | Mitigation |
|---|---|---|
| Token proves identity not query | `policy_resolver` | RS256-signed query-hash-bound proof |
| RBAC can't govern dynamic queries | `orchestrator/eligibility` | Catalog-driven pre-invocation gating |
| Cross-call aggregation | `orchestrator/eligibility` | Per-asset access check per call |
| Prompt injection | `injection_detection` | 4-layer pattern detection before tool dispatch |
| Context leakage | `context_governance` | Heuristic classifier + redaction between agents |
| Redis cache cross-identity | `cache` | Identity-scoped keys + policy-version TTLs |
| MCP as decision point | `mcp_server` | Enforcement-only — proof verifies, never decides |
| Context window as shared memory | `agents/session_isolation` | Declared need-to-know via SessionStateStore |
| Entra ID identity ≠ query compliance | `auth/entra_integration` | OID embedded in Signed Access Token; groups → brand scope; roles → clearance |
| OBO delegation drops policy context | `auth/claim_mapper` | `apply_obo_constraints()` degrades context explicitly; proof carries original context |

---

## Limitations & Production Notes

- The `catalog/` implementation is an **in-memory stub**. Production deployments
  should replace it with a real catalog backend (an enterprise data catalog (e.g. Databricks Unity Catalog, Microsoft Purview).
- The `mcp_server/` is an in-process reference implementation. Production use should
  integrate with your actual MCP transport layer (FastAPI/ASGI).
- GPU KV cache isolation (vLLM prefix cache) requires infrastructure-layer controls
  outside the scope of this Python library. Dedicated inference endpoints per tenant
  are the most reliable mitigation available today.
- Proof revocation on mid-session policy changes is tracked in-process. Production
  deployments need a distributed revocation store (Redis, DynamoDB).
- The context governance classifier is heuristic. Production deployments should
  augment with a fine-tuned NER model for higher precision at acceptable latency.
- The `auth/` JWKS cache is in-process. Production deployments with multiple instances
  need a shared cache (Redis) so a key rotation is picked up by all instances simultaneously.
- When a user belongs to more than 200 Entra groups, Entra omits group claims from the
  token and sets a `_claim_names` overage indicator. The `claim_mapper` detects this and
  returns empty `brand_scope` (fail-closed). Production systems should call Microsoft Graph
  to resolve the full group list in the overage case.
- OBO delegation loses app role claims. The `apply_obo_constraints()` method models this
  explicitly, but downstream agents operating on OBO tokens must be designed to work with
  `brand_scope=[]` and `clearance=INTERNAL` unless the original Signed Access Token is
  passed alongside the OBO token.
