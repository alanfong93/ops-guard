# 0006 — LAN MCP transport and authentication

- Status: Accepted
- Date: 2026-09-29
- Decided by: plan-loop design (issue #54); implemented with this issue
- Consumers: #57 (MCP propose_fix tool), #61 (Telegram approval transport), #62 (standing-authorization preconditions)

## Context

The earlier project direction described ops-guard as a local MCP program with no network deployment. The stage plan now needs LAN-connected MCP clients against the cited-guidance service. HTTP bearer tokens are credentials: RFC 6750 §1 and §5.3 cover bearer tokens from any source and require TLS or equivalent transport protection. A LAN plaintext listener would expose the reusable token and request data to on-path observers.

## Decision

Serve the existing retrieval-only MCP surface using FastMCP Streamable HTTP with native Uvicorn TLS at the configured LAN endpoint. Require a static high-entropy bearer token and stable proposal/audit keys from environment variables; fail closed on missing configuration. Validate Host and Origin against configured allowlists. Use a custom FastMCP `TokenVerifier` with constant-time comparison; do not use `StaticTokenVerifier` in this service. Run owner-based crash reconciliation before opening the listener. Expose only `search_runbook` in this stage. The operator provisions a certificate whose SAN matches the URL and configures client trust. Token and key rotation is manual: change the environment value and restart.

## Environment contract (`python -m ops_guard`)

All variables are required; a missing, empty, or invalid value exits before a listener opens, naming the variable and never a secret value:

| Variable | Meaning | Validation |
|---|---|---|
| `OPS_GUARD_HTTP_BEARER_TOKEN` | Static MCP transport credential | ≥ 32 characters |
| `OPS_GUARD_PROPOSAL_TOKEN_KEY` | Proposal token key | 64 hex characters (32 bytes) |
| `OPS_GUARD_AUDIT_FINGERPRINT_KEY` | Audit fingerprint/redaction key | 64 hex characters (32 bytes) |
| `OPS_GUARD_DB_PATH` | SQLite path shared by audit and proposals | writable path |
| `OPS_GUARD_RUNBOOK_DIR` | Directory of runbook JSON revisions | existing directory |
| `OPS_GUARD_BIND_HOST` | LAN interface to bind | non-empty host |
| `OPS_GUARD_PORT` | TCP port | 1–65535 |
| `OPS_GUARD_TLS_CERTFILE` | TLS certificate chain (PEM) | loadable with the key |
| `OPS_GUARD_TLS_KEYFILE` | TLS private key (PEM) | loadable with the certificate |
| `OPS_GUARD_ALLOWED_HOSTS` | Host-header allowlist (comma-separated) | non-empty list |
| `OPS_GUARD_ALLOWED_ORIGINS` | Origin allowlist (comma-separated) | non-empty list |

Runbook loading preserves the existing contract: malformed, unverified, and tampered revisions are excluded and reported without exposing content; a missing or unreadable directory fails startup. An empty or all-rejected corpus serves empty results. Reconciliation runs before the listener; only counts are logged, and an exception or database error aborts startup before binding.

## Rejected alternatives

- Local stdio-only transport — does not provide the chosen LAN endpoint.
- Plaintext LAN HTTP — does not protect bearer-token transit.
- OAuth / multi-operator identity — out of scope for this single-operator service.
- FastMCP's development-only `StaticTokenVerifier` — its docs mark it for development/testing only.
- Custom health routes — FastMCP custom routes are unauthenticated by default.

## Accepted limits

One shared service token, no per-client identity or automated rotation; service availability depends on operator-provisioned TLS trust/certificate lifecycle; only the retrieval tool is exposed; the static bearer token is transport authentication, not proposal-bound approval or execution authorization.
