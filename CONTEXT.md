# CONTEXT

The authoritative glossary for ops-guard terms. Product terms derive from `docs/PRODUCT.md`, `README.md`, `docs/architecture.md`, and `docs/system_flow.md`; contract terms link to their ADR. Rejected aliases are recorded only where they create a dangerous ambiguity — do not use them in docs, issues, code, or review.

## Terms

### Frozen proposal
An immutable persisted record of one canonical invocation and its one-time token binding. It is created once, is never edited, and a correction is a new proposal. Authority: [ADR 0002](docs/adr/0002-frozen-invocation-audit-contract.md). Rejected alias: **"pending fix"** — a proposal changes nothing and authorizes nothing; "fix" implies both.

### Canonical invocation identity
The SHA-256 digest of the JCS (RFC 8785) canonicalization of the complete invocation: action, target, typed arguments, preconditions, and runbook revision content hash. Any difference in any bound field is a different identity. Authority: [ADR 0002](docs/adr/0002-frozen-invocation-audit-contract.md). Rejected alias: **"token fingerprint"** — the token digest is a keyed HMAC of a random value and carries no invocation information.

### Execution token
The 256-bit opaque single-use handle returned exactly once when a proposal is created; it proves possession of the capability for exactly one frozen invocation until its absolute expiry, and is stored only as a keyed digest. Authority: [ADR 0002](docs/adr/0002-frozen-invocation-audit-contract.md). Rejected alias: **"authorization"** — a token is a capability handle, not permission; authorization is standing authorization or proposal-bound approval, verified separately.

### Approval record
The server-recorded, single-use permission binding the configured operator to one frozen proposal, created only on the internal operator path and spent exactly when the proposal's token is consumed. Authority: [ADR 0003](docs/adr/0003-approval-verifier-boundary.md). Rejected alias: **"host approval"** — anything the proposing MCP host presents is by definition not an approval record and is rejected.

### Audit event
One append-only, versioned envelope recording an operational occurrence: gapless global sequence, event id, recorded timestamp, correlation and proposal references, invocation digest, evidence references, authorization path, redacted judge snapshot when present, redacted payload, and outcome or failure code. Every gate refusal, execution outcome, and unknown completion is one. Authority: the audit contract in `src/ops_guard/audit.py`. Rejected alias: **"log line"** — audit events are structured, sequenced, and required-for-execution, not free text.

### Keyed fingerprint
The truncated keyed HMAC persisted in place of a redacted sensitive value so the same value can be recognized later without being revealed. It is keyed with the operator's persistent audit key. Authority: the audit contract in `src/ops_guard/audit.py`. Rejected alias: **"token fingerprint"** — that phrase is reserved for the rejected idea that a token digest is an invocation identity (see Canonical invocation identity); a keyed fingerprint redacts a value and never identifies an invocation.
