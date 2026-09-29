# API Reference

ops-guard exposes its capabilities as MCP tools. This document is the
authoritative surface specification; each tool links to the contract that
defines its semantics.

## Transport and authentication

`python -m ops_guard` serves the tool surface over MCP Streamable HTTP with
native Uvicorn TLS at the configured LAN endpoint ([ADR 0006](adr/0006-lan-mcp-transport.md)):

- **Endpoint** — `https://<bind-host>:<port>/mcp` (Streamable HTTP). The
  operator provisions a certificate whose SAN matches the client URL and
  configures client trust; an invalid or missing certificate/key pair
  prevents startup.
- **Authentication** — a static high-entropy bearer token from
  `OPS_GUARD_HTTP_BEARER_TOKEN` (≥ 32 characters), compared in constant
  time by a custom FastMCP `TokenVerifier` (`src/ops_guard/service.py`).
  Missing, wrong, or absent tokens are rejected before any tool executes.
  The token is transport authentication only — it is not proposal-bound
  approval or execution authorization.
- **Host/Origin protection** — FastMCP `host_origin_protection` runs in
  strict mode with the `OPS_GUARD_ALLOWED_HOSTS` and
  `OPS_GUARD_ALLOWED_ORIGINS` allowlists. A disallowed Host header (HTTP
  421) or Origin header (HTTP 403) is rejected before the MCP endpoint.
- **Fail-closed recording boundary** — as with the tool contract below,
  every rejection happens before any result is returned: no rejected
  request can obtain a result, logged or unlogged.
- **Configuration** — all environment variables from
  [ADR 0006's environment contract](adr/0006-lan-mcp-transport.md) are
  required; a missing, empty, or invalid value exits before a listener
  opens, naming the variable and never a secret value.

## Tools

### `search_runbook`

Cited runbook guidance. Every successful result identifies one exact
human-verified passage, bound to the revision content hash it was verified
against. Unverified, tampered, or malformed revisions are excluded at load
time and never appear as evidence. Contract: [runbook format](runbook-format.md);
implementation: `src/ops_guard/retrieval.py`.

- **Input**
  - `question` (string, required) — non-empty natural-language query.
  - `limit` (integer, optional, default 5, minimum 1) — maximum results.
- **Result** — list (possibly empty) of evidence objects:
  - `runbook_id` (string)
  - `revision` (string)
  - `content_hash` (string, 64-hex) — the revision this citation is bound to
  - `locator` (string)
  - `passage_text` (string)
  - `operation` — `{action, target}`
  - `preconditions` — list of `{name, expected}`
  - `verification` — `{verifier, verified_at, applicability}`

No execution, authorization, or judgment is exposed through this tool.

### `propose_fix`

Freeze a host-composed operation into an audited proposal with a one-time
token. Contract: [ADR 0008](adr/0008-host-composed-proposal-mcp-contract.md);
implementation: `src/ops_guard/proposal_tool.py`. The request has exactly two
top-level inputs; extra fields are rejected.

- **Input**
  - `invocation` (object, required) — the complete structured invocation:
    - `action` (string), `target` (string)
    - `arguments` (object, JSON mapping)
    - `preconditions` (array of `{name, expected}` objects, order significant)
    - `runbook_revision_hash` (string)
  - `citation` (object, required) — evidence reference:
    - `runbook_id` (string), `revision` (string)
    - `content_hash` (string), `locator` (string)

  No free-text problem, `ttl`, approval, standing authorization, observed
  preconditions, script path/bytes, executor, or operator identity is
  accepted at any nesting level.

- **Validation, before any proposal exists** — the server resolves the
  citation through its configured verified `RunbookLibrary` (never a
  caller-supplied document) and requires: the citation resolves to a
  verified revision; `invocation.runbook_revision_hash` equals its
  `content_hash`; `action` and `target` equal the cited revision's
  operation; the full ordered precondition sequence canonically equals the
  cited revision's preconditions. A citation may name any verified
  immutable revision in the configured library; there is no
  "latest revision" concept.

- **Result** — the `IssuedProposal` shape on success:
  - `proposal_id` (string)
  - `invocation_digest` (string) — SHA-256 of the frozen canonical invocation
  - `expires_at` (string, timezone-aware ISO-8601) — computed by the
    proposal service's clock from the server-configured TTL (15 minutes by
    default; `OPS_GUARD_PROPOSAL_TTL_SECONDS` operator override; never
    caller-controlled)
  - `token` (string) — the raw one-time execution token, revealed in this
    response only; never stored or logged (proposals store an HMAC digest)

  Repeated valid calls create distinct proposals; there is no request
  idempotency key, so clients must not retry blindly after an ambiguous
  response.

- **Typed errors** (stable codes prefix the message; text contains no token
  or secret values; every failure happens before `open_proposal` except
  `proposal_write_failed`):
  - `invalid_invocation` — the invocation is not a well-formed complete
    invocation (shape, types, non-serializable values).
  - `invalid_citation` — malformed, unverified, tampered, or unknown-locator
    citation; the citation does not resolve to a verified revision.
  - `invocation_evidence_mismatch` — the invocation's revision hash, action,
    target, or ordered preconditions differ from the resolved evidence.
  - `proposal_write_failed` — proposal persistence or its audit append
    failed; no proposal row, event, or token exists.

- **Evidence provenance** — the proposal audit event records the
  proposal-time citation (`runbook_id@revision`, `content_hash`, `locator`)
  as its `evidence_refs` in the same insert transaction. This is provenance
  only: it is not part of the frozen invocation digest, not an approval
  binding, and never an authorization input. At execution the gate
  independently re-resolves the citation actually used against the same
  frozen revision/action/target/preconditions and audits it; a different
  valid locator in the same revision is provenance, not an authorization
  failure. Comparing the proposal and execution audit references makes any
  locator difference visible.

- **Advisory judgment (audit-only)** — every `propose_fix` call also records
  a local risk judgment on the proposal audit event
  ([ADR 0009](adr/0009-local-advisory-judge-audit-projection.md)): a closed
  `ops-guard-risk-projection-v1` projection (risk class from the fixed
  `routine`/`review`/`critical` menu, vote share, repeated-sample agreement,
  versions, fixed inference settings, model/trace identity, citation
  references, request fingerprint) or one closed typed failure
  (`judge_unavailable`, `judge_timeout`, `judge_inability`,
  `judge_invalid_output`, `judge_input_rejected`, `judge_error`). The
  judgment is **not returned in this response** and never influences
  proposal issuance, authorization, or execution. A judge failure never
  blocks proposal creation.

### Search recording

For every valid `search_runbook` call, before any result is returned, two
audit events are appended atomically (one transaction, one shared
`correlation_id`):

- **`request`** — `payload`:
  - `question_fingerprint` — keyed HMAC-SHA-256 prefix (16 hex characters)
    over the canonicalized question. The raw question text is never stored;
    the search question is free text and may contain credentials or personal
    data.
  - `limit` — the requested maximum result count.
- **`guidance`** — `payload`:
  - `results` — list of `{runbook_id, revision, content_hash, locator,
    operation: {action, target}}`, one entry per returned hit. With the cited
    content hash these references reconstruct the exact returned guidance
    from the verified revision; the passage body is not duplicated.

Recording is fail-closed: if either event cannot persist, the search fails
with `AuditWriteFailure` and no result is returned unlogged. Invalid input
(empty question, `limit` below 1) is rejected before any event is written;
no attempt events exist for rejected input.

## Proposal creation recording

`open_proposal` appends one **`proposal`** event in the same transaction as
the frozen-proposal insert, before the one-time token is returned:

- `payload` — `proposal_id`, `invocation_digest`, `expires_at`. The raw
  one-time token is never stored.
- `correlation_id` — the proposal's own id.

If the append cannot persist, the transaction rolls back: no proposal row is
created and no token is returned.

## Audit events

All audit events are insert-only, versioned, and written to the authoritative
audit store — the same SQLite database that holds proposal and approval state
(the one-database boundary is validated when the proposal service and the
execution gate are constructed). Payloads are redacted at write time: values
under sensitive keys are replaced by an explicit marker plus a keyed
fingerprint. The event envelope (`sequence`, `event_id`, `schema_version`,
`recorded_at`, event type, `correlation_id`, references, payload, outcome) is
defined by the audit contract; the interaction-specific events are:

| Event | When | Payload beyond the envelope |
|---|---|---|
| `request` | valid search, before results | `question_fingerprint`, `limit` |
| `guidance` | valid search, same transaction as `request` | `results` (reconstructible references) |
| `proposal` | proposal creation, same transaction as the insert | `proposal_id`, `invocation_digest`, `expires_at` |
| `execution_start` | gate dispatch, same transaction as token consumption | phase, script path + hash, evidence refs |
| `execution_outcome` | after the executor returns | outcome (`success`/`failure`/`unknown`) |
| `refusal` | every failed gate check, before any side effect | reason, gate |
