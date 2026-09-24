# API Reference

ops-guard exposes its capabilities as MCP tools. This document is the
authoritative surface specification; each tool links to the contract that
defines its semantics.

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
