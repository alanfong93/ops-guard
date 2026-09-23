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
