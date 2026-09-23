# Runbook revision format — the cited-evidence contract

A runbook revision is an immutable, human-verified JSON document. It is the
only source of *required procedural evidence*: a cited passage qualifies
solely when it is bound to a revision that (a) parses to the exact canonical
shape, (b) carries human-verification metadata, (c) whose content hash
recomputes exactly, and (d) contains the cited locator. Incomplete or
unverified guidance can never qualify. Retrieval ranking and MCP tools are
out of scope here.

## Canonical revision shape

Exactly these keys, no others:

```json
{
  "runbook_id": "n8n-restart",
  "revision": "2026-09-23.1",
  "operation": {"action": "restart", "target": "n8n"},
  "preconditions": [{"name": "healthcheck", "expected": "passing"}],
  "passages": [
    {"locator": "restart/steps", "text": "cd ~/stack && docker compose restart n8n, then poll /healthz until 200."}
  ],
  "verification": {
    "verifier": "alan",
    "verified_at": "2026-09-23T09:00:00.000000+00:00",
    "applicability": "alan's self-hosted docker host"
  },
  "content_hash": "<sha256 hex>"
}
```

- `runbook_id`, `revision` — non-empty strings; together they name the revision.
- `operation` — the single operation this revision evidences: non-empty `action` and `target` strings.
- `preconditions` — list of `{name, expected}` objects with non-empty string fields; may be empty.
- `passages` — non-empty list; `locator`s are unique non-empty strings; `text` is non-empty.
- `verification` — non-empty `verifier`, timezone-aware `verified_at`, non-empty `applicability`. Absent or blank verification means the revision is not human-verified and can never qualify.
- `content_hash` — SHA-256 hex of the JCS (RFC 8785) canonicalization of the revision document **without** the `content_hash` key: the hash binds the **literal document as stored**. Any change to any other field — including timestamp spelling — changes the hash.

**Trust boundary.** Verification metadata is operator-curated and unauthenticated: the `verifier` string records who reviewed the procedure, and whoever can write a revision into the store holds the authority to certify evidence. The execution gate (#14) binds proposals to the revision content hash; the store's write path is the control point.

## Citations

A citation is `{runbook_id, revision, content_hash, locator}`. Resolution is
all-or-nothing; every failure below is a typed rejection:

1. The named revision must parse to the canonical shape — otherwise malformed.
2. `verification` must be present and complete — otherwise unverified.
3. `content_hash` must equal the recomputed hash of the stored revision — otherwise tampered: **a changed hash voids the citation for execution purposes.**
4. The `locator` must exist in that revision — otherwise unknown passage.

A resolved citation identifies the operation and its preconditions (the
revision's `operation` and `preconditions`) plus the exact passage text at
`locator`. That triple — passage, operation, conditions — is what "required
procedural evidence" means downstream.
