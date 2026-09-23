# CONTEXT

The authoritative glossary for ops-guard terms. Product terms derive from `docs/PRODUCT.md`, `README.md`, `docs/architecture.md`, and `docs/system_flow.md`; contract terms link to their ADR. Rejected aliases are recorded only where they create a dangerous ambiguity — do not use them in docs, issues, code, or review.

## Terms

### Human-verified runbook
A runbook revision whose verification metadata names the operator who reviewed it and when; only such revisions are sources of procedural evidence. The metadata is operator-curated and unauthenticated — write access to the revision store is the certification authority, not a cryptographic attestation. Authority: [runbook format](docs/runbook-format.md); constraint: `docs/PRODUCT.md` ("Return cited runbook guidance; absent required procedural evidence, refuse execution"). Rejected alias: **"trusted doc"** — trust attaches to the verified revision and its content hash, not to a document; **"attested revision"** — nothing is signed.

### Required procedural evidence
A cited passage from a human-verified runbook revision, bound to an unchanged content hash, that identifies the intended operation and its preconditions. Without it, fresh approval alone is not enough to execute. Authority: [runbook format](docs/runbook-format.md); constraint: `docs/PRODUCT.md` ("Return cited runbook guidance; absent required procedural evidence, refuse execution"). Rejected alias: **"context"** — retrieved text that does not resolve as a citation is context, never evidence.

### Standing authorization
An operator-authored record of the complete permitted invocation — verified script identity, action, target, typed arguments, preconditions, runbook revision hash — matched as exact equality. Matching invocations may run unattended. The script identity's "verified" is a runtime path-and-SHA-256 match at the gate, not human review; human verification attaches to runbook revisions only. Authority: [ADR 0004](docs/adr/0004-exact-standing-authorization.md); constraint: `docs/PRODUCT.md` ("Bind standing authorization to the verified script and complete permitted invocation"). Rejected aliases: **"standing policy"** and **"policy"** — a policy implies a set of acceptable invocations; a standing authorization permits exactly one. **"auto-approve rule"** — nothing is auto-approved; a matching invocation has already been individually authorized by the operator's record. **"Standing approval"** — approval is single-use and proposal-bound; standing authorization is neither, and calling it an approval conflates the two authorization paths.

### Complete permitted invocation
The exact invocation a standing authorization declares: every field mandatory, no wildcards, no partial matches, sequence order significant. Authority: [ADR 0004](docs/adr/0004-exact-standing-authorization.md). Rejected alias: **"profile"** — a profile implies a set of acceptable invocations; a standing authorization permits exactly one.

### Proposal-bound approval
A one-time permission from the configured operator through an approval channel independent of the proposing MCP host. It binds the frozen proposal and expiry and is consumed atomically — spent exactly when the proposal's token is consumed. The proposing host cannot supply it. Authority: [ADR 0003](docs/adr/0003-approval-verifier-boundary.md); constraint: `docs/PRODUCT.md`. The mechanism is the approval record (see below). Rejected alias: **"user consent"** — consent framing hides the binding, independence, and single-use requirements.

### Declared baseline
The named retrieval comparator and assessment method recorded with a published retrieval result, declared before measuring and never tuned after. Authority: [retrieval evaluation](docs/retrieval-evaluation.md); constraint: `docs/PRODUCT.md` ("Publish retrieval-quality evidence against a declared baseline"). The dataset 1.0.0 declared baseline is the document-order ranking; the comparator is the #11 keyword search.

### Judge advisory signal
An estimate attached to a judge risk assessment. Its meaning and derivation are recorded with the audit event; it never grants, withdraws, or substitutes for authorization, is not evidence that the assessment is correct, and judge unavailability does not grant authorization. Authority: `docs/PRODUCT.md`. Rejected alias: **"safety score"** — the signal is not a safety guarantee and must never read as one.

### Observed outcome
The execution result recorded after the operation: success, failure, or an explicitly unknown completion when the result cannot be confirmed. Authority: [execution demonstration](docs/execution-demonstration.md); constraint: `docs/PRODUCT.md`. Rejected alias: **"result"** unqualified — an unconfirmed completion must be recorded as unknown, not silently treated as success.

### Audit record
The product word for an **audit event** (same artifact — one append-only, versioned envelope: gapless sequence, event id, timestamp, references, redacted payload, outcome or failure code; see Audit event below). Required records must persist or execution is refused. Authority: the audit contract in `src/ops_guard/audit.py`; constraint: `docs/PRODUCT.md` ("Keep append-only durable audit records ... Refuse execution if required audit recording fails"). Rejected alias: **"log entry"** — audit records are structured, sequenced, and required-for-execution, not free-form lines.

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

### Runbook revision
The immutable, human-verified unit of procedural evidence: one operation, its preconditions, its passages, and verification metadata, identified by a content hash that must recompute exactly. Authority: [runbook format](docs/runbook-format.md). Rejected alias: **"the runbook"** — loose speech for a living document; only an immutable revision can back a citation.

### Citation
A reference binding one passage locator to one runbook revision content hash. It qualifies as required procedural evidence only when the revision is verified and unchanged. Authority: [runbook format](docs/runbook-format.md). Rejected alias: **"quote"** — a quotation without revision binding drifts when the document changes and is not evidence.

### Comparator
The retrieval ranker declared before an assessment runs — currently the #11 keyword scoring. It is frozen while a dataset is measured; changing it after seeing results is tuning-to-the-test. Authority: [retrieval evaluation](docs/retrieval-evaluation.md). Rejected alias: **"the retriever"** — the comparator is the evaluated ranker under a declared protocol, not the production retrieval subsystem as a whole.

### Document-order baseline
The declared no-relevance ranking (fixed dataset order) against which a comparator must outperform. It deliberately ignores the question. Authority: [retrieval evaluation](docs/retrieval-evaluation.md). Rejected alias: **"random baseline"** — the declared baseline is deterministic and reproducible, not stochastic.

### Top-1 citation correctness
The only retrieval metric: the single returned result must carry the expected runbook id and locator, bound to the expected revision content hash. Answer plausibility is never scored. Authority: [retrieval evaluation](docs/retrieval-evaluation.md). Rejected alias: **"accuracy"** — unqualified accuracy invites plausibility scoring, which the metric exists to avoid.
