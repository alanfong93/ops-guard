# Execution demonstration — permitted and refused paths (issue #16)

Reproducible run: `.venv/Scripts/python.exe demonstrations/execution_demo.py`
(the script prints this trace; `tests/test_demonstration.py` pins it). The
demonstration drives the real proposal lifecycle, approval verifier, audit
log, and execution gate over one shared database — no mocks on the trust
path. The executor is a stub that records it was called; it represents the
side effect boundary.

## Scenario trace

| Scenario | Dispatched | Path | Executor invocations | Outcome |
|---|---|---|---|---|
| standing-authorization-success | yes | standing | 1 | success |
| independent-approval-success | yes | proposal-bound | 1 | success |
| missing-evidence-refusal | no | — | 0 | refused |
| stale-evidence-refusal | no | — | 0 | refused |
| failed-precondition-refusal | no | — | 0 | refused |
| invalid-token-refusal | no | — | 0 | refused |
| expired-token-refusal | no | — | 0 | refused |
| audit-write-refusal | no | — | 0 | refused |
| reused-token-first-dispatch | yes | standing | 1 | success |
| reused-token-refusal | no | — | 0 | refused |
| unknown-outcome | yes | standing | 1 | unknown |

Total executor invocations: 4 — one per permitted dispatch, zero for any
refusal. The audit log holds 15 ordered events: `execution_start` /
`execution_outcome` pairs for each permitted dispatch (the unknown completion
recorded explicitly as `outcome="unknown"`), interleaved with a `refusal`
event for every failed check.

## What each refusal proves

- **missing-evidence** — an absent runbook document refuses at the evidence
  step; nothing is resolved, nothing consumed.
- **stale-evidence** — a different, self-consistent, human-verified revision
  than the one the proposal froze refuses at the revision binding: the
  citation's content hash must equal the frozen invocation's
  `runbook_revision_hash`.
- **failed-precondition** — an observed precondition that contradicts the
  frozen invocation's requirement refuses before dispatch.
- **invalid-token / expired-token** — unknown and expired proposals refuse
  with typed lifecycle rejections.
- **audit-write** — a failing execution-start audit append rolls back the
  token consumption in the same transaction: the token stays eligible
  (nothing ran, nothing is spent).
- **reused-token** — the second dispatch of a consumed token refuses at the
  lifecycle check; the first dispatch's executor invocation is not repeated.

## Known residuals (documented, not demonstrated)

- On the proposal-bound path, `request.script` is recorded as supplied; the
  MCP layer must verify the executed script against it (#14 handoff).
- If the audit store dies after dispatch, the outcome record cannot be
  written (the execution-start record is durable; the gap is documented in
  the gate).
