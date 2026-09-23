# 0003 — Approval verifier boundary

- Status: Accepted
- Date: 2026-09-23
- Decided by: tribunal (binding contract), recorded via issue #12
- Consumers: #14 (execution gate), #9 (audit recording of verification results)

## Context

The proposing MCP host must never manufacture the approval that authorizes its own proposal. PRODUCT requires fresh human approval, bound to the specific proposal, arriving through a channel independent of the proposing host. This ADR fixes the server-internal mechanism that makes that requirement enforceable: an approval verifier port that authenticates configured-operator approval and binds it to the frozen proposal contract ([ADR 0002](0002-frozen-invocation-audit-contract.md)).

## Decision

Adopt the following binding contract for the approval verifier.

1. **Internal port only.** Approval recording and verification are server-internal capabilities. No MCP tool exposes them; the proposing host can never present an approval claim that the verifier would consult. Verification consults only approvals recorded on the verifier-internal operator path by the configured operator identity.
2. **Binding.** A recorded approval binds the proposal's token digest, proposal id, invocation digest, runbook revision hash, and the proposal's absolute expiry — the digests and expiry are copied from the frozen proposal at record time and re-checked against the live proposal at verification time. Divergence in any bound field is a mismatch and fails closed.
3. **One approval per proposal.** The approval store keys on the token digest (the raw token is never stored — ADR 0002 rule 3). A second recording for the same proposal is rejected; approval cannot be re-manufactured or overwritten. A correction is a new proposal with its own approval.
4. **Single use.** An approval transitions `recorded → used` exactly once. The transition is a compare-and-swap that must join the token-consumption transaction (ADR 0002 rule 6), so an approval is spent exactly when its proposal token is consumed. Verification after that transition is a replay and fails closed.
5. **Deterministic rejection order.** Host-supplied (no recorded approval for the presented token digest) → operator mismatch → replayed (approval already used) → proposal terminal (consumed or expired, per ADR 0002) → binding mismatch. Every verification produces a structured outcome the audit layer (#9) can record; there is no silent path.
6. **Verification is read-only.** `verify` changes no state; the authoritative transition happens only inside the consumption transaction. Verification of an unexpired, recorded, unused approval is advisory until the gate consumes the token.
7. **Required verification.** Tests must prove: only a verifier-recorded configured-operator approval authorizes its bound unexpired proposal; host-supplied, operator-mismatched, expired, replayed, and consumed attempts fail closed with typed rejections; the approval flip and the token consumption commit or roll back atomically.

## Rejected alternatives

- **Host-supplied approval claims** (the host signing or asserting approval). The proposing agent would be able to manufacture the permission the gate exists to require — the exact failure PRODUCT forbids.
- **Keying approvals on the raw token.** Raw tokens are never persisted; approvals key on the keyed digest like every other stored reference.
- **Mutable approvals (re-approval overwrites the record).** Binding requires immutability; a changed approval must mean a new proposal.
- **`verify` consuming the approval.** The consume belongs to the gate's atomic unit (#14); a verify-side transition would split the audit pairing.

## Consequences

- The gate (#14) composes `verify` + token CAS + approval flip + audit append in one transaction.
- The operator identity is a configured single-operator value; multi-operator policy is out of scope (PRODUCT boundary).
- Approval transport (how the operator's yes reaches the internal path) is out of scope here; the port consumes an already-authenticated operator identity.
