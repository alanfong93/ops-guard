# 0002 — Frozen invocation, one-time token, and audit-transaction contract

- Status: Accepted
- Date: 2026-09-22
- Decided by: tribunal (binding contract), recorded via issue #10
- Consumers: #12 (approval verification), #13 (standing authorization), #14 (execution gate), #9 (audit recording)

## Context

Proposal-bound approval is meaningful only when it binds the exact invocation, expires predictably, and cannot be replayed or consumed twice. The proposing MCP host must never be able to alter a proposal after approval, extend its life, or redeem its token a second time. The execution gate (#14) must also be able to consume the token and append the execution-start audit record (#9) as one all-or-nothing step, so a crash can never leave an execution that is authorized but unrecorded, or recorded but unauthorized.

## Decision

Adopt the following binding contract for the proposal lifecycle.

1. **Canonical invocation identity.** The complete invocation — action, target, typed arguments, preconditions, and runbook revision content hash — is serialized with JCS (RFC 8785) and identified by the SHA-256 digest of those canonical bytes. Any difference in any bound field yields a different identity. Sequence order inside the invocation is significant; callers must sort unordered collections before freezing.
2. **Frozen bytes are immutable.** Creating a proposal persists the canonical invocation bytes and their digest. There is no update path. A correction creates a new proposal; the original is never mutated or deleted.
3. **Opaque one-time token.** Creation mints a 256-bit token from a cryptographically secure random generator and returns it exactly once. Only an HMAC-SHA-256 keyed digest of the token is stored; the raw token is never persisted. The key is an operator-configured secret.
4. **Absolute expiry.** The expiry timestamp is fixed at creation. There is no extension and no sliding window. A token is eligible only while its proposal is unconsumed and the current time is strictly before the expiry.
5. **Exactly-once consumption.** Consumption is a compare-and-swap transition of the proposal into a terminal consumed state. Exactly one eligible attempt commits; every other concurrent attempt fails. Unknown, expired, mismatched, and already-consumed tokens are rejected before any execution or side effect. A caller may present an expected invocation digest; a mismatch is rejected.
6. **Audit-transaction pairing.** Token consumption and the pre-execution audit append must commit in a single durable transaction. Partial commit — consumed without audit, or audit without consumption — is forbidden. (The audit writer itself is delivered by #9; this contract fixes the pairing requirement.)
7. **Required verification.** Property-based tests must prove: exactly-once consumption under concurrency; the expiry boundary (eligible strictly before expiry, rejected at and after it); canonical serialization stability; and crash boundaries — no half-committed proposal, half-consumed token, or consumed-without-audit state survives a crash.

## Rejected alternatives

- **Persisting raw tokens, or sequential/guessable token ids.** A storage leak would become a replay capability; only a keyed digest may be stored.
- **Mutable proposal rows (edit-in-place, supersede flags).** Approval binds to frozen bytes; any mutation breaks what the approval proved. Corrections are new proposals.
- **Sliding or extendable expiry.** Expiry must not be influenceable after creation.
- **Check-then-set consumption without compare-and-swap.** Two concurrent attempts could both observe eligibility and both execute.
- **Ad-hoc JSON serialization instead of JCS.** Non-canonical serialization makes the same invocation produce different digests (binding fails spuriously) or, worse, lets differing invocations collide on one digest (binding fails open).

## Consequences

- Consumers (#12, #13, #14) bind to the invocation digest, not to a proposal id or human-readable description.
- Matching is all-or-nothing by design: no partial invocation match exists (#13 requires missing or unequal fields never to match).
- Storage must support durable transactions; an embedded transactional store (SQLite) satisfies this contract.
- The token is a capability handle for one specific frozen invocation. It is not itself authorization; authorization is verified separately (#12, #13).
