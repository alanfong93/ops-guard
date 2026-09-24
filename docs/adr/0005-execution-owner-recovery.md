# 0005 — Execution owner recovery

- Status: Accepted
- Date: 2026-09-24
- Decided by: plan-loop design (issue #39); implemented with this issue
- Consumers: #14 (execution gate), #9 (audit recording)

## Context

A committed `execution_start` with no terminal outcome may represent either a crashed process or an operation that is still running in another gate process. A single-instance assumption or elapsed-time threshold cannot distinguish those cases safely. PRODUCT §18 requires an explicitly unknown outcome when completion cannot be confirmed, but a recovery sweep must not mislabel another live gate instance's operation as crashed, and an already-consumed token must never cause automatic re-execution.

## Decision

1. **Owner identity is a random process-instance ID, not a PID.** Each gate process creates a random process-instance ID and holds an OS exclusive lock file named after it in a per-database owner directory, for the process's lifetime. The ID is not a PID, so PID reuse cannot transfer ownership.
2. **The execution-start record names its owner.** The `execution_start` event records the owner ID in the same durable transaction as the token consumption and its audit event (ADR 0002 rule 6).
3. **Liveness is proven by the lock, never inferred.** Recovery probes the owner's lock non-blockingly: a held lock means the owner is alive; successfully acquiring an existing lock is positive evidence that its owner is gone; a missing, inaccessible, or unsupported lock state is indeterminate and must not be treated as dead.
4. **Reconciliation appends one `unknown`, once.** For an execution whose owner is proven dead and which has no terminal outcome, recovery appends exactly one `unknown` terminal event, checking for an existing terminal event in the same SQLite write transaction (so it serializes with ordinary outcome writes). A pre-existing terminal outcome is never overwritten — the audit is insert-only, and reconciliation never writes twice for the same start.
5. **Recovery never re-executes.** No retry, compensation, or replay of the interrupted operation happens during or after recovery.
6. **Lock files outlive their references.** Lock files are not removed while any incomplete start refers to them; this implementation never deletes them.

## Rejected alternatives

- **A singleton-gate-process assumption.** A second live gate could incorrectly classify the first gate's operation as crashed.
- **PID-only checks or age/lease expiry.** They do not prove that the process which owned the operation is gone: PIDs are reused, and an expired lease proves nothing about a slow-but-live owner.

## Consequences

- The lock mechanism must use OS process-lifetime semantics. If the backing filesystem or platform cannot provide that proof, recovery leaves the execution unresolved and reports the indeterminate state.
- Reconciliation is idempotent: repeating a sweep after a successful recovery finds the terminal outcome and appends nothing.
- Tests cover concurrent gate processes, transaction races, and the live/dead/indeterminate/repeat/concurrent-terminal state transitions.
