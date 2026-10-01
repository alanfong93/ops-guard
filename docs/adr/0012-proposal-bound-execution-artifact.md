# 0012 — Proposal-bound execution artifact

- Status: Accepted
- Date: 2026-09-30
- Decided by: plan-loop design (issue #64); implemented with this issue
- Consumers: S7-5 end-to-end demonstration; amends ADR 0003 and ADR 0004

## Context

ADR 0002 freezes action, target, arguments, preconditions and runbook revision, but not script identity. ADR 0003 binds fresh approval to that invocation, not to a later `ExecutionRequest.script_path`. ADR 0004 binds path/hash only for standing authorization. The gate hashes operator-source bytes, then passes them to an injected executor; the proposal-bound path does not compare that hash with what the operator approved.

## Decision

The server resolves one immutable **ExecutionBinding** per proposal: after the `propose_fix` handler validates the Invocation/Citation, the operator-owned execution catalog (keyed by exact verified runbook id/revision/content hash plus action/target) maps the key to exactly one local script id/path and expected SHA-256 — zero or ambiguous matches fail before a token exists. The binding records proposal id, invocation digest, verified runbook revision, script id/path/hash, catalog-entry digest, runner-profile id/digest, and a canonical binding digest; it persists with the proposal row and audit event in one SQLite transaction (no script bytes stored). A missing or failed resolution creates no token.

The Telegram preview shows the invocation plus the bound script path/hash and runner-profile identity/digest; the approval binds `execution_binding_digest` alongside its existing fields — a changed binding, catalog entry, script hash, or runner profile invalidates the pending approval. Standing authorization additionally binds the current runner-profile digest; a profile change invalidates standing matches until the operator reissues the affected rules. No wildcard or partial match is introduced.

`execute_fix` accepts a token and verified Citation only — no script path, bytes, id, runner, standing record, operator identity, or observed preconditions from the host. The gate re-resolves the citation, loads the immutable binding, verifies catalog/profile/source digests, stages the operator-source bytes into a per-execution private temporary file (hash re-verified on the staged copy; never reopens the original path), and dispatches the staged copy through the operator-configured runner profile — explicit argv with `shell=False`, canonical JCS Invocation JSON on stdin, no inherited host environment beyond the allowlist, bounded stdout/stderr, bounded child-process timeout with process-tree termination. Timeouts and uncertain completions map to `unknown` (ADR 0005); there is no automatic retry. Temporary directories are removed on ordinary exits; crash leftovers are cleaned only after owner death is proven.

## Rejected alternatives

- Host-visible script ids/paths/bytes or a runner chosen by the agent — the host must never select what executes.
- Model-created scripts or publishing private operator scripts.
- `shell=True` or arbitrary command/endpoint execution — a code-execution surface, not an observer.
- Per-script runner profiles in v1 — one operator-controlled profile per service suffices until evidence shows otherwise.
- Automatic retry or re-execution after timeout/unknown.

## Consequences

The public `propose_fix` input/output and the canonical Invocation are unchanged; the binding is a server-internal sidecar. Legacy proposals without a binding cannot dispatch through the new path. The operator sees script path/hash/profile in the approval message but never receives script bytes or the raw proposal token. Claiming an OS sandbox against independent host-level access remains out of scope (PRODUCT boundary).

## Amendment (2026-09-30, review cycle 4 of issue #64)

If a descendant inherits the staged runner's stdio pipes and outlives the direct child, the runner detects the still-open pipes after the direct child exits, terminates the tree, and reports the explicitly `unknown` outcome with no failure code. On Windows the tree kill targets the (already exited) direct child PID, so a pipe-holding grandchild may be orphaned until it exits on its own; the outcome remains `unknown` and nothing is dispatched or re-run. POSIX `killpg` (the child runs in its own session) reaches the whole group.

A follow-up review probe (cycle 4) showed that on Windows a grandchild spawned by the staged script may not deterministically inherit the runner's stdio pipe handles, in which case the pipe-holding detection sees EOF and the direct child's clean exit is reported as `success` while an orphan continues briefly. The still-open-pipe safety net remains for platforms where the handles are inherited (POSIX). On Windows the outcome contract for this corner is therefore best-effort: scripts that spawn detached descendants should manage their own lifetime, and the gate records the direct child's exit honestly.

Windows staging correction (cycle 4 of issue #64): the staged child is assigned to a kill-on-close Job Object (stdlib ctypes, no new dependency) at spawn. On every return path — timeout, output overflow, still-open pipes after a clean child exit — the job is terminated or closed, which ends every descendant in it. The still-open-pipe detection maps a pipe-holding descendant to the explicitly `unknown` outcome; the earlier best-effort language about non-inherited handles no longer applies on Windows. The audited `failure_code` follows the return path, not the outcome: a timeout audits `executor-timeout`, a spawn failure — an unspawnable executable or a failed containment arm — audits `spawn-failure`, an internal runner error after a successful spawn audits `executor-error`, and a still-open descendant audits no failure code (`None`) — unless an output overflow coincided, in which case it audits `output-limit`.

Containment hardening (cycle 6 review of issue #64): the staged child on Windows is created suspended (`CREATE_SUSPENDED`) and its initial thread resumed only after the Job Object is armed, so no descendant can be created outside the job — there is no arming race. If the job cannot be armed (creation, limit assignment, or resume failure), the runner kills the child and reports the explicitly `unknown` outcome with `spawn-failure`: containment failure is fail-closed, never a silent best-effort `success`. Every return path also waits, bounded at 5 seconds, for the job to report zero active processes (on POSIX, for the process group to die) before returning, so no contained descendant outlives the outcome the caller observes; a failed drain query degrades to the bounded wait without changing the outcome.
