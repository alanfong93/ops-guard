# 0008 — Host-composed proposal MCP contract

- Status: Accepted
- Date: 2026-09-29
- Decided by: plan-loop design (issue #57); implemented with this issue
- Consumers: #58 (audit-only local risk judgment), #61 (Telegram approval transport), #64 (proposal-bound script execution), #65 (judge advisory in proposal response)

## Context

The public service must freeze an agent's proposed operation without becoming another agent or an authorization authority. The repository already defines the canonical `Invocation`, `Citation`, verified runbook resolution, one-time proposal lifecycle, and the 15-minute default selected for this service.

## Decision

`propose_fix` accepts only a complete structured `Invocation` and a `Citation` — exactly two top-level inputs; extra fields are rejected. Before creating anything, the server resolves the citation from its verified `RunbookLibrary` and checks exact equality of the Invocation's runbook revision hash, action, target, and ordered preconditions against the resolved evidence. It then calls the existing proposal service with a server-configured TTL (15 minutes by default via `OPS_GUARD_PROPOSAL_TTL_SECONDS`; absent selects 900 seconds; an explicitly empty, malformed, or non-positive override fails startup; never caller-controlled). The proposal event records the proposal-time Citation in `evidence_refs` atomically with the insert, but that reference does not alter the frozen Invocation digest or approval binding. At execution, the gate independently re-resolves and audits the citation actually used; any locator change within the same verified revision and matching operation/conditions is provenance, not an authorization failure. The audit reference does not authorize execution. The tool returns `IssuedProposal` and reveals the raw token once in that response only. It does not generate a plan, invoke the judge, accept approval, observe preconditions, accept a standing authorization, or execute a script. Repeated valid calls create distinct proposal IDs/tokens; there is no request idempotency key.

Typed tool errors are stable and reveal no token or secret values: `invalid_invocation`, `invalid_citation`, `invocation_evidence_mismatch`, `proposal_write_failed`. Authentication failures remain in the FastMCP transport boundary and never reach the tool handler.

## Rejected alternatives

- A free-text problem request with server-side plan/model generation — ops-guard is not an agent/model host.
- Caller-selected TTL — the proposer must not extend its own capability.
- Proposal creation without a verified citation.
- Binding the exact citation locator into canonical Invocation/approval bytes — ADR 0002 deliberately binds the immutable runbook revision and operation, and a locator-only change does not change the authorized operation.
- Host-supplied approval, observation, standing-authorization, script, or executor fields — would move trust back to the proposing host.

## Consequences

- The caller composes the complete candidate invocation and supplies its evidence citation.
- The audit trail preserves both the citation presented at proposal time and the citation used at execution without creating a second authorization source.
- Later approval and execution tools enforce the remaining independent controls.
- The API response is the existing proposal summary plus one-time token; it is not an approval or authorization decision.
