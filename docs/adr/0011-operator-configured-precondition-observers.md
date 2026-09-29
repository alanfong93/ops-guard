# 0011 — Operator-configured precondition observers

- Status: Accepted
- Date: 2026-09-30
- Decided by: plan-loop design (issue #62); implemented with this issue
- Consumers: #64 (proposal-bound script execution), S7-5 (end-to-end demonstration)

## Context

PRODUCT requires preconditions and source observations to be checked independently of model judgment and not accepted as caller assertions. ADR 0004 makes standing authorization operator-curated and exact. Runbooks are human-verified declarative procedure/evidence records; their verification `verifier` field is an identity, not an authenticated observer. The current gate compares `ExecutionRequest.observed_preconditions` supplied by its caller, and no observer registry exists.

## Decision

Keep runbook preconditions as `{name, expected}`. A local operator-owned policy file maps each exact verified revision and precondition index to one fixed, read-only adapter ID implemented by ops-guard code and its strictly typed, allowlisted settings. Runbooks cannot select commands, URLs, endpoints, credentials, or probe code. Missing or ambiguous mappings refuse execution. The gate obtains a fresh observation through the server registry, compares it exactly with `expected`, and records the observer ID plus canonical policy digest in the audit trail. Standing authorization is loaded from the same operator policy and continues to use ADR 0004's exact complete-invocation match. Policy changes require a server restart; no MCP tool can edit or supply policy or observations.

## Rejected alternatives

- Caller-provided observation strings — they let the proposing host assert the state it must prove.
- Runbook-carried probe descriptors/endpoints — they couple source selection to runbook content and widen the human-verified format.
- Arbitrary shell/HTTP probes — they create a code execution or SSRF surface rather than a fixed observer.
- Deferring all observation — it leaves the current self-asserted gate unusable.

The main residual risk is mapping drift; operator-owned config is therefore strict, versioned by its canonical digest, and recorded per observation.

## Consequences

Each newly verified precondition needs an operator mapping to an implemented observer. An unsupported condition remains non-executable until a trusted source is deliberately added. External state may change after observation; the gate records the snapshot/time but does not claim an atomic lock on other systems. No public MCP/API field carries an observation or standing authorization.
