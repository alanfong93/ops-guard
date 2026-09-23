# 0004 — Exact complete-invocation standing authorization

- Status: Accepted
- Date: 2026-09-23
- Decided by: tribunal (binding contract), recorded via issue #13
- Consumers: #14 (execution gate), #16 (demonstration)

## Context

Standing authorization lets an invocation run unattended, so it must never generalize. PRODUCT binds standing authorization to the verified script and the complete permitted invocation — action, target, arguments, and preconditions. The design question this ADR settles is how matching behaves at the boundary: what the authorization record binds, and what happens when anything differs.

## Decision

1. **The authorization record declares the complete permitted invocation.** A standing authorization binds, as exact literal values: the verified script identity (path and SHA-256 of the script bytes), the action, the target, the typed arguments, the preconditions, and the runbook revision content hash it draws procedural evidence from. All fields are mandatory; an authorization with a missing field is malformed and never matches.
2. **Matching is all-or-nothing equality.** Every field must equal the corresponding field of the frozen invocation (and the presented script identity). Comparison is over canonical JSON values: `1` and `1.0` are the same value; precondition sequence order is significant (ADR 0002 rule 1). One result object reports matched or not, with the first differing field as the reason.
3. **Missing or unequal fields never match.** There are no defaults, no fallbacks, no partial credit.
4. **No wildcards, no prefixes, no templates.** Wildcard or partial matching would let one rule cover invocations the operator never enumerated, which is precisely the generalization standing authorization exists to avoid. A new invocation shape requires a new authorization the operator writes.

## Rejected alternatives

- **Wildcards or glob patterns in any field.** One rule would silently cover an open set of invocations; the operator would authorize a pattern while believing they authorized a case.
- **Partial matching (subset of arguments or preconditions).** A proposal could add arguments the operator never permitted.
- **Matching on invocation digest alone.** The digest is computed from the proposal; authorizations are written before proposals exist. Field equality against the declared permitted invocation is the operator-authorable form.
- **Model judgment in the match.** Judge advice is advisory and never grants authorization (PRODUCT constraint); the match is deterministic equality.

## Consequences

- The gate (#14) composes: standing-authorization match or proposal-bound approval verification (#12), then token consumption with audit pairing (ADR 0002 rule 6).
- The script identity is presented by the caller that intends to execute; #14 resolves the script and passes its path and content hash. A mismatch fails closed here.
- The gate also resolves the authorization's `runbook_revision_hash` against the runbook store — `parse_revision` recomputes the content hash — before trusting a match. A hash with no verified, human-reviewed revision behind it never grants unattended execution, even when every field equality holds.
- Authorization records are operator-curated configuration, like runbook verification metadata: unauthenticated data whose authority comes from the operator's control of the configuration store.
- Permitted invocations obey the same numeric freeze contract as real invocations: an authorization declaring an integer that is not exactly representable as an IEEE-754 double is malformed and never loads.
