# 0013 — Delegated vs personal verification is a documented string convention, not a schema field

Date: 2026-10-01
Status: accepted
Supersedes: none
Related: ADR 0007 (public runbooks, operator-local scripts), runbook format (docs/runbook-format.md), CONTEXT.md

## Context

Issue #55's public corpus was content-reviewed by a delegated agent tribunal while the operator was AFK (ADR 0007). The only machine-readable record of that delegation is the free-text `verification.verifier` string ("agent-tribunal review (delegated by alan, 2026-09-29)"). The format doc defined a human-verified runbook as one that "names the operator who reviewed it and when", which a delegated review strains; and downstream readers could not mechanically distinguish a personal verification from a delegated one, or ratified from un-ratified (issue #67).

## Decision

The distinction is first-class in the documentation, not in the schema:

- The `verifier` string grammar is pinned in docs/runbook-format.md — **personal**: the operator names themselves (`alan`); **delegated**: `<delegate> review (delegated by <operator>, <date>)`. The literal marker `delegated by ` is the mechanical distinguisher.
- **Ratification** is defined as a superseding revision whose verifier is personal — always a new immutable revision with a new content hash, never an edit of the delegated revision and never a separate field. A veto is the same mechanism with replaced content.
- CONTEXT.md gains the terms *delegated verification* and *ratification* with their rejected aliases.
- The #55 corpus already conforms to the pinned grammar and is unchanged: rewriting its `verifier` strings would change the revisions' content hashes and invalidate every citation bound to them, for zero informational gain.

## Alternatives considered

- **Schema fields** (`authority: personal | delegated`, `ratified_at`/`ratified_by`): rejected for now. Format and parser changes are deliberate non-goals; no downstream reader (observers #62, authorization binding #64) branches on verifier identity — the gate binds to content hashes, not to who verified. Revisit if a consumer needs to mechanically filter on verification authority, e.g. a policy that refuses delegated revisions for some class of operations. That consumer is the trigger to re-open this.
- **Convention-only, undocumented** (ratification = superseding personal revision, nothing written down): rejected — an unwritten convention is not mechanically discoverable by a reader and would drift.

## Consequences

- A reader (human or machine) distinguishes personal / delegated / ratified / un-ratified by string inspection under a pinned grammar, with zero parser change.
- The unauthenticated nature of verification metadata is unchanged (docs/runbook-format.md trust boundary): the marker records authority honestly but is a curation signal, never an execution key. Execution still requires standing authorization (ADR 0004) or proposal-bound approval (ADR 0003).
- The loader-side scrub enforcement and generalized scrub patterns surfaced by the #66 reviews remain corpus-scoped test tripwires; they are verification-hygiene concerns, not part of this distinction, and can be filed separately if the corpus grows.
