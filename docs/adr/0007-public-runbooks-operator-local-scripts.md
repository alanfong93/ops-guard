# 0007 — Public runbooks and operator-local scripts

- Status: Accepted
- Date: 2026-09-29
- Decided by: plan-loop design (issue #55); first content review by delegated agent tribunal (2026-09-29), pending operator ratification
- Consumers: #62 (standing-authorization preconditions), #64 (proposal-bound script execution)

## Context

ops-guard is a public trust layer. PRODUCT requires cited, human-verified procedures, while ADR 0004 binds standing authorization to each operator's exact script path and SHA-256. The selected starter procedures come from the operator's n8n/OpenWebUI guidance; their real executable scripts and paths are local. The repository has no chosen LICENSE.

## Decision

Publish scrubbed procedure/evidence JSON only. Operators supply and authorize their exact executable bytes privately; a public runbook or example never pre-authorizes a script. Any test/demo executor fixture is explicitly non-operational and is never loaded as a production script. No license or downstream reuse right is implied.

A runbook is marked human-verified only after review of its exact public content. The corpus's first content review was performed by a delegated agent tribunal under the operator's written session delegation (he was away from the keyboard and authorized decisions to be made through the tribunal); the `verification.verifier` string names that delegated review and its date. The operator's post-return review of the PR ratifies it or vetoes it — a veto is one superseding revision with a new content hash, and nothing downstream had bound the superseded hash. Verification metadata remains operator-curated and unauthenticated (docs/runbook-format.md); it is a curation signal, not an execution key: verification alone never grants execution, which still requires the operator's own standing authorization (ADR 0004) or proposal-bound approval (ADR 0003).

## Rejected alternative

Publish generic operational script bodies alongside the runbooks now. The current Product done-when requires demonstration of gate behavior, not a production update; issue #16 explicitly excludes production integration and the existing demonstration uses a stub executor. Public scripts add drift/maintenance and an implied reuse path without being required for current acceptance. They can be reconsidered later if a new requirement calls for clean-clone production execution, with a separate license and review decision.

## Consequences

- The public corpus can be searched and cited, but each operator must provide the script source and standing authorization for their own environment.
- Test-only fixtures demonstrate the gate without claiming to update a live system.
- The verifier string is the honest record of who reviewed and under what authority; a delegated verification is recorded as such, never attributed to the operator personally.
