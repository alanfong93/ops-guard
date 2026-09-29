# 0009 — Local advisory judge and privacy-preserving audit projection

- Status: Accepted
- Date: 2026-09-29
- Decided by: plan-loop design (issue #58); implemented with this issue
- Consumers: #60 (risk rubric usefulness evaluation), #65 (judge advisory in proposal response)

## Context

The product requires a risk class and advisory signal on proposals while requiring an evidence snapshot, model/configuration, rubric/state schema, candidate menu, thresholds, and result/failure in audit. The audit writer redacts values under sensitive-looking mapping keys, but it does not scrub arbitrary strings. The pinned local-judge trace contains raw state, rendered messages, and raw attempts. Persisting that trace verbatim could copy sensitive values into audit records.

## Decision

Consume the pinned local-judge Python-library implementation through one ops-guard adapter (`src/ops_guard/judge.py`; local-judge pinned to immutable commit `fca3fbde28312e7a1fa18940b8738ae406714f43`). Fix the local profile (`qwen3:8b` on a literal-loopback Ollama base URL), the Choice menu/rubric (`routine` / `review` / `critical`), sample count (exactly three sequential samples), temperature (0), and per-sample timeout (10000 ms) in server code; no caller override exists.

The pinned `SamplingOrchestrator` does not pass its generated output schema to the model port, so the adapter wraps the `OllamaModelPort` and forwards `ChoiceExecutor.output_schema(question)` as `response_schema` on every attempt. (A future local-judge re-pin that forwards the schema upstream may drop the wrapper.)

The judge state shape is `ops-guard-risk-state-v1`: the host-composed Invocation plus the resolved verified-Citation evidence (revision references, operation, preconditions, cited passage). The prompt and rubric are `ops-guard-risk-prompt-v1` and `ops-guard-risk-rubric-v1`. The reusable private `evaluate_question_map(state, question_ids)` helper generates every question from the same fixed prompt/menu/profile; the MCP `propose_fix` path calls it with exactly one fixed question ID. It is never an MCP tool and never accepts client-supplied questions, models, rubrics, or inference settings.

Persist a closed, versioned projection (`ops-guard-risk-projection-v1`) containing only: the selected risk class, vote-share map, agreement (repeated-sample consistency, never confidence), versions, fixed inference settings, the menu/rubric identifiers, model identity and digest (or an explicit unavailable marker), the local-judge trace UUID when a trace exists (`null` on structural rejection before any trace), citation references, and an HMAC fingerprint of the exact judge request (the composed state plus the question it was asked under). Do not persist raw state, passage text, rendered prompts, raw attempts, arbitrary model output, exception text, or the proposal token. The failure codes are closed: `judge_unavailable`, `judge_timeout`, `judge_inability` (including aggregation tie), `judge_invalid_output`, `judge_input_rejected` (including size/context rejection), `judge_error`. The adapter never raises past its boundary: every internal failure becomes one of these codes.

Accepted limit: the one-time `/api/show` digest probe trusts the operator's loopback Ollama response body (bounded by a 2-second timeout, not by byte count) — a hostile loopback endpoint is outside the trust boundary, since it could equally serve hostile model outputs.

Local inference runs before `ProposalService.open_proposal()` enters its SQLite write transaction; the projection rides the existing atomic proposal insert + audit append as `judge_snapshot`. A judge timeout, unavailability, inability, or invalid output records the safe failure and still creates the proposal when persistence succeeds; an audit-write failure rolls back everything and returns no token. The judgment is audit-only: it is never returned to the host, never read by `ExecutionGate`, and never grants, withdraws, or substitutes for authorization. The label stays audit-only until the S7-6 evaluation (#60) passes; surfacing it is #65's separate decision.

## Rejected alternatives

- Persist the full local-judge trace — key-based redaction cannot remove sensitive values inside strings.
- Run local-judge as a second HTTP service — the documented Python-library face avoids another service boundary.
- Let the judge grant, deny, or alter authorization — the judge is advisory (PRODUCT constraint).
- Hold Qwen resident or add a warmup path in this issue — the measured model occupies about 6.2 GB VRAM and cold-start failures are fail-open by decision; #60 must count them.

## Consequences

- The audit event preserves a privacy-safe reconstruction reference (citation refs + proposal/invocation refs + request fingerprint) rather than the raw input.
- Cold-start timeouts (~53–142 s measured cold loads vs the fixed 10 s per-sample budget) record `judge_timeout`; three sequential client attempt budgets total about 30 s, which is not an end-to-end service deadline.
- The S7-6 report must count timeout/unavailable results against coverage; no judge result is returned to the host or used by execution until #65 is planned after the evaluation passes.
