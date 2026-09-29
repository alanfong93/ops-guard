# Judge risk-rubric evaluation (corpus v1, report v1)

This is the S7-6 measurement (issue #60): does the advisory local risk
rubric (`routine` / `review` / `critical`, [ADR 0009](adr/0009-local-advisory-judge-audit-projection.md))
demonstrate usefulness on the pinned model profile before any caller ever
sees a label?

**Outcome: the report FAILED. `demonstrated_usefulness: false`. The judge
advisory remains audit-only and S7-7 (issue #65) stays blocked.** A failed
report is a valid evaluation outcome, not a broken gate.

## Configuration under test (all fixed, none caller-controlled)

- Model: `qwen3:8b` via local Ollama 0.34.4 on literal loopback
  (`127.0.0.1:11434`), thinking disabled at the transport boundary
  ([ADR 0009 amendment](adr/0009-local-advisory-judge-audit-projection.md)).
- Pinned local-judge commit `fca3fbde28312e7a1fa18940b8738ae406714f43`;
  `run_corpus(cases, face, thresholds=None)` is the sole authoritative
  gate implementation.
- Fixed: 3 sequential samples, temperature 0, `timeout_ms=10000`,
  identifiers `ops-guard-risk-state-v1` / `ops-guard-risk-rubric-v1` /
  `ops-guard-risk-prompt-v1`, menu definitions from ADR 0009.
- Corpus: `evaluation/judge/manifest.json` (`ops-guard-judge-corpus-v1`),
  256 cases — 6 deterministic fixtures (one per contract category), 50
  labelled normal, 20 ambiguous (explicit allowed-answer sets), 20
  adversarial matched to normal twins, and 20 pairs for each of the four
  metamorphic relations (base+variant both evaluated: 160 cases). All
  states are synthetic or derived from the public verified runbook corpus;
  each invocation is paired with evidence describing the same operation.

## Results (report-v1.json, live run, 288 s)

| Gate | Result |
|---|---|
| deterministic_fixtures (6/6 categories) | **pass** |
| normal_cases (≥50, coverage ≥0.9, accuracy ≥0.8) | **fail** — answered 0/50 |
| ambiguous_cases (≥20, allowed-outcome coverage ≥0.8) | **fail** — 0/20 answered |
| adversarial_matched_pairs (≥20, drop ≤10 pp) | **fail** — 0 pairs answerable |
| metamorphic_invariance (≥0.8 per relation) | **fail** — 0 answered entries |

Failure counts (sidecar, per question entry across live classes — produced by the evaluation face as supplemental instrumentation, never by the pinned runner, whose own inability_rate and coverage denominators appear in `report-v1.json` under `authoritative.metrics`): 269
`INSUFFICIENT_EVIDENCE`, 139 `AMBIGUOUS_EVIDENCE`, 2
`UNSUPPORTED_QUESTION` — 410 of 410 non-answers. Zero `MODEL_TIMEOUT`
(thinking disabled keeps every sample well inside the 10 s budget); zero
invalid outputs; zero backend errors. Agreement distribution: none (no
answered entries). Supplemental full-map invariance: **not evaluable** — all 20 pairs per
relation have non-answered entries on at least one side, so no pair
exercises the invariance comparison (identical inabilities are not
evidence of invariance); the report marks every relation `vacuous: true`
with `answered_pairs: 0`. The authoritative runner likewise scores
invariance 0.0 because it counts answered entries only.

## Expectation versus outcome

The live fixtures were built to be answerable: every invocation is paired with evidence describing the same operation, and the labelled classes follow the menu definitions. The abstention below was **discovered**, not designed: pilot probes before the declared run found the model answering the same classification through a plain prompt and refusing it through the pinned engine contract. The declared run then measured that finding across the full corpus.

## Diagnosis (from the pilot probes recorded before the declared run)

1. The model answers the *same classification task* when asked through a
   plain prompt with a plain schema (e.g. `critical` for an irreversible
   volume deletion), so the capability is present.
2. Through the pinned engine prompt with the sample-union schema (a typed
   answer **or** an explicit inability object), `qwen3:8b` at temperature 0
   takes the inability exit on essentially every input — including states
   whose labelled class is decisive, and with directive caller
   instructions. The abstention branch dominates constrained decoding for
   this small model.
3. With thinking enabled the model still abstains (`AMBIGUOUS_EVIDENCE`)
   at ~17 s per sample — exceeding the fixed 10 s budget anyway.

The first two points together indicate the failure is an interaction
between the fixed prompt/schema configuration and this small model, not a
property of the risk rubric itself.

## Consequences

- No label may be surfaced to any caller; `propose_fix` continues to
  record audit-only advisory results (all typed failures today).
- Issue #65 (S7-7, advisory in the proposal response) stays blocked.
- A corrective/re-evaluation issue is filed with this diagnosis; candidate
  directions there include revising the caller-declared instructions under
  a bumped prompt version (via plan-loop, since #58 froze them), trying a
  model whose constrained decoding tolerates the sample union, or raising
  the fixed per-sample budget to permit thinking mode — each is a new
  plan decision, not an inline change.

## Non-claims

This report does not claim injection resistance, calibrated confidence, or
operational safety. Agreement is repeated-sample consistency, never
confidence. Retrieval scores are unrelated to risk classes. A passing
report would not have authorized execution; a failing report changes no
authorization behaviour.
