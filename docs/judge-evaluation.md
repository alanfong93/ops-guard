# Judge risk-rubric evaluation (corpus v1, reports v1 and v2)

This is the S7-6 measurement (issue #60, re-evaluated by the issue #74
corrective): does the advisory local risk rubric (`routine` / `review` /
`critical`, [ADR 0009](adr/0009-local-advisory-judge-audit-projection.md))
demonstrate usefulness on the pinned model profile before any caller ever
sees a label?

**Outcome: both reports FAILED. `demonstrated_usefulness: false` in
report-v1 and in report-v2. The judge advisory remains audit-only and
S7-7 (issue #65) stays blocked.** A failed report is a valid evaluation
outcome, not a broken gate. Report-v2 (prompt v2) is major progress over
report-v1 — three of five gates now pass — but the two remaining gates
fail on model capability, not on format.

## Configuration under test (all fixed, none caller-controlled)

- Model: `qwen3:8b` via local Ollama 0.34.4 on literal loopback
  (`127.0.0.1:11434`), thinking disabled at the transport boundary
  ([ADR 0009 amendment](adr/0009-local-advisory-judge-audit-projection.md)).
- Pinned local-judge commit `fca3fbde28312e7a1fa18940b8738ae406714f43`;
  `run_corpus(cases, face, thresholds=None)` is the sole authoritative
  gate implementation.
- Fixed: 3 sequential samples, temperature 0, `timeout_ms=10000`,
  identifiers `ops-guard-risk-state-v1` / `ops-guard-risk-rubric-v1` /
  `ops-guard-risk-prompt-v2` (issue #74 corrective; v1 abstained on every input under the sample union), menu definitions from ADR 0009.
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

## Re-evaluation (report-v2.json, issue #74 corrective, prompt v2, 103 s)

The #74 corrective settled direction 1 — revised caller-declared
instructions under the bumped `ops-guard-risk-prompt-v2`. Probes
root-caused v1's abstention: the sample union offers the answer as a
**bare JSON string** or an inability **object**, and constrained decoding
makes a small model prefer the object shape; the model was shape-driven,
not semantically unable. v2 states the format explicitly (bare-string
output; the inability object reserved for literally unreadable or
self-contradictory states) and the same model answers through the
unchanged union and unchanged pinned library.

| Gate | report-v1 | report-v2 |
|---|---|---|
| deterministic_fixtures | pass | **pass** |
| normal_cases | fail (0/50 answered) | **pass** (accuracy 1.0) |
| ambiguous_cases | fail | **pass** (coverage 1.0) |
| adversarial_matched_pairs | fail | **fail in both runs** — task preservation 0.75 / 0.737 (needs ≥ 0.9), drop 25–26 pp (needs ≤ 10) |
| metamorphic_invariance | fail | pass on the declared run (all four relations 1.0) — but **unstable**: an earlier live run of the identical configuration scored irrelevant-evidence-insertion 0.65 |

`demonstrated_usefulness` stays **false**: the adversarial gate fails in
every run — the model drops ~25 accuracy points under role-spoofing and
sibling vectors, a stable capability limit of the pinned 8B model. Two
findings from probing are recorded as evidence, not claims: (1) v1's
abstention was shape-driven (fixed by v2's explicit format instructions);
(2) irrelevant-evidence invariance at temperature 0 is not stable for
this model — identical configuration scored 0.65 and 1.0 across runs —
so no robustness claim is made from either number. Under the same union,
every locally available model reproduces the shape-driven inability exit
(`qwen3:8b`, `huihui_ai/qwen3.5-abliterated:4b`, `gemma4:e4b`), so
direction 2 has no local candidate; a larger or non-local judge model is
an operator decision (cost and locality trade against the frozen local
profile) and remains the next re-plan lever.

The #73-review hardening is folded into the runner: each full-map
relation now reports `underpowered` below five answered pairs, and the
pinned consumer semantics state that `rate: null` or `vacuous: true`
never satisfies the 0.8 bar numerically.

## Consequences

- No label may be surfaced to any caller; `propose_fix` continues to
  record audit-only advisory results (the judge now answers, but the
  gate contract requires a full pass).
- Issue #65 (S7-7, advisory in the proposal response) stays blocked.
- The next re-plan lever is direction 2 with a non-local (or larger)
  judge model — an operator decision on cost and locality; direction 3
  (thinking budget) is not indicated: thinking is disabled for latency
  and the model abstained with it enabled anyway.

## Non-claims

This report does not claim injection resistance, calibrated confidence, or
operational safety. Agreement is repeated-sample consistency, never
confidence. Retrieval scores are unrelated to risk classes. A passing
report would not have authorized execution; a failing report changes no
authorization behaviour.
