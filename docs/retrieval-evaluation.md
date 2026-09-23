# Retrieval evaluation — dataset 1.0.0

Reproducible run: `.venv/Scripts/python.exe evaluation/run_assessment.py`
(the script prints this same result set; `tests/test_evaluation.py` pins it).

## Declared before measuring

- **Comparator** — the keyword-ranking `search_runbook` delivered in #11:
  lowercase alphanumeric tokens of the question matched against passage-text
  and operation tokens, occurrence-counted, ranked by score then
  runbook id/locator. Declared as the naive baseline comparator in the #11
  contract; it was **not** tuned after seeing these results.
- **Baseline** — document-order ranking with no query relevance (fixed order
  over the dataset, first passage top-1).
- **Metric** — top-1 citation correctness: the single returned result must
  carry the expected runbook id and locator, bound to the expected revision
  content hash. Answer plausibility is **not** scored: passage text quality
  is separated from citation correctness by construction.
- **Dataset** — version 1.0.0, 5 verified revisions / 10 passages / 8
  labelled cases (`evaluation/dataset/manifest.json`; revision content
  hashes pinned in the manifest).

## Results

| Metric | Comparator (keyword) | Baseline (document order) |
|---|---|---|
| Top-1 citation correctness | **5 / 8** | 1 / 8 |

Comparator outperforms the baseline 5:1 on this dataset.

## Categorized failures (comparator)

| Case | Category | Cause |
|---|---|---|
| C2 (`verify the n8n restart finished`) | `wrong_revision` | Stopword inflation: the declared comparator counts occurrences of "the", letting the backup-restore revision outscore the target passage. Declared limitation of the naive baseline. |
| C4 (`openwebui will not start after updating`) | `wrong_passage_same_revision` | Sibling-passage near miss: `update/steps` shares "openwebui"/"updating" terms with the expected `update/rollback`. Same revision, wrong passage — citation correctness still identifies the revision correctly. |

Non-procedural questions (C8) correctly return no evidence: the comparator
does not manufacture plausible-sounding results for questions that have no
procedural match.

## Not claimed

These numbers measure citation correctness on a small labelled dataset.
They are not a claim of operational safety, and they say nothing about
answer plausibility, judgment quality, or authorization behavior.
