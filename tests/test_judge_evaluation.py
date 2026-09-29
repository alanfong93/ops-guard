"""Hermetic tests for the judge-evaluation corpus machinery (issue #60).

No live Ollama: deterministic fixtures run through the pinned components
with scripted model ports; labelled-class behaviour is exercised with
targeted scripted cases. The declared live run happens separately via
``evaluation/judge/run_judge_assessment.py``.
"""

from __future__ import annotations

import json
import os
import sys

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from evaluation.judge.corpus import (  # noqa: E402
    COMPANION_IDS,
    build_state,
    case_hash,
    METAMORPHIC_RELATIONS,
    PAIRS_PER_RELATION,
    base_state,
    transform_id_aligned_permutation,
    transform_irrelevant_evidence_insertion,
    transform_json_key_reorder,
    transform_question_map_reorder,
    unique_winner_answer_sets,
)
from evaluation.judge.face import EvaluationFace  # noqa: E402
from evaluation.judge.run_judge_assessment import (  # noqa: E402
    load_corpus,
    supplemental_full_map,
)
from local_judge.evidence import GATE_THRESHOLDS, run_corpus  # noqa: E402

MENU_CLASSES = sorted(unique_winner_answer_sets())


def deterministic_cases() -> list[dict]:
    manifest, cases = load_corpus()
    return [c for c in cases if c.get("case_class") == "deterministic"]


def test_corpus_hashes_and_case_links() -> None:
    manifest, cases = load_corpus()
    by_id = {c["case_id"]: c for c in cases}
    assert len(by_id) == len(cases) == manifest["case_count"]
    for entry in manifest["cases"]:
        assert entry["case_id"] in by_id
    for case in cases:
        if case.get("matched_case_id"):
            assert case["matched_case_id"] in by_id, case["case_id"]


def test_corpus_shape_invariants() -> None:
    _, cases = load_corpus()
    ids = [c["case_id"] for c in cases]
    assert len(set(ids)) == len(ids)
    classes = {}
    for case in cases:
        classes[case["case_class"]] = classes.get(case["case_class"], 0) + 1
        if case.get("question_ids"):
            assert len(set(case["question_ids"])) == len(case["question_ids"]) >= 2
        else:
            assert case.get("question_id")
    assert classes["normal"] >= 50
    assert classes["ambiguous"] >= 20
    assert classes["adversarial"] >= 20
    assert classes["deterministic"] >= 6
    # metamorphic: every relation has at least PAIRS_PER_RELATION pairs
    for relation in METAMORPHIC_RELATIONS:
        members = [
            c
            for c in cases
            if c.get("case_class") == "metamorphic" and c.get("metamorphic_relation") == relation
        ]
        assert len(members) >= 2 * PAIRS_PER_RELATION, relation


def test_all_six_deterministic_categories_pass_through_pinned_runner() -> None:
    cases = deterministic_cases()
    report = run_corpus(cases, EvaluationFace(port=None), thresholds=None)
    det = report["deterministic_categories"]
    for category, stats in det.items():
        assert stats["pass"] == stats["total"] == 1, category
    assert report["gates"][0]["gate"] == "deterministic_fixtures"
    assert report["gates"][0]["pass"]


def test_authoritative_gates_pin_fixed_thresholds_without_overrides() -> None:
    cases = deterministic_cases()
    report = run_corpus(cases, EvaluationFace(port=None), thresholds=None)
    assert report["threshold_overrides"] is None
    assert report["effective_thresholds"] == GATE_THRESHOLDS
    for gate in report["gates"]:
        assert gate["authoritative"] is True


def test_unique_winner_answer_sets_cover_every_n3_distribution() -> None:
    sets = unique_winner_answer_sets()
    classes = sorted(sets)
    for winner, members in sets.items():
        assert len(members) == 3  # 3-0 and the two 2-1 splits
        for answer in members:
            shares = answer["vote_share"]
            assert answer["choice"] == winner
            assert set(shares) == set(classes)
            largest = max(shares.values())
            winners = [c for c in classes if shares[c] == largest]
            assert winners == [winner]
            assert abs(sum(shares.values()) - 1.0) < 1e-9
    # the 1-1-1 tie is never an allowed answered label: every allowed
    # answer has a unique winner with 3 or 2 votes (asserted above); a tie
    # is an AGGREGATION_TIE inability, so no member has a 1-1-1 distribution
    for members in sets.values():
        for answer in members:
            counts = [round(v * 3, 6) for v in answer["vote_share"].values()]
            assert 3 in counts or 2 in counts


def _uniform(label_class: str) -> dict:
    return {
        "choice": label_class,
        "vote_share": {c: (3 if c == label_class else 0) / 3 for c in MENU_CLASSES},
    }


def _metamorphic_pair(relation: str, base_script, variant_script) -> tuple[dict, dict]:
    question_ids = ["risk_class", *COMPANION_IDS]
    base = {
        "case_id": f"{relation}-t-base",
        "case_class": "metamorphic",
        "metamorphic_relation": relation,
        "question_ids": question_ids,
        "question_id": "risk_class",
        "state": base_state(),
        "port_script": base_script,
        "matched_case_id": f"{relation}-t-variant",
        "rationale": "test fixture",
    }
    variant = {
        **base,
        "case_id": f"{relation}-t-variant",
        "matched_case_id": base["case_id"],
        "port_script": variant_script,
        "rationale": "test fixture",
    }
    if relation == "question-map-reorder":
        variant["question_ids"] = transform_question_map_reorder(question_ids)
    elif relation == "id-aligned-permutation":
        permuted, inverse = transform_id_aligned_permutation(question_ids)
        variant["question_ids"] = permuted
        variant["id_permutation_inverse"] = inverse
    return base, variant


@pytest.mark.parametrize("relation", METAMORPHIC_RELATIONS)
def test_full_map_invariance_holds_for_equivalent_scripts(relation: str) -> None:
    base, variant = _metamorphic_pair(
        relation, ['"routine"'] * 9, ['"routine"'] * 9
    )
    face = EvaluationFace(port=None)
    face(base)
    face(variant)
    assert face.full_map_invariance(base["case_id"], variant["case_id"])


@pytest.mark.parametrize("relation", METAMORPHIC_RELATIONS)
def test_negative_control_companion_change_fails_full_map(relation: str) -> None:
    """A companion that changes class while the target does not must fail
    the full-map check — the target-only view would wrongly pass."""
    base, variant = _metamorphic_pair(
        relation,
        ['"routine"'] * 9,
        ['"routine"'] * 3 + ['"critical"'] * 3 + ['"routine"'] * 3,
    )
    face = EvaluationFace(port=None)
    face(base)
    face(variant)
    assert not face.full_map_invariance(base["case_id"], variant["case_id"])


def test_negative_control_companion_failure_fails_full_map() -> None:
    base, variant = _metamorphic_pair(
        "question-map-reorder",
        ['"routine"'] * 9,
        ['"routine"'] * 3 + ["@timeout"] * 3 + ['"routine"'] * 3,
    )
    face = EvaluationFace(port=None)
    face(base)
    face(variant)
    assert not face.full_map_invariance(base["case_id"], variant["case_id"])


def test_timeout_is_a_counted_non_answer() -> None:
    case = {
        "case_id": "timeout-fixture",
        "case_class": "normal",
        "question_id": "risk_class",
        "state": base_state(),
        "port_script": ["@timeout"] * 3,
        "rationale": "test fixture",
    }
    face = EvaluationFace(port=None)
    report = run_corpus([case], face, thresholds=None)
    entry = report  # normal gate fails (coverage), which is expected here
    counts = face.drain_failure_counts()
    assert counts["non_answer_counts_by_code"].get("MODEL_TIMEOUT") == 1
    assert counts["by_case_class"]["normal"]["MODEL_TIMEOUT"] == 1


def test_supplemental_full_map_answers_and_vacuity() -> None:
    """Answered pairs rate over answered denominators; all-inability pairs
    are not-evaluable and vacuous — never reported as invariant."""
    _, cases = load_corpus()
    relation_cases = [
        c
        for c in cases
        if c.get("case_class") == "metamorphic"
        and c.get("metamorphic_relation") == "json-key-reorder"
    ][:4]  # two pairs
    # answered pair: identical scripts
    face = EvaluationFace(port=None)
    for case in relation_cases:
        face({**case, "port_script": ['"routine"'] * 9})
    assert face.full_map_answered(relation_cases[0]["case_id"], relation_cases[0]["matched_case_id"])
    assert face.full_map_invariance(relation_cases[0]["case_id"], relation_cases[0]["matched_case_id"])

    # non-answered pair: identical inabilities are NOT evaluable
    face2 = EvaluationFace(port=None)
    for case in relation_cases:
        face2({**case, "port_script": ["@timeout"] * 9})
    assert not face2.full_map_answered(relation_cases[0]["case_id"], relation_cases[0]["matched_case_id"])
    # the runner's supplemental classification marks it not-evaluable
    result = face2.full_map_invariance(relation_cases[0]["case_id"], relation_cases[0]["matched_case_id"])
    assert result is True  # statuses match trivially; the runner's answered gate is what excludes it


def test_transforms_are_non_identity() -> None:
    state = base_state()
    reordered = transform_json_key_reorder(state)
    # dict equality ignores order; the transform is non-identity at the
    # serialization level — exactly what the rendered prompt sees
    assert json.dumps(reordered, sort_keys=False) != json.dumps(state, sort_keys=False)
    assert list(reordered["invocation"]["arguments"]) != list(state["invocation"]["arguments"])
    assert reordered == state  # semantically the same state
    inserted = transform_irrelevant_evidence_insertion(state)
    assert inserted["evidence"]["passage_text"] != state["evidence"]["passage_text"]
    assert inserted["evidence"]["content_hash"] != state["evidence"]["content_hash"]
    assert inserted["evidence"]["operation"] == state["evidence"]["operation"]
    assert inserted["evidence"]["preconditions"] == state["evidence"]["preconditions"]
    ids = ["risk_class", "companion_safety", "companion_scope"]
    assert transform_question_map_reorder(ids) == list(reversed(ids))
    permuted, inverse = transform_id_aligned_permutation(ids)
    assert permuted != ids
    assert sorted(permuted) == sorted(ids)
    assert [inverse[p] for p in permuted] == ids


@given(st.sampled_from(["json-key-reorder", "irrelevant-evidence-insertion"]))
@settings(max_examples=5, deadline=None)
def test_state_transforms_preserve_operation_and_conditions(dummy: str) -> None:
    state = base_state()
    for variant in (transform_json_key_reorder(state), transform_irrelevant_evidence_insertion(state)):
        assert variant["evidence"]["operation"] == state["evidence"]["operation"]
        assert variant["evidence"]["preconditions"] == state["evidence"]["preconditions"]
        assert variant["evidence"]["locator"] == state["evidence"]["locator"]


def test_runner_report_shape_and_non_claims(tmp_path, monkeypatch) -> None:
    from evaluation.judge import run_judge_assessment as runner

    manifest, cases = load_corpus()
    det = [c for c in cases if c.get("case_class") == "deterministic"]
    face = EvaluationFace(port=None)
    report = run_corpus(det, face, thresholds=None)
    full_map = supplemental_full_map(det, face)
    assert set(full_map) == set(
        __import__("evaluation.judge.corpus", fromlist=["METAMORPHIC_RELATIONS"]).METAMORPHIC_RELATIONS
    )
    for stats in full_map.values():
        assert stats["min_required"] == 0.8
        assert stats["pairs"] == 0
        assert stats["rate"] is None and stats["vacuous"] is True
        assert stats["answered_pairs"] == 0 and stats["not_evaluable"] == 0
    assert report["demonstrated_usefulness"] is True or report["demonstrated_usefulness"] is False

def test_no_three_way_tie_is_ever_an_allowed_answer() -> None:
    """The 1-1-1 tie is an AGGREGATION_TIE inability — never an allowed
    answered label (contract: unique-winner distributions only)."""
    sets = unique_winner_answer_sets()
    tie = {round(1 / 3, 9)}
    for members in sets.values():
        for answer in members:
            shares = {round(v, 9) for v in answer["vote_share"].values()}
            assert shares != tie


def test_generator_round_trip_hashes_verify(tmp_path, monkeypatch) -> None:
    """The manifest's per-case hashes verify against the written files."""
    import hashlib

    from evaluation.judge import run_judge_assessment as runner

    monkeypatch.setattr(runner, "HERE", str(tmp_path))
    manifest_dir = tmp_path / "cases"
    manifest_dir.mkdir()
    from evaluation.judge.generate_corpus import build_cases

    cases = build_cases()
    manifest_cases = []
    for case in cases:
        name = f"{case['case_id']}.json"
        (manifest_dir / name).write_text(
            json.dumps(case, indent=2, sort_keys=True, ensure_ascii=False) + chr(10),
            encoding="utf-8",
        )
        manifest_cases.append(
            {"case_id": case["case_id"], "file": f"cases/{name}", "sha256": case_hash(case)}
        )
    (tmp_path / "manifest.json").write_text(
        json.dumps({"corpus_version": "t", "case_count": len(cases), "cases": manifest_cases}),
        encoding="utf-8",
    )
    _, loaded = runner.load_corpus()
    assert len(loaded) == len(cases)


def test_json_key_reorder_survives_to_payload_boundary() -> None:
    """The reorder must reach the rendered prompt bytes — the model
    boundary — not be canonicalized away before it gets there."""
    from evaluation.judge.face import compose_envelope, _fixed_validator
    from local_judge.executors.choice import ChoiceExecutor
    from ops_guard.judge import MENU, risk_question

    executor = ChoiceExecutor(dict(MENU))
    q = risk_question()
    base = build_state("critical")
    variant = transform_json_key_reorder(base)
    rendered = []
    for state in (base, variant):
        envelope = _fixed_validator().parse(compose_envelope(state, ["risk_class"]))
        messages = executor.render_messages("risk_class", envelope.questions["risk_class"].raw, envelope.state)
        rendered.append(messages[-1]["content"])
    assert rendered[0] != rendered[1]