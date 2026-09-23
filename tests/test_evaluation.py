"""Reproducibility pin for the published retrieval evaluation (issue #15)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))

from run_assessment import run  # noqa: E402

PUBLISHED = {
    "dataset_version": "1.0.0",
    "comparator_top1_correct": 5,
    "baseline_top1_correct": 1,
    "per_case": [
        ("C1", "correct", "correct"),
        ("C2", "wrong_runbook", "wrong_passage_same_revision"),
        ("C3", "correct", "wrong_runbook"),
        ("C4", "wrong_passage_same_revision", "wrong_runbook"),
        ("C5", "correct", "wrong_runbook"),
        ("C6", "correct", "wrong_runbook"),
        ("C7", "correct", "wrong_runbook"),
        ("C8", "returned_evidence_when_none_expected", "returned_evidence_when_none_expected"),
    ],
}


def test_assessment_reproduces_the_published_results() -> None:
    result = run()
    assert result["dataset_version"] == PUBLISHED["dataset_version"]
    assert result["comparator_top1_correct"] == PUBLISHED["comparator_top1_correct"]
    assert result["baseline_top1_correct"] == PUBLISHED["baseline_top1_correct"]
    for (case_id, comparator_category, baseline_category), entry in zip(
        PUBLISHED["per_case"], result["cases"]
    ):
        assert entry["case_id"] == case_id
        assert entry["comparator"]["category"] == comparator_category
        assert entry["baseline"]["category"] == baseline_category
    categories = {
        entry["comparator"]["category"] for entry in result["cases"]
    }
    assert "correct" in categories
    # Categorized failures are part of the published result set.
    assert "wrong_runbook" in categories
    assert "wrong_passage_same_revision" in categories
    assert "returned_evidence_when_none_expected" in categories


def test_comparator_outperforms_the_declared_baseline() -> None:
    result = run()
    assert result["comparator_top1_correct"] > result["baseline_top1_correct"]


def test_every_case_is_categorized() -> None:
    result = run()
    for entry in result["cases"]:
        assert entry["comparator"]["category"]
        assert entry["baseline"]["category"]
