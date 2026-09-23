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
}


def test_assessment_reproduces_the_published_results() -> None:
    result = run()
    assert result["dataset_version"] == PUBLISHED["dataset_version"]
    assert result["comparator_top1_correct"] == PUBLISHED["comparator_top1_correct"]
    assert result["baseline_top1_correct"] == PUBLISHED["baseline_top1_correct"]
    categories = {
        entry["comparator"]["category"] for entry in result["cases"]
    }
    assert "correct" in categories
    # Categorized failures are part of the published result set.
    assert "wrong_revision" in categories
    assert "wrong_passage_same_revision" in categories


def test_comparator_outperforms_the_declared_baseline() -> None:
    result = run()
    assert result["comparator_top1_correct"] > result["baseline_top1_correct"]


def test_every_case_is_categorized() -> None:
    result = run()
    for entry in result["cases"]:
        assert entry["comparator"]["category"]
        assert entry["baseline"]["category"]
