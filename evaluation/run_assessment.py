"""Reproducible retrieval assessment harness (issue #15).

Declares the comparator and scoring BEFORE measuring, runs both the
keyword-ranking comparator and the no-relevance baseline over the versioned
dataset, and emits the results as JSON. Citation correctness (the expected
runbook and locator, bound to the expected content hash) is the only
success measure; answer plausibility is deliberately not scored.

Usage: .venv/Scripts/python.exe evaluation/run_assessment.py
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ops_guard.retrieval import RunbookLibrary  # noqa: E402

DATASET_DIR = os.path.join(os.path.dirname(__file__), "dataset")


def load_manifest() -> dict:
    with open(os.path.join(DATASET_DIR, "manifest.json"), encoding="utf-8") as handle:
        return json.load(handle)


def load_documents(manifest: dict) -> list[dict]:
    documents = []
    for entry in manifest["revisions"]:
        with open(os.path.join(DATASET_DIR, os.path.basename(entry["file"])), encoding="utf-8") as handle:
            documents.append(json.load(handle))
    return documents


def document_order_baseline(manifest: dict, question: str, limit: int = 1) -> list[dict]:
    """The declared baseline: fixed document order, no query relevance."""
    results = []
    for entry in manifest["revisions"]:
        with open(os.path.join(DATASET_DIR, os.path.basename(entry["file"])), encoding="utf-8") as handle:
            document = json.load(handle)
        for passage in document["passages"]:
            results.append({
                "runbook_id": document["runbook_id"],
                "locator": passage["locator"],
                "content_hash": document["content_hash"],
            })
            if len(results) >= limit:
                return results
    return results


def score(harness_results: list[dict], expected: dict | None) -> dict:
    if expected is None:
        return {"top1_correct": len(harness_results) == 0, "category": "no-evidence-expected"}
    if not harness_results:
        return {"top1_correct": False, "category": "no_result"}
    top = harness_results[0]
    if top["content_hash"] != expected.get("content_hash"):
        return {"top1_correct": False, "category": "wrong_revision"}
    if top["runbook_id"] != expected["runbook_id"]:
        return {"top1_correct": False, "category": "wrong_runbook"}
    if top["locator"] != expected["locator"]:
        return {"top1_correct": False, "category": "wrong_passage_same_revision"}
    return {"top1_correct": True, "category": "correct"}


def run() -> dict:
    manifest = load_manifest()
    documents = load_documents(manifest)
    library, rejections = RunbookLibrary.load(documents)
    if rejections:
        raise SystemExit(f"dataset contains invalid revisions: {rejections}")
    expected_hashes = {entry["content_hash"] for entry in manifest["revisions"]}

    results = []
    for case in manifest["cases"]:
        comparator = library.search(case["question"], limit=1)
        comparator_dicts = [
            {
                "runbook_id": r.runbook_id,
                "locator": r.locator,
                "content_hash": r.content_hash,
            }
            for r in comparator
        ]
        baseline = document_order_baseline(manifest, case["question"], limit=1)
        comparator_score = score(comparator_dicts, case["expected"])
        baseline_score = score(baseline, case["expected"])
        if case["expected"] is not None:
            case_hash = next(
                entry["content_hash"]
                for entry in manifest["revisions"]
                if entry["runbook_id"] == case["expected"]["runbook_id"]
            )
            case = {**case, "expected": {**case["expected"], "content_hash": case_hash}}
            comparator_score = score(comparator_dicts, case["expected"])
            baseline_score = score(baseline, case["expected"])
        results.append({
            "case_id": case["case_id"],
            "category": case["category"],
            "comparator": comparator_score,
            "baseline": baseline_score,
        })

    correct = lambda key: sum(1 for r in results if r[key]["top1_correct"])
    summary = {
        "dataset_version": manifest["dataset_version"],
        "revision_hashes": sorted(expected_hashes),
        "cases": results,
        "comparator_top1_correct": correct("comparator"),
        "baseline_top1_correct": correct("baseline"),
        "error_categories": sorted({r[side]["category"] for r in results for side in ("comparator", "baseline")}),
    }
    return summary


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
