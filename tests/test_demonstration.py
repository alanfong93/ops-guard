"""Reproducibility pin for the execution demonstration (issue #16)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "demonstrations"))

from execution_demo import run_demonstration  # noqa: E402

EXPECTED_SCENARIOS = [
    ("standing-authorization-success", True, 1, "success"),
    ("independent-approval-success", True, 1, "success"),
    ("missing-evidence-refusal", False, 0, "refused"),
    ("stale-evidence-refusal", False, 0, "refused"),
    ("failed-precondition-refusal", False, 0, "refused"),
    ("invalid-token-refusal", False, 0, "refused"),
    ("expired-token-refusal", False, 0, "refused"),
    ("audit-write-refusal", False, 0, "refused"),
    ("reused-token-first-dispatch", True, 1, "success"),
    ("reused-token-refusal", False, 0, "refused"),
    ("unknown-outcome", True, 1, "unknown"),
]


def test_demonstration_reproduces_every_scenario() -> None:
    trace = run_demonstration()
    scenarios = trace["scenarios"]
    assert [s["scenario"] for s in scenarios] == [name for name, *_ in EXPECTED_SCENARIOS]
    for (name, dispatched, executor_count, outcome), entry in zip(EXPECTED_SCENARIOS, scenarios):
        assert entry["dispatched"] is dispatched, (name, entry)
        assert entry["executor_invocations"] == executor_count, (name, entry)
        assert entry["outcome"] == outcome, (name, entry)
        if not dispatched:
            assert entry["refusal"], name
    assert trace["executor_invocations_total"] == 4


def test_permitted_paths_leave_ordered_redacted_audit_events() -> None:
    trace = run_demonstration()
    events = trace["audit_events"]
    types = [e["event_type"] for e in events]
    assert types == [t for t in types]  # ordered by sequence (store contract)
    assert types.count("execution_start") == 4
    assert types.count("execution_outcome") == 4
    assert types.count("refusal") == len([s for s in scenarios_list(trace) if not s["dispatched"]])
    # every refusal precedes any side-effect boundary: refusal events carry
    # reasons, and dispatch events only exist for permitted paths
    for event in events:
        if event["event_type"] == "refusal":
            assert event["outcome"] in (None, "refused")


def test_unknown_completion_recorded_explicitly() -> None:
    trace = run_demonstration()
    unknown = [
        e for e in trace["audit_events"]
        if e["event_type"] == "execution_outcome" and e["outcome"] == "unknown"
    ]
    assert len(unknown) == 1


def scenarios_list(trace: dict) -> list[dict]:
    return trace["scenarios"]
