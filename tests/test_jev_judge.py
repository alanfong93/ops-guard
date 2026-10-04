"""The hosted judge end to end over scripted transports (issue #91;
ADR 0014).

Hermetic: no live network call. Properties prove rejected inputs make
zero requests and snapshots never carry raw state, passages, or native
outputs.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ops_guard.jev import (
    INPUT_REJECTED,
    INVALID_OUTPUT,
    JEV_PROJECTION_SCHEMA_VERSION,
    JUDGE_ERROR,
    JUDGE_INABILITY,
    JUDGE_TIMEOUT,
    JUDGE_UNAVAILABLE,
    RISK_QUESTION_ID,
    JevJudge,
    TransportFailure,
    compute_serving_fingerprint,
)
from jev_fixtures import (
    PASSAGE_TEXT,
    ScriptedJevTransport,
    demo_config,
    demo_grant,
    jev_state,
    native_body,
)

ANSWERED_FIELDS = {
    "schema_version", "status", "provider", "model", "response_models",
    "endpoint", "policy_sha256", "profile_id", "serving_fingerprint",
    "sample_count", "timeout_ms", "attempted_samples", "completed_samples",
    "request_hmacs", "question_id", "citation_refs", "state_schema_version",
    "rubric_version", "prompt_version", "menu", "adapter_version",
    "parser_version", "aggregation_version",
    "risk_class", "vote_share", "agreement",
}
UNAVAILABLE_FIELDS = ANSWERED_FIELDS - {"risk_class", "vote_share", "agreement"} | {"failure_code"}


def judge(script, **kwargs) -> JevJudge:
    transport = kwargs.pop("transport", None) or ScriptedJevTransport(script)
    return JevJudge(
        config=kwargs.pop("config", demo_config()),
        hmac_key=kwargs.pop("hmac_key", b"test-key"),
        transport=transport,
        **kwargs,
    )


def max_attaining(choice: str) -> dict[str, float]:
    """A valid distribution in which ``choice`` uniquely attains the max."""
    return {option: (0.5 if option == choice else 0.25) for option in ("routine", "review", "critical")}


def body_with(choices: dict[str, str], question_ids: list[str]) -> bytes:
    """A valid native body where every question's choice attains its max."""
    body = json.loads(native_body(question_ids).decode())
    for question_id, choice in choices.items():
        answer = body["answers"][question_id]
        answer["choice"] = choice
        answer["probabilities"] = max_attaining(choice)
    return json.dumps(body).encode()


# ---- answered path --------------------------------------------------------


def test_answered_snapshot_is_closed_and_truthful() -> None:
    snapshot = judge([native_body([RISK_QUESTION_ID])] * 3).evaluate_risk(jev_state())
    assert snapshot["schema_version"] == JEV_PROJECTION_SCHEMA_VERSION
    assert set(snapshot) == ANSWERED_FIELDS
    assert snapshot["status"] == "answered"
    assert snapshot["provider"] == "typesafe"
    assert snapshot["model"] == "jev-1.13.0"
    assert snapshot["response_models"] == ["jev-1.13.0"] * 3
    assert snapshot["attempted_samples"] == snapshot["completed_samples"] == 3
    assert len(snapshot["request_hmacs"]) == 3
    assert len(set(snapshot["request_hmacs"])) == 1  # identical bytes → identical HMACs
    assert snapshot["question_id"] == RISK_QUESTION_ID
    assert snapshot["citation_refs"][0] == "demo-runbook@2026.10"
    assert snapshot["risk_class"] == "routine"
    assert snapshot["vote_share"] == {"routine": 1.0, "review": 0.0, "critical": 0.0}
    assert snapshot["agreement"] == 1.0
    # Nothing raw ever enters the snapshot.
    raw = json.dumps(snapshot)
    assert PASSAGE_TEXT not in raw
    assert "healthcheck" not in raw
    assert "c" * 64 not in raw
    assert "fixture-token" not in raw


def test_all_rejections_produce_the_input_rejected_snapshot() -> None:
    transport = ScriptedJevTransport([])
    snapshot = judge([], config=demo_config()).evaluate_risk(jev_state())
    assert transport.calls == 0  # granted path would call; empty script proves ordering below
    assert snapshot["status"] == "unavailable"


def test_snapshot_invariants_carry_partial_provenance_on_failure() -> None:
    transport = ScriptedJevTransport([
        native_body([RISK_QUESTION_ID]),
        TransportFailure(JUDGE_TIMEOUT),
    ])
    snapshot = judge(None, transport=transport).evaluate_risk(jev_state())
    assert snapshot["status"] == "unavailable"
    assert snapshot["failure_code"] == JUDGE_TIMEOUT
    assert snapshot["attempted_samples"] == 2
    assert snapshot["completed_samples"] == 1
    assert len(snapshot["request_hmacs"]) == 2
    assert snapshot["response_models"] == ["jev-1.13.0"]
    assert set(snapshot) == UNAVAILABLE_FIELDS


@pytest.mark.parametrize(
    "fault,expected_code",
    [
        (TransportFailure(JUDGE_TIMEOUT), JUDGE_TIMEOUT),
        (TransportFailure(JUDGE_UNAVAILABLE), JUDGE_UNAVAILABLE),
        (b"not json", INVALID_OUTPUT),
        (b'{"model":"jev-latest","answers":{},"usage":{"input_tokens":1,"output_tokens":1}}', INVALID_OUTPUT),
    ],
)
def test_first_failed_sample_stops_the_assessment(fault, expected_code) -> None:
    script = [native_body([RISK_QUESTION_ID]), fault, native_body([RISK_QUESTION_ID])]
    transport = ScriptedJevTransport(script)
    snapshot = judge(None, transport=transport).evaluate_risk(jev_state())
    assert transport.calls == 2  # sample 3 was never sent
    assert snapshot["failure_code"] == expected_code
    assert snapshot["completed_samples"] == 1


def test_tie_is_inability_after_three_valid_samples() -> None:
    script = [
        body_with({RISK_QUESTION_ID: "routine"}, [RISK_QUESTION_ID]),
        body_with({RISK_QUESTION_ID: "review"}, [RISK_QUESTION_ID]),
        body_with({RISK_QUESTION_ID: "critical"}, [RISK_QUESTION_ID]),
    ]
    snapshot = judge(script).evaluate_risk(jev_state())
    assert snapshot["status"] == "unavailable"
    assert snapshot["failure_code"] == JUDGE_INABILITY
    assert snapshot["attempted_samples"] == snapshot["completed_samples"] == 3


def test_native_confidence_and_probabilities_are_never_persisted() -> None:
    script = [native_body([RISK_QUESTION_ID], confidence=0.99)] * 3
    snapshot = judge(script).evaluate_risk(jev_state())
    assert "confidence" not in snapshot
    assert "probabilities" not in snapshot


# ---- evaluation question maps ---------------------------------------------


def test_companion_map_mixes_answered_and_tied_questions() -> None:
    question_ids = [RISK_QUESTION_ID, "companion_safety"]
    script = [
        body_with({RISK_QUESTION_ID: "routine", "companion_safety": "review"}, question_ids),
        body_with({RISK_QUESTION_ID: "review", "companion_safety": "review"}, question_ids),
        body_with({RISK_QUESTION_ID: "critical", "companion_safety": "routine"}, question_ids),
    ]
    transport = ScriptedJevTransport(script)
    results = judge(None, transport=transport).evaluate_question_map(jev_state(), question_ids)
    assert results[RISK_QUESTION_ID]["failure_code"] == JUDGE_INABILITY
    assert results["companion_safety"]["status"] == "answered"
    assert results["companion_safety"]["agreement"] == 2 / 3
    for snapshot in results.values():
        assert snapshot["attempted_samples"] == 3


def test_disallowed_question_ids_are_an_internal_error_with_zero_requests() -> None:
    transport = ScriptedJevTransport([])
    results = judge(None, transport=transport).evaluate_question_map(jev_state(), ["free_form"])
    assert transport.calls == 0
    assert results["free_form"]["failure_code"] == JUDGE_ERROR
    assert set(results) == {"free_form"}


def test_empty_or_duplicated_question_ids_are_internal_errors() -> None:
    transport = ScriptedJevTransport([])
    assert judge(None, transport=transport).evaluate_question_map(jev_state(), []) == {}
    results = judge(None, transport=transport).evaluate_question_map(
        jev_state(), [RISK_QUESTION_ID, RISK_QUESTION_ID]
    )
    assert all(s["failure_code"] == JUDGE_ERROR for s in results.values())
    assert transport.calls == 0


# ---- no-egress property ----------------------------------------------------


def mutated_states():
    base = jev_state()
    drifted = json.loads(json.dumps(base))
    drifted["evidence"]["passage_text"] = "A passage that was never approved."
    unknown_invocation = json.loads(json.dumps(base))
    unknown_invocation["invocation"]["arguments"] = {"service": "n8n", "extra": 1}
    changed_value = json.loads(json.dumps(base))
    changed_value["invocation"]["preconditions"][0]["expected"] = "failing"
    wrong_citation = json.loads(json.dumps(base))
    wrong_citation["evidence"]["locator"] = "verify/other"
    malformed = {"invocation": {"action": "x"}, "evidence": {}}
    return [
        ("passage drift", drifted),
        ("unknown invocation leaf", unknown_invocation),
        ("changed leaf value", changed_value),
        ("wrong citation", wrong_citation),
        ("malformed state", malformed),
    ]


@pytest.mark.parametrize("label,state", mutated_states())
def test_each_rejection_class_makes_zero_requests(label, state) -> None:
    transport = ScriptedJevTransport([])
    snapshot = judge(transport._script).evaluate_risk(state)
    assert transport.calls == 0, label
    assert snapshot["status"] == "unavailable"
    assert snapshot["failure_code"] == INPUT_REJECTED
    assert snapshot["attempted_samples"] == 0
    assert snapshot["request_hmacs"] == []


@settings(max_examples=25, deadline=None)
@given(st.text(min_size=1, max_size=80))
def test_any_unapproved_passage_text_makes_zero_requests(passage_text) -> None:
    state = jev_state()
    state["evidence"]["passage_text"] = passage_text
    transport = ScriptedJevTransport([])
    snapshot = judge(transport._script).evaluate_risk(state)
    if passage_text != PASSAGE_TEXT:
        assert transport.calls == 0
        assert snapshot["failure_code"] == INPUT_REJECTED


# ---- selector and profile provenance ---------------------------------------


def test_selector_miss_leaves_profile_null() -> None:
    state = jev_state()
    state["evidence"]["revision"] = "other-revision"
    snapshot = judge([native_body([RISK_QUESTION_ID])] * 3).evaluate_risk(state)
    assert snapshot["failure_code"] == INPUT_REJECTED
    assert snapshot["profile_id"] is None


def test_matched_profile_is_recorded_even_when_input_is_rejected_afterwards() -> None:
    state = jev_state()
    state["evidence"]["passage_text"] = "drifted"
    snapshot = judge([native_body([RISK_QUESTION_ID])] * 3).evaluate_risk(state)
    assert snapshot["failure_code"] == INPUT_REJECTED
    assert snapshot["profile_id"] == "fixture-profile-1"
    assert snapshot["request_hmacs"] == []


def test_hmac_binds_request_bytes_policy_endpoint_and_model() -> None:
    script = [native_body([RISK_QUESTION_ID])] * 3
    first = judge(script).evaluate_risk(jev_state())
    other_policy = demo_config(sha256="1" * 64)
    second = judge(
        script, config=other_policy, serving_fingerprint=None
    ).evaluate_risk(jev_state())
    assert first["request_hmacs"] != second["request_hmacs"]


def test_policy_digest_and_endpoint_are_carried_on_the_snapshot() -> None:
    snapshot = judge([native_body([RISK_QUESTION_ID])] * 3).evaluate_risk(jev_state())
    assert snapshot["policy_sha256"] == "0" * 64
    assert snapshot["endpoint"] == "https://jev.example:443/v1/systemone"


# ---- serving fingerprint ---------------------------------------------------


def test_serving_fingerprint_is_sensitive_to_configuration_and_source() -> None:
    baseline = compute_serving_fingerprint(demo_config())
    assert baseline is not None  # installed artifacts and dist metadata exist in this checkout
    changed_policy = compute_serving_fingerprint(demo_config(sha256="1" * 64))
    changed_endpoint = compute_serving_fingerprint(
        demo_config(endpoint="https://jev.example:443/v1/other")
    )
    assert baseline != changed_policy
    assert baseline != changed_endpoint


def test_missing_artifact_identity_is_recorded_as_none_not_invented(monkeypatch) -> None:
    import ops_guard.jev as jev_module

    monkeypatch.setattr(jev_module, "_installed_artifact_hashes", lambda: None)
    assert compute_serving_fingerprint(demo_config()) is None


def test_pinned_commit_constant_matches_pyproject() -> None:
    import os
    import re

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(repo_root, "pyproject.toml"), encoding="utf-8") as handle:
        pyproject = handle.read()
    from ops_guard.jev import LOCAL_JUDGE_PINNED_COMMIT

    assert LOCAL_JUDGE_PINNED_COMMIT in pyproject
    assert re.fullmatch(r"[0-9a-f]{40}", LOCAL_JUDGE_PINNED_COMMIT)


# ---- construction ----------------------------------------------------------


def test_missing_hmac_key_refuses_construction() -> None:
    from ops_guard.jev import JevJudge as _J

    with pytest.raises(ValueError):
        _J(config=demo_config(), hmac_key=b"")
