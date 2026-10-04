"""Strict native wire contract: response parser and sample aggregation
(issue #91; ADR 0014).

Property-based: for any valid probability distribution over the fixed
menu the parser accepts, and any structural or numeric break it rejects.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ops_guard.jev import (
    JEV_MODEL,
    JEV_SAMPLE_COUNT,
    NativeResponseError,
    aggregate_native_samples,
    native_request_bytes,
    parse_native_response,
    project_jev_state,
    serialize_exact,
)
from ops_guard.judge import MENU, RISK_QUESTION_ID
from jev_fixtures import (
    PASSAGE_TEXT,
    demo_grant,
    native_body,
    synthetic_invocation_json,
)

QUESTION_IDS = [RISK_QUESTION_ID]


# ---- parser ---------------------------------------------------------------


def test_valid_response_parses_to_validated_answers() -> None:
    parsed = parse_native_response(native_body(QUESTION_IDS), QUESTION_IDS)
    assert parsed["model"] == JEV_MODEL
    answer = parsed["answers"][RISK_QUESTION_ID]
    assert answer["choice"] == "routine"
    assert set(answer["probabilities"]) == set(MENU)
    assert 0.0 <= answer["confidence"] <= 1.0
    assert parsed["usage"] == {"input_tokens": 120, "output_tokens": 8}


def test_selected_choice_may_tie_for_the_maximum() -> None:
    body = json.loads(native_body(QUESTION_IDS).decode())
    answer = body["answers"][RISK_QUESTION_ID]
    answer["probabilities"] = {"routine": 0.5, "review": 0.5, "critical": 0.0}
    answer["choice"] = "review"
    parsed = parse_native_response(json.dumps(body).encode(), QUESTION_IDS)
    assert parsed["answers"][RISK_QUESTION_ID]["choice"] == "review"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda body: body.update(extra=1),
        lambda body: body.pop("usage"),
        lambda body: body.update(model="jev-latest"),
        lambda body: body["answers"].update(companion_safety={}),
        lambda body: body["answers"].pop(RISK_QUESTION_ID),
        lambda body: body["answers"].update({RISK_QUESTION_ID: {"type": "score", "choice": "routine", "probabilities": {"routine": 1.0, "review": 0.0, "critical": 0.0}, "confidence": 0.5}}),
        lambda body: body["answers"][RISK_QUESTION_ID].update(choice="invented"),
        lambda body: body["answers"][RISK_QUESTION_ID].update(choice=["routine"]),
        lambda body: body["answers"][RISK_QUESTION_ID]["probabilities"].update(routine=0.9),
        lambda body: body["answers"][RISK_QUESTION_ID]["probabilities"].update(critical=1.5),
        lambda body: body["answers"][RISK_QUESTION_ID]["probabilities"].update(routine=True),
        lambda body: body["answers"][RISK_QUESTION_ID].update(confidence=1.5),
        lambda body: body["answers"][RISK_QUESTION_ID].update(confidence=True),
        lambda body: body["answers"][RISK_QUESTION_ID].pop("confidence"),
        lambda body: body["answers"][RISK_QUESTION_ID].update(extra_field=1),
        lambda body: body.update(usage={"input_tokens": -1, "output_tokens": 1}),
        lambda body: body.update(usage={"input_tokens": 1.5, "output_tokens": 1}),
        lambda body: body.update(usage={"input_tokens": True, "output_tokens": 1}),
        lambda body: body.update(usage={"input_tokens": 1, "output_tokens": 1, "total": 2}),
    ],
)
def test_broken_responses_rejected(mutate) -> None:
    body = json.loads(native_body(QUESTION_IDS).decode())
    mutate(body)
    with pytest.raises(NativeResponseError):
        parse_native_response(json.dumps(body).encode(), QUESTION_IDS)


def test_probability_sum_tolerance_is_strict() -> None:
    for distribution, ok in [
        ({"routine": 0.4, "review": 0.3, "critical": 0.3}, True),
        ({"routine": 0.4, "review": 0.3, "critical": 0.3000005}, True),
        ({"routine": 0.4, "review": 0.3, "critical": 0.301}, False),
    ]:
        body = json.loads(native_body(QUESTION_IDS).decode())
        body["answers"][RISK_QUESTION_ID]["probabilities"] = distribution
        if ok:
            parse_native_response(json.dumps(body).encode(), QUESTION_IDS)
        else:
            with pytest.raises(NativeResponseError):
                parse_native_response(json.dumps(body).encode(), QUESTION_IDS)


def test_duplicate_keys_and_nonfinite_rejected() -> None:
    duplicated = (
        '{"model":"jev-1.13.0","answers":{},"usage":{"input_tokens":1,"output_tokens":1},'
        '"answers":{}}'
    )
    with pytest.raises(NativeResponseError, match="duplicate"):
        parse_native_response(duplicated.encode(), QUESTION_IDS)
    with pytest.raises(NativeResponseError):
        parse_native_response(
            b'{"model":"jev-1.13.0","answers":{},"usage":{"input_tokens":NaN,"output_tokens":1}}',
            QUESTION_IDS,
        )
    with pytest.raises(NativeResponseError):
        parse_native_response(
            b'{"model":"jev-1.13.0","answers":{},'
            b'"usage":{"input_tokens":1e999,"output_tokens":1}}',
            QUESTION_IDS,
        )


def test_invalid_utf8_and_garbage_rejected() -> None:
    with pytest.raises(NativeResponseError):
        parse_native_response(b"\xff\xfe{}", QUESTION_IDS)
    with pytest.raises(NativeResponseError):
        parse_native_response(b"not json", QUESTION_IDS)


def test_question_map_must_match_exactly() -> None:
    with pytest.raises(NativeResponseError):
        parse_native_response(native_body([RISK_QUESTION_ID]), [])
    with pytest.raises(NativeResponseError):
        parse_native_response(
            native_body([RISK_QUESTION_ID]),
            [RISK_QUESTION_ID, "companion_safety"],
        )


# ---- aggregation ----------------------------------------------------------


def labels(*choices: str) -> list[dict]:
    return [{RISK_QUESTION_ID: choice} for choice in choices]


def test_unique_majority_answers_with_counts_over_three() -> None:
    aggregate = aggregate_native_samples(labels("routine", "routine", "review"), QUESTION_IDS)
    assert aggregate[RISK_QUESTION_ID]["choice"] == "routine"
    assert aggregate[RISK_QUESTION_ID]["vote_share"] == {
        "routine": 2 / 3,
        "review": 1 / 3,
        "critical": 0.0,
    }
    assert aggregate[RISK_QUESTION_ID]["agreement"] == 2 / 3


def test_unanimous_answers_have_full_agreement() -> None:
    aggregate = aggregate_native_samples(labels("critical", "critical", "critical"), QUESTION_IDS)
    assert aggregate[RISK_QUESTION_ID]["agreement"] == 1.0


def test_three_way_tie_is_inability() -> None:
    aggregate = aggregate_native_samples(labels("routine", "review", "critical"), QUESTION_IDS)
    assert aggregate[RISK_QUESTION_ID] == {"failure": "judge_inability"}


def test_aggregation_requires_all_three_samples() -> None:
    with pytest.raises(ValueError):
        aggregate_native_samples(labels("routine", "routine"), QUESTION_IDS)


def test_companion_questions_aggregate_independently() -> None:
    question_ids = [RISK_QUESTION_ID, "companion_safety"]
    samples = [
        {RISK_QUESTION_ID: "routine", "companion_safety": "review"},
        {RISK_QUESTION_ID: "review", "companion_safety": "review"},
        {RISK_QUESTION_ID: "critical", "companion_safety": "routine"},
    ]
    aggregate = aggregate_native_samples(samples, question_ids)
    assert aggregate[RISK_QUESTION_ID] == {"failure": "judge_inability"}
    assert aggregate["companion_safety"]["choice"] == "review"
    assert aggregate["companion_safety"]["agreement"] == 2 / 3


# ---- request bytes --------------------------------------------------------


def test_native_request_carries_exactly_model_state_questions() -> None:
    state = project_jev_state(
        invocation_json=synthetic_invocation_json(),
        passage_text=PASSAGE_TEXT,
        grant=demo_grant(),
    )
    raw = native_request_bytes(state, [RISK_QUESTION_ID])
    body = json.loads(raw.decode("utf-8"))
    assert set(body) == {"model", "state", "questions"}
    assert body["model"] == JEV_MODEL
    assert set(body["questions"]) == {RISK_QUESTION_ID}
    question = body["questions"][RISK_QUESTION_ID]
    assert set(question) == {"type", "instructions", "criteria"}
    assert question["criteria"] == dict(MENU)
    assert raw == serialize_exact(body)


def test_native_request_preserves_question_order() -> None:
    state = project_jev_state(
        invocation_json=synthetic_invocation_json(),
        passage_text=PASSAGE_TEXT,
        grant=demo_grant(),
    )
    ordered = ["companion_scope", "risk_class", "companion_safety"]
    body = json.loads(native_request_bytes(state, ordered).decode("utf-8"))
    assert list(body["questions"]) == ordered


# ---- properties ------------------------------------------------------------

valid_probability = st.floats(min_value=0.0, max_value=1.0)


@settings(max_examples=50, deadline=None)
@given(
    st.tuples(valid_probability, valid_probability, valid_probability).filter(lambda t: sum(t) > 0),
    st.sampled_from(sorted(MENU)),
)
def test_any_normalized_distribution_with_attaining_choice_parses(weights, choice) -> None:
    total = sum(weights)
    values = [weight / total for weight in weights]
    distribution = dict(zip(sorted(MENU), values))
    body = json.loads(native_body(QUESTION_IDS).decode())
    answer = body["answers"][RISK_QUESTION_ID]
    answer["probabilities"] = distribution
    # The selected choice must attain (one of) the maxima.
    top = max(distribution.values())
    answer["choice"] = choice if distribution[choice] >= top else max(distribution, key=distribution.get)
    parsed = parse_native_response(json.dumps(body).encode(), QUESTION_IDS)
    assert parsed["answers"][RISK_QUESTION_ID]["choice"] == answer["choice"]
    assert parsed["answers"][RISK_QUESTION_ID]["probabilities"] == distribution


def test_aggregation_equations_hold_for_every_label_multiset() -> None:
    # The space is small: every multiset of 3 labels over 3 options.
    from itertools import product

    for combo in product(sorted(MENU), repeat=JEV_SAMPLE_COUNT):
        aggregate = aggregate_native_samples(labels(*combo), QUESTION_IDS)
        counts = {option: combo.count(option) for option in MENU}
        top = max(counts.values())
        winners = [option for option, count in counts.items() if count == top]
        if len(winners) > 1:
            assert aggregate[RISK_QUESTION_ID] == {"failure": "judge_inability"}
        else:
            assert aggregate[RISK_QUESTION_ID]["choice"] == winners[0]
            assert aggregate[RISK_QUESTION_ID]["agreement"] == top / 3
            assert aggregate[RISK_QUESTION_ID]["vote_share"] == {
                option: count / 3 for option, count in counts.items()
            }
