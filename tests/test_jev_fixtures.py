"""Self-verifying contract fixtures (issue #91; ADR 0014).

The committed fixtures under ``tests/fixtures/jev/`` are regenerated here
from the fixed definitions and compared byte-for-byte: a drift in the
question object, the menu, the projection, or the serializer fails the
suite instead of silently changing the wire contract. The request-HMAC
example pins the exact HMAC message layout.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os

from ops_guard.jev import (
    JEV_MODEL,
    RISK_QUESTION_ID,
    native_request_bytes,
    parse_native_response,
    project_jev_state,
    serialize_exact,
)
from ops_guard.judge import risk_question

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures", "jev")

FIXTURE_INVOCATION = {
    "action": "verify",
    "target": "n8n",
    "arguments": {},
    "preconditions": [],
    "runbook_revision_hash": "c" * 64,
}
FIXTURE_PASSAGE = "An explicitly approved exact passage."


def _read_fixture(name: str) -> dict:
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as handle:
        return json.load(handle)


def _fixture_state() -> dict:
    import sys

    sys.path.insert(0, HERE)
    from jev_fixtures import demo_grant

    grant = demo_grant(invocation_json=FIXTURE_INVOCATION, passage_text=FIXTURE_PASSAGE)
    return project_jev_state(
        invocation_json=FIXTURE_INVOCATION, passage_text=FIXTURE_PASSAGE, grant=grant
    )


def test_request_fixture_matches_the_fixed_definitions() -> None:
    fixture = _read_fixture("native-request.fixture.json")
    request = native_request_bytes(_fixture_state(), [RISK_QUESTION_ID])
    assert request == fixture["exact_bytes"].encode("utf-8")
    assert hashlib.sha256(request).hexdigest() == fixture["sha256"]
    body = json.loads(request.decode("utf-8"))
    assert list(body) == ["model", "state", "questions"]
    assert body["model"] == JEV_MODEL
    assert list(body["questions"]) == [RISK_QUESTION_ID]
    assert body["questions"][RISK_QUESTION_ID] == risk_question()


def test_response_fixture_parses_under_the_closed_schema() -> None:
    fixture = _read_fixture("native-response.fixture.json")
    raw = serialize_exact(fixture["response"])
    assert raw == fixture["exact_bytes"].encode("utf-8")
    assert hashlib.sha256(raw).hexdigest() == fixture["sha256"]
    parsed = parse_native_response(raw, [RISK_QUESTION_ID])
    assert parsed["model"] == JEV_MODEL
    assert parsed["answers"][RISK_QUESTION_ID]["choice"] == "routine"


def test_request_hmac_message_layout_is_pinned() -> None:
    """The audit HMAC covers the exact request bytes, the policy digest, the
    endpoint identity, and the model — in that order, newline-joined."""
    from ops_guard.jev import JevConfig, EgressPolicy, JevJudge
    from jev_fixtures import demo_grant

    config = JevConfig(
        endpoint="https://jev.example:443/v1/systemone",
        allowed_endpoints=("https://jev.example:443/v1/systemone",),
        bearer_token="fixture-token-" + "x" * 24,
        policy=EgressPolicy(grants=(demo_grant(
            invocation_json=FIXTURE_INVOCATION, passage_text=FIXTURE_PASSAGE
        ),), sha256="0" * 64),
    )
    request = native_request_bytes(_fixture_state(), [RISK_QUESTION_ID])
    judge = JevJudge(config=config, hmac_key=bytes.fromhex("aa" * 32), transport=None)
    expected = hmac.new(
        bytes.fromhex("aa" * 32),
        b"\n".join([
            request,
            b"0" * 64,
            b"https://jev.example:443/v1/systemone",
            b"jev-1.13.0",
        ]),
        hashlib.sha256,
    ).hexdigest()
    assert judge._request_hmac(request) == expected
