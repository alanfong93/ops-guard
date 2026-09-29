"""Local advisory judge and privacy-preserving audit projection (issue #58; ADR 0009).

Hermetic: a fake transport stands in for Ollama; no live model is contacted.
The judge is audit-only — every outcome (answered or typed failure) rides the
existing proposal transaction and never touches authorization.
"""

from __future__ import annotations

import json
import os
from datetime import timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ops_guard import AuditLog, AuditStore, ProposalService, ProposalStore
from ops_guard.judge import (
    FIXED_MODEL,
    MENU,
    RISK_QUESTION_ID,
    RUBRIC_VERSION,
    STATE_SCHEMA_VERSION,
    risk_question,
)
from local_judge.ollama import OllamaTransportTimeout, OllamaTransportUnavailable
from helpers import FakeClock
from tests_helpers_runbook import VALID_RUNBOOK

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
N8N_UPDATE = os.path.join(REPO_ROOT, "runbooks", "n8n-update.json")


def cited_revision() -> dict:
    with open(N8N_UPDATE, encoding="utf-8") as handle:
        return json.load(handle)


class FakeTransport:
    """Records every POST and replays canned outputs / transport faults."""

    def __init__(self, outputs=None, *, status_code=200, body=None, fault=None):
        self.posts: list[dict] = []
        self._outputs = list(outputs or [])
        self._status_code = status_code
        self._body = body
        self._fault = fault  # "timeout" | "unavailable" | None

    def post(self, path, payload, timeout_ms):
        self.posts.append({"path": path, "payload": payload, "timeout_ms": timeout_ms})
        if path.endswith("/api/show"):
            return type("R", (), {"status_code": 404, "body": "not found"})()
        if self._fault == "timeout":
            raise OllamaTransportTimeout("too slow")
        if self._fault == "unavailable":
            raise OllamaTransportUnavailable("down")
        if self._status_code != 200:
            return type("R", (), {"status_code": self._status_code, "body": self._body or ""})()
        output = self._outputs.pop(0) if self._outputs else '{"reason": "INSUFFICIENT_EVIDENCE"}'
        return type(
            "R", (), {"status_code": 200, "body": json.dumps({"message": {"content": output}})}
        )()

    def attempt_count(self) -> int:
        return len([p for p in self.posts if p["path"].endswith("/api/chat")])


def sample_state() -> dict:
    revision = cited_revision()
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "invocation": {
            "action": revision["operation"]["action"],
            "target": revision["operation"]["target"],
            "arguments": {"service": "n8n"},
            "preconditions": [dict(item) for item in revision["preconditions"]],
        },
        "evidence": {
            "runbook_id": revision["runbook_id"],
            "revision": revision["revision"],
            "content_hash": revision["content_hash"],
            "locator": "update/ordering",
            "operation": dict(revision["operation"]),
            "preconditions": [dict(item) for item in revision["preconditions"]],
            "passage_text": "PUBLIC-PASSAGE-SENTINEL update n8n first",
        },
    }


def make_judge(transport, **kwargs):
    from ops_guard.judge import LocalJudge

    return LocalJudge(transport=transport, **kwargs)


def test_fixed_profile_menu_settings_are_immutable() -> None:
    transport = FakeTransport(
        outputs=['"routine"', '"routine"', '"routine"']
    )
    judge = make_judge(transport)
    projection = judge.evaluate_risk(sample_state())
    assert FIXED_MODEL == "qwen3:8b"
    assert set(MENU) == {"routine", "review", "critical"}
    assert RUBRIC_VERSION == "ops-guard-risk-rubric-v1"
    assert STATE_SCHEMA_VERSION == "ops-guard-risk-state-v1"
    assert projection["sample_count"] == 3
    assert projection["temperature"] == 0
    assert projection["timeout_ms"] == 10000
    assert projection["model"] == "qwen3:8b"
    assert projection["status"] == "answered"
    assert projection["risk_class"] == "routine"


def test_exact_menu_schema_forwarded_in_every_format_payload() -> None:
    transport = FakeTransport(outputs=['"review"', '"review"', '"review"'])
    judge = make_judge(transport)
    judge.evaluate_risk(sample_state())
    from local_judge.executors.choice import ChoiceExecutor

    expected = ChoiceExecutor(MENU).output_schema(risk_question())
    chats = [p for p in transport.posts if p["path"].endswith("/api/chat")]
    assert len(chats) == 3
    for post in chats:
        assert post["payload"]["format"] == expected
        assert post["payload"]["model"] == FIXED_MODEL
        assert post["payload"]["stream"] is False
        assert post["payload"]["options"]["temperature"] == 0


def test_answered_vote_share_and_agreement() -> None:
    transport = FakeTransport(outputs=['"review"', '"review"', '"critical"'])
    judge = make_judge(transport)
    projection = judge.evaluate_risk(sample_state())
    assert projection["status"] == "answered"
    assert projection["risk_class"] == "review"
    assert projection["vote_share"] == {"routine": 0.0, "review": pytest.approx(2 / 3), "critical": pytest.approx(1 / 3)}
    assert projection["agreement"] == pytest.approx(2 / 3)


def test_exactly_three_sequential_attempts() -> None:
    transport = FakeTransport(outputs=['"routine"'] * 3)
    judge = make_judge(transport)
    judge.evaluate_risk(sample_state())
    assert transport.attempt_count() == 3


def test_single_and_multi_question_internal_evaluator() -> None:
    transport = FakeTransport(
        outputs=['"routine"', '"routine"', '"routine"', '"critical"', '"critical"', '"critical"']
    )
    judge = make_judge(transport)
    state = sample_state()
    results = judge.evaluate_question_map(state, ["q1", "q2"])
    assert set(results) == {"q1", "q2"}
    assert results["q1"]["risk_class"] == "routine"
    assert results["q2"]["risk_class"] == "critical"
    assert transport.attempt_count() == 6


def test_transport_timeout_maps_to_judge_timeout() -> None:
    transport = FakeTransport(fault="timeout")
    judge = make_judge(transport)
    projection = judge.evaluate_risk(sample_state())
    assert projection["status"] == "judge_timeout"
    assert set(projection) <= ALLOWED_PROJECTION_FIELDS


def test_transport_unavailable_maps_to_judge_unavailable() -> None:
    transport = FakeTransport(fault="unavailable")
    judge = make_judge(transport)
    projection = judge.evaluate_risk(sample_state())
    assert projection["status"] == "judge_unavailable"


def test_invalid_model_output_maps_to_judge_invalid_output() -> None:
    transport = FakeTransport(outputs=["not json", "also not json", '{"choice": "routine"}'])
    judge = make_judge(transport)
    projection = judge.evaluate_risk(sample_state())
    assert projection["status"] == "judge_invalid_output"


def test_aggregation_tie_maps_to_judge_inability() -> None:
    transport = FakeTransport(outputs=['"routine"', '"review"', '"critical"'])
    judge = make_judge(transport)
    projection = judge.evaluate_risk(sample_state())
    assert projection["status"] == "judge_inability"


def test_context_overflow_maps_to_judge_input_rejected() -> None:
    transport = FakeTransport(status_code=400, body="context window exceeded")
    judge = make_judge(transport)
    projection = judge.evaluate_risk(sample_state())
    assert projection["status"] == "judge_input_rejected"


def test_oversized_input_is_rejected_structurally() -> None:
    transport = FakeTransport()
    judge = make_judge(transport)
    state = sample_state()
    state["invocation"]["arguments"] = {"blob": "x" * (300 * 1024)}
    projection = judge.evaluate_risk(state)
    assert projection["status"] == "judge_input_rejected"
    assert projection["trace_id"] is None
    assert transport.attempt_count() == 0


def test_model_digest_unavailable_is_recorded_never_blocking() -> None:
    transport = FakeTransport(outputs=['"routine"'] * 3)  # /api/show 404s
    judge = make_judge(transport)
    projection = judge.evaluate_risk(sample_state())
    assert projection["model_digest"] is None
    assert projection["model_digest_status"] == "unavailable"
    assert projection["status"] == "answered"


def test_trace_id_present_when_answered_and_null_on_structural_rejection() -> None:
    transport = FakeTransport(outputs=['"routine"'] * 3)
    judge = make_judge(transport)
    answered = judge.evaluate_risk(sample_state())
    assert isinstance(answered["trace_id"], str) and answered["trace_id"]

    oversized = sample_state()
    oversized["invocation"]["arguments"] = {"blob": "x" * (300 * 1024)}
    rejected = judge.evaluate_risk(oversized)
    assert rejected["trace_id"] is None


def test_request_fingerprint_is_stable_and_present() -> None:
    transport = FakeTransport(outputs=['"routine"'] * 3)
    audit = AuditLog(AuditStore(":memory:"), fingerprint_key=os.urandom(32), clock=FakeClock())
    judge = make_judge(transport, fingerprint=audit.fingerprint)
    first = judge.evaluate_risk(sample_state())
    second = judge.evaluate_risk(sample_state())
    assert first["request_fingerprint"]
    assert first["request_fingerprint"] == second["request_fingerprint"]


def test_no_raw_secret_or_passage_text_in_projection() -> None:
    transport = FakeTransport(outputs=['"routine"'] * 3)
    judge = make_judge(transport, fingerprint=lambda value: "fp")
    state = sample_state()
    state["evidence"]["passage_text"] = "SECRET-CREDENTIALS-MARKER"
    state["invocation"]["arguments"] = {"password": "SECRET-ARG-MARKER"}
    projection = judge.evaluate_risk(state)
    serialized = json.dumps(projection)
    assert "SECRET-CREDENTIALS-MARKER" not in serialized
    assert "SECRET-ARG-MARKER" not in serialized
    assert "PUBLIC-PASSAGE-SENTINEL" not in serialized


ALLOWED_PROJECTION_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "risk_class",
        "vote_share",
        "agreement",
        "sample_count",
        "temperature",
        "timeout_ms",
        "state_schema_version",
        "rubric_version",
        "prompt_version",
        "menu",
        "model",
        "model_digest",
        "model_digest_status",
        "trace_id",
        "question_id",
        "citation_refs",
        "request_fingerprint",
    }
)


def test_projection_is_closed_and_versioned() -> None:
    transport = FakeTransport(outputs=['"routine"'] * 3)
    judge = make_judge(transport, fingerprint=lambda value: "fp")
    projection = judge.evaluate_risk(sample_state())
    assert set(projection) <= ALLOWED_PROJECTION_FIELDS
    assert projection["schema_version"] == "ops-guard-risk-projection-v1"
    assert projection["citation_refs"][0].endswith("@2026-09-29.1")


@given(junk=st.text(min_size=0, max_size=20))
@settings(max_examples=25, deadline=None)
def test_judge_outcome_never_blocks_issuance(tmp_path_factory, junk: str) -> None:
    """No judge outcome (any class or failure) changes proposal issuance."""
    tmp_path = tmp_path_factory.mktemp("judge-neutral")
    clock = FakeClock()
    db = str(tmp_path / "j.db")
    audit = AuditLog(AuditStore(db), fingerprint_key=os.urandom(32), clock=clock)
    service = ProposalService(
        ProposalStore(db), token_key=os.urandom(32), clock=clock, audit=audit
    )
    from ops_guard.invocation import Invocation

    invocation = Invocation(
        action="update",
        target="n8n",
        arguments={},
        preconditions=[{"name": "docker-engine", "expected": "running"}],
        runbook_revision_hash=VALID_RUNBOOK["content_hash"],
    )
    for snapshot in (
        {"schema_version": "ops-guard-risk-projection-v1", "status": "answered", "risk_class": "routine"},
        {"schema_version": "ops-guard-risk-projection-v1", "status": "judge_timeout"},
        {"schema_version": "ops-guard-risk-projection-v1", "status": "judge_error"},
        None,
    ):
        issued = service.open_proposal(
            invocation, ttl=timedelta(minutes=15), judge_snapshot=snapshot
        )
        assert issued.token
        assert issued.proposal_id
