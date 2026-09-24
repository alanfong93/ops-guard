"""Fail-closed execution gate (issue #14; adversarial done-when tests)."""

from __future__ import annotations

import json
import os
from datetime import timedelta

import pytest

from ops_guard import (
    ApprovalStore,
    ApprovalVerifier,
    AuditLog,
    AuditStore,
    AuditWriteFailure,
    Citation,
    ExecutionGate,
    ExecutionRequest,
    GateConfigurationError,
    Invocation,
    ProposalService,
    ProposalStore,
    ScriptIdentity,
    StandingAuthorization,
    TokenAlreadyConsumedError,
    parse_authorization,
)
from helpers import make_invocation
from tests_helpers_runbook import VALID_RUNBOOK

OPERATOR = "alan"
SCRIPT = ScriptIdentity(path="/opt/scripts/restart-n8n.sh", sha256="a" * 64)


def base_authorization() -> StandingAuthorization:
    return parse_authorization({
        "authorization_id": "auth-restart-n8n",
        "script_path": SCRIPT.path,
        "script_sha256": SCRIPT.sha256,
        "action": "restart",
        "target": "n8n",
        "arguments": {"service": "n8n", "timeout_seconds": 30},
        "preconditions": [{"name": "healthcheck", "expected": "passing"}],
        "runbook_revision_hash": VALID_RUNBOOK["content_hash"],
    })


def citation() -> Citation:
    return Citation(
        runbook_id=VALID_RUNBOOK["runbook_id"],
        revision=VALID_RUNBOOK["revision"],
        content_hash=VALID_RUNBOOK["content_hash"],
        locator="restart/steps",
    )


def make_request(**overrides) -> ExecutionRequest:
    fields = dict(
        token="token-placeholder",
        script=SCRIPT,
        runbook_document=VALID_RUNBOOK,
        citation=citation(),
        observed_preconditions={"healthcheck": "passing"},
        operator_identity=OPERATOR,
        standing=base_authorization(),
        expected_digest=None,
    )
    fields.update(overrides)
    return ExecutionRequest(**fields)


class Harness:
    """Wired gate on one shared database."""

    def __init__(self, tmp_path, token_key, clock):
        path = str(tmp_path / "ops-guard.db")
        self.clock = clock
        self.service = ProposalService(ProposalStore(path), token_key=token_key, clock=clock)
        self.verifier = ApprovalVerifier(
            ApprovalStore(path), self.service, operator_identity=OPERATOR, clock=clock
        )
        self.audit = AuditLog(AuditStore(path), fingerprint_key=os.urandom(32), clock=clock)
        self.gate = ExecutionGate(self.service, self.verifier, self.audit, clock=clock)
        self.executor_calls: list[Invocation] = []

    def issue(self, **overrides) -> object:
        overrides.setdefault("runbook_revision_hash", VALID_RUNBOOK["content_hash"])
        invocation = make_invocation(**overrides)
        issued = self.service.open_proposal(invocation, ttl=timedelta(minutes=10))
        return issued

    def executor(self, invocation: Invocation) -> str:
        self.executor_calls.append(invocation)
        return "success"


@pytest.fixture()
def harness(tmp_path, token_key, clock) -> Harness:
    return Harness(tmp_path, token_key, clock)



def test_successful_standing_dispatch_consumes_and_records(harness: Harness) -> None:
    issued = harness.issue()
    request = make_request(token=issued.token, expected_digest=issued.invocation_digest)
    outcome = harness.gate.execute(request, harness.executor)
    assert outcome.dispatched and outcome.authorization_path == "standing"
    assert outcome.outcome == "success"
    assert len(harness.executor_calls) == 1
    with pytest.raises(TokenAlreadyConsumedError):
        harness.service.resolve(issued.token)
    events = harness.audit.events()
    types = [e.event_type for e in events]
    assert types[0] == "execution_start"
    assert "execution_outcome" in types
    assert events[0].proposal_ref == issued.proposal_id


def test_gate_rejects_split_audit_store_before_any_dispatch(tmp_path, token_key, clock) -> None:
    """One execution history must live in one database (issue #36)."""
    proposal_path = str(tmp_path / "ops-guard.db")
    audit_path = str(tmp_path / "audit-elsewhere.db")
    service = ProposalService(ProposalStore(proposal_path), token_key=token_key, clock=clock)
    verifier = ApprovalVerifier(
        ApprovalStore(proposal_path), service, operator_identity=OPERATOR, clock=clock
    )
    audit = AuditLog(AuditStore(audit_path), fingerprint_key=os.urandom(32), clock=clock)
    executor_calls: list[Invocation] = []

    def executor(invocation: Invocation) -> str:
        executor_calls.append(invocation)
        return "success"

    with pytest.raises(GateConfigurationError):
        ExecutionGate(service, verifier, audit, clock=clock)

    # The mismatched configuration never reached dispatch: the executor did
    # not run and no partial execution trail was written to either database.
    assert executor_calls == []
    with ProposalStore(proposal_path).read() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM proposals WHERE state = 'consumed'"
        ).fetchone()[0] == 0
        # No audit record landed in the proposal database: in a split
        # configuration the audit_events table does not even exist there.
        tables = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert "audit_events" not in tables
    split_audit = AuditLog(AuditStore(audit_path), fingerprint_key=os.urandom(32), clock=clock)
    assert split_audit.events() == []


def test_gate_on_one_shared_database_dispatches_atomically(tmp_path, token_key, clock) -> None:
    harness = Harness(tmp_path, token_key, clock)
    issued = harness.issue()
    outcome = harness.gate.execute(
        make_request(token=issued.token, expected_digest=issued.invocation_digest),
        harness.executor,
    )
    assert outcome.dispatched and outcome.authorization_path == "standing"
    events = harness.audit.events()
    assert [e.event_type for e in events][0] == "execution_start"
    with pytest.raises(TokenAlreadyConsumedError):
        harness.service.resolve(issued.token)


def test_successful_approval_dispatch_spends_the_approval(harness: Harness) -> None:
    issued = harness.issue()
    harness.verifier.record_approval(issued.token, operator_identity=OPERATOR)
    request = make_request(
        token=issued.token, standing=None, expected_digest=issued.invocation_digest
    )
    outcome = harness.gate.execute(request, harness.executor)
    assert outcome.dispatched and outcome.authorization_path == "proposal-bound"
    with pytest.raises(Exception, match="already spent"):
        harness.verifier.verify(issued.token, operator_identity=OPERATOR)


def test_unknown_outcome_is_recorded_explicitly(harness: Harness) -> None:
    issued = harness.issue()

    def unknown_executor(invocation: Invocation) -> str:
        harness.executor_calls.append(invocation)
        return "unknown"

    outcome = harness.gate.execute(make_request(token=issued.token), unknown_executor)
    assert outcome.dispatched and outcome.outcome == "unknown"
    outcome_events = [e for e in harness.audit.events() if e.event_type == "execution_outcome"]
    assert outcome_events[-1].outcome == "unknown"


def test_executor_failure_is_recorded_then_raised(harness: Harness) -> None:
    issued = harness.issue()

    def failing_executor(invocation: Invocation) -> str:
        harness.executor_calls.append(invocation)
        raise RuntimeError("service did not come back")

    with pytest.raises(RuntimeError):
        harness.gate.execute(make_request(token=issued.token), failing_executor)
    events = harness.audit.events()
    failure = [e for e in events if e.event_type == "execution_outcome"]
    assert failure and failure[-1].outcome == "failure"
    assert failure[-1].failure_code == "executor-error"


@pytest.mark.parametrize(
    "mutation",
    [
        "absent-evidence",
        "tampered-evidence",
        "unverified-evidence",
        "unknown-passage",
        "evidence-operation-mismatch",
        "missing-observation",
        "wrong-observation",
        "unknown-token",
        "expired-token",
        "consumed-token",
        "no-standing-no-approval",
        "approval-replay",
        "host-supplied-approval",
        "wrong-operator",
        "audit-failure",
        "mismatched-expected-digest",
        "different-revision-evidence",
    ],
)
def test_every_unavailable_input_prevents_dispatch(mutation: str, harness: Harness) -> None:
    issued = harness.issue()
    harness.verifier.record_approval(issued.token, operator_identity=OPERATOR)

    overrides: dict = {"token": issued.token, "standing": None}
    if mutation == "absent-evidence":
        overrides["runbook_document"] = {}
    elif mutation == "tampered-evidence":
        document = json.loads(json.dumps(VALID_RUNBOOK))
        document["passages"][0]["text"] = "edited after verification"
        overrides["runbook_document"] = document
    elif mutation == "unverified-evidence":
        document = json.loads(json.dumps(VALID_RUNBOOK))
        del document["verification"]
        overrides["runbook_document"] = document
    elif mutation == "unknown-passage":
        overrides["citation"] = Citation(
            runbook_id=VALID_RUNBOOK["runbook_id"],
            revision=VALID_RUNBOOK["revision"],
            content_hash=VALID_RUNBOOK["content_hash"],
            locator="nope",
        )
    elif mutation == "evidence-operation-mismatch":
        overrides["standing"] = base_authorization()
        overrides["standing"] = parse_authorization({
            "authorization_id": "other",
            "script_path": SCRIPT.path,
            "script_sha256": SCRIPT.sha256,
            "action": "destroy",
            "target": "n8n",
            "arguments": {"service": "n8n", "timeout_seconds": 30},
            "preconditions": [{"name": "healthcheck", "expected": "passing"}],
            "runbook_revision_hash": "b" * 64,
        })
        harness_issue = harness.issue(action="destroy")
        overrides["token"] = harness_issue.token
        harness.verifier.record_approval(harness_issue.token, operator_identity=OPERATOR)
    elif mutation == "missing-observation":
        overrides["observed_preconditions"] = {}
    elif mutation == "wrong-observation":
        overrides["observed_preconditions"] = {"healthcheck": "failing"}
    elif mutation == "unknown-token":
        overrides["token"] = "never-issued"
    elif mutation == "expired-token":
        harness.clock.advance(11 * 60)
    elif mutation == "consumed-token":
        harness.service.consume(issued.token)
    elif mutation == "no-standing-no-approval":
        plain = harness.issue()
        overrides["token"] = plain.token
        overrides["standing"] = None
    elif mutation == "approval-replay":
        harness.service.consume(issued.token, same_transaction=harness.verifier.mark_used_append(issued.token))
        second = harness.issue()
        overrides["token"] = second.token
        harness.verifier.record_approval(second.token, operator_identity=OPERATOR)
        # spend the second approval, then present the spent token again below
        harness.service.consume(second.token)
        overrides["token"] = issued.token
        overrides["standing"] = None
    elif mutation == "host-supplied-approval":
        plain = harness.issue()
        overrides["token"] = plain.token
        overrides["standing"] = None
    elif mutation == "wrong-operator":
        overrides["operator_identity"] = "mallory"
        overrides["standing"] = None
    elif mutation == "audit-failure":
        original_append_on = harness.audit.append_on

        def failing_append_on(conn, event_type, **kwargs):
            if event_type == "execution_start":
                raise AuditWriteFailure("audit store unavailable")
            return original_append_on(conn, event_type, **kwargs)

        harness.audit.append_on = failing_append_on  # type: ignore[method-assign]
    elif mutation == "mismatched-expected-digest":
        overrides["expected_digest"] = "0" * 64
    elif mutation == "different-revision-evidence":
        # A different, fully valid, human-verified revision - same operation,
        # different content. The proposal froze the original revision's hash.
        import hashlib

        from ops_guard.invocation import canonicalize_json

        other = json.loads(json.dumps(VALID_RUNBOOK))
        other["revision"] = "2026-09-23.2"
        other["passages"][0]["text"] = "a different procedure the proposal never froze"
        body = {k: v for k, v in other.items() if k != "content_hash"}
        other["content_hash"] = hashlib.sha256(canonicalize_json(body)).hexdigest()
        overrides["runbook_document"] = other
        overrides["citation"] = Citation(
            runbook_id=other["runbook_id"],
            revision=other["revision"],
            content_hash=other["content_hash"],
            locator="restart/steps",
        )
        overrides["standing"] = base_authorization()

    outcome = harness.gate.execute(make_request(**overrides), harness.executor)

    assert not outcome.dispatched
    assert outcome.refusal
    assert harness.executor_calls == []  # never dispatched
    if mutation not in ("consumed-token", "approval-replay", "unknown-token", "expired-token"):
        # the token stays eligible - nothing was spent by a refused attempt.
        # A TokenAlreadyConsumedError here is real leakage: fail the test.
        frozen = harness.service.resolve(issued.token)
        assert not frozen.consumed


def test_refusals_are_audit_recorded_before_any_side_effect(harness: Harness) -> None:
    issued = harness.issue()
    outcome = harness.gate.execute(make_request(token=issued.token, standing=None), harness.executor)
    assert not outcome.dispatched
    refusals = [e for e in harness.audit.events() if e.event_type == "refusal"]
    assert refusals, "refusal must be audit-recorded"
    assert refusals[-1].payload["reason"]


def test_expired_token_refusal(harness: Harness) -> None:
    issued = harness.issue()
    harness.clock.advance(11 * 60)
    outcome = harness.gate.execute(make_request(token=issued.token), harness.executor)
    assert not outcome.dispatched and "expired" in outcome.refusal


def test_standing_mismatch_falls_back_to_approval(harness: Harness) -> None:
    """Pinned deliberately (cycle 2): a standing mismatch is not a refusal —
    the approval path still authorizes, and the supplied script identity is
    recorded as-is for the MCP layer to verify (#16 handoff)."""
    issued = harness.issue()
    harness.verifier.record_approval(issued.token, operator_identity=OPERATOR)
    mismatched = parse_authorization({
        "authorization_id": "other-rule",
        "script_path": SCRIPT.path,
        "script_sha256": SCRIPT.sha256,
        "action": "destroy",
        "target": "n8n",
        "arguments": {"service": "n8n", "timeout_seconds": 30},
        "preconditions": [{"name": "healthcheck", "expected": "passing"}],
        "runbook_revision_hash": VALID_RUNBOOK["content_hash"],
    })
    outcome = harness.gate.execute(
        make_request(token=issued.token, standing=mismatched), harness.executor
    )
    assert outcome.dispatched and outcome.authorization_path == "proposal-bound"
    start = [e for e in harness.audit.events() if e.event_type == "execution_start"]
    assert start[-1].payload["script_path"] == SCRIPT.path


def test_standing_dispatch_spends_a_recorded_approval(harness: Harness) -> None:
    """ADR 0003 rule 4: spent exactly when the token is consumed — the
    standing path must not strand a recorded approval in 'recorded'."""
    issued = harness.issue()
    harness.verifier.record_approval(issued.token, operator_identity=OPERATOR)
    outcome = harness.gate.execute(make_request(token=issued.token), harness.executor)
    assert outcome.dispatched and outcome.authorization_path == "standing"
    conn = __import__("sqlite3").connect(harness.service.store._path)
    try:
        state = conn.execute(
            "SELECT state FROM approvals WHERE token_digest = ?",
            (harness.service.token_digest(issued.token),),
        ).fetchone()[0]
    finally:
        conn.close()
    assert state == "used"


def test_garbage_executor_report_is_recorded_as_failure(harness: Harness) -> None:
    issued = harness.issue()

    def liar(invocation: Invocation) -> str:
        harness.executor_calls.append(invocation)
        return "excellent"

    with pytest.raises(ValueError):
        harness.gate.execute(make_request(token=issued.token), liar)
    failure = [e for e in harness.audit.events() if e.event_type == "execution_outcome"]
    assert failure and failure[-1].outcome == "failure"


def test_base_exception_from_executor_still_records_failure(harness: Harness) -> None:
    issued = harness.issue()

    def exits(invocation: Invocation) -> str:
        harness.executor_calls.append(invocation)
        raise SystemExit(3)

    with pytest.raises(SystemExit):
        harness.gate.execute(make_request(token=issued.token), exits)
    failure = [e for e in harness.audit.events() if e.event_type == "execution_outcome"]
    assert failure and failure[-1].outcome == "failure"


def test_script_sha256_is_recorded_in_execution_start(harness: Harness) -> None:
    """Pins the script-provenance field (#16 handoff): if a refactor drops
    the recorded hash, the MCP layer loses its verification anchor."""
    issued = harness.issue()
    outcome = harness.gate.execute(make_request(token=issued.token), harness.executor)
    assert outcome.dispatched
    start = [e for e in harness.audit.events() if e.event_type == "execution_start"]
    assert start[-1].payload["script_sha256"] == SCRIPT.sha256


def test_refusal_append_failure_escapes_fail_closed(harness: Harness) -> None:
    """Documented window: if the refusal append itself cannot persist, the
    AuditWriteFailure escapes (fail-closed) — the executor never runs."""
    issued = harness.issue()
    original_append_on = harness.audit.append_on

    def failing_append_on(conn, event_type, **kwargs):
        if event_type == "refusal":
            raise AuditWriteFailure("audit store unavailable")
        return original_append_on(conn, event_type, **kwargs)

    harness.audit.append_on = failing_append_on  # type: ignore[method-assign]
    with pytest.raises(AuditWriteFailure):
        harness.gate.execute(make_request(token=issued.token, standing=None), harness.executor)
    assert harness.executor_calls == []
    frozen = harness.service.resolve(issued.token)
    assert not frozen.consumed


def test_outcome_append_failure_escapes_after_dispatch(harness: Harness) -> None:
    """Documented window: the outcome append failing after the executor ran
    propagates AuditWriteFailure — but the execution_start record is durable
    and the token is consumed (the side effect already happened)."""
    issued = harness.issue()
    original_append_on = harness.audit.append_on

    def failing_append_on(conn, event_type, **kwargs):
        if event_type == "execution_outcome":
            raise AuditWriteFailure("audit store unavailable")
        return original_append_on(conn, event_type, **kwargs)

    harness.audit.append_on = failing_append_on  # type: ignore[method-assign]
    with pytest.raises(AuditWriteFailure):
        harness.gate.execute(make_request(token=issued.token), harness.executor)
    from tests_helpers_runbook import VALID_RUNBOOK as _RB

    expected_invocation = make_invocation(runbook_revision_hash=_RB["content_hash"])
    assert harness.executor_calls == [expected_invocation]
    events = harness.audit.events()
    assert [e.event_type for e in events] == ["execution_start"]
    with pytest.raises(TokenAlreadyConsumedError):
        harness.service.resolve(issued.token)
