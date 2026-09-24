"""Fail-closed execution gate (issue #14; adversarial done-when tests)."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

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
    StandingAuthorization,
    TokenAlreadyConsumedError,
    parse_authorization,
)
from ops_guard.retrieval import RunbookLibrary
from helpers import make_invocation
from tests_helpers_runbook import VALID_RUNBOOK

OPERATOR = "alan"
SCRIPT_PATH = "/opt/scripts/restart-n8n.sh"
SCRIPT_BYTES = b"#!/bin/sh\necho restarting n8n\n"
SCRIPT_SHA256 = hashlib.sha256(SCRIPT_BYTES).hexdigest()


def base_authorization() -> StandingAuthorization:
    return parse_authorization({
        "authorization_id": "auth-restart-n8n",
        "script_path": SCRIPT_PATH,
        "script_sha256": SCRIPT_SHA256,
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
        script_path=SCRIPT_PATH,
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
        self.audit = AuditLog(AuditStore(path), fingerprint_key=os.urandom(32), clock=clock)
        self.service = ProposalService(
            ProposalStore(path), token_key=token_key, clock=clock, audit=self.audit
        )
        self.verifier = ApprovalVerifier(
            ApprovalStore(path), self.service, operator_identity=OPERATOR, clock=clock
        )
        self.library, _rejections = RunbookLibrary.load([VALID_RUNBOOK])
        self.scripts: dict[str, bytes] = {SCRIPT_PATH: SCRIPT_BYTES}
        self.gate = ExecutionGate(
            self.service,
            self.verifier,
            self.audit,
            runbooks=self.library,
            script_source=self.scripts.__getitem__,
            clock=clock,
        )
        self.executor_calls: list[tuple[Invocation, bytes]] = []

    def issue(self, **overrides) -> object:
        overrides.setdefault("runbook_revision_hash", VALID_RUNBOOK["content_hash"])
        invocation = make_invocation(**overrides)
        issued = self.service.open_proposal(invocation, ttl=timedelta(minutes=10))
        return issued

    def rebuild_library(self, documents: list[dict]) -> None:
        """Swap the verified library and rewire the gate to it."""
        self.library, _ = RunbookLibrary.load(documents)
        self.gate = ExecutionGate(
            self.service,
            self.verifier,
            self.audit,
            runbooks=self.library,
            script_source=self.scripts.__getitem__,
            clock=self.clock,
        )

    def executor(self, invocation: Invocation, script_bytes: bytes) -> str:
        self.executor_calls.append((invocation, script_bytes))
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
    assert types == ["proposal", "execution_start", "execution_outcome"]
    assert events[1].proposal_ref == issued.proposal_id


def test_store_database_identity_is_pinned_at_construction(tmp_path, monkeypatch) -> None:
    """A cwd change after store construction must not merge two databases
    into one validated boundary (issue #36, adversarial finding)."""
    from ops_guard.store import same_database

    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()
    monkeypatch.chdir(first)
    proposal_store = ProposalStore("ops-guard.db")
    monkeypatch.chdir(second)
    audit_store = AuditStore("ops-guard.db")
    assert not same_database(proposal_store.path, audit_store.path)


def test_gate_rejects_split_audit_store_before_any_dispatch(tmp_path, token_key, clock) -> None:
    """One execution history must live in one database (issue #36)."""
    proposal_path = str(tmp_path / "ops-guard.db")
    audit_path = str(tmp_path / "audit-elsewhere.db")
    # The proposal service is wired to the audit log sharing its database.
    shared_audit = AuditLog(AuditStore(proposal_path), fingerprint_key=os.urandom(32), clock=clock)
    service = ProposalService(
        ProposalStore(proposal_path), token_key=token_key, clock=clock, audit=shared_audit
    )
    verifier = ApprovalVerifier(
        ApprovalStore(proposal_path), service, operator_identity=OPERATOR, clock=clock
    )
    # The gate is handed a different audit log: a split configuration.
    split_audit = AuditLog(AuditStore(audit_path), fingerprint_key=os.urandom(32), clock=clock)
    executor_calls: list[Invocation] = []

    def executor(invocation: Invocation, script_bytes: bytes) -> str:
        executor_calls.append((invocation, script_bytes))
        return "success"

    with pytest.raises(GateConfigurationError):
        ExecutionGate(
            service,
            verifier,
            split_audit,
            runbooks=RunbookLibrary.load([VALID_RUNBOOK])[0],
            script_source=lambda p: SCRIPT_BYTES,
            clock=clock,
        )

    # The mismatched configuration never reached dispatch: the executor did
    # not run and no partial execution trail was written to either database.
    assert executor_calls == []
    with ProposalStore(proposal_path).read() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM proposals WHERE state = 'consumed'"
        ).fetchone()[0] == 0
    assert shared_audit.events() == []
    assert split_audit.events() == []


def test_gate_on_one_shared_database_dispatches_atomically(tmp_path, token_key, clock) -> None:
    harness = Harness(tmp_path, token_key, clock)
    issued = harness.issue()
    outcome = harness.gate.execute(
        make_request(token=issued.token, expected_digest=issued.invocation_digest),
        harness.executor,
    )
    assert outcome.dispatched and outcome.authorization_path == "standing"
    types = [e.event_type for e in harness.audit.events()]
    assert types == ["proposal", "execution_start", "execution_outcome"]
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

    def unknown_executor(invocation: Invocation, script_bytes: bytes) -> str:
        harness.executor_calls.append((invocation, script_bytes))
        return "unknown"

    outcome = harness.gate.execute(make_request(token=issued.token), unknown_executor)
    assert outcome.dispatched and outcome.outcome == "unknown"
    outcome_events = [e for e in harness.audit.events() if e.event_type == "execution_outcome"]
    assert outcome_events[-1].outcome == "unknown"


def test_executor_failure_is_recorded_then_raised(harness: Harness) -> None:
    issued = harness.issue()

    def failing_executor(invocation: Invocation, script_bytes: bytes) -> str:
        harness.executor_calls.append((invocation, script_bytes))
        raise RuntimeError("service did not come back")

    with pytest.raises(RuntimeError):
        harness.gate.execute(make_request(token=issued.token), failing_executor)
    events = harness.audit.events()
    failure = [e for e in events if e.event_type == "execution_outcome"]
    assert failure and failure[-1].outcome == "failure"
    assert failure[-1].failure_code == "executor-error"


def test_executor_timeout_is_recorded_as_unknown_without_exception_text(harness: Harness) -> None:
    """A timeout leaves completion unconfirmed: unknown, never failure, and
    the exception text (which may carry secrets) is not persisted (issue #38)."""
    issued = harness.issue()
    secret = "healthcheck token=super-secret-value"

    def timing_out_executor(invocation: Invocation, script_bytes: bytes) -> str:
        harness.executor_calls.append((invocation, script_bytes))
        raise TimeoutError(f"no healthy reply within 30s using {secret}")

    with pytest.raises(TimeoutError):
        harness.gate.execute(make_request(token=issued.token), timing_out_executor)

    outcome = [e for e in harness.audit.events() if e.event_type == "execution_outcome"][-1]
    assert outcome.outcome == "unknown"
    assert outcome.failure_code == "executor-timeout"
    persisted = json.dumps(outcome.payload)
    assert "super-secret-value" not in persisted
    assert "no healthy reply" not in persisted
    assert "TimeoutError" not in persisted


def test_subprocess_timeout_is_recorded_as_unknown_without_command_text(harness: Harness) -> None:
    import subprocess

    issued = harness.issue()

    def timing_out_executor(invocation: Invocation, script_bytes: bytes) -> str:
        harness.executor_calls.append((invocation, script_bytes))
        raise subprocess.TimeoutExpired(
            cmd="/opt/scripts/restart-n8n.sh --healthcheck-url http://10.0.0.2:5678",
            timeout=30,
        )

    with pytest.raises(subprocess.TimeoutExpired):
        harness.gate.execute(make_request(token=issued.token), timing_out_executor)

    outcome = [e for e in harness.audit.events() if e.event_type == "execution_outcome"][-1]
    assert outcome.outcome == "unknown"
    assert outcome.failure_code == "executor-timeout"
    persisted = json.dumps(outcome.payload)
    assert "restart-n8n.sh" not in persisted
    assert "10.0.0.2" not in persisted


def test_ordinary_exception_stays_failure_and_persists_no_exception_text(harness: Harness) -> None:
    issued = harness.issue()

    def failing_executor(invocation: Invocation, script_bytes: bytes) -> str:
        harness.executor_calls.append((invocation, script_bytes))
        try:
            raise ValueError("inner api-key=sk-secret-123 refused")
        except ValueError as inner:
            raise RuntimeError("outer connection to 10.0.0.9 lost") from inner

    with pytest.raises(RuntimeError):
        harness.gate.execute(make_request(token=issued.token), failing_executor)

    outcome = [e for e in harness.audit.events() if e.event_type == "execution_outcome"][-1]
    assert outcome.outcome == "failure"
    assert outcome.failure_code == "executor-error"
    persisted = json.dumps(outcome.payload)
    # No message, no nested cause, no traceback, no exception class name.
    assert "sk-secret-123" not in persisted
    assert "10.0.0.9" not in persisted
    assert "inner" not in persisted
    assert "outer" not in persisted
    assert "ValueError" not in persisted
    assert "RuntimeError" not in persisted
    assert "Traceback" not in persisted


@pytest.mark.parametrize(
    "mutation",
    [
        "absent-evidence",
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
        "script-unresolvable",
        "forged-script-bytes",
    ],
)
def test_every_unavailable_input_prevents_dispatch(mutation: str, harness: Harness) -> None:
    issued = harness.issue()
    if mutation != "forged-script-bytes":
        # The forged case must not fall back to the approval path: it exists
        # to pin that a standing match against resolved bytes fails closed.
        harness.verifier.record_approval(issued.token, operator_identity=OPERATOR)

    overrides: dict = {"token": issued.token, "standing": None}
    if mutation == "absent-evidence":
        # A well-formed citation whose revision the library never verified.
        overrides["citation"] = Citation(
            runbook_id=VALID_RUNBOOK["runbook_id"],
            revision=VALID_RUNBOOK["revision"],
            content_hash="c" * 64,
            locator="restart/steps",
        )
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
            "script_path": SCRIPT_PATH,
            "script_sha256": SCRIPT_SHA256,
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
        harness.rebuild_library([VALID_RUNBOOK, other])
        overrides["citation"] = Citation(
            runbook_id=other["runbook_id"],
            revision=other["revision"],
            content_hash=other["content_hash"],
            locator="restart/steps",
        )
        overrides["standing"] = base_authorization()
    elif mutation == "script-unresolvable":
        overrides["script_path"] = "/opt/scripts/never-there.sh"
        overrides["standing"] = base_authorization()
    elif mutation == "forged-script-bytes":
        # The authorization binds the real bytes; the authoritative source
        # serves different ones. The gate must match against the bytes it
        # resolved — and refuse — never against a caller-supplied digest.
        harness.scripts[SCRIPT_PATH] = SCRIPT_BYTES + b"# tampered after authorization\n"
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
    the approval path still authorizes, and the gate-resolved script
    provenance is what gets recorded (issue #34)."""
    issued = harness.issue()
    harness.verifier.record_approval(issued.token, operator_identity=OPERATOR)
    mismatched = parse_authorization({
        "authorization_id": "other-rule",
        "script_path": SCRIPT_PATH,
        "script_sha256": SCRIPT_SHA256,
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
    assert start[-1].payload["script_path"] == SCRIPT_PATH


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

    def liar(invocation: Invocation, script_bytes: bytes) -> str:
        harness.executor_calls.append((invocation, script_bytes))
        return "excellent"

    with pytest.raises(ValueError):
        harness.gate.execute(make_request(token=issued.token), liar)
    failure = [e for e in harness.audit.events() if e.event_type == "execution_outcome"]
    assert failure and failure[-1].outcome == "failure"


def test_base_exception_from_executor_still_records_failure(harness: Harness) -> None:
    issued = harness.issue()

    def exits(invocation: Invocation, script_bytes: bytes) -> str:
        harness.executor_calls.append((invocation, script_bytes))
        raise SystemExit(3)

    with pytest.raises(SystemExit):
        harness.gate.execute(make_request(token=issued.token), exits)
    failure = [e for e in harness.audit.events() if e.event_type == "execution_outcome"]
    assert failure and failure[-1].outcome == "failure"


def test_script_sha256_is_recorded_in_execution_start(harness: Harness) -> None:
    """Pins the script-provenance field: the recorded hash is the gate's
    own digest of the resolved bytes (issue #34), the anchor any downstream
    provenance check verifies against."""
    issued = harness.issue()
    outcome = harness.gate.execute(make_request(token=issued.token), harness.executor)
    assert outcome.dispatched
    start = [e for e in harness.audit.events() if e.event_type == "execution_start"]
    assert start[-1].payload["script_sha256"] == SCRIPT_SHA256


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
    assert [call[0] for call in harness.executor_calls] == [expected_invocation]
    events = harness.audit.events()
    # The proposal event committed at issue time; execution_start is the
    # durable record this test pins (outcome append failed after dispatch).
    assert [e.event_type for e in events] == ["proposal", "execution_start"]
    with pytest.raises(TokenAlreadyConsumedError):
        harness.service.resolve(issued.token)


def test_executor_receives_exactly_the_resolved_script_bytes(harness: Harness) -> None:
    """The executor runs on the bytes the gate resolved and hashed — the
    same bytes whose digest matched the authorization and whose hash is
    recorded as provenance (issue #34, no re-read/TOCTOU gap)."""
    issued = harness.issue()
    outcome = harness.gate.execute(make_request(token=issued.token), harness.executor)
    assert outcome.dispatched
    assert harness.executor_calls[-1][1] is SCRIPT_BYTES
    start = [e for e in harness.audit.events() if e.event_type == "execution_start"]
    assert start[-1].payload["script_sha256"] == SCRIPT_SHA256


def test_citation_never_resolves_without_a_verified_library_revision(
    harness: Harness,
) -> None:
    """A well-formed citation backed by no verified revision refuses, no
    matter what a caller might claim: the library is the only evidence
    source (issue #34)."""
    harness.rebuild_library([])  # the operator verified nothing
    issued = harness.issue()
    outcome = harness.gate.execute(make_request(token=issued.token), harness.executor)
    assert not outcome.dispatched
    assert "no verified revision carries this content hash" in outcome.refusal
    assert harness.executor_calls == []
    frozen = harness.service.resolve(issued.token)
    assert not frozen.consumed


@given(
    corrupt=st.sampled_from(
        ["none", "script-bytes", "script-path", "revision-hash", "observation"]
    ),
    via_standing=st.booleans(),
)
@settings(max_examples=25, deadline=None)
def test_only_exact_resolved_artifacts_dispatch(corrupt: str, via_standing: bool) -> None:
    """Authorization-boundary property (issue #34): any mismatch between the
    caller's presentation and the gate-resolved artifacts refuses before
    consumption or execution; only the exact resolution dispatches."""
    import tempfile

    from helpers import fresh_service

    service, clock = fresh_service()
    path = service.store.path
    audit = AuditLog(AuditStore(path), fingerprint_key=os.urandom(32), clock=clock)
    verifier = ApprovalVerifier(
        ApprovalStore(path), service, operator_identity=OPERATOR, clock=clock
    )
    library, _ = RunbookLibrary.load([VALID_RUNBOOK])
    scripts: dict[str, bytes] = {SCRIPT_PATH: SCRIPT_BYTES}
    gate = ExecutionGate(
        service,
        verifier,
        audit,
        runbooks=library,
        script_source=scripts.__getitem__,
        clock=clock,
    )

    overrides: dict = {"standing": base_authorization() if via_standing else None}
    if corrupt == "script-bytes":
        scripts[SCRIPT_PATH] = SCRIPT_BYTES + b"# malicious appendage\n"
        if via_standing:
            pass  # the standing match must refuse on the resolved digest
        else:
            # proposal-bound: dispatch proceeds, but on the resolved bytes —
            # the provenance record is the gate's own digest.
            pass
    elif corrupt == "script-path":
        overrides["script_path"] = "/opt/scripts/never-there.sh"
    elif corrupt == "revision-hash":
        overrides["citation"] = Citation(
            runbook_id=VALID_RUNBOOK["runbook_id"],
            revision=VALID_RUNBOOK["revision"],
            content_hash="d" * 64,
            locator="restart/steps",
        )
    elif corrupt == "observation":
        overrides["observed_preconditions"] = {"healthcheck": "failing"}

    invocation = make_invocation(runbook_revision_hash=VALID_RUNBOOK["content_hash"])
    issued = service.open_proposal(invocation, ttl=timedelta(minutes=10))
    overrides["token"] = issued.token
    if not via_standing:
        verifier.record_approval(issued.token, operator_identity=OPERATOR)

    calls: list[bytes] = []

    def executor(invocation: Invocation, script_bytes: bytes) -> str:
        calls.append(script_bytes)
        return "success"

    outcome = gate.execute(make_request(**overrides), executor)

    if corrupt == "none":
        assert outcome.dispatched
        assert calls == [SCRIPT_BYTES]
    elif corrupt == "script-bytes" and not via_standing:
        # Proposal-bound dispatch still runs on the gate's resolution: the
        # bytes actually served by the source, never a caller's substitute.
        assert outcome.dispatched
        assert calls == [scripts[SCRIPT_PATH]]
        assert calls != [SCRIPT_BYTES]
    else:
        assert not outcome.dispatched and outcome.refusal
        assert calls == []
        assert not _consumed(service, issued)


def _consumed(service: ProposalService, issued: object) -> bool:
    try:
        return service.resolve(issued.token).consumed  # type: ignore[attr-defined]
    except TokenAlreadyConsumedError:
        return True


def test_script_source_returning_non_bytes_refuses_fail_closed(
    harness: Harness,
) -> None:
    """A broken or misconfigured source must produce a refusal — audited,
    unconsumed — never a raw TypeError escaping the gate (review cycle 1)."""
    issued = harness.issue()
    harness.verifier.record_approval(issued.token, operator_identity=OPERATOR)
    harness.scripts[SCRIPT_PATH] = None  # type: ignore[assignment]
    outcome = harness.gate.execute(make_request(token=issued.token, standing=None), harness.executor)
    assert not outcome.dispatched
    assert "script could not be resolved" in outcome.refusal
    assert harness.executor_calls == []
    frozen = harness.service.resolve(issued.token)
    assert not frozen.consumed
    refusals = [e for e in harness.audit.events() if e.event_type == "refusal"]
    assert refusals and "script_source must resolve a path to bytes" in refusals[-1].payload["reason"]
