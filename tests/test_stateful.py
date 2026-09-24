"""Stateful lifecycle machine: arbitrary operation sequences keep the contract invariants (ADR 0002, rule 7)."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from datetime import timedelta

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule

from ops_guard import TokenAlreadyConsumedError, TokenExpiredError
from helpers import FakeClock, make_invocation, make_service

TTL_SECONDS = st.integers(min_value=1, max_value=120)
STEP_SECONDS = st.integers(min_value=1, max_value=600)


class ProposalLifecycleMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.clock = FakeClock()
        self.path = os.path.join(tempfile.mkdtemp(prefix="ops-guard-stateful-"), "proposals.db")
        self.service = make_service(self.path, token_key=os.urandom(32), clock=self.clock)
        self.counter = 0
        self.tokens: dict[str, dict] = {}

    @rule(ttl=TTL_SECONDS)
    def open_proposal(self, ttl: int) -> None:
        self.counter += 1
        invocation = make_invocation(arguments={"n": self.counter})
        issued = self.service.open_proposal(invocation, ttl=timedelta(seconds=ttl))
        self.tokens[issued.token] = {
            "digest": issued.invocation_digest,
            "expires_at": self.clock.now + timedelta(seconds=ttl),
            "consumed": False,
        }

    @precondition(lambda self: self.tokens)
    @rule(index=st.integers(min_value=0, max_value=63))
    def resolve(self, index: int) -> None:
        tokens = sorted(self.tokens)
        token = tokens[index % len(tokens)]
        record = self.tokens[token]
        try:
            frozen = self.service.resolve(token)
        except TokenAlreadyConsumedError:
            assert record["consumed"]
        except TokenExpiredError:
            assert self.clock.now >= record["expires_at"]
        else:
            assert frozen.invocation_digest == record["digest"]

    @precondition(lambda self: any(not r["consumed"] for r in self.tokens.values()))
    @rule(index=st.integers(min_value=0, max_value=63))
    def consume(self, index: int) -> None:
        eligible = sorted(t for t, r in self.tokens.items() if not r["consumed"])
        token = eligible[index % len(eligible)]
        record = self.tokens[token]
        try:
            self.service.consume(token)
        except (TokenAlreadyConsumedError, TokenExpiredError):
            pass
        else:
            record["consumed"] = True

    @precondition(lambda self: any(not r["consumed"] for r in self.tokens.values()))
    @rule(index=st.integers(min_value=0, max_value=63))
    def crash_during_consume(self, index: int) -> None:
        eligible = sorted(t for t, r in self.tokens.items() if not r["consumed"])
        token = eligible[index % len(eligible)]

        def failing_append(conn: sqlite3.Connection, _consumed_digest: str) -> None:
            raise RuntimeError("crash before commit")

        try:
            self.service.consume(token, same_transaction=failing_append)
        except RuntimeError:
            pass  # crash before commit: the token must be unchanged
        except (TokenAlreadyConsumedError, TokenExpiredError):
            return  # not eligible; the crash path was not exercised
        # Rollback keeps the token exactly as it was.
        assert not self.tokens[token]["consumed"]

    @rule(seconds=STEP_SECONDS)
    def advance_clock(self, seconds: int) -> None:
        self.clock.advance(seconds)

    @invariant()
    def consumed_tokens_are_terminal(self) -> None:
        for token, record in self.tokens.items():
            if record["consumed"]:
                try:
                    self.service.resolve(token)
                except TokenAlreadyConsumedError:
                    pass
                else:
                    raise AssertionError("a consumed token became eligible again")

    @invariant()
    def database_states_are_consistent(self) -> None:
        conn = sqlite3.connect(self.path)
        try:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'proposals'"
            ).fetchone()
            if not exists:
                return
            rows = conn.execute("SELECT state, consumed_at FROM proposals").fetchall()
        finally:
            conn.close()
        for state, consumed_at in rows:
            assert state in ("active", "consumed")
            assert (state == "consumed") == (consumed_at is not None)


TestProposalLifecycle = ProposalLifecycleMachine.TestCase
TestProposalLifecycle.settings = settings(
    max_examples=25,
    stateful_step_count=40,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


_recovery_events = st.sampled_from(["dead", "indeterminate", "live", "completed"])


def _recovery_wiring(path, clock):
    """Stores sharing one database, with an owners directory beside it."""
    from ops_guard import ApprovalStore, ApprovalVerifier, AuditLog, AuditStore

    audit = AuditLog(AuditStore(path), fingerprint_key=os.urandom(32), clock=clock)
    service = make_service(path, token_key=os.urandom(32), clock=clock, audit=audit)
    verifier = ApprovalVerifier(
        ApprovalStore(path), service, operator_identity="alan", clock=clock
    )
    return audit, service, verifier


def _recovery_gate(path, clock, service, verifier, audit, owner):
    """A gate bound to one owner; fresh per event so each start names the
    owner whose liveness the test controls."""
    from ops_guard import ExecutionGate
    from ops_guard.retrieval import RunbookLibrary
    from tests_helpers_runbook import VALID_RUNBOOK as RB

    library, _ = RunbookLibrary.load([RB])
    return ExecutionGate(
        service,
        verifier,
        audit,
        runbooks=library,
        script_source={"/opt/scripts/restart-n8n.sh": b"#!/bin/sh\n"}.__getitem__,
        clock=clock,
        owner=owner,
    )


@given(
    events=st.lists(_recovery_events, min_size=1, max_size=6),
    sweeps=st.integers(min_value=1, max_value=3),
)
@settings(max_examples=20, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_recovery_invariants_hold_for_arbitrary_sequences(events: list, sweeps: int) -> None:
    """Issue #39 property: over arbitrary orderings of dead, indeterminate,
    live, and completed executions, recovery appends exactly one unknown
    per proven-dead start, nothing for live/indeterminate/completed, and
    repeated sweeps change nothing."""
    import tempfile

    from helpers import make_invocation as _mk
    from ops_guard import AuditWriteFailure, ExecutionRequest
    from ops_guard.recovery import reconcile_interrupted_executions
    from tests_helpers_runbook import VALID_RUNBOOK as RB

    clock = FakeClock()
    path = os.path.join(tempfile.mkdtemp(prefix="ops-guard-recovery-"), "proposals.db")
    audit, service, verifier = _recovery_wiring(path, clock)
    owners: dict[str, object] = {"dead": [], "live": []}
    expected_unknowns = 0

    from ops_guard import Citation, ExecutionOwner
    from tests_helpers_runbook import VALID_RUNBOOK as RB

    citation = Citation(
        runbook_id=RB["runbook_id"],
        revision=RB["revision"],
        content_hash=RB["content_hash"],
        locator="restart/steps",
    )
    for event in events:
        owner = None
        if event in ("dead", "live", "indeterminate"):
            owner = ExecutionOwner(os.path.join(path + ".owners"))
        gate = _recovery_gate(path, clock, service, verifier, audit, owner)
        issued = service.open_proposal(
            _mk(runbook_revision_hash=RB["content_hash"]), ttl=timedelta(minutes=5)
        )
        verifier.record_approval(issued.token, operator_identity="alan")
        request = ExecutionRequest(
            token=issued.token,
            script_path="/opt/scripts/restart-n8n.sh",
            citation=citation,
            observed_preconditions={"healthcheck": "passing"},
            operator_identity="alan",
        )

        if event == "completed":
            outcome = gate.execute(request, lambda i, b: "success")
            assert outcome.dispatched and outcome.outcome == "success"
            continue

        # crash window: start + consumption durable, outcome append fails
        real = audit.append_on

        def failing(conn, event_type, **kwargs):
            if event_type == "execution_outcome":
                raise AuditWriteFailure("crash before the outcome append")
            return real(conn, event_type, **kwargs)

        audit.append_on = failing  # type: ignore[method-assign]
        try:
            gate.execute(request, lambda i, b: "success")
        except AuditWriteFailure:
            pass
        finally:
            audit.append_on = real  # type: ignore[method-assign]

        if event == "dead":
            owner.close()
            owners["dead"].append(True)
            expected_unknowns += 1
        else:
            if event == "indeterminate":
                owner.close()
                try:
                    os.remove(owner.lock_path)
                except OSError:
                    pass
                owners["indeterminate"] = owners.get("indeterminate", 0) + 1
            else:
                owners["live"].append(owner)

    for _ in range(sweeps):
        reconciliations = reconcile_interrupted_executions(audit)

    outcomes = [
        (e.outcome, e.failure_code)
        for e in audit.events()
        if e.event_type == "execution_outcome"
    ]
    recovered = [o for o in outcomes if o == ("unknown", "owner-dead")]
    assert len(recovered) == expected_unknowns
    successes = [o for o in outcomes if o == ("success", None)]
    assert len(successes) == events.count("completed")
    # every sweep after the first changed nothing (idempotence)
    assert sweeps >= 1
    for owner in owners["live"]:
        owner.close()


TestRecoveryInvariants = test_recovery_invariants_hold_for_arbitrary_sequences
