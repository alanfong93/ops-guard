"""Approval verifier contract (ADR 0003; issue #12 done-when)."""

from __future__ import annotations

import sqlite3
import threading
from datetime import timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ops_guard import (
    ApprovalAlreadyRecordedError,
    ApprovalOperatorMismatchError,
    ApprovalReplayedError,
    ApprovalStore,
    ApprovalVerifier,
    HostSuppliedApprovalError,
    InvocationMismatchError,
    ProposalService,
    TokenAlreadyConsumedError,
    TokenExpiredError,
    UnknownTokenError,
)
from helpers import fresh_service, make_invocation

OPERATOR = "alan"


@pytest.fixture()
def service(tmp_path, token_key, clock) -> ProposalService:
    import os

    from helpers import make_service
    from ops_guard import AuditLog, AuditStore

    path = tmp_path / "ops-guard.db"
    audit = AuditLog(AuditStore(str(path)), fingerprint_key=os.urandom(32), clock=clock)
    return make_service(path, token_key=token_key, clock=clock, audit=audit)


@pytest.fixture()
def verifier(service, clock) -> ApprovalVerifier:
    return ApprovalVerifier(
        ApprovalStore(service.store._path),
        service,
        operator_identity=OPERATOR,
        clock=clock,
    )


def _recorded(verifier, service, ttl=timedelta(minutes=10)):
    issued = service.open_proposal(make_invocation(), ttl=ttl)
    record = verifier.record_approval(issued.token, operator_identity=OPERATOR)
    return issued, record


def test_recorded_approval_verifies_and_spends_atomically(service, verifier) -> None:
    issued, record = _recorded(verifier, service)
    decision = verifier.verify(issued.token, operator_identity=OPERATOR)
    assert decision.allowed
    assert decision.approval_id == record.approval_id
    assert decision.proposal_id == issued.proposal_id
    assert decision.invocation_digest == issued.invocation_digest

    consumed = service.consume(
        issued.token, same_transaction=verifier.mark_used_append(issued.token)
    )
    assert consumed.consumed
    with pytest.raises(ApprovalReplayedError):
        verifier.verify(issued.token, operator_identity=OPERATOR)
    with pytest.raises(TokenAlreadyConsumedError):
        service.consume(
            issued.token, same_transaction=verifier.mark_used_append(issued.token)
        )


def test_host_supplied_approval_is_rejected(verifier, service) -> None:
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))
    with pytest.raises(HostSuppliedApprovalError):
        verifier.verify(issued.token, operator_identity=OPERATOR)


@given(st.text(min_size=1, max_size=64))
@settings(max_examples=50)
def test_unrecorded_tokens_never_verify(attempt: str) -> None:
    service, clock = fresh_service()
    lone = ApprovalVerifier(
        ApprovalStore(service.store._path), service, operator_identity=OPERATOR, clock=clock
    )
    with pytest.raises(HostSuppliedApprovalError):
        lone.verify(attempt, operator_identity=OPERATOR)


def test_wrong_operator_cannot_record_or_verify(service, verifier) -> None:
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))
    with pytest.raises(ApprovalOperatorMismatchError):
        verifier.record_approval(issued.token, operator_identity="not-alan")
    verifier.record_approval(issued.token, operator_identity=OPERATOR)
    with pytest.raises(ApprovalOperatorMismatchError):
        verifier.verify(issued.token, operator_identity="not-alan")


def test_one_approval_per_proposal(service, verifier) -> None:
    issued, _ = _recorded(verifier, service)
    with pytest.raises(ApprovalAlreadyRecordedError):
        verifier.record_approval(issued.token, operator_identity=OPERATOR)


def test_expired_proposal_cannot_be_recorded_or_verified(service, verifier, clock) -> None:
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))
    clock.advance(6 * 60)
    with pytest.raises(TokenExpiredError):
        verifier.record_approval(issued.token, operator_identity=OPERATOR)
    issued2 = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))
    verifier.record_approval(issued2.token, operator_identity=OPERATOR)
    clock.advance(6 * 60)
    with pytest.raises(TokenExpiredError):
        verifier.verify(issued2.token, operator_identity=OPERATOR)
    with pytest.raises(TokenExpiredError):
        service.consume(
            issued2.token, same_transaction=verifier.mark_used_append(issued2.token)
        )


def test_consumed_or_unknown_tokens_cannot_be_approved(service, verifier) -> None:
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))
    service.consume(issued.token)
    with pytest.raises(TokenAlreadyConsumedError):
        verifier.record_approval(issued.token, operator_identity=OPERATOR)
    with pytest.raises(UnknownTokenError):
        verifier.record_approval("never-issued", operator_identity=OPERATOR)


def test_tampered_binding_fails_closed(service, verifier) -> None:
    tamper_legs = [
        lambda pid, digest: (
            f"UPDATE proposals SET invocation_digest = '{'f' * 64}' WHERE proposal_id = '{pid}'",
            InvocationMismatchError,
        ),
        lambda pid, digest: (
            f"UPDATE proposals SET expires_at = '2099-01-01T00:00:00.000000+00:00' "
            f"WHERE proposal_id = '{pid}'",
            InvocationMismatchError,
        ),
        lambda pid, digest: (
            f"UPDATE approvals SET expires_at = '2099-01-01T00:00:00.000000+00:00' "
            f"WHERE token_digest = '{digest}'",
            InvocationMismatchError,
        ),
        lambda pid, digest: (
            f"UPDATE approvals SET invocation_digest = '{'0' * 64}' WHERE token_digest = '{digest}'",
            InvocationMismatchError,
        ),
        lambda pid, digest: (
            f"UPDATE approvals SET runbook_revision_hash = 'tampered' WHERE token_digest = '{digest}'",
            InvocationMismatchError,
        ),
        lambda pid, digest: (
            f"UPDATE approvals SET proposal_id = 'other' WHERE token_digest = '{digest}'",
            InvocationMismatchError,
        ),
        lambda pid, digest: (
            f"UPDATE approvals SET operator_identity = 'mallory' WHERE token_digest = '{digest}'",
            ApprovalOperatorMismatchError,
        ),
    ]
    for leg in tamper_legs:
        issued, _ = _recorded(verifier, service)
        statement, expected = leg(issued.proposal_id, service.token_digest(issued.token))
        conn = sqlite3.connect(service.store._path)
        cursor = conn.execute(statement)
        changed = cursor.rowcount
        conn.commit()
        conn.close()
        assert changed == 1  # the tamper must actually reach the current row
        with pytest.raises(expected):
            verifier.verify(issued.token, operator_identity=OPERATOR)
        conn = sqlite3.connect(service.store._path)
        conn.execute("DELETE FROM approvals")
        conn.execute("DELETE FROM proposals")
        conn.commit()
        conn.close()


def test_verify_rejects_consumed_proposal(service, verifier) -> None:
    issued, _ = _recorded(verifier, service)
    service.consume(issued.token)
    with pytest.raises(TokenAlreadyConsumedError):
        verifier.verify(issued.token, operator_identity=OPERATOR)


def test_operator_gate_precedes_existence_oracle(service, verifier) -> None:
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))
    # Wrong operator + never-recorded token: the identity gate answers first.
    with pytest.raises(ApprovalOperatorMismatchError):
        verifier.verify(issued.token, operator_identity="mallory")


def test_approval_cas_is_pinned_at_store_level(service, verifier) -> None:
    issued, _ = _recorded(verifier, service)
    digest = service.token_digest(issued.token)
    conn = sqlite3.connect(service.store._path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        assert ApprovalStore.mark_used_on(conn, digest, "2026-09-23T00:00:00.000000+00:00")
        assert not ApprovalStore.mark_used_on(
            conn, digest, "2026-09-23T00:00:01.000000+00:00"
        )
        conn.execute("ROLLBACK")
    finally:
        conn.close()


def test_flip_cannot_be_cross_wired_to_another_proposal(service, verifier) -> None:
    first, _ = _recorded(verifier, service)
    second = service.open_proposal(make_invocation(), ttl=timedelta(minutes=10))
    verifier.record_approval(second.token, operator_identity=OPERATOR)

    from ops_guard import ApprovalError

    with pytest.raises(ApprovalError):
        service.consume(second.token, same_transaction=verifier.mark_used_append(first.token))

    # Nothing happened: second is unspent, first's approval still recorded.
    assert not service.resolve(second.token).consumed
    assert verifier.verify(first.token, operator_identity=OPERATOR).allowed


def test_verifier_rejects_mismatched_store_paths(tmp_path, token_key, clock) -> None:
    from helpers import make_service

    service = make_service(tmp_path / "proposals.db", token_key=token_key, clock=clock)
    with pytest.raises(ValueError):
        ApprovalVerifier(
            ApprovalStore(str(tmp_path / "elsewhere.db")),
            service,
            operator_identity=OPERATOR,
            clock=clock,
        )


def test_verifier_rejects_naive_clock(service, tmp_path) -> None:
    from datetime import datetime

    naive = ApprovalVerifier(
        ApprovalStore(service.store._path),
        service,
        operator_identity=OPERATOR,
        clock=lambda: datetime(2026, 9, 23, 12, 0, 0),
    )
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))
    with pytest.raises(ValueError):
        naive.record_approval(issued.token, operator_identity=OPERATOR)


def test_approval_flip_rolls_back_with_the_consume(service, verifier) -> None:
    issued, _ = _recorded(verifier, service)

    def failing_append(conn: sqlite3.Connection) -> None:
        raise RuntimeError("audit write failed")

    combined = verifier.mark_used_append(issued.token)

    def both(conn: sqlite3.Connection) -> None:
        combined(conn)
        failing_append(conn)

    with pytest.raises(RuntimeError):
        service.consume(issued.token, same_transaction=both)

    # The approval flip rolled back with the consumption.
    conn = sqlite3.connect(service.store._path)
    try:
        state = conn.execute(
            "SELECT state FROM approvals WHERE token_digest = ?",
            (service.token_digest(issued.token),),
        ).fetchone()[0]
    finally:
        conn.close()
    assert state == "recorded"
    assert not service.resolve(issued.token).consumed

    consumed = service.consume(
        issued.token, same_transaction=verifier.mark_used_append(issued.token)
    )
    assert consumed.consumed
    with pytest.raises(ApprovalReplayedError):
        verifier.verify(issued.token, operator_identity=OPERATOR)


@given(workers=st.integers(min_value=2, max_value=12))
@settings(max_examples=20, deadline=None)
def test_exactly_one_gate_attempt_spends_the_approval(workers: int) -> None:
    service, _clock = fresh_service()
    verifier = ApprovalVerifier(
        ApprovalStore(service.store._path),
        service,
        operator_identity=OPERATOR,
        clock=_clock,
    )
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=30))
    verifier.record_approval(issued.token, operator_identity=OPERATOR)

    barrier = threading.Barrier(workers)
    outcomes: list[Exception | None] = []
    lock = threading.Lock()

    def gate_attempt() -> None:
        barrier.wait()
        try:
            service.consume(
                issued.token, same_transaction=verifier.mark_used_append(issued.token)
            )
            result = None
        except Exception as error:  # noqa: BLE001 - race outcome is the assertion
            result = error
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=gate_attempt) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len([o for o in outcomes if o is None]) == 1
    for error in outcomes:
        if error is not None:
            assert isinstance(error, (TokenAlreadyConsumedError, ApprovalReplayedError))
    with pytest.raises(ApprovalReplayedError):
        verifier.verify(issued.token, operator_identity=OPERATOR)


@given(approach=st.integers(min_value=1, max_value=590))
@settings(max_examples=30, deadline=None)
def test_verify_eligibility_boundary_is_the_proposal_expiry(approach: int) -> None:
    service, clock = fresh_service()
    verifier = ApprovalVerifier(
        ApprovalStore(service.store._path),
        service,
        operator_identity=OPERATOR,
        clock=clock,
    )
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=10))
    verifier.record_approval(issued.token, operator_identity=OPERATOR)
    clock.advance(min(approach, 599))
    assert verifier.verify(issued.token, operator_identity=OPERATOR).allowed
    clock.advance(600)  # at or past the ten-minute boundary
    with pytest.raises(TokenExpiredError):
        verifier.verify(issued.token, operator_identity=OPERATOR)
