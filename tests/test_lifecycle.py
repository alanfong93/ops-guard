"""Lifecycle contract: issue, resolve, expiry boundary, rejection order (ADR 0002, rules 3-5)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ops_guard import (
    InvocationMismatchError,
    TokenAlreadyConsumedError,
    TokenExpiredError,
    UnknownTokenError,
)
from helpers import fresh_service, make_invocation

ttl_strategy = st.timedeltas(min_value=timedelta(seconds=1), max_value=timedelta(days=365))
approach = st.integers(min_value=1, max_value=10_000)


def test_issue_and_resolve_roundtrip(service) -> None:
    invocation = make_invocation()
    issued = service.open_proposal(invocation, ttl=timedelta(minutes=10))
    frozen = service.resolve(issued.token)
    assert frozen.proposal_id == issued.proposal_id
    assert frozen.invocation_digest == issued.invocation_digest == invocation.digest
    assert frozen.invocation.digest == invocation.digest
    assert frozen.invocation.to_json() == invocation.to_json()
    assert not frozen.consumed


def test_raw_token_is_never_persisted(service, tmp_path) -> None:
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=10))
    db_bytes = (tmp_path / "proposals.db").read_bytes()
    assert issued.token.encode("utf-8") not in db_bytes


def test_ttl_must_be_positive(service) -> None:
    with pytest.raises(ValueError):
        service.open_proposal(make_invocation(), ttl=timedelta(0))


@given(st.text(min_size=1, max_size=64))
@settings(max_examples=50)
def test_unknown_tokens_are_rejected(attempt: str) -> None:
    service, _clock = fresh_service()
    service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))
    with pytest.raises(UnknownTokenError):
        service.resolve(attempt)


def test_expiry_boundary_is_absolute(service, clock) -> None:
    issued = service.open_proposal(make_invocation(), ttl=timedelta(seconds=100))
    clock.advance(99.999)
    assert service.resolve(issued.token).invocation_digest == issued.invocation_digest
    clock.advance(0.001)  # exactly at the declared boundary
    with pytest.raises(TokenExpiredError):
        service.resolve(issued.token)
    clock.advance(1)
    with pytest.raises(TokenExpiredError):
        service.resolve(issued.token)


@given(ttl=ttl_strategy, before=approach)
@settings(max_examples=50, deadline=None)
def test_eligible_only_strictly_before_expiry(ttl, before: int) -> None:
    service, clock = fresh_service()
    ttl_seconds = ttl.total_seconds()
    issued = service.open_proposal(make_invocation(), ttl=ttl)
    clock.advance(min(before, ttl_seconds - 0.000001))
    assert service.resolve(issued.token).proposal_id == issued.proposal_id
    clock.advance(ttl_seconds)  # jump at-or-past the boundary
    with pytest.raises(TokenExpiredError):
        service.resolve(issued.token)


def test_consumed_token_is_terminal(service) -> None:
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))
    consumed = service.consume(issued.token)
    assert consumed.consumed and consumed.consumed_at is not None
    with pytest.raises(TokenAlreadyConsumedError):
        service.resolve(issued.token)
    with pytest.raises(TokenAlreadyConsumedError):
        service.consume(issued.token)


def test_expected_digest_mismatch_is_rejected(service) -> None:
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))
    with pytest.raises(InvocationMismatchError):
        service.resolve(issued.token, expected_digest="0" * 64)
    with pytest.raises(InvocationMismatchError):
        service.consume(issued.token, expected_digest="0" * 64)
    resolved = service.resolve(issued.token, expected_digest=issued.invocation_digest)
    assert resolved.proposal_id == issued.proposal_id


def test_rejection_order_is_deterministic(service, clock) -> None:
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))
    # A wrong expected digest is reported before lifecycle state.
    with pytest.raises(InvocationMismatchError):
        service.resolve(issued.token, expected_digest="0" * 64)
    service.consume(issued.token)
    with pytest.raises(InvocationMismatchError):
        service.resolve(issued.token, expected_digest="0" * 64)
    # With a correct digest, the terminal consumed state precedes expiry.
    clock.advance(6 * 60)
    with pytest.raises(TokenAlreadyConsumedError):
        service.resolve(issued.token)
    # A never-consumed expired token reports expiry.
    expired = service.open_proposal(make_invocation(), ttl=timedelta(minutes=1))
    clock.advance(60)
    with pytest.raises(TokenExpiredError):
        service.resolve(expired.token)


def test_correction_creates_a_new_proposal(service) -> None:
    invocation = make_invocation()
    first = service.open_proposal(invocation, ttl=timedelta(minutes=5))
    second = service.open_proposal(invocation, ttl=timedelta(minutes=5))
    assert first.proposal_id != second.proposal_id
    assert first.token != second.token
    assert first.invocation_digest == second.invocation_digest
    assert service.resolve(first.token).proposal_id == first.proposal_id
    assert service.resolve(second.token).proposal_id == second.proposal_id
    service.consume(first.token)
    assert service.resolve(second.token).proposal_id == second.proposal_id


def test_frozen_bytes_are_immutable_across_operations(service) -> None:
    invocation = make_invocation(arguments={"n": 1})
    issued = service.open_proposal(invocation, ttl=timedelta(minutes=5))
    before = service.resolve(issued.token).invocation.canonical_bytes()
    service.consume(issued.token)
    stored = service._store  # direct read of the persisted bytes
    import sqlite3

    conn = sqlite3.connect(stored._path)
    try:
        raw = conn.execute(
            "SELECT invocation_bytes FROM proposals WHERE proposal_id = ?", (issued.proposal_id,)
        ).fetchone()[0]
    finally:
        conn.close()
    assert raw == before
