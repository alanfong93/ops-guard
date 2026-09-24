"""Exactly-once consumption under concurrency (ADR 0002, rules 5 and 7)."""

from __future__ import annotations

import sqlite3
import threading
from datetime import timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ops_guard import (
    ApprovalStore,
    ApprovalVerifier,
    TokenAlreadyConsumedError,
    TokenExpiredError,
    UnknownTokenError,
)
from helpers import fresh_service, make_invocation
from ops_guard.proposals import format_timestamp

worker_counts = st.integers(min_value=2, max_value=16)


@given(workers=worker_counts)
@settings(max_examples=25, deadline=None)
def test_exactly_one_concurrent_consume_wins(workers: int) -> None:
    service, _clock = fresh_service()
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=10))
    barrier = threading.Barrier(workers)
    outcomes: list[Exception | None] = []
    lock = threading.Lock()

    def attempt() -> None:
        barrier.wait()
        try:
            service.consume(issued.token)
            result = None
        except Exception as error:  # noqa: BLE001 - the race outcome is the assertion
            result = error
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=attempt) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    successes = [result for result in outcomes if result is None]
    assert len(successes) == 1
    for error in outcomes:
        if error is not None:
            assert isinstance(error, TokenAlreadyConsumedError)

    # Post-state: the token is terminal; eligibility never returns.
    try:
        service.resolve(issued.token)
    except TokenAlreadyConsumedError:
        pass
    else:
        raise AssertionError("token must be terminal after a winning consume")


@given(
    resolvers=st.integers(min_value=1, max_value=8),
    consumers=st.integers(min_value=1, max_value=4),
)
@settings(max_examples=15, deadline=None)
def test_concurrent_resolvers_and_consumers_never_see_unknown(
    resolvers: int, consumers: int
) -> None:
    service, _clock = fresh_service()
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=10))
    start = threading.Event()
    observations: list[object] = []
    lock = threading.Lock()

    def record(call, token) -> None:
        start.wait()
        try:
            result = call(token)
        except Exception as error:  # noqa: BLE001 - rejection type is the assertion
            result = error
        with lock:
            observations.append(result)

    threads = [threading.Thread(target=record, args=(service.resolve, issued.token)) for _ in range(resolvers)]
    threads += [threading.Thread(target=record, args=(service.consume, issued.token)) for _ in range(consumers)]
    for thread in threads:
        thread.start()
    start.set()
    for thread in threads:
        thread.join()

    successes = [o for o in observations if not isinstance(o, Exception)]
    consume_successes = [o for o in successes if getattr(o, "consumed", False)]
    assert len(consume_successes) <= 1
    for observation in observations:
        assert not isinstance(observation, UnknownTokenError)
        if isinstance(observation, Exception):
            assert isinstance(observation, (TokenAlreadyConsumedError, TokenExpiredError))


def test_late_approval_racing_a_consume_is_refused_in_transaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deterministic race regression (issue #35): the proposal dies while an
    approval recording is in flight. The recording must revalidate inside
    its own write transaction — consume wins the lock first, so the late
    approval is refused with a typed error and no row is written."""
    service, clock = fresh_service()
    verifier = ApprovalVerifier(
        ApprovalStore(service.store.path),
        service,
        operator_identity="alan",
        clock=clock,
    )
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=10))
    digest = service.token_digest(issued.token)

    # Signal the moment the recording's eligibility check has completed, so
    # the consume can be committed exactly in the window before the insert.
    resolved = threading.Event()
    original_resolve = service.resolve

    def resolving(token: str, **kwargs: object) -> object:
        result = original_resolve(token, **kwargs)  # type: ignore[arg-type]
        resolved.set()
        return result

    monkeypatch.setattr(service, "resolve", resolving)

    holder = sqlite3.connect(service.store.path, isolation_level=None)
    try:
        # The concurrent consume owns the write lock, its write uncommitted.
        holder.execute("BEGIN IMMEDIATE")
        holder.execute(
            "UPDATE proposals SET state = 'consumed', consumed_at = ?"
            " WHERE token_digest = ?",
            (format_timestamp(clock.now), digest),
        )

        outcome: list[object] = []

        def record() -> None:
            try:
                verifier.record_approval(issued.token, operator_identity="alan")
                outcome.append("recorded")
            except Exception as error:  # noqa: BLE001 - the race outcome is the assertion
                outcome.append(error)

        thread = threading.Thread(target=record)
        thread.start()
        # Old code performs its eligibility check outside the transaction, so
        # the event fires and the consume lands in the insert window. New code
        # checks inside the lock and can never observe the pre-consume state,
        # so the wait times out and the commit simply precedes the revalidate.
        resolved.wait(timeout=5.0)
        holder.commit()
        thread.join(timeout=30.0)
    finally:
        holder.close()
    assert not thread.is_alive(), "approval recording deadlocked against the consume"

    result = outcome[0]
    assert isinstance(result, TokenAlreadyConsumedError)
    with service.store.read() as conn:
        assert ApprovalStore.fetch_on(conn, digest) is None, (
            "a consumed proposal must not carry an approval row"
        )
        state = conn.execute(
            "SELECT state FROM proposals WHERE token_digest = ?", (digest,)
        ).fetchone()
    assert state is not None and state["state"] == "consumed"
