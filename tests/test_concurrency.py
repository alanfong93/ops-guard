"""Exactly-once consumption under concurrency (ADR 0002, rules 5 and 7)."""

from __future__ import annotations

import threading
from datetime import timedelta

from hypothesis import given, settings
from hypothesis import strategies as st

from ops_guard import (
    TokenAlreadyConsumedError,
    TokenExpiredError,
    UnknownTokenError,
)
from helpers import fresh_service, make_invocation

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
