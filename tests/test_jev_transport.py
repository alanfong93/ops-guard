"""Bounded native transport (issue #91; ADR 0014).

Hermetic: a fake ``http.client``-shaped connection stands in for the
endpoint; nothing leaves the process. The deadline tests use shortened
budgets and millisecond-scale sleeps.
"""

from __future__ import annotations

import time

import pytest

from ops_guard.jev import (
    INPUT_REJECTED,
    JUDGE_TIMEOUT,
    JUDGE_UNAVAILABLE,
    REQUEST_CAP_BYTES,
    RESPONSE_CAP_BYTES,
    JevConfigError,
    JevTransport,
    TransportFailure,
)
from jev_fixtures import ENDPOINT_IDENTITY


class FakeResponse:
    def __init__(self, *, status=200, chunks=(), drip_delay=0.0):
        self.status = status
        self._chunks = list(chunks)
        self._drip_delay = drip_delay

    def read(self, size):
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        if self._drip_delay:
            time.sleep(self._drip_delay)
        return chunk


class FakeConnection:
    """The slice of ``http.client.HTTPSConnection`` the transport uses."""

    def __init__(self, response, *, fault=None):
        self.response = response
        self.fault = fault  # callable invoked at getresponse time
        self.sock = FakeSocket()
        self.requests: list[dict] = []
        self.closed = False

    def putrequest(self, method, path, **kwargs):
        self.requests.append({"method": method, "path": path, "headers": {}})

    def putheader(self, name, value):
        self.requests[-1]["headers"][name] = value

    def endheaders(self, message_body=None):
        self.requests[-1]["body"] = message_body

    def getresponse(self):
        if self.fault is not None:
            raise self.fault()
        return self.response

    def close(self):
        self.closed = True


class FakeSocket:
    def __init__(self):
        self.timeouts: list[float] = []

    def settimeout(self, value):
        self.timeouts.append(value)


def make_transport(connection, **overrides) -> JevTransport:
    return JevTransport(
        endpoint=ENDPOINT_IDENTITY,
        allowed_endpoints=(ENDPOINT_IDENTITY,),
        bearer_token="fixture-token-" + "x" * 24,
        connection_factory=lambda host, port, timeout: connection,
        **overrides,
    )


def recorded_request(connection) -> dict:
    return connection.requests[0]


# ---- construction --------------------------------------------------------


def test_endpoint_outside_the_allowlist_is_refused_at_construction() -> None:
    with pytest.raises(JevConfigError):
        JevTransport(
            endpoint="https://other.example:443/x",
            allowed_endpoints=(ENDPOINT_IDENTITY,),
            bearer_token="fixture-token-" + "x" * 24,
        )


def test_oversized_request_never_leaves_the_process() -> None:
    connection = FakeConnection(FakeResponse())
    transport = make_transport(connection)
    with pytest.raises(TransportFailure) as caught:
        transport.post_sample(b"x" * (REQUEST_CAP_BYTES + 1))
    assert caught.value.failure_code == INPUT_REJECTED
    assert connection.requests == []


# ---- request shape -------------------------------------------------------


def test_request_carries_exact_bytes_and_credentials_only_here() -> None:
    connection = FakeConnection(FakeResponse(chunks=[b"{}"]))
    transport = make_transport(connection)
    body = b'{"model":"jev-1.13.0"}'
    assert transport.post_sample(body) == b"{}"
    request = recorded_request(connection)
    assert request["path"] == "/v1/systemone"
    assert request["body"] is body
    assert request["headers"]["Authorization"] == "Bearer fixture-token-" + "x" * 24
    assert request["headers"]["Content-Type"] == "application/json"
    assert request["headers"]["Content-Length"] == str(len(body))


# ---- status and transport faults -----------------------------------------


@pytest.mark.parametrize("status", [301, 302, 307, 308, 400, 401, 402, 403, 422, 429, 500, 529])
def test_every_non_200_status_is_unavailable_including_redirects(status) -> None:
    connection = FakeConnection(
        FakeResponse(status=status, chunks=[b"redirect-or-error"])
    )
    transport = make_transport(connection)
    with pytest.raises(TransportFailure) as caught:
        transport.post_sample(b"{}")
    assert caught.value.failure_code == JUDGE_UNAVAILABLE


def test_connection_faults_split_timeout_from_unavailable() -> None:
    timeout_connection = FakeConnection(FakeResponse(), fault=TimeoutError)
    with pytest.raises(TransportFailure) as caught:
        make_transport(timeout_connection).post_sample(b"{}")
    assert caught.value.failure_code == JUDGE_TIMEOUT

    down_connection = FakeConnection(FakeResponse(), fault=OSError)
    with pytest.raises(TransportFailure) as caught:
        make_transport(down_connection).post_sample(b"{}")
    assert caught.value.failure_code == JUDGE_UNAVAILABLE


def test_connection_is_closed_after_every_sample() -> None:
    connection = FakeConnection(FakeResponse(chunks=[b"{}"]))
    make_transport(connection).post_sample(b"{}")
    assert connection.closed
    failing = FakeConnection(FakeResponse(status=500))
    with pytest.raises(TransportFailure):
        make_transport(failing).post_sample(b"{}")
    assert failing.closed


# ---- bounds ---------------------------------------------------------------


def test_response_over_the_cap_is_unavailable() -> None:
    chunks = [b"x" * 8192] * 9  # 72 KiB > 64 KiB
    connection = FakeConnection(FakeResponse(chunks=chunks))
    transport = make_transport(connection)
    with pytest.raises(TransportFailure) as caught:
        transport.post_sample(b"{}")
    assert caught.value.failure_code == JUDGE_UNAVAILABLE


def test_exactly_the_cap_is_accepted() -> None:
    body = b"x" * (RESPONSE_CAP_BYTES - 2)
    connection = FakeConnection(FakeResponse(chunks=[body, b""]))
    transport = make_transport(connection)
    assert transport.post_sample(b"{}") == body


def test_slow_drip_cannot_extend_the_total_deadline() -> None:
    chunks = [b"y" * 64] * 40  # 40 drips at 10 ms ≈ 400 ms total
    connection = FakeConnection(FakeResponse(chunks=chunks, drip_delay=0.01))
    transport = make_transport(connection, timeout_ms=100)
    started = time.monotonic()
    with pytest.raises(TransportFailure) as caught:
        transport.post_sample(b"{}")
    elapsed = time.monotonic() - started
    assert caught.value.failure_code == JUDGE_TIMEOUT
    assert elapsed < 1.0  # the drip ran 400 ms worth of chunks; deadline held


def test_slow_drip_within_the_deadline_completes() -> None:
    chunks = [b"y" * 64] * 5
    connection = FakeConnection(FakeResponse(chunks=chunks, drip_delay=0.005))
    transport = make_transport(connection, timeout_ms=2000)
    assert transport.post_sample(b"{}") == b"y" * 320


def test_read_timeouts_track_the_remaining_deadline() -> None:
    seen = []

    class RecordingSocket(FakeSocket):
        def settimeout(self, value):
            seen.append(value)
            super().settimeout(value)

    connection = FakeConnection(FakeResponse(chunks=[b"a" * 8192, b"b" * 10]))
    connection.sock = RecordingSocket()
    transport = make_transport(connection, timeout_ms=5000)
    transport.post_sample(b"{}")
    assert all(0 < value <= 5.0 for value in seen)
