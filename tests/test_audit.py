"""Audit recording contract (issue #9; property-based + fault injection)."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import threading
from datetime import datetime, timedelta, timezone

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ops_guard import (
    AUDIT_SCHEMA_VERSION,
    AuditLog,
    AuditStore,
    AuditWriteFailure,
    ProposalService,
    ProposalStore,
    redact,
)
from helpers import FakeClock, make_invocation

UTC = timezone.utc


@pytest.fixture()
def audit(tmp_path, token_key, clock):
    path = str(tmp_path / "ops-guard.db")
    store = AuditStore(path)
    service = ProposalService(ProposalStore(path), token_key=token_key, clock=clock)
    log = AuditLog(store, fingerprint_key=os.urandom(32), clock=clock)
    return log, service


def test_events_are_ordered_and_versioned(audit) -> None:
    log, _service = audit
    for index in range(5):
        log.append("request", payload={"n": index})
    events = log.events()
    assert [e.sequence for e in events] == [1, 2, 3, 4, 5]
    assert all(e.schema_version == AUDIT_SCHEMA_VERSION for e in events)
    assert len({e.event_id for e in events}) == 5


@given(bursts=st.lists(st.integers(min_value=1, max_value=4), min_size=1, max_size=12))
@settings(max_examples=25, deadline=None)
def test_sequences_are_gapless_across_generated_bursts(bursts) -> None:
    path = os.path.join(tempfile.mkdtemp(prefix="ops-guard-audit-"), "ops-guard.db")
    log = AuditLog(AuditStore(path), fingerprint_key=os.urandom(32), clock=_FixedClock())
    for burst in bursts:
        for _ in range(burst):
            log.append("request", payload={})
    events = log.events()
    assert [e.sequence for e in events] == list(range(1, len(events) + 1))


def test_redaction_at_write_time(audit) -> None:
    log, _ = audit
    log.append(
        "authorization",
        payload={
            "action": "restart",
            "credentials": {"password": "hunter2", "shape": "basic"},
            "nested": {"api_key": "sk-123", "note": "keep me"},
            "items": [{"token": "abc", "ok": 1}],
        },
        judge_snapshot={"risk": "low", "authorization": "Bearer xyz"},
    )
    event = log.events()[0]
    assert event.payload["action"] == "restart"
    assert event.payload["credentials"] == {
        "__redacted__": "sensitive-key",
        "fingerprint": event.payload["credentials"]["fingerprint"],
    }
    assert event.payload["nested"]["api_key"]["__redacted__"] == "sensitive-key"
    assert event.payload["nested"]["note"] == "keep me"
    assert event.payload["items"][0]["token"]["__redacted__"] == "sensitive-key"
    assert event.payload["items"][0]["ok"] == 1
    assert event.judge_snapshot["risk"] == "low"
    assert event.judge_snapshot["authorization"]["__redacted__"] == "sensitive-key"
    # The secret never reached storage.
    log_path = log._store._path
    assert b"hunter2" not in open(log_path, "rb").read()
    assert b"sk-123" not in open(log_path, "rb").read()


def test_fingerprints_are_keyed_and_stable() -> None:
    payload = {"password": "same-secret"}
    first = redact(payload, fingerprint_key=b"k1")
    again = redact(payload, fingerprint_key=b"k1")
    other = redact(payload, fingerprint_key=b"k2")
    assert first["password"]["fingerprint"] == again["password"]["fingerprint"]
    assert first["password"]["fingerprint"] != other["password"]["fingerprint"]


def test_compound_sensitive_key_variants_are_redacted() -> None:
    payload = {
        "access_token": "leak-me",
        "api-key": "leak-me-too",
        "authToken": "and-me",
        "set-cookie": "session=xyz",
        "private_key": "-----BEGIN",
        "note": "keep",
    }
    redacted = redact(payload, fingerprint_key=b"k")
    for key in ("access_token", "api-key", "authToken", "set-cookie", "private_key"):
        assert redacted[key]["__redacted__"] == "sensitive-key"
    assert redacted["note"] == "keep"


def test_redaction_marker_injection_is_rejected(audit) -> None:
    log, _ = audit
    with pytest.raises(AuditWriteFailure):
        log.append(
            "request",
            payload={"__redacted__": "not-actually-redacted", "secret": "real"},
        )


def test_non_serializable_sensitive_value_fails_the_write(audit) -> None:
    log, _ = audit
    with pytest.raises(AuditWriteFailure):
        log.append("request", payload={"password": object()})
    assert log.events() == []


def test_schema_version_is_read_back_not_constant(audit) -> None:
    log, _ = audit
    log.append("request", payload={})
    assert log.events()[0].schema_version == AUDIT_SCHEMA_VERSION
    # A historical row written by an older schema version must read back as
    # its stored version, not the current constant.
    conn = sqlite3.connect(log._store._path)
    conn.execute("UPDATE audit_events SET schema_version = 7")
    conn.commit()
    conn.close()
    assert log.events()[0].schema_version == 7


def test_fingerprint_key_is_required(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "ops-guard.db"))
    with pytest.raises((TypeError, ValueError)):
        AuditLog(store, clock=_FixedClock())  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        AuditLog(store, fingerprint_key=b"", clock=_FixedClock())


def test_outcome_vocabulary_is_validated(audit) -> None:
    log, _ = audit
    with pytest.raises(ValueError):
        log.append("request", payload={}, outcome="excellent")
    log.append("execution_outcome", payload={}, outcome="unknown")
    log.append("execution_outcome", payload={}, outcome="refused", failure_code="E-1")
    outcomes = [e.outcome for e in log.events()]
    assert outcomes == ["unknown", "refused"]


def test_interface_is_insert_only(audit) -> None:
    log, _ = audit
    log.append("request", payload={"a": 1})
    before = json.dumps([e.__dict__ for e in log.events()], sort_keys=True, default=str)
    for name in ("append", "append_on", "events"):
        assert callable(getattr(log, name))
    public = [n for n in dir(log) if not n.startswith("_")]
    assert not any(n.startswith(("update", "delete", "rewrite", "purge")) for n in public)
    after = json.dumps([e.__dict__ for e in log.events()], sort_keys=True, default=str)
    assert before == after


def test_execution_start_then_outcome_with_unknown_result(audit) -> None:
    log, service = audit
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))
    correlation = issued.proposal_id
    log.append(
        "execution_start",
        payload={"phase": "pre-execution"},
        correlation_id=correlation,
        proposal_ref=issued.proposal_id,
        invocation_digest=issued.invocation_digest,
        authorization_path="standing",
    )
    log.append(
        "execution_outcome",
        payload={"phase": "post-execution"},
        correlation_id=correlation,
        outcome="unknown",
        failure_code=None,
    )
    start, outcome = log.events()
    assert start.event_type == "execution_start" and outcome.event_type == "execution_outcome"
    assert start.sequence < outcome.sequence
    assert outcome.outcome == "unknown"
    assert start.correlation_id == outcome.correlation_id == correlation


def test_required_audit_failure_rolls_back_token_consumption(audit) -> None:
    log, service = audit
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))

    def failing_append(conn: sqlite3.Connection) -> None:
        # A required audit write that cannot persist (unserializable payload).
        log.append_on(conn, "execution_start", payload={"bad": object()})

    with pytest.raises(AuditWriteFailure):
        service.consume(issued.token, same_transaction=failing_append)

    assert not service.resolve(issued.token).consumed  # fail-closed: nothing ran
    assert log.events() == []  # nothing half-recorded


def test_gate_pairing_commits_start_with_the_consume(audit) -> None:
    log, service = audit
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))

    def append_start(conn: sqlite3.Connection) -> None:
        log.append_on(
            conn,
            "execution_start",
            payload={"phase": "pre-execution"},
            proposal_ref=issued.proposal_id,
            invocation_digest=issued.invocation_digest,
            authorization_path="proposal-bound",
        )

    consumed = service.consume(issued.token, same_transaction=append_start)
    assert consumed.consumed
    events = log.events()
    assert len(events) == 1 and events[0].event_type == "execution_start"
    assert events[0].proposal_ref == issued.proposal_id


def test_crashed_append_leaves_no_gap(audit) -> None:
    log, _ = audit
    log.append("request", payload={"n": 1})
    store = AuditStore(log._store._path)
    with pytest.raises(RuntimeError):
        with store.transaction() as conn:
            sequence = AuditStore.next_sequence_on(conn)
            conn.execute(
                "INSERT INTO audit_events (sequence, event_id, schema_version, recorded_at,"
                " event_type, evidence_refs, payload) VALUES (?, 'x', 1, 't', 'request', '[]', '{}')",
                (sequence,),
            )
            raise RuntimeError("crash before commit")
    log.append("request", payload={"n": 2})
    assert [e.sequence for e in log.events()] == [1, 2]  # no gap, no reuse of a visible row


class _FixedClock:
    def __init__(self) -> None:
        self._clock = FakeClock()

    def __call__(self) -> datetime:
        return self._clock()


@given(workers=st.integers(min_value=2, max_value=10))
@settings(max_examples=15, deadline=None)
def test_concurrent_appends_stay_ordered_and_unique(workers: int) -> None:
    path = os.path.join(tempfile.mkdtemp(prefix="ops-guard-audit-"), "ops-guard.db")
    store = AuditStore(path)
    log = AuditLog(store, fingerprint_key=os.urandom(32), clock=_FixedClock())
    barrier = threading.Barrier(workers)

    def append_one() -> None:
        barrier.wait()
        log.append("request", payload={"w": workers})

    threads = [threading.Thread(target=append_one) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    events = log.events()
    assert len(events) == workers
    sequences = [e.sequence for e in events]
    assert sequences == list(range(1, workers + 1))
