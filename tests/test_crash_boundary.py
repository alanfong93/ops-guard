"""Crash boundaries: no half-committed proposal or consumed-without-audit state (ADR 0002, rules 6-7)."""

from __future__ import annotations

import sqlite3
from datetime import timedelta

import pytest

from ops_guard import TokenAlreadyConsumedError, UnknownTokenError
from ops_guard.store import ProposalStore
from helpers import make_invocation, make_service

PROBE_SCHEMA = "CREATE TABLE IF NOT EXISTS audit_probe (id INTEGER PRIMARY KEY, note TEXT)"


@pytest.fixture()
def db_path(tmp_path):
    return tmp_path / "proposals.db"


def probe_rows(path) -> list:
    conn = sqlite3.connect(path)
    try:
        conn.execute(PROBE_SCHEMA)
        return conn.execute("SELECT note FROM audit_probe").fetchall()
    finally:
        conn.close()


def test_crash_during_open_leaves_no_proposal(db_path, token_key, clock) -> None:
    service = make_service(db_path, token_key=token_key, clock=clock)
    store = ProposalStore(db_path)
    with pytest.raises(RuntimeError):
        with store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO proposals (
                    proposal_id, invocation_bytes, invocation_digest,
                    token_digest, created_at, expires_at, state, consumed_at
                ) VALUES ('x', x'00', 'd', 't', 'now', 'later', 'active', NULL)
                """
            )
            raise RuntimeError("crash before commit")
    with pytest.raises(UnknownTokenError):
        service.resolve("any-token")


def test_consume_rolls_back_when_audit_append_fails(db_path, token_key, clock) -> None:
    service = make_service(db_path, token_key=token_key, clock=clock)
    conn = sqlite3.connect(db_path)
    conn.execute(PROBE_SCHEMA)
    conn.commit()
    conn.close()
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))

    def failing_append(conn: sqlite3.Connection) -> None:
        conn.execute("INSERT INTO audit_probe (note) VALUES ('should-not-persist')")
        raise RuntimeError("audit write failed")

    with pytest.raises(RuntimeError):
        service.consume(issued.token, same_transaction=failing_append)

    # The speculative audit row rolled back with the consumption.
    assert probe_rows(db_path) == []

    # Fail-closed: the token is still eligible and consumable exactly once.
    resolved = service.resolve(issued.token)
    assert not resolved.consumed
    consumed = service.consume(issued.token)
    assert consumed.consumed


def test_consume_and_audit_append_commit_atomically(db_path, token_key, clock) -> None:
    service = make_service(db_path, token_key=token_key, clock=clock)
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))
    conn = sqlite3.connect(db_path)
    conn.execute(PROBE_SCHEMA)
    conn.commit()
    conn.close()

    def audit_append(conn: sqlite3.Connection) -> None:
        conn.execute("INSERT INTO audit_probe (note) VALUES ('execution-start')")

    consumed = service.consume(issued.token, same_transaction=audit_append)
    assert consumed.consumed

    assert probe_rows(db_path) == [("execution-start",)]
    check = sqlite3.connect(db_path)
    try:
        state, consumed_at = check.execute(
            "SELECT state, consumed_at FROM proposals WHERE proposal_id = ?",
            (issued.proposal_id,),
        ).fetchone()
    finally:
        check.close()
    assert state == "consumed"
    assert consumed_at is not None

    with pytest.raises(TokenAlreadyConsumedError):
        service.consume(issued.token)
