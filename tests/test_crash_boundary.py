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
    # Direct row check: the rollback must have removed the crashed insert.
    check = sqlite3.connect(db_path)
    try:
        count = check.execute(
            "SELECT COUNT(*) FROM proposals WHERE proposal_id = 'x'"
        ).fetchone()[0]
    finally:
        check.close()
    assert count == 0
    with pytest.raises(UnknownTokenError):
        service.resolve("any-token")


def test_callback_cannot_commit_the_consume_transaction(db_path, token_key, clock) -> None:
    service = make_service(db_path, token_key=token_key, clock=clock)
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))

    def committing_callback(conn) -> None:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_probe (id INTEGER PRIMARY KEY, note TEXT)"
        )
        conn.execute("INSERT INTO audit_probe (note) VALUES ('execution-start')")
        conn.commit()  # must be unreachable through the guarded connection

    with pytest.raises(AttributeError):
        service.consume(issued.token, same_transaction=committing_callback)

    # Nothing committed: no audit row, token still eligible and consumable.
    assert probe_rows(db_path) == []
    resolved = service.resolve(issued.token)
    assert not resolved.consumed
    consumed = service.consume(issued.token)
    assert consumed.consumed


def test_callback_cannot_send_transaction_control_sql(db_path, token_key, clock) -> None:
    service = make_service(db_path, token_key=token_key, clock=clock)
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))
    attempts = [
        "COMMIT",
        "  commit;",
        "ROLLBACK",
        "BEGIN IMMEDIATE",
        "SAVEPOINT sneaky",
        "RELEASE sneaky",
        "VACUUM",
    ]

    for statement in attempts:
        def hostile(conn, statement=statement):
            conn.execute(statement)
            raise AssertionError("transaction-control SQL must be rejected first")

        with pytest.raises(ValueError):
            service.consume(issued.token, same_transaction=hostile)

    # Every attempt was blocked before reaching SQLite; the token is intact.
    resolved = service.resolve(issued.token)
    assert not resolved.consumed
    assert service.consume(issued.token).consumed


def test_guarded_cursor_hides_the_real_connection(db_path, token_key, clock) -> None:
    service = make_service(db_path, token_key=token_key, clock=clock)
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))
    observed = {}

    def probing_callback(conn) -> None:
        conn.execute("CREATE TABLE IF NOT EXISTS audit_probe (id INTEGER PRIMARY KEY, note TEXT)")
        cursor = conn.execute(
            "INSERT INTO audit_probe (note) VALUES ('execution-start')"
        )
        observed["lastrowid"] = cursor.lastrowid
        observed["fetch"] = conn.execute(
            "SELECT note FROM audit_probe"
        ).fetchone()
        for escape in ("_conn", "connection", "commit", "rollback", "executescript"):
            try:
                getattr(conn, escape)
            except AttributeError:
                pass
            else:
                raise AssertionError(f"guarded connection exposed {escape!r}")
        try:
            cursor.connection
        except AttributeError:
            pass
        else:
            raise AssertionError("guarded cursor exposed .connection")

    service.consume(issued.token, same_transaction=probing_callback)
    assert observed["lastrowid"] == 1
    assert observed["fetch"][0] == "execution-start"
    assert probe_rows(db_path) == [("execution-start",)]


def test_callback_that_ends_the_transaction_raises_honestly(db_path) -> None:
    store = ProposalStore(db_path)
    with pytest.raises(RuntimeError, match="committed or rolled back inside the callback"):
        with store.transaction() as conn:
            conn.execute("COMMIT")
            raise ValueError("boom")
    # The original error stays visible as the cause.
    try:
        with store.transaction() as conn:
            conn.execute("COMMIT")
            raise ValueError("boom")
    except RuntimeError as error:
        assert isinstance(error.__cause__, ValueError)


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
