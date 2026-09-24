"""Crash boundaries: no half-committed proposal or consumed-without-audit state (ADR 0002, rules 6-7)."""

from __future__ import annotations

import os
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

    def committing_callback(conn, _consumed_digest: str) -> None:
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
        "-- x\nCOMMIT",
        "/* c */ COMMIT",
        "COMMIT-- x",
        "-- x\nROLLBACK",
        "-- x\nBEGIN IMMEDIATE",
        "/* c */ RELEASE sneaky",
    ]

    for statement in attempts:
        def hostile(conn, _consumed_digest: str, statement=statement):
            conn.execute(statement)
            raise AssertionError("transaction-control SQL must be rejected first")

        with pytest.raises(ValueError):
            service.consume(issued.token, same_transaction=hostile)

    # Every attempt was blocked before reaching SQLite; the token is intact.
    resolved = service.resolve(issued.token)
    assert not resolved.consumed
    assert service.consume(issued.token).consumed


def test_comment_rollback_and_rebegin_chain_is_blocked(db_path, token_key, clock) -> None:
    """The cycle-3 silent-defeat chain: comment ROLLBACK, comment BEGIN, INSERT."""
    service = make_service(db_path, token_key=token_key, clock=clock)
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))

    def evasive_callback(conn, _consumed_digest: str) -> None:
        conn.execute("-- undo\nROLLBACK")
        conn.execute("-- reopen\nBEGIN")
        conn.execute("CREATE TABLE IF NOT EXISTS audit_probe (id INTEGER PRIMARY KEY, note TEXT)")
        conn.execute("INSERT INTO audit_probe (note) VALUES ('unpaired')")

    with pytest.raises(ValueError):
        service.consume(issued.token, same_transaction=evasive_callback)

    conn = sqlite3.connect(db_path)
    try:
        state = conn.execute(
            "SELECT state FROM proposals WHERE proposal_id = ?", (issued.proposal_id,)
        ).fetchone()[0]
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE name = 'audit_probe'"
        ).fetchall()
    finally:
        conn.close()
    assert state == "active"  # consume never happened
    assert tables == []  # the foreign transaction was never opened


def test_obscured_keyword_forms_are_rejected(db_path, token_key, clock) -> None:
    """BOM / control-char prefixes and quote-glued keywords fail closed."""
    service = make_service(db_path, token_key=token_key, clock=clock)
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))
    obscured = [
        "\ufeffROLLBACK",  # SQLite skips a leading BOM; the filter must not
        "\ufeffCOMMIT",
        "\x1bCOMMIT",
        "ATTACH's' AS y",
        "SAVEPOINT's1'",
        "-- only a comment",
        "/* only a comment */",
    ]

    for statement in obscured:
        def hostile(conn, _consumed_digest: str, statement=statement):
            conn.execute(statement)

        with pytest.raises(ValueError):
            service.consume(issued.token, same_transaction=hostile)

    assert service.resolve(issued.token).proposal_id == issued.proposal_id
    assert not service.resolve(issued.token).consumed


def test_guarded_cursor_hides_the_real_connection(db_path, token_key, clock) -> None:
    service = make_service(db_path, token_key=token_key, clock=clock)
    issued = service.open_proposal(make_invocation(), ttl=timedelta(minutes=5))
    observed = {}

    def probing_callback(conn, _consumed_digest: str) -> None:
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

    def failing_append(conn: sqlite3.Connection, _consumed_digest: str) -> None:
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

    def audit_append(conn: sqlite3.Connection, _consumed_digest: str) -> None:
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


# --- Owner recovery (issue #39; ADR 0005) ---------------------------------


def _recovery_wiring(db_path, token_key, clock, owner):
    import os as _os

    from ops_guard import (
        ApprovalStore,
        ApprovalVerifier,
        AuditLog,
        AuditStore,
        Citation,
        ExecutionGate,
        ExecutionRequest,
    )
    from ops_guard.retrieval import RunbookLibrary
    from tests_helpers_runbook import VALID_RUNBOOK

    audit = AuditLog(AuditStore(str(db_path)), fingerprint_key=_os.urandom(32), clock=clock)
    service = make_service(db_path, token_key=token_key, clock=clock, audit=audit)
    verifier = ApprovalStore(str(db_path))
    from ops_guard import ApprovalVerifier as _AV

    verifier = _AV(ApprovalStore(str(db_path)), service, operator_identity="alan", clock=clock)
    library, _ = RunbookLibrary.load([VALID_RUNBOOK])
    scripts = {"/opt/scripts/restart-n8n.sh": b"#!/bin/sh\n"}
    gate = ExecutionGate(
        service,
        verifier,
        audit,
        runbooks=library,
        script_source=scripts.__getitem__,
        clock=clock,
        owner=owner,
    )
    citation = Citation(
        runbook_id=VALID_RUNBOOK["runbook_id"],
        revision=VALID_RUNBOOK["revision"],
        content_hash=VALID_RUNBOOK["content_hash"],
        locator="restart/steps",
    )
    authorization = None
    return audit, service, verifier, gate, citation, authorization


def _dispatch_crash(audit, verifier, gate, service, citation):
    """Commit execution_start, then fail the outcome append: the documented
    crash window (start durable, token consumed, no terminal outcome)."""
    from ops_guard import AuditWriteFailure, ExecutionRequest
    from tests_helpers_runbook import VALID_RUNBOOK as _RB

    issued = service.open_proposal(
        make_invocation(runbook_revision_hash=_RB["content_hash"]),
        ttl=timedelta(minutes=5),
    )
    verifier.record_approval(issued.token, operator_identity="alan")
    real = audit.append_on

    def failing(conn, event_type, **kwargs):
        if event_type == "execution_outcome":
            raise AuditWriteFailure("crash before the outcome append")
        return real(conn, event_type, **kwargs)

    audit.append_on = failing  # type: ignore[method-assign]
    try:
        request = ExecutionRequest(
            token=issued.token,
            script_path="/opt/scripts/restart-n8n.sh",
            citation=citation,
            observed_preconditions={"healthcheck": "passing"},
            operator_identity="alan",
        )
        gate.execute(request, lambda invocation, script_bytes: "success")
    except AuditWriteFailure:
        pass  # the crash window: start is durable, no outcome exists
    finally:
        audit.append_on = real  # type: ignore[method-assign]
    return issued


def test_recovery_records_exactly_one_unknown_for_proven_dead_owner(
    db_path, token_key, clock
) -> None:
    from ops_guard import ExecutionOwner
    from ops_guard.recovery import reconcile_interrupted_executions

    owners_dir = os.path.join(str(db_path) + ".owners")
    owner = ExecutionOwner(owners_dir)
    audit, service, verifier, gate, citation, _ = _recovery_wiring(
        db_path, token_key, clock, owner
    )
    _dispatch_crash(audit, verifier, gate, service, citation)
    owner.close()  # the process dies: its lock becomes acquirable

    recovered = reconcile_interrupted_executions(audit)
    assert [r.action for r in recovered] == ["recovered"]

    events = audit.events()
    outcomes = [e for e in events if e.event_type == "execution_outcome"]
    assert len(outcomes) == 1
    assert outcomes[0].outcome == "unknown"
    assert outcomes[0].failure_code == "owner-dead"

    # Idempotent: a repeat sweep finds the terminal outcome and appends nothing.
    assert reconcile_interrupted_executions(audit) == []
    outcomes_after = [e for e in audit.events() if e.event_type == "execution_outcome"]
    assert len(outcomes_after) == 1


def test_recovery_leaves_live_owner_unresolved(db_path, token_key, clock) -> None:
    from ops_guard import ExecutionOwner
    from ops_guard.recovery import reconcile_interrupted_executions

    owners_dir = os.path.join(str(db_path) + ".owners")
    owner = ExecutionOwner(owners_dir)
    audit, service, verifier, gate, citation, _ = _recovery_wiring(
        db_path, token_key, clock, owner
    )
    _dispatch_crash(audit, verifier, gate, service, citation)
    # The owner is still alive: its lock stays held by this wiring.

    reconciliations = reconcile_interrupted_executions(audit)
    assert [r.action for r in reconciliations] == ["alive"]
    assert [e for e in audit.events() if e.event_type == "execution_outcome"] == []
    owner.close()


def test_recovery_leaves_indeterminate_owner_unresolved(db_path, token_key, clock) -> None:
    import os as _os

    from ops_guard import ExecutionOwner
    from ops_guard.recovery import reconcile_interrupted_executions

    owners_dir = os.path.join(str(db_path) + ".owners")
    owner = ExecutionOwner(owners_dir)
    audit, service, verifier, gate, citation, _ = _recovery_wiring(
        db_path, token_key, clock, owner
    )
    _dispatch_crash(audit, verifier, gate, service, citation)
    owner.close()  # release, so the platform allows removing the file
    _os.remove(owner.lock_path)  # lock state lost: proof is impossible

    reconciliations = reconcile_interrupted_executions(audit)
    assert [r.action for r in reconciliations] == ["indeterminate"]
    assert [e for e in audit.events() if e.event_type == "execution_outcome"] == []
    owner.close()


def test_recovery_never_touches_a_terminal_outcome(db_path, token_key, clock) -> None:
    import os as _os

    from ops_guard import ExecutionOwner
    from ops_guard.recovery import reconcile_interrupted_executions
    from tests_helpers_runbook import VALID_RUNBOOK as _RB

    owners_dir = os.path.join(str(db_path) + ".owners")
    owner = ExecutionOwner(owners_dir)
    audit, service, verifier, gate, citation, _ = _recovery_wiring(
        db_path, token_key, clock, owner
    )
    from tests_helpers_runbook import VALID_RUNBOOK as _RB

    issued = service.open_proposal(
        make_invocation(runbook_revision_hash=_RB["content_hash"]),
        ttl=timedelta(minutes=5),
    )
    verifier.record_approval(issued.token, operator_identity="alan")
    from ops_guard import Citation, ExecutionRequest

    request = ExecutionRequest(
        token=issued.token,
        script_path="/opt/scripts/restart-n8n.sh",
        citation=Citation(
            runbook_id=_RB["runbook_id"],
            revision=_RB["revision"],
            content_hash=_RB["content_hash"],
            locator="restart/steps",
        ),
        observed_preconditions={"healthcheck": "passing"},
        operator_identity="alan",
    )
    outcome = gate.execute(request, lambda invocation, script_bytes: "success")
    assert outcome.dispatched

    assert reconcile_interrupted_executions(audit) == []
    outcomes = [e for e in audit.events() if e.event_type == "execution_outcome"]
    assert [o.outcome for o in outcomes] == ["success"]
    owner.close()
