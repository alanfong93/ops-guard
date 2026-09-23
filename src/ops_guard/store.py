"""Transactional SQLite persistence for frozen proposals (ADR 0002, rules 2 and 6).

Proposal bytes are immutable: there is no update path for invocation content.
Every mutation runs inside an explicit BEGIN IMMEDIATE transaction so token
consumption can commit atomically with the pre-execution audit append.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS proposals (
    proposal_id       TEXT PRIMARY KEY,
    invocation_bytes  BLOB NOT NULL,
    invocation_digest TEXT NOT NULL,
    token_digest      TEXT NOT NULL UNIQUE,
    created_at        TEXT NOT NULL,
    expires_at        TEXT NOT NULL,
    state             TEXT NOT NULL CHECK (state IN ('active', 'consumed')),
    consumed_at       TEXT
);
CREATE INDEX IF NOT EXISTS idx_proposals_invocation_digest
    ON proposals (invocation_digest);
"""

_TRANSACTION_CONTROL = frozenset(
    {"begin", "commit", "end", "rollback", "abort", "savepoint", "release",
     "vacuum", "attach", "detach"}
)


def _reject_transaction_control(sql: str) -> None:
    parts = sql.lstrip(" \t\r\n(;").split(None, 1)
    lead = parts[0].lower().rstrip(";") if parts else ""
    if lead in _TRANSACTION_CONTROL:
        raise ValueError(
            f"statement {lead.upper()!r} is not allowed inside an audit transaction callback"
        )


class _GuardedCursor:
    """Cursor facade exposing only reads; ``.connection`` is not reachable."""

    __slots__ = ("_cursor",)
    _allowed = frozenset({"fetchone", "fetchall", "fetchmany", "lastrowid", "rowcount"})

    def __init__(self, cursor: sqlite3.Cursor) -> None:
        object.__setattr__(self, "_cursor", cursor)

    def __getattribute__(self, name: str):
        if name in _GuardedCursor._allowed:
            return object.__getattribute__(self, name)
        raise AttributeError(
            f"{name!r} is not available inside an audit transaction callback"
        )

    def fetchone(self):
        return object.__getattribute__(self, "_cursor").fetchone()

    def fetchall(self):
        return object.__getattribute__(self, "_cursor").fetchall()

    def fetchmany(self, size: int = 1):
        return object.__getattribute__(self, "_cursor").fetchmany(size)

    @property
    def lastrowid(self):
        return object.__getattribute__(self, "_cursor").lastrowid

    @property
    def rowcount(self):
        return object.__getattribute__(self, "_cursor").rowcount


class GuardedConnection:
    """Capability boundary around a live transaction connection.

    ``__getattribute__`` whitelists the surface, so the real connection is not
    reachable through instance attributes, and transaction-control SQL is
    rejected up front (sqlite3 also refuses multi-statement strings, so a
    statement-prefix check is sufficient). This prevents accidental or casual
    transaction control by the audit callback. A determined in-process
    adversary can bypass any Python-level guard; that residual is caught by
    the ``in_transaction`` checks in ``ProposalStore.transaction``, which
    raise instead of leaving a silent partial commit.
    """

    __slots__ = ("_conn",)
    _allowed = frozenset({"execute", "executemany", "in_transaction"})

    def __init__(self, conn: sqlite3.Connection) -> None:
        object.__setattr__(self, "_conn", conn)

    def __getattribute__(self, name: str):
        if name in GuardedConnection._allowed:
            return object.__getattribute__(self, name)
        raise AttributeError(
            f"{name!r} is not available inside an audit transaction callback"
        )

    def execute(self, sql: str, parameters: tuple = ()) -> _GuardedCursor:
        _reject_transaction_control(sql)
        conn = object.__getattribute__(self, "_conn")
        return _GuardedCursor(conn.execute(sql, parameters))

    def executemany(self, sql: str, parameters: list[tuple]) -> _GuardedCursor:
        _reject_transaction_control(sql)
        conn = object.__getattribute__(self, "_conn")
        return _GuardedCursor(conn.executemany(sql, parameters))

    @property
    def in_transaction(self) -> bool:
        return object.__getattribute__(self, "_conn").in_transaction


AuditAppend = Callable[[GuardedConnection], None]


class ProposalStore:
    """File-backed store; one short-lived connection per operation."""

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.executescript(_SCHEMA)
        return conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """One durable unit of work; commits on clean exit, rolls back on any error.

        If the callback itself ended the transaction, the honest error is
        raised — the on-disk state may then be durable and must be inspected —
        rather than a misleading rollback failure masking the cause.
        """
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException as error:
                if not conn.in_transaction:
                    raise RuntimeError(
                        "unit of work was committed or rolled back inside the callback; "
                        "on-disk state must be inspected"
                    ) from error
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass  # the original error is the one that matters
                raise
            if not conn.in_transaction:
                raise RuntimeError(
                    "unit of work was committed or rolled back inside the callback"
                )
            conn.execute("COMMIT")
        finally:
            conn.close()

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        """Read-only access without taking the write lock."""
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()
