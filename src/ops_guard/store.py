"""Transactional SQLite persistence for frozen proposals (ADR 0002, rules 2 and 6).

Proposal bytes are immutable: there is no update path for invocation content.
Every mutation runs inside an explicit BEGIN IMMEDIATE transaction so token
consumption can commit atomically with the pre-execution audit append.
"""

from __future__ import annotations

import os.path
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
     "vacuum", "attach", "detach", "delete", "drop", "alter", "truncate",
     "replace"}
)


def _lead_keyword(sql: str) -> str:
    """First meaningful keyword of a statement, skipping whitespace and SQL comments.

    Only the statement head is tokenized; the rest of the string is not
    interpreted, so string literals containing comment markers elsewhere in
    the statement are unaffected.
    """
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch.isspace() or ch in "(;":
            i += 1
        elif sql.startswith("--", i):
            newline = sql.find("\n", i)
            i = n if newline == -1 else newline + 1
        elif sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            if end == -1:
                return ""  # unterminated block comment: sqlite will reject
            i = end + 2
        else:
            break
    parts = sql[i:].split(None, 1)
    if not parts:
        return ""
    word = parts[0].lower()
    # A comment marker glued to the keyword ("COMMIT-- x") ends the keyword.
    for marker in ("--", "/*"):
        word = word.split(marker, 1)[0]
    word = word.rstrip(";")
    # The statement must start with a plain alphabetic keyword. Anything else
    # — a BOM or control-character prefix, quote-glued operands, empty text —
    # is either an evasion of this filter or a statement SQLite would reject
    # anyway; both fail closed here.
    if not (word.isascii() and word.isalpha()):
        raise ValueError(
            "statement does not start with a plain SQL keyword; "
            "not allowed inside an audit transaction callback"
        )
    return word


def _reject_transaction_control(sql: str) -> None:
    lead = _lead_keyword(sql)
    if not lead or lead in _TRANSACTION_CONTROL:
        raise ValueError(
            f"statement {lead!r} is not allowed inside an audit transaction callback; "
            "statements must start with a plain SQL keyword"
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
    reachable through instance attributes, and transaction-control SQL —
    including comment-obscured forms — is rejected up front (sqlite3 also
    refuses multi-statement strings, so a lead-keyword check after comment
    stripping is sufficient). This prevents accidental or casual transaction
    control by the audit callback. A determined in-process adversary can
    bypass any Python-level guard; the ``in_transaction`` checks in
    ``ProposalStore.transaction`` catch the common bypasses (an ended
    transaction) and raise instead of leaving a silent partial commit, but
    the pairing remains a defensive boundary, not an in-process sandbox.
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


def same_database(left: str, right: str) -> bool:
    """True when two store paths denote one SQLite database file.

    Comparison is over absolute, case-normalized paths so relative and
    differently-cased spellings of the same file match. ``:memory:`` is
    never the same database as anything — every connection to it is a
    separate, empty database — so a memory-backed store always fails this
    check (fail-closed, issue #36).
    """
    if str(left).strip().lower() == ":memory:" or str(right).strip().lower() == ":memory:":
        return False
    return os.path.normcase(os.path.abspath(str(left))) == os.path.normcase(
        os.path.abspath(str(right))
    )


class ProposalStore:
    """File-backed store; one short-lived connection per operation."""

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)

    @property
    def path(self) -> str:
        """The database file this store persists to (store-pairing validation)."""
        return self._path

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
