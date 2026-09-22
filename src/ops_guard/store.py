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
        """One durable unit of work; commits on clean exit, rolls back on any error."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")
        finally:
            conn.close()


AuditAppend = Callable[[sqlite3.Connection], None]
