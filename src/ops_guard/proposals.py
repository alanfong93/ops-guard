"""Proposal lifecycle: freeze, resolve, consume exactly once (ADR 0002).

Enforcement mechanism: every writer transaction opens BEGIN IMMEDIATE, so
writes are serialized from transaction start and the pre-transaction checks
classify the rejection precisely; the compare-and-swap UPDATE's state and
expiry predicates are belt-and-braces, not the load-bearing guarantee.

Rejection order on a presented token is deterministic: unknown, then
invocation mismatch, then already consumed, then expired. Every rejection
happens before any execution or side effect.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Optional

from ops_guard.errors import (
    InvocationMismatchError,
    ProposalError,
    TokenAlreadyConsumedError,
    TokenExpiredError,
    UnknownTokenError,
)
from ops_guard.invocation import Invocation, parse_frozen_invocation
from ops_guard.store import AuditAppend, GuardedConnection, ProposalStore, same_database

if TYPE_CHECKING:
    from ops_guard.audit import AuditLog


def default_clock() -> datetime:
    return datetime.now(timezone.utc)


def format_timestamp(moment: datetime) -> str:
    """Fixed-width UTC ISO-8601 so lexicographic order equals chronological order."""
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds")


def parse_timestamp(text: str) -> datetime:
    return datetime.fromisoformat(text)


@dataclass(frozen=True)
class IssuedProposal:
    """Returned exactly once at creation; the raw token is never stored."""

    proposal_id: str
    token: str
    invocation_digest: str
    expires_at: datetime


@dataclass(frozen=True)
class FrozenProposal:
    proposal_id: str
    invocation: Invocation
    invocation_digest: str
    token_digest: str
    created_at: datetime
    expires_at: datetime
    consumed_at: Optional[datetime]

    @property
    def consumed(self) -> bool:
        return self.consumed_at is not None


class ProposalService:
    def __init__(
        self,
        store: ProposalStore,
        *,
        token_key: bytes,
        clock: Callable[[], datetime] = default_clock,
        audit: "AuditLog",
    ) -> None:
        """``audit`` is required (issue #40): proposal creation records its
        event in the insert transaction, so it must share the store's one
        authoritative database boundary."""
        if not token_key:
            raise ValueError("token_key must be a non-empty secret")
        if not same_database(store.path, audit.store.path):
            raise ValueError(
                "the audit log and the proposal store must share one database: "
                f"proposals={store.path!r}, audit={audit.store.path!r}"
            )
        self._store = store
        self._token_key = token_key
        self._clock = clock
        self._audit = audit

    @property
    def store(self) -> ProposalStore:
        """The transactional store, so consumers can join our transactions."""
        return self._store

    def _token_digest(self, token: str) -> str:
        return hmac.new(self._token_key, token.encode("utf-8"), hashlib.sha256).hexdigest()

    def token_digest(self, token: str) -> str:
        """Public keyed digest of a token, for consumer correlation (ADR 0003).

        Approvals and audit records key on this digest; the raw token is
        never stored.
        """
        return self._token_digest(token)

    def _now(self) -> datetime:
        moment = self._clock()
        if moment.tzinfo is None or moment.utcoffset() is None:
            raise ValueError("clock must return timezone-aware datetimes")
        return moment

    def open_proposal(self, invocation: Invocation, *, ttl: timedelta) -> IssuedProposal:
        """Freeze the invocation, mint a 256-bit token, fix the absolute expiry."""
        if not isinstance(ttl, timedelta) or ttl.total_seconds() <= 0:
            raise ValueError("ttl must be a positive timedelta")
        now = self._now()
        frozen_bytes = invocation.canonical_bytes()
        digest = hashlib.sha256(frozen_bytes).hexdigest()
        proposal_id = uuid.uuid4().hex
        token = secrets.token_urlsafe(32)
        expires_at = now + ttl
        with self._store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO proposals (
                    proposal_id, invocation_bytes, invocation_digest,
                    token_digest, created_at, expires_at, state, consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'active', NULL)
                """,
                (
                    proposal_id,
                    frozen_bytes,
                    digest,
                    self._token_digest(token),
                    format_timestamp(now),
                    format_timestamp(expires_at),
                ),
            )
            # Same transaction as the insert (issue #40): a proposal never
            # exists without its audit event, and a failed append rolls the
            # creation back — no proposal row, no token returned.
            self._audit.append_on(
                conn,
                "proposal",
                payload={
                    "proposal_id": proposal_id,
                    "invocation_digest": digest,
                    "expires_at": format_timestamp(expires_at),
                },
                correlation_id=proposal_id,
            )
        return IssuedProposal(
            proposal_id=proposal_id,
            token=token,
            invocation_digest=digest,
            expires_at=expires_at,
        )

    def resolve(self, token: str, *, expected_digest: str | None = None) -> FrozenProposal:
        """Read-only eligibility check; raises on unknown, mismatched, consumed, expired."""
        digest = self._token_digest(token)
        with self._store.read() as conn:
            row = conn.execute(
                "SELECT * FROM proposals WHERE token_digest = ?", (digest,)
            ).fetchone()
            self._check(row, digest, expected_digest, self._now())
            return _row_to_proposal(row)

    def resolve_on(
        self,
        conn: sqlite3.Connection,
        token: str,
        *,
        expected_digest: str | None = None,
    ) -> FrozenProposal:
        """Eligibility check against a caller-owned transaction's view (issue #35).

        Same rejections as ``resolve``, but the row is read from ``conn`` —
        the caller's write transaction — so the verdict reflects the state
        the rest of that transaction will pair with, not a pre-transaction
        snapshot that a concurrent consume can invalidate.
        """
        digest = self._token_digest(token)
        row = conn.execute(
            "SELECT * FROM proposals WHERE token_digest = ?", (digest,)
        ).fetchone()
        self._check(row, digest, expected_digest, self._now())
        return _row_to_proposal(row)

    def consume(
        self,
        token: str,
        *,
        expected_digest: str | None = None,
        same_transaction: AuditAppend | None = None,
    ) -> FrozenProposal:
        """Consume exactly once, optionally committing ``same_transaction`` atomically.

        The callback receives a ``GuardedConnection`` so the pre-execution
        audit append can join the consume transaction (ADR 0002, rule 6):
        transaction-control SQL and attribute reach-ins are rejected. If the
        callback raises, the consumption rolls back and the token stays
        eligible. If a callback somehow ends the transaction itself, the
        store raises instead of committing silently — the guarantee is
        detection with fail-closed behaviour, not a Python sandbox.
        """
        digest = self._token_digest(token)
        with self._store.transaction() as conn:
            # Sampled after the write lock is held so expiry is judged at
            # execution time, not queue-entry time.
            now = self._now()
            row = conn.execute(
                "SELECT * FROM proposals WHERE token_digest = ?", (digest,)
            ).fetchone()
            self._check(row, digest, expected_digest, now)
            cursor = conn.execute(
                """
                UPDATE proposals
                   SET state = 'consumed', consumed_at = ?
                 WHERE token_digest = ? AND state = 'active' AND expires_at > ?
                """,
                (format_timestamp(now), digest, format_timestamp(now)),
            )
            if cursor.rowcount != 1:
                # A concurrent winner or the expiry boundary decided first.
                fresh = conn.execute(
                    "SELECT * FROM proposals WHERE token_digest = ?", (digest,)
                ).fetchone()
                self._check(fresh, digest, expected_digest, self._now())
                raise ProposalError("consume did not apply although all checks passed")
            if same_transaction is not None:
                # Second argument: the digest of the token this transaction
                # is consuming — callbacks bind to exactly this consumption
                # (issue #19; ADR 0003 rule 4).
                same_transaction(GuardedConnection(conn), digest)
            final = conn.execute(
                "SELECT * FROM proposals WHERE token_digest = ?", (digest,)
            ).fetchone()
            return _row_to_proposal(final)

    def _check(
        self,
        row: sqlite3.Row | None,
        digest: str,
        expected_digest: str | None,
        now: datetime,
    ) -> None:
        if row is None:
            raise UnknownTokenError("no proposal is bound to this token")
        if expected_digest is not None and expected_digest != row["invocation_digest"]:
            raise InvocationMismatchError("invocation digest differs from the frozen one")
        if row["state"] == "consumed":
            raise TokenAlreadyConsumedError("proposal token was already consumed")
        if not (now < parse_timestamp(row["expires_at"])):
            raise TokenExpiredError("proposal expiry has passed")


def _row_to_proposal(row: sqlite3.Row) -> FrozenProposal:
    return FrozenProposal(
        proposal_id=row["proposal_id"],
        invocation=parse_frozen_invocation(row["invocation_bytes"]),
        invocation_digest=row["invocation_digest"],
        token_digest=row["token_digest"],
        created_at=parse_timestamp(row["created_at"]),
        expires_at=parse_timestamp(row["expires_at"]),
        consumed_at=parse_timestamp(row["consumed_at"]) if row["consumed_at"] else None,
    )
