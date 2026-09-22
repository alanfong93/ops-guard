"""Proposal lifecycle: freeze, resolve, consume exactly once (ADR 0002).

Rejection order on a presented token is deterministic: unknown, then
invocation mismatch, then already consumed, then expired. The compare-and-swap
UPDATE inside the transaction — not the pre-checks — is the authority on
exactly-once consumption.
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
from typing import Optional

from ops_guard.errors import (
    InvocationMismatchError,
    ProposalError,
    TokenAlreadyConsumedError,
    TokenExpiredError,
    UnknownTokenError,
)
from ops_guard.invocation import Invocation, parse_frozen_invocation
from ops_guard.store import AuditAppend, ProposalStore


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
    ) -> None:
        if not token_key:
            raise ValueError("token_key must be a non-empty secret")
        self._store = store
        self._token_key = token_key
        self._clock = clock

    def _token_digest(self, token: str) -> str:
        return hmac.new(self._token_key, token.encode("utf-8"), hashlib.sha256).hexdigest()

    def open_proposal(self, invocation: Invocation, *, ttl: timedelta) -> IssuedProposal:
        """Freeze the invocation, mint a 256-bit token, fix the absolute expiry."""
        if not isinstance(ttl, timedelta) or ttl.total_seconds() <= 0:
            raise ValueError("ttl must be a positive timedelta")
        now = self._clock()
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
        return IssuedProposal(
            proposal_id=proposal_id,
            token=token,
            invocation_digest=digest,
            expires_at=expires_at,
        )

    def resolve(self, token: str, *, expected_digest: str | None = None) -> FrozenProposal:
        """Read-only eligibility check; raises on unknown, mismatched, consumed, expired."""
        digest = self._token_digest(token)
        with self._store.transaction() as conn:
            row = conn.execute(
                "SELECT * FROM proposals WHERE token_digest = ?", (digest,)
            ).fetchone()
            self._check(row, digest, expected_digest, self._clock())
            return _row_to_proposal(row)

    def consume(
        self,
        token: str,
        *,
        expected_digest: str | None = None,
        same_transaction: AuditAppend | None = None,
    ) -> FrozenProposal:
        """Consume exactly once, optionally committing ``same_transaction`` atomically.

        The callback receives the live connection so the pre-execution audit
        append can join the consume transaction (ADR 0002, rule 6). If it
        raises, the consumption rolls back and the token stays eligible.
        """
        digest = self._token_digest(token)
        now = self._clock()
        with self._store.transaction() as conn:
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
                self._check(fresh, digest, expected_digest, self._clock())
                raise ProposalError("consume did not apply although all checks passed")
            if same_transaction is not None:
                same_transaction(conn)
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
        created_at=parse_timestamp(row["created_at"]),
        expires_at=parse_timestamp(row["expires_at"]),
        consumed_at=parse_timestamp(row["consumed_at"]) if row["consumed_at"] else None,
    )
