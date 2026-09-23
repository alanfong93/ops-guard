"""Proposal-bound approval verification (ADR 0003).

Approvals are recorded only on the internal operator path, bound to the
frozen proposal, and single-use: the recorded-to-used transition joins the
token-consumption transaction so an approval is spent exactly when its
proposal token is consumed. Verification is read-only; every rejection is
typed and deterministic (host-supplied, operator mismatch, replayed, then
the proposal-lifecycle rejections of ADR 0002).
"""

from __future__ import annotations

import hmac
import sqlite3
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from ops_guard.errors import (
    ApprovalAlreadyRecordedError,
    ApprovalError,
    ApprovalOperatorMismatchError,
    ApprovalReplayedError,
    HostSuppliedApprovalError,
    InvocationMismatchError,
)
from ops_guard.proposals import ProposalService, format_timestamp
from ops_guard.store import AuditAppend

_APPROVAL_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    approval_id            TEXT PRIMARY KEY,
    token_digest           TEXT NOT NULL UNIQUE,
    proposal_id            TEXT NOT NULL,
    operator_identity      TEXT NOT NULL,
    invocation_digest      TEXT NOT NULL,
    runbook_revision_hash  TEXT NOT NULL,
    expires_at             TEXT NOT NULL,
    created_at             TEXT NOT NULL,
    state                  TEXT NOT NULL CHECK (state IN ('recorded', 'used')),
    used_at                TEXT
);
"""


def _connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.executescript(_APPROVAL_SCHEMA)
    return conn


def _aware(moment: datetime) -> datetime:
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("clock must return timezone-aware datetimes")
    return moment


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    token_digest: str
    proposal_id: str
    operator_identity: str
    invocation_digest: str
    runbook_revision_hash: str
    expires_at: datetime
    created_at: datetime
    used: bool


@dataclass(frozen=True)
class ApprovalDecision:
    """Structured verification outcome; the audit layer records every result."""

    allowed: bool
    approval_id: str
    proposal_id: str
    invocation_digest: str
    reason: str


class ApprovalStore:
    """Same-file persistence for approval records; one connection per operation.

    The schema is created eagerly at construction: composed operations (the
    gate's consume transaction, verification reads) run on connections from
    other stores, so the table must exist before any of them run.
    """

    def __init__(self, path: str) -> None:
        self._path = str(path)
        conn = self._local_conn()
        try:
            conn.executescript(_APPROVAL_SCHEMA)
        finally:
            conn.close()

    def _local_conn(self) -> sqlite3.Connection:
        return _connect(self._path)

    @staticmethod
    def insert_on(
        conn: sqlite3.Connection,
        *,
        approval_id: str,
        token_digest: str,
        proposal_id: str,
        operator_identity: str,
        invocation_digest: str,
        runbook_revision_hash: str,
        expires_at: str,
        created_at: str,
    ) -> None:
        conn.execute(
            """
            INSERT INTO approvals (
                approval_id, token_digest, proposal_id, operator_identity,
                invocation_digest, runbook_revision_hash, expires_at,
                created_at, state, used_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'recorded', NULL)
            """,
            (
                approval_id,
                token_digest,
                proposal_id,
                operator_identity,
                invocation_digest,
                runbook_revision_hash,
                expires_at,
                created_at,
            ),
        )

    @staticmethod
    def fetch_on(conn: sqlite3.Connection, token_digest: str) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM approvals WHERE token_digest = ?", (token_digest,)
        ).fetchone()

    @staticmethod
    def mark_used_on(conn: sqlite3.Connection, token_digest: str, used_at: str) -> bool:
        """Compare-and-swap recorded-to-used; safe on any connection to the DB."""
        cursor = conn.execute(
            """
            UPDATE approvals
               SET state = 'used', used_at = ?
             WHERE token_digest = ? AND state = 'recorded'
            """,
            (used_at, token_digest),
        )
        return cursor.rowcount == 1


class ApprovalVerifier:
    def __init__(
        self,
        store: ApprovalStore,
        proposals: ProposalService,
        *,
        operator_identity: str,
        clock: Callable[[], datetime],
    ) -> None:
        if not operator_identity:
            raise ValueError("operator_identity must be a non-empty configured identity")
        if store._path != proposals.store._path:
            raise ValueError(
                "ApprovalStore and the proposal service must share one database"
            )
        self._store = store
        self._proposals = proposals
        self._operator_identity = operator_identity
        self._clock = clock

    def _now(self) -> datetime:
        return _aware(self._clock())

    def _identity_matches(self, presented: str) -> bool:
        return hmac.compare_digest(
            presented.encode("utf-8"), self._operator_identity.encode("utf-8")
        )

    def record_approval(self, token: str, *, operator_identity: str) -> ApprovalRecord:
        """Internal operator path: record configured-operator approval for a proposal.

        The caller must present the configured operator identity; the proposal
        must be live (unknown, consumed, and expired tokens are rejected by the
        proposal lifecycle). Re-recordings are rejected — a correction is a new
        proposal with its own approval.
        """
        if not self._identity_matches(operator_identity):
            raise ApprovalOperatorMismatchError(
                "only the configured operator may record approval"
            )
        frozen = self._proposals.resolve(token)
        token_digest = self._proposals.token_digest(token)
        now = self._now()
        record = ApprovalRecord(
            approval_id=uuid.uuid4().hex,
            token_digest=token_digest,
            proposal_id=frozen.proposal_id,
            operator_identity=self._operator_identity,
            invocation_digest=frozen.invocation_digest,
            runbook_revision_hash=frozen.invocation.runbook_revision_hash,
            expires_at=frozen.expires_at,
            created_at=now,
            used=False,
        )
        with self._proposals.store.transaction() as conn:
            try:
                ApprovalStore.insert_on(
                    conn,
                    approval_id=record.approval_id,
                    token_digest=record.token_digest,
                    proposal_id=record.proposal_id,
                    operator_identity=record.operator_identity,
                    invocation_digest=record.invocation_digest,
                    runbook_revision_hash=record.runbook_revision_hash,
                    expires_at=format_timestamp(record.expires_at),
                    created_at=format_timestamp(record.created_at),
                )
            except sqlite3.IntegrityError as error:
                raise ApprovalAlreadyRecordedError(
                    "this proposal already carries an approval"
                ) from error
        return record

    def verify(self, token: str, *, operator_identity: str) -> ApprovalDecision:
        """Read-only check of a proposal-bound approval (ADR 0003, rule 6).

        Rejection order: the operator-identity gate runs first — an
        unauthenticated caller gets no oracle over approval existence — then
        host-supplied, stored-operator mismatch (tamper), replayed, the
        proposal-lifecycle rejections, and the binding re-check.
        """
        token_digest = self._proposals.token_digest(token)
        if not self._identity_matches(operator_identity):
            raise ApprovalOperatorMismatchError(
                "presented operator identity does not match the configured operator"
            )
        with self._proposals.store.read() as conn:
            row = ApprovalStore.fetch_on(conn, token_digest)
            if row is None:
                raise HostSuppliedApprovalError(
                    "no server-recorded approval exists for this token"
                )
            if not self._identity_matches(row["operator_identity"]):
                raise ApprovalOperatorMismatchError(
                    "recorded approval does not belong to the configured operator"
                )
            if row["state"] == "used":
                raise ApprovalReplayedError("approval was already spent")
        frozen = self._proposals.resolve(token)  # typed unknown/consumed/expired
        if (
            frozen.proposal_id != row["proposal_id"]
            or frozen.invocation_digest != row["invocation_digest"]
            or frozen.invocation.runbook_revision_hash != row["runbook_revision_hash"]
            or format_timestamp(frozen.expires_at) != row["expires_at"]
        ):
            raise InvocationMismatchError(
                "recorded approval diverges from the live frozen proposal"
            )
        return ApprovalDecision(
            allowed=True,
            approval_id=row["approval_id"],
            proposal_id=frozen.proposal_id,
            invocation_digest=frozen.invocation_digest,
            reason="verifier-recorded configured-operator approval",
        )

    def mark_used_append(self, token: str) -> AuditAppend:
        """Callback factory for the gate: flip the approval inside the consume tx.

        Pass the returned callable as ``ProposalService.consume``'s
        ``same_transaction`` so the approval flip commits or rolls back with
        the token consumption (ADR 0002 rule 6 + ADR 0003 rule 4). The flip
        re-checks inside the transaction that its own proposal is the one
        transitioning; wiring this callback to a different token's consume
        fails closed and rolls the whole unit back.
        """
        token_digest = self._proposals.token_digest(token)

        def append(conn: sqlite3.Connection) -> None:
            row = conn.execute(
                "SELECT state FROM proposals WHERE token_digest = ?", (token_digest,)
            ).fetchone()
            if row is None or row["state"] != "consumed":
                raise ApprovalError(
                    "approval flip must join the consumption of its own proposal"
                )
            if not ApprovalStore.mark_used_on(
                conn, token_digest, format_timestamp(self._now())
            ):
                raise ApprovalReplayedError("approval was already spent")

        return append
