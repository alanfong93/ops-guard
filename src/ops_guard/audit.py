"""Audit recording: durable, ordered, redacted, insert-only (issue #9).

Contract. Every operational event is one versioned envelope:

- ``sequence`` — globally monotonic, assigned by the store inside the write
  transaction (MAX+1 under BEGIN IMMEDIATE, so no gaps and no reuse).
- ``event_id`` — unique random identifier.
- ``recorded_at`` — timezone-aware UTC instant.
- ``event_type`` — what happened ("request", "guidance", "proposal",
  "authorization", "execution_start", "execution_outcome", "refusal", ...).
- ``correlation_id`` / ``proposal_ref`` / ``invocation_digest`` — references
  tying related events together.
- ``evidence_refs`` — cited passage references backing the event.
- ``authorization_path`` — which authorization applied, when one did.
- ``judge_snapshot`` — the advisory judge context, when present; redacted
  like every payload.
- ``payload`` — the redacted event body.
- ``outcome`` / ``failure_code`` — terminal result when the event has one:
  "success", "failure", "unknown", or "refused".

Redaction happens at write time, before persistence: a mapping key is
sensitive when its normalized form matches a root set (so ``access_token``
and ``api-key`` match); values under sensitive keys are replaced by an
explicit redaction marker plus a keyed fingerprint (keyed with the operator's
persistent audit key, not the token key) so later correlation stays possible
without revealing the value. Only mapping payloads are walked;
``correlation_id``, ``evidence_refs``, ``authorization_path`` and
``event_type`` are stored raw by contract.

The audit *interface* is insert-only — append (standalone or inside a
caller-owned transaction, so the execution gate can pair the pre-execution
append with the proposal-token consumption in one durable transaction) and
read. There is no update or delete method on this surface. The underlying
guarded-connection boundary is defensive, not a sandbox (see
``ops_guard.store``): it additionally rejects delete/drop/alter/truncate/
replace statement heads — while update and insert-or-replace remain allowed
for the approval flip — and narrowing the seam to vetted operations is
tracked for the execution gate. Storage failure propagates: a required
append that cannot persist raises ``AuditWriteFailure``, and the caller must
not execute.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime

from ops_guard.invocation import canonicalize_json
from ops_guard.proposals import format_timestamp, parse_timestamp

AUDIT_SCHEMA_VERSION = 1

DEFAULT_SENSITIVE_KEYS = frozenset(
    {"password", "secret", "token", "apikey", "authorization", "auth",
     "credential", "credentials", "privatekey", "cookie", "session"}
)

_REDACTED_MARKER = "__redacted__"


def _normalized(key: str) -> str:
    """Lowercase and strip separators so access_token, api-key, authToken all
    match the apikey/token roots."""
    return "".join(ch for ch in key.lower() if ch not in "_- ")


def _is_sensitive(key: str, sensitive_roots: frozenset[str]) -> bool:
    normalized = _normalized(key)
    return any(root in normalized for root in sensitive_roots)


def _jsonable(value):
    """Best-effort JSON-model coercion for fingerprint input; rejects values
    that are not JSON-representable (they cannot be correlated stably)."""
    if isinstance(value, (bool, str, int, float, type(None))):
        return value
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    raise ValueError(
        f"sensitive values must be JSON-representable to fingerprint, got {type(value).__name__}"
    )

_AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    sequence           INTEGER PRIMARY KEY,
    event_id           TEXT NOT NULL UNIQUE,
    schema_version     INTEGER NOT NULL,
    recorded_at        TEXT NOT NULL,
    event_type         TEXT NOT NULL,
    correlation_id     TEXT,
    proposal_ref       TEXT,
    invocation_digest  TEXT,
    evidence_refs      TEXT NOT NULL,
    authorization_path TEXT,
    judge_snapshot     TEXT,
    payload            TEXT NOT NULL,
    outcome            TEXT,
    failure_code       TEXT
);
"""


class AuditWriteFailure(RuntimeError):
    """A required audit append could not be persisted; the caller must not execute."""


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    event_id: str
    schema_version: int
    recorded_at: datetime
    event_type: str
    correlation_id: str | None
    proposal_ref: str | None
    invocation_digest: str | None
    evidence_refs: tuple[str, ...]
    authorization_path: str | None
    judge_snapshot: Mapping | None
    payload: Mapping
    outcome: str | None
    failure_code: str | None


def redact(
    value,
    *,
    sensitive_keys: frozenset[str] = DEFAULT_SENSITIVE_KEYS,
    fingerprint_key: bytes | None = None,
    _reason: str = "sensitive-key",
):
    """Write-time redaction walk. A mapping key is sensitive when its
    normalized form (lowercase, separators stripped) contains one of
    ``sensitive_keys`` — so ``access_token``, ``api-key``, ``authToken`` and
    ``secret_key`` all match. Values under sensitive keys are replaced by
    ``{__redacted__: reason, fingerprint: ...}``; the optional keyed
    fingerprint (JCS-serialized input, HMAC prefix) preserves later
    correlation without revealing the value. Caller-supplied ``__redacted__``
    markers are rejected — the marker is reserved for write-time redaction.
    Only mappings are walked: ``correlation_id``, ``evidence_refs``,
    ``authorization_path`` and ``event_type`` are stored raw by contract."""
    if isinstance(value, Mapping):
        if _REDACTED_MARKER in value:
            raise ValueError(
                "redaction marker key is reserved for write-time redaction"
            )
        out = {}
        for key, item in value.items():
            if isinstance(key, str) and _is_sensitive(key, sensitive_keys):
                replacement = {_REDACTED_MARKER: _reason}
                if fingerprint_key is not None:
                    digest_input = canonicalize_json(_jsonable(item))
                    replacement["fingerprint"] = hmac.new(
                        fingerprint_key, digest_input, hashlib.sha256
                    ).hexdigest()[:16]
                out[key] = replacement
            else:
                out[key] = redact(
                    item,
                    sensitive_keys=sensitive_keys,
                    fingerprint_key=fingerprint_key,
                    _reason=_reason,
                )
        return out
    if isinstance(value, (list, tuple)):
        return [
            redact(item, sensitive_keys=sensitive_keys, fingerprint_key=fingerprint_key, _reason=_reason)
            for item in value
        ]
    return value


class AuditStore:
    """Same-file persistence for audit events (shares the proposal DB)."""

    def __init__(self, path: str) -> None:
        self._path = str(path)
        conn = self._local_conn()
        try:
            conn.executescript(_AUDIT_SCHEMA)
        finally:
            conn.close()

    @property
    def path(self) -> str:
        """The database file this store persists to (store-pairing validation)."""
        return self._path

    def _local_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 30000")
        return conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """One durable unit of work; commits on clean exit, rolls back on any error."""
        conn = self._local_conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException as error:
                if not conn.in_transaction:
                    raise RuntimeError(
                        "unit of work was committed or rolled back inside the callback"
                    ) from error
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
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
        conn = self._local_conn()
        try:
            yield conn
        finally:
            conn.close()

    @staticmethod
    def next_sequence_on(conn: sqlite3.Connection) -> int:
        row = conn.execute("SELECT COALESCE(MAX(sequence), 0) AS last FROM audit_events").fetchone()
        return int(row["last"]) + 1

    @staticmethod
    def insert_on(conn: sqlite3.Connection, event: AuditEvent) -> None:
        conn.execute(
            """
            INSERT INTO audit_events (
                sequence, event_id, schema_version, recorded_at, event_type,
                correlation_id, proposal_ref, invocation_digest, evidence_refs,
                authorization_path, judge_snapshot, payload, outcome, failure_code
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.sequence,
                event.event_id,
                event.schema_version,
                format_timestamp(event.recorded_at),
                event.event_type,
                event.correlation_id,
                event.proposal_ref,
                event.invocation_digest,
                canonicalize_json(list(event.evidence_refs)).decode("utf-8"),
                event.authorization_path,
                canonicalize_json(event.judge_snapshot).decode("utf-8")
                if event.judge_snapshot is not None
                else None,
                canonicalize_json(event.payload).decode("utf-8"),
                event.outcome,
                event.failure_code,
            ),
        )

    @staticmethod
    def fetch_all_on(conn: sqlite3.Connection) -> Iterator[sqlite3.Row]:
        return conn.execute("SELECT * FROM audit_events ORDER BY sequence").fetchall()


class AuditLog:
    def __init__(
        self,
        store: AuditStore,
        *,
        fingerprint_key: bytes,
        sensitive_keys: frozenset[str] = DEFAULT_SENSITIVE_KEYS,
        clock: Callable[[], datetime],
    ) -> None:
        """``fingerprint_key`` is required and must persist across restarts:
        it is what makes redacted-value fingerprints correlate over time."""
        if not fingerprint_key:
            raise ValueError("fingerprint_key must be a non-empty persistent secret")
        self._store = store
        self._fingerprint_key = fingerprint_key
        self._sensitive_keys = sensitive_keys
        self._clock = clock

    @property
    def store(self) -> AuditStore:
        """The persistence store, so gate configuration can validate that
        proposal and audit records share one database boundary (issue #36)."""
        return self._store

    def _validate(self, event_type, payload, evidence_refs, outcome):
        """Cheap caller validation; runs outside the write-failure wrapper."""
        if not isinstance(event_type, str) or not event_type:
            raise ValueError("event_type must be a non-empty string")
        if outcome is not None and outcome not in {"success", "failure", "unknown", "refused"}:
            raise ValueError("outcome must be one of success/failure/unknown/refused")
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be a mapping")
        refs = tuple(evidence_refs)
        if not all(isinstance(ref, str) for ref in refs):
            raise ValueError("evidence_refs must be strings")
        moment = self._clock()
        if moment.tzinfo is None or moment.utcoffset() is None:
            raise ValueError("clock must return timezone-aware datetimes")
        return refs, moment

    def _build(self, event_type: str, sequence: int, payload, *, moment: datetime,
               correlation_id, proposal_ref, invocation_digest, evidence_refs,
               authorization_path, judge_snapshot, outcome, failure_code) -> AuditEvent:
        return AuditEvent(
            sequence=sequence,
            event_id=uuid.uuid4().hex,
            schema_version=AUDIT_SCHEMA_VERSION,
            recorded_at=moment,
            event_type=event_type,
            correlation_id=correlation_id,
            proposal_ref=proposal_ref,
            invocation_digest=invocation_digest,
            evidence_refs=tuple(evidence_refs),
            authorization_path=authorization_path,
            judge_snapshot=None
            if judge_snapshot is None
            else redact(judge_snapshot, sensitive_keys=self._sensitive_keys, fingerprint_key=self._fingerprint_key),
            payload=redact(payload, sensitive_keys=self._sensitive_keys, fingerprint_key=self._fingerprint_key),
            outcome=outcome,
            failure_code=failure_code,
        )

    def append(self, event_type: str, *, payload: Mapping, correlation_id: str | None = None,
               proposal_ref: str | None = None, invocation_digest: str | None = None,
               evidence_refs: Sequence[str] = (), authorization_path: str | None = None,
               judge_snapshot: Mapping | None = None, outcome: str | None = None,
               failure_code: str | None = None) -> AuditEvent:
        """Standalone append in its own durable transaction."""
        with self._store.transaction() as conn:
            return self.append_on(conn, event_type, payload=payload,
                                  correlation_id=correlation_id, proposal_ref=proposal_ref,
                                  invocation_digest=invocation_digest, evidence_refs=evidence_refs,
                                  authorization_path=authorization_path,
                                  judge_snapshot=judge_snapshot, outcome=outcome,
                                  failure_code=failure_code)

    def append_on(self, conn: sqlite3.Connection, event_type: str, *, payload: Mapping,
                  correlation_id: str | None = None, proposal_ref: str | None = None,
                  invocation_digest: str | None = None, evidence_refs: Sequence[str] = (),
                  authorization_path: str | None = None, judge_snapshot: Mapping | None = None,
                  outcome: str | None = None, failure_code: str | None = None) -> AuditEvent:
        """Append inside a caller-owned transaction (gate pairing seam).

        Persistence failures — including payloads that cannot be canonically
        serialized or redacted — raise ``AuditWriteFailure`` so the caller
        refuses execution (PRODUCT: refuse when required recording fails)."""
        refs, moment = self._validate(event_type, payload, evidence_refs, outcome)
        try:
            sequence = AuditStore.next_sequence_on(conn)
            event = self._build(event_type, sequence, payload, moment=moment,
                                correlation_id=correlation_id, proposal_ref=proposal_ref,
                                invocation_digest=invocation_digest, evidence_refs=refs,
                                authorization_path=authorization_path,
                                judge_snapshot=judge_snapshot, outcome=outcome,
                                failure_code=failure_code)
            AuditStore.insert_on(conn, event)
            return event
        except (sqlite3.Error, TypeError, ValueError, AttributeError,
                UnicodeEncodeError, RecursionError, OverflowError) as error:
            raise AuditWriteFailure(f"required audit append failed: {error}") from error

    def events(self) -> list[AuditEvent]:
        with self._store.read() as conn:
            return [_row_to_event(row) for row in AuditStore.fetch_all_on(conn)]


def _row_to_event(row: sqlite3.Row) -> AuditEvent:
    return AuditEvent(
        sequence=int(row["sequence"]),
        event_id=row["event_id"],
        schema_version=int(row["schema_version"]),
        recorded_at=parse_timestamp(row["recorded_at"]),
        event_type=row["event_type"],
        correlation_id=row["correlation_id"],
        proposal_ref=row["proposal_ref"],
        invocation_digest=row["invocation_digest"],
        evidence_refs=tuple(json.loads(row["evidence_refs"])),
        authorization_path=row["authorization_path"],
        judge_snapshot=json.loads(row["judge_snapshot"]) if row["judge_snapshot"] else None,
        payload=json.loads(row["payload"]),
        outcome=row["outcome"],
        failure_code=row["failure_code"],
    )
