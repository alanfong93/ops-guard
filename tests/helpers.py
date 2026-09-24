"""Test helpers shared across test modules."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from ops_guard import AuditLog, AuditStore, Invocation, ProposalService, ProposalStore

UTC = timezone.utc

DEFAULT_NOW = datetime(2026, 9, 22, 12, 0, 0, tzinfo=UTC)


class FakeClock:
    def __init__(self, now: datetime = DEFAULT_NOW) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)


def make_invocation(**overrides: Any) -> Invocation:
    fields: dict[str, Any] = {
        "action": "restart",
        "target": "n8n",
        "arguments": {"service": "n8n", "timeout_seconds": 30},
        "preconditions": [{"name": "healthcheck", "expected": "passing"}],
        "runbook_revision_hash": "b" * 64,
    }
    fields.update(overrides)
    return Invocation(**fields)


def make_service(path, *, token_key: bytes, clock: Callable[[], datetime], audit: AuditLog | None = None) -> ProposalService:
    """Service with its paired audit log; one is auto-wired on the same
    database when not supplied (the service itself requires the pairing)."""
    if audit is None:
        audit = AuditLog(AuditStore(str(path)), fingerprint_key=os.urandom(32), clock=clock)
    return ProposalService(ProposalStore(path), token_key=token_key, clock=clock, audit=audit)


def fresh_service() -> tuple[ProposalService, FakeClock]:
    """A new service (with its paired audit log) on a fresh database;
    for use inside @given examples."""
    path = os.path.join(tempfile.mkdtemp(prefix="ops-guard-test-"), "proposals.db")
    clock = FakeClock()
    audit = AuditLog(AuditStore(path), fingerprint_key=os.urandom(32), clock=clock)
    service = ProposalService(
        ProposalStore(path), token_key=os.urandom(32), clock=clock, audit=audit
    )
    return service, clock
