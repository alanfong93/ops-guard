"""Test helpers shared across test modules."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from ops_guard import Invocation, ProposalService, ProposalStore

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


def make_service(path, *, token_key: bytes, clock: Callable[[], datetime]) -> ProposalService:
    return ProposalService(ProposalStore(path), token_key=token_key, clock=clock)


def fresh_service() -> tuple[ProposalService, FakeClock]:
    """A new service on a fresh database; for use inside @given examples."""
    path = os.path.join(tempfile.mkdtemp(prefix="ops-guard-test-"), "proposals.db")
    clock = FakeClock()
    return ProposalService(ProposalStore(path), token_key=os.urandom(32), clock=clock), clock
