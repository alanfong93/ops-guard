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


def make_observer_registry(values: dict[str, str] | None = None):
    """A registry with one scripted test observer plus the real fixed set
    minus live I/O (issue #62). The 'static_test' observer returns the
    configured value per observer-id key ('static_test' -> values.get)."""
    from ops_guard.preconditions import ObserverRegistry, PolicyError

    registry = ObserverRegistry()
    state = {"value": (values or {}).get("static_test", "passing")}

    def static_adapter(settings):
        return state["value"]

    def static_validator(settings):
        if not isinstance(settings, dict) or settings != {}:
            raise PolicyError("static_test settings must be exactly {}")

    registry.register("static_test", static_adapter, static_validator)
    registry._test_state = state
    return registry


def make_policy_document(
    *,
    runbook_id: str,
    revision: str,
    content_hash: str,
    standing=(),
    bindings: bool = True,
):
    """A minimal valid operator policy document for tests.

    ``bindings=False`` yields no observer bindings: every precondition is
    unmapped and must refuse (issue #62 fail-closed)."""
    return {
        "schema_version": "ops-guard-policy-v1",
        "standing_authorizations": [
            {
                "authorization_id": record.authorization_id,
                "script_path": record.script_path,
                "script_sha256": record.script_sha256,
                "action": record.action,
                "target": record.target,
                "arguments": dict(record.arguments),
                "preconditions": [dict(p) for p in record.preconditions],
                "runbook_revision_hash": record.runbook_revision_hash,
                "runner_profile_digest": record.runner_profile_digest,
            }
            for record in standing
        ],
        "observer_bindings": (
            [
                {
                    "runbook_id": runbook_id,
                    "revision": revision,
                    "content_hash": content_hash,
                    "precondition_index": 0,
                    "observer_id": "static_test",
                    "settings": {},
                }
            ]
            if bindings
            else []
        ),
    }


def load_test_policy(document, registry):
    from ops_guard.preconditions import load_policy

    return load_policy(document, registry)

def make_runner_profile():
    """The test runner profile (ADR 0012): deterministic digest."""
    from ops_guard.execution_binding import RunnerProfile

    return RunnerProfile(
        profile_id="test-runner",
        executable="python3",
        executable_sha256="e" * 64,
        argv=("python3", "-c", "pass"),
        working_directory=".",
        env_allowlist=("PATH",),
        timeout_seconds=10,
    )


def make_execution_catalog(runbook, script_path, script_sha256, profile=None, action="restart", target="n8n"):
    """A catalog binding the runbook's operation to the script."""
    from ops_guard.execution_binding import CatalogEntry

    profile = profile or make_runner_profile()
    entry = CatalogEntry(
        runbook_id=runbook["runbook_id"],
        revision=runbook["revision"],
        content_hash=runbook["content_hash"],
        action=action,
        target=target,
        script_id="fixture-script",
        script_path=script_path,
        script_sha256=script_sha256,
    )
    entries = {entry.key(): entry}
    return entries, {profile.profile_id: profile}


def binding_template(runbook, script_path, script_sha256, invocation, entries=None, profiles=None):
    """The resolved binding template for the invocation's action/target."""
    from ops_guard.execution_binding import resolve_binding

    if entries is None or profiles is None:
        entries, profiles = make_execution_catalog(
            runbook, script_path, script_sha256,
            action=invocation.action, target=invocation.target,
        )
    return resolve_binding(
        entries,
        profiles,
        runbook_id=runbook["runbook_id"],
        revision=runbook["revision"],
        content_hash=runbook["content_hash"],
        action=invocation.action,
        target=invocation.target,
    )