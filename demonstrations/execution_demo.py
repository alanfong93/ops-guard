"""Permitted and refused execution paths, demonstrated end-to-end (issue #16).

Runs the real gate (and the real proposal/approval/audit layers) through a
fixed scenario script and returns an ordered trace. Every refusal records an
audit event before any side effect; permitted paths consume the token, commit
the execution-start audit record, run the executor, and record the outcome —
including an explicitly unknown completion. Reproducible: same inputs, same
trace structure.

Usage (from repo root):
    .venv/Scripts/python.exe demonstrations/execution_demo.py
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from datetime import timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))

from ops_guard import (  # noqa: E402
    ApprovalStore,
    ApprovalVerifier,
    AuditLog,
    AuditStore,
    ExecutionGate,
    ExecutionRequest,
    Invocation,
    ProposalService,
    ProposalStore,
    ScriptIdentity,
    parse_authorization,
)
from ops_guard.invocation import canonicalize_json  # noqa: E402
from ops_guard.runbooks import parse_revision  # noqa: E402

OPERATOR = "alan"
SCRIPT = ScriptIdentity(path="/opt/scripts/restart-n8n.sh", sha256="a" * 64)


def _verified_runbook() -> dict:
    fixture = os.path.join(
        os.path.dirname(__file__), "..", "tests", "fixtures", "runbooks",
        "valid-n8n-restart.json",
    )
    with open(fixture, encoding="utf-8") as handle:
        return json.load(handle)


def build_invocation(runbook_hash: str) -> Invocation:
    return Invocation(
        action="restart",
        target="n8n",
        arguments={"service": "n8n", "timeout_seconds": 30},
        preconditions=[{"name": "healthcheck", "expected": "passing"}],
        runbook_revision_hash=runbook_hash,
    )


def run_demonstration() -> dict:
    """Execute every scenario; return the ordered demonstration trace."""
    runbook = _verified_runbook()
    revision_hash = runbook["content_hash"]
    parsed = parse_revision(runbook)

    import os as _os

    from helpers import FakeClock  # tests package helper

    path = os.path.join(tempfile.mkdtemp(prefix="ops-guard-demo-"), "ops-guard.db")
    clock = FakeClock()
    audit = AuditLog(AuditStore(path), fingerprint_key=_os.urandom(32), clock=clock)
    service = ProposalService(ProposalStore(path), token_key=_os.urandom(32), clock=clock, audit=audit)
    verifier = ApprovalVerifier(ApprovalStore(path), service, operator_identity=OPERATOR, clock=clock)
    gate = ExecutionGate(service, verifier, audit, clock=clock)

    standing = parse_authorization({
        "authorization_id": "auth-restart-n8n",
        "script_path": SCRIPT.path,
        "script_sha256": SCRIPT.sha256,
        "action": "restart",
        "target": "n8n",
        "arguments": {"service": "n8n", "timeout_seconds": 30},
        "preconditions": [{"name": "healthcheck", "expected": "passing"}],
        "runbook_revision_hash": revision_hash,
    })

    from ops_guard import Citation

    citation = Citation(
        runbook_id=runbook["runbook_id"],
        revision=runbook["revision"],
        content_hash=revision_hash,
        locator="restart/steps",
    )

    trace: list[dict] = []

    def record(scenario: str, ran: bool, outcome) -> None:
        executed = ran and harness_executor_calls[-1:] or []
        trace.append({
            "scenario": scenario,
            "dispatched": outcome.dispatched,
            "refusal": outcome.refusal,
            "authorization_path": outcome.authorization_path,
            "outcome": outcome.outcome,
            "executor_invocations": len(executed),
        })

    harness_executor_calls: list[Invocation] = []

    def executor(invocation: Invocation) -> str:
        harness_executor_calls.append(invocation)
        return "success"

    def unknown_executor(invocation: Invocation) -> str:
        harness_executor_calls.append(invocation)
        return "unknown"

    def request(token: str, **overrides) -> ExecutionRequest:
        fields = dict(
            token=token,
            script=SCRIPT,
            runbook_document=runbook,
            citation=citation,
            observed_preconditions={"healthcheck": "passing"},
            operator_identity=OPERATOR,
            standing=standing,
            expected_digest=None,
        )
        fields.update(overrides)
        return ExecutionRequest(**fields)

    def scenario(name: str, request_obj: ExecutionRequest, worker=executor) -> None:
        before = len(harness_executor_calls)
        outcome = gate.execute(request_obj, worker)
        record(name, len(harness_executor_calls) > before, outcome)

    # 1. Standing-authorization success.
    issued = service.open_proposal(build_invocation(revision_hash), ttl=timedelta(minutes=10))
    scenario("standing-authorization-success", request(issued.token, expected_digest=issued.invocation_digest))

    # 2. Independent approval success.
    issued = service.open_proposal(build_invocation(revision_hash), ttl=timedelta(minutes=10))
    verifier.record_approval(issued.token, operator_identity=OPERATOR)
    scenario("independent-approval-success", request(issued.token, standing=None))

    # 3. Missing-evidence refusal.
    issued = service.open_proposal(build_invocation(revision_hash), ttl=timedelta(minutes=10))
    scenario("missing-evidence-refusal", request(issued.token, runbook_document={}))

    # 4. Stale-evidence refusal (a different verified revision than frozen).
    stale = json.loads(json.dumps(runbook))
    stale["revision"] = "2026-09-23.2"
    stale["passages"][0]["text"] = "a procedure the proposal never froze"
    stale_body = {k: v for k, v in stale.items() if k != "content_hash"}
    stale["content_hash"] = hashlib.sha256(canonicalize_json(stale_body)).hexdigest()
    stale_citation = Citation(
        runbook_id=stale["runbook_id"], revision=stale["revision"],
        content_hash=stale["content_hash"], locator="restart/steps",
    )
    scenario("stale-evidence-refusal", request(issued.token, runbook_document=stale, citation=stale_citation))

    # 5. Failed-precondition refusal.
    issued = service.open_proposal(build_invocation(revision_hash), ttl=timedelta(minutes=10))
    scenario("failed-precondition-refusal", request(issued.token, observed_preconditions={"healthcheck": "failing"}))

    # 6. Invalid-token refusal.
    scenario("invalid-token-refusal", request("never-issued"))

    # 7. Expired-token refusal.
    issued = service.open_proposal(build_invocation(revision_hash), ttl=timedelta(minutes=10))
    clock.advance(11 * 60)
    scenario("expired-token-refusal", request(issued.token))
    clock = FakeClock()  # restore the clock for later scenarios
    audit = AuditLog(AuditStore(path), fingerprint_key=_os.urandom(32), clock=clock)
    service = ProposalService(ProposalStore(path), token_key=_os.urandom(32), clock=clock, audit=audit)
    verifier = ApprovalVerifier(ApprovalStore(path), service, operator_identity=OPERATOR, clock=clock)
    gate = ExecutionGate(service, verifier, audit, clock=clock)

    # 8. Audit-write refusal (execution-start append fails; nothing runs).
    issued = service.open_proposal(build_invocation(revision_hash), ttl=timedelta(minutes=10))
    original_append_on = audit.append_on

    def failing_append_on(conn, event_type, **kwargs):
        if event_type == "execution_start":
            raise __import__("ops_guard").AuditWriteFailure("audit store unavailable")
        return original_append_on(conn, event_type, **kwargs)

    audit.append_on = failing_append_on  # type: ignore[method-assign]
    scenario("audit-write-refusal", request(issued.token))
    audit.append_on = original_append_on  # type: ignore[method-assign]

    # 9. Reused-token refusal (replay after a successful dispatch).
    issued = service.open_proposal(build_invocation(revision_hash), ttl=timedelta(minutes=10))
    scenario("reused-token-first-dispatch", request(issued.token))
    scenario("reused-token-refusal", request(issued.token))

    # 10. Post-dispatch unknown outcome.
    issued = service.open_proposal(build_invocation(revision_hash), ttl=timedelta(minutes=10))
    scenario("unknown-outcome", request(issued.token), worker=unknown_executor)

    audit_events = [
        {
            "sequence": event.sequence,
            "event_type": event.event_type,
            "proposal_ref": event.proposal_ref,
            "authorization_path": event.authorization_path,
            "outcome": event.outcome,
        }
        for event in audit.events()
    ]
    return {
        "scenarios": trace,
        "executor_invocations_total": len(harness_executor_calls),
        "audit_events": audit_events,
    }


if __name__ == "__main__":
    print(json.dumps(run_demonstration(), indent=2))
