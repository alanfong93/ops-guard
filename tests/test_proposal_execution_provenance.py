"""Proposal-time vs execution-time citation provenance (issue #57; ADR 0008).

The proposal audit event records the citation presented at proposal time;
the execution-start event records the citation actually used. Either
reference is provenance only: neither authorizes execution, and the gate
independently re-resolves the execution citation against the frozen
invocation and its own authorization path.
"""

from __future__ import annotations

import json
import os
from datetime import timedelta

import pytest

from ops_guard import (
    ApprovalStore,
    ApprovalVerifier,
    AuditLog,
    AuditStore,
    Citation,
    ExecutionGate,
    ExecutionRequest,
    ProposalService,
    ProposalStore,
)
from ops_guard.retrieval import RunbookLibrary, build_mcp_server
from helpers import FakeClock

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
N8N_UPDATE = os.path.join(REPO_ROOT, "runbooks", "n8n-update.json")


def cited_revision() -> dict:
    with open(N8N_UPDATE, encoding="utf-8") as handle:
        return json.load(handle)


def corpus_library() -> RunbookLibrary:
    root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runbooks")
    documents = []
    for name in sorted(os.listdir(root)):
        with open(os.path.join(root, name), encoding="utf-8") as handle:
            documents.append(json.load(handle))
    library, rejections = RunbookLibrary.load(documents)
    assert rejections == []
    return library


class Wiring:
    """Tool + gate over one service/audit pair (locator provenance tests)."""

    def __init__(self, tmp_path):
        self.clock = FakeClock()
        self.db_path = str(tmp_path / "provenance.db")
        self.audit = AuditLog(
            AuditStore(self.db_path), fingerprint_key=os.urandom(32), clock=self.clock
        )
        self.service = ProposalService(
            ProposalStore(self.db_path), token_key=os.urandom(32), clock=self.clock, audit=self.audit
        )
        with self.service.store.transaction() as conn:
            conn.execute("SELECT 1").fetchone()
        self.library = corpus_library()
        from test_proposal_tool import hermetic_judge

        self.server = build_mcp_server(
            self.library,
            self.audit,
            proposals=self.service,
            proposal_ttl=timedelta(minutes=15),
            judge=hermetic_judge(self.audit),
        )
        self.verifier = ApprovalVerifier(
            ApprovalStore(self.db_path), self.service, operator_identity="alan", clock=self.clock
        )
        self.scripts = {"/opt/scripts/restart-n8n.sh": b"#!/bin/sh\necho ok\n"}
        from helpers import make_observer_registry, make_policy_document, load_test_policy

        registry = make_observer_registry({"static_test": "running"})
        cited = cited_revision()
        policy = load_test_policy(
            make_policy_document(
                runbook_id=cited["runbook_id"],
                revision=cited["revision"],
                content_hash=cited["content_hash"],
            ),
            registry,
        )
        self.gate = ExecutionGate(
            self.service,
            self.verifier,
            self.audit,
            runbooks=self.library,
            script_source=self.scripts.__getitem__,
            clock=self.clock,
            observer_registry=registry,
            authorization_catalog=policy,
            operator_identity="alan",
        )

    def propose(self, locator: str) -> dict:
        from fastmcp import Client

        revision = cited_revision()
        payload = {
            "invocation": {
                "action": revision["operation"]["action"],
                "target": revision["operation"]["target"],
                "arguments": {"service": "n8n"},
                "preconditions": [dict(item) for item in revision["preconditions"]],
                "runbook_revision_hash": revision["content_hash"],
            },
            "citation": {
                "runbook_id": revision["runbook_id"],
                "revision": revision["revision"],
                "content_hash": revision["content_hash"],
                "locator": locator,
            },
        }

        async def call():
            async with Client(self.server) as client:
                result = await client.call_tool("propose_fix", payload)
                return json.loads(result.content[0].text)

        return asyncio_run(call())

    def events(self, event_type: str):
        return [e for e in self.audit.events() if e.event_type == event_type]


def asyncio_run(coroutine):
    import asyncio

    return asyncio.run(coroutine)


@pytest.fixture()
def wiring(tmp_path):
    return Wiring(tmp_path)


def test_locator_a_at_proposal_time_and_locator_b_at_execution_are_both_audited(wiring) -> None:
    issued = wiring.propose("update/ordering")
    wiring.verifier.record_approval(issued["token"], operator_identity="alan")
    request = ExecutionRequest(
        token=issued["token"],
        script_path="/opt/scripts/restart-n8n.sh",
        citation=Citation(
            runbook_id=cited_revision()["runbook_id"],
            revision=cited_revision()["revision"],
            content_hash=cited_revision()["content_hash"],
            locator="update/steps",
        ),
    )
    outcome = wiring.gate.execute(request, lambda invocation, script: "success")
    assert outcome.dispatched
    proposal_events = wiring.events("proposal")
    assert len(proposal_events) == 1
    assert tuple(proposal_events[0].evidence_refs)[2] == "update/ordering"
    start_events = wiring.events("execution_start")
    assert len(start_events) == 1
    assert tuple(start_events[0].evidence_refs)[2] == "update/steps"


def test_matching_proposal_evidence_refs_alone_cannot_authorize_execution(wiring) -> None:
    issued = wiring.propose("update/ordering")
    request = ExecutionRequest(
        token=issued["token"],
        script_path="/opt/scripts/restart-n8n.sh",
        citation=Citation(
            runbook_id=cited_revision()["runbook_id"],
            revision=cited_revision()["revision"],
            content_hash=cited_revision()["content_hash"],
            locator="update/ordering",
        ),
    )
    outcome = wiring.gate.execute(request, lambda invocation, script: "success")
    assert not outcome.dispatched
    assert outcome.refusal
    assert wiring.events("execution_start") == []


def test_invalid_execution_evidence_still_refuses(wiring) -> None:
    issued = wiring.propose("update/ordering")
    wiring.verifier.record_approval(issued["token"], operator_identity="alan")
    request = ExecutionRequest(
        token=issued["token"],
        script_path="/opt/scripts/restart-n8n.sh",
        citation=Citation(
            runbook_id=cited_revision()["runbook_id"],
            revision=cited_revision()["revision"],
            content_hash="c" * 64,  # not a verified revision hash in the library
            locator="update/ordering",
        ),
    )
    outcome = wiring.gate.execute(request, lambda invocation, script: "success")
    assert not outcome.dispatched
    assert outcome.refusal
    assert wiring.events("execution_start") == []
