"""The authenticated ``propose_fix`` path behind the hosted judge
(issue #91; ADR 0014).

Mirrors the local-judge harness: an in-process FastMCP server over the
real proposal service and audit log, with the judge swapped for
``JevJudge`` over a scripted transport. Proves proposal/token shape and
transaction behavior are unchanged: any judge outcome still issues the
proposal; an audit write failure still returns no proposal; authorization
outcomes never inspect judge advice.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
from datetime import timedelta

import pytest

from ops_guard import AuditLog, AuditStore, ProposalService, ProposalStore
from ops_guard.invocation import Invocation
from ops_guard.jev import (
    JEV_PROJECTION_SCHEMA_VERSION,
    JUDGE_UNAVAILABLE,
    RISK_QUESTION_ID,
    JevJudge,
    DisclosureGrant,
    EgressPolicy,
    terminal_leaves,
    _tokens_to_pointer,
)
from ops_guard.retrieval import RunbookLibrary, build_mcp_server
from ops_guard.jev import TransportFailure
from helpers import FakeClock
from tests_helpers_runbook import VALID_RUNBOOK

from test_jev_judge import body_with
from jev_fixtures import ScriptedJevTransport

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC_CORPUS = os.path.join(REPO_ROOT, "runbooks")
N8N_UPDATE = os.path.join(PUBLIC_CORPUS, "n8n-update.json")

DEFAULT_TTL = timedelta(minutes=15)
ENDPOINT_IDENTITY = "https://jev.example:443/v1/systemone"


def corpus_library() -> RunbookLibrary:
    documents = []
    for name in sorted(os.listdir(PUBLIC_CORPUS)):
        with open(os.path.join(PUBLIC_CORPUS, name), encoding="utf-8") as handle:
            documents.append(json.load(handle))
    library, rejections = RunbookLibrary.load(documents)
    assert rejections == []
    return library


def cited_passage():
    from ops_guard.runbooks import Citation

    library = corpus_library()
    with open(N8N_UPDATE, encoding="utf-8") as handle:
        document = json.load(handle)
    citation = Citation(
        runbook_id=document["runbook_id"],
        revision=document["revision"],
        content_hash=document["content_hash"],
        locator="update/ordering",
    )
    return library.resolve_citation(citation)


def corpus_grant() -> DisclosureGrant:
    """A grant for the public corpus invocation: every leaf approved except
    ``runbook_revision_hash``. The corpus is public; nothing private is
    encoded here."""
    cited = cited_passage()
    invocation = Invocation(
        action=cited.operation_action,
        target=cited.operation_target,
        arguments={"service": "n8n", "timeout_seconds": 30},
        preconditions=list(cited.preconditions),
        runbook_revision_hash=cited.citation.content_hash,
    )
    invocation_json = invocation.to_json()
    leaves = {
        _tokens_to_pointer(tokens): value for tokens, value in terminal_leaves(invocation_json)
    }
    return DisclosureGrant(
        profile_id="corpus-fixture",
        invocation_sha256=invocation.digest,
        citation={
            "runbook_id": cited.citation.runbook_id,
            "revision": cited.citation.revision,
            "content_hash": cited.citation.content_hash,
            "locator": cited.citation.locator,
        },
        passage_sha256=hashlib.sha256(cited.passage.text.encode("utf-8")).hexdigest(),
        approved={pointer: value for pointer, value in leaves.items()
                  if pointer != "/runbook_revision_hash"},
        omitted={"/runbook_revision_hash": "binding retained locally"},
    )


def valid_invocation() -> dict:
    cited = cited_passage()
    return {
        "action": cited.operation_action,
        "target": cited.operation_target,
        "arguments": {"service": "n8n", "timeout_seconds": 30},
        "preconditions": [dict(item) for item in cited.preconditions],
        "runbook_revision_hash": cited.citation.content_hash,
    }


def citation_input() -> dict:
    cited = cited_passage()
    return {
        "runbook_id": cited.citation.runbook_id,
        "revision": cited.citation.revision,
        "content_hash": cited.citation.content_hash,
        "locator": cited.citation.locator,
    }


class JevHarness:
    """The proposal tool registered over a real proposal service, with the
    hosted judge on a scripted transport."""

    def __init__(self, tmp_path, *, script=None, audit_append=None):
        self.clock = FakeClock()
        self.db_path = str(tmp_path / "jev-mcp.db")
        self.audit = AuditLog(
            AuditStore(self.db_path), fingerprint_key=os.urandom(32), clock=self.clock
        )
        if audit_append is not None:
            self.audit.append_on = audit_append.__get__(self.audit)
        self.service = ProposalService(
            ProposalStore(self.db_path), token_key=os.urandom(32), clock=self.clock,
            audit=self.audit,
        )
        with self.service.store.transaction() as conn:
            conn.execute("SELECT 1").fetchone()
        grant = corpus_grant()
        config = JevConfig_for(grant)
        if script is None:
            script = [body_with({RISK_QUESTION_ID: "routine"}, [RISK_QUESTION_ID])] * 3
        judge = JevJudge(
            config=config,
            hmac_key=os.urandom(32),
            transport=ScriptedJevTransport(script),
            serving_fingerprint="fixture-fingerprint",
        )
        self.server = build_mcp_server(
            corpus_library(),
            self.audit,
            proposals=self.service,
            proposal_ttl=DEFAULT_TTL,
            judge=judge,
        )

    def call(self, invocation=None, citation=None):
        from fastmcp import Client

        arguments = {
            "invocation": invocation or valid_invocation(),
            "citation": citation or citation_input(),
        }

        async def call():
            async with Client(self.server) as client:
                return await client.call_tool("propose_fix", arguments)

        return asyncio.run(call())

    def proposal_rows(self) -> list[sqlite3.Row]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            return conn.execute("SELECT * FROM proposals").fetchall()

    def proposal_events(self):
        return [e for e in self.audit.events() if e.event_type == "proposal"]


def JevConfig_for(grant: DisclosureGrant):
    from ops_guard.jev import JevConfig

    return JevConfig(
        endpoint=ENDPOINT_IDENTITY,
        allowed_endpoints=(ENDPOINT_IDENTITY,),
        bearer_token="fixture-token-" + "x" * 24,
        policy=EgressPolicy(grants=(grant,), sha256="e" * 64),
    )


@pytest.fixture()
def harness(tmp_path):
    return JevHarness(tmp_path)


def test_propose_fix_issues_the_proposal_with_a_hosted_snapshot(harness) -> None:
    result = harness.call()
    payload = json.loads(result.content[0].text)
    assert sorted(payload) == ["expires_at", "invocation_digest", "proposal_id", "token"]
    rows = harness.proposal_rows()
    assert len(rows) == 1 and rows[0]["state"] == "active"
    events = harness.proposal_events()
    assert len(events) == 1
    snapshot = events[0].judge_snapshot
    assert snapshot["schema_version"] == JEV_PROJECTION_SCHEMA_VERSION
    assert snapshot["status"] == "answered"
    assert snapshot["risk_class"] == "routine"
    assert snapshot["profile_id"] == "corpus-fixture"
    assert snapshot["serving_fingerprint"] == "fixture-fingerprint"
    assert events[0].evidence_refs == (
        "n8n-update@" + citation_input()["revision"],
        citation_input()["content_hash"],
        "update/ordering",
    )
    # The raw token rides this one response and is never stored.
    stored = [
        json.dumps(
            {
                key: row[key].decode("utf-8", "replace") if isinstance(row[key], bytes) else row[key]
                for key in row.keys()
            }
        )
        for row in harness.proposal_rows()
    ]
    assert all(payload["token"] not in document for document in stored)


def test_judge_failure_still_issues_the_proposal(tmp_path) -> None:
    harness = JevHarness(tmp_path, script=[TransportFailure(JUDGE_UNAVAILABLE)])
    result = harness.call()
    payload = json.loads(result.content[0].text)
    assert payload["proposal_id"]
    snapshot = harness.proposal_events()[0].judge_snapshot
    assert snapshot["status"] == "unavailable"
    assert snapshot["failure_code"] == JUDGE_UNAVAILABLE
    assert "risk_class" not in snapshot
    assert len(harness.proposal_rows()) == 1


def test_audit_failure_still_returns_no_proposal(tmp_path) -> None:
    from ops_guard.audit import AuditWriteFailure

    def failing_append(self, conn, event_type, **kwargs):
        raise AuditWriteFailure("required audit append failed: injected")

    harness = JevHarness(tmp_path, audit_append=failing_append)
    with pytest.raises(Exception, match="proposal_write_failed"):
        harness.call()
    assert harness.proposal_rows() == []


def test_authorization_outcome_is_identical_regardless_of_judgment(tmp_path) -> None:
    """The gate and token lifecycle never read judge advice: proposals whose
    hosted snapshots disagree resolve and consume identically."""
    answered = JevHarness(tmp_path)
    answered_payload = json.loads(answered.call().content[0].text)
    unavailable = JevHarness(tmp_path, script=[])
    unavailable_payload = json.loads(unavailable.call().content[0].text)
    for harness, payload in ((answered, answered_payload), (unavailable, unavailable_payload)):
        resolved = harness.service.resolve(payload["token"])
        assert resolved.proposal_id == payload["proposal_id"]
        consumed = harness.service.consume(payload["token"])
        assert consumed.consumed
    assert answered_payload["invocation_digest"] == unavailable_payload["invocation_digest"]


def test_unsupported_invocation_still_creates_a_proposal_with_rejected_snapshot(tmp_path) -> None:
    """A policy rejection is audit-only: the proposal path is unchanged."""
    harness = JevHarness(tmp_path, script=[])
    invocation = valid_invocation()
    invocation["arguments"] = {"service": "n8n", "timeout_seconds": 30, "unsanctioned": True}
    result = harness.call(invocation=invocation)
    payload = json.loads(result.content[0].text)
    assert payload["proposal_id"]
    snapshot = harness.proposal_events()[0].judge_snapshot
    assert snapshot["failure_code"] == "judge_input_rejected"
    assert snapshot["attempted_samples"] == 0
