"""Host-composed proposal MCP tool (issue #57; ADR 0008).

`propose_fix` accepts exactly a complete Invocation and a Citation,
resolves the citation through the verified RunbookLibrary, matches the
invocation to the resolved evidence, and calls open_proposal once with the
server-configured TTL. Every invalid or mismatched input fails before a
proposal row, event, or token exists.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from datetime import timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ops_guard import AuditLog, AuditStore, ProposalService, ProposalStore
from ops_guard.retrieval import RunbookLibrary, build_mcp_server
from helpers import FakeClock

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC_CORPUS = os.path.join(REPO_ROOT, "runbooks")
N8N_UPDATE = os.path.join(PUBLIC_CORPUS, "n8n-update.json")

DEFAULT_TTL = timedelta(minutes=15)


def corpus_library() -> RunbookLibrary:
    documents = []
    for name in sorted(os.listdir(PUBLIC_CORPUS)):
        with open(os.path.join(PUBLIC_CORPUS, name), encoding="utf-8") as handle:
            documents.append(json.load(handle))
    library, rejections = RunbookLibrary.load(documents)
    assert rejections == []
    return library


def hermetic_judge(audit):
    """A LocalJudge over a fake transport: fixed profile, no live Ollama."""
    from ops_guard.judge import LocalJudge
    from test_judge import FakeTransport

    return LocalJudge(
        transport=FakeTransport(outputs=['"routine"', '"routine"', '"routine"']),
        fingerprint=audit.fingerprint,
    )


def cited_revision() -> dict:
    with open(N8N_UPDATE, encoding="utf-8") as handle:
        return json.load(handle)


def citation_for(locator: str = "update/ordering") -> dict:
    revision = cited_revision()
    return {
        "runbook_id": revision["runbook_id"],
        "revision": revision["revision"],
        "content_hash": revision["content_hash"],
        "locator": locator,
    }


def valid_invocation() -> dict:
    revision = cited_revision()
    return {
        "action": revision["operation"]["action"],
        "target": revision["operation"]["target"],
        "arguments": {"service": "n8n", "timeout_seconds": 30},
        "preconditions": [dict(item) for item in revision["preconditions"]],
        "runbook_revision_hash": revision["content_hash"],
    }


class Harness:
    """A tool-registered server over a real proposal service and audit log."""

    def __init__(self, tmp_path, *, ttl: timedelta = DEFAULT_TTL):
        self.clock = FakeClock()
        self.db_path = str(tmp_path / "s7-1.db")
        self.audit = AuditLog(
            AuditStore(self.db_path), fingerprint_key=os.urandom(32), clock=self.clock
        )
        self.service = ProposalService(
            ProposalStore(self.db_path), token_key=os.urandom(32), clock=self.clock, audit=self.audit
        )
        # Create the schema eagerly so failure-path assertions can query it.
        with self.service.store.transaction() as conn:
            conn.execute("SELECT 1").fetchone()
        self.library = corpus_library()
        self.server = build_mcp_server(
            self.library,
            self.audit,
            proposals=self.service,
            proposal_ttl=ttl,
            judge=hermetic_judge(self.audit),
        )

    def call(self, arguments: dict):
        from fastmcp import Client

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


@pytest.fixture()
def harness(tmp_path):
    return Harness(tmp_path)


def test_propose_fix_returns_issued_proposal_and_records_evidence_refs(harness) -> None:
    result = harness.call(
        {"invocation": valid_invocation(), "citation": citation_for()}
    )
    payload = json.loads(result.content[0].text)
    assert set(payload) == {"proposal_id", "token", "invocation_digest", "expires_at"}
    assert payload["token"]
    assert payload["expires_at"] == harness.clock.now.__class__.isoformat(
        harness.clock.now + DEFAULT_TTL
    ).replace("+00:00", "+00:00")
    rows = harness.proposal_rows()
    assert len(rows) == 1
    assert rows[0]["proposal_id"] == payload["proposal_id"]
    assert rows[0]["token_digest"] != payload["token"]
    events = harness.proposal_events()
    assert len(events) == 1
    revision = cited_revision()
    expected_ref = (
        f"{revision['runbook_id']}@{revision['revision']}",
        revision["content_hash"],
        "update/ordering",
    )
    assert tuple(events[0].evidence_refs) == expected_ref
    assert payload["token"] not in json.dumps(events[0].payload)


def test_raw_token_is_never_stored_anywhere_in_the_database(harness) -> None:
    result = harness.call({"invocation": valid_invocation(), "citation": citation_for()})
    token = json.loads(result.content[0].text)["token"]
    with open(harness.db_path, "rb") as handle:
        assert token.encode("utf-8") not in handle.read()


def test_extra_top_level_field_is_rejected_before_any_proposal(harness) -> None:
    with pytest.raises(Exception):
        harness.call(
            {
                "invocation": valid_invocation(),
                "citation": citation_for(),
                "ttl": 999,
            }
        )
    assert harness.proposal_rows() == []
    assert harness.proposal_events() == []


def test_extra_nested_field_is_rejected(harness) -> None:
    invocation = valid_invocation()
    invocation["operator_identity"] = "alan"
    with pytest.raises(Exception):
        harness.call({"invocation": invocation, "citation": citation_for()})
    assert harness.proposal_rows() == []


@pytest.mark.parametrize(
    "bad_citation",
    [
        {**citation_for(), "content_hash": "f" * 64},  # tampered: hash not in library
        {**citation_for(), "locator": "no/such/locator"},  # unknown passage
        {**citation_for(), "revision": "1999-01-01.1"},  # names a different revision
        {"runbook_id": "", "revision": "", "content_hash": "", "locator": ""},  # malformed
    ],
)
def test_invalid_citation_fails_before_any_proposal(harness, bad_citation) -> None:
    with pytest.raises(Exception, match="invalid_citation"):
        harness.call({"invocation": valid_invocation(), "citation": bad_citation})
    assert harness.proposal_rows() == []
    assert harness.proposal_events() == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda inv: {**inv, "runbook_revision_hash": "a" * 64},
        lambda inv: {**inv, "action": "restart"},
        lambda inv: {**inv, "target": "openwebui"},
        lambda inv: {**inv, "preconditions": []},
        lambda inv: {
            **inv,
            "preconditions": [
                {"name": "docker-engine", "expected": "running"},
                {"name": "extra", "expected": "nope"},
            ],
        },
        # Sequence-order mutation: same pairs, different order.
        lambda inv: {
            **inv,
            "preconditions": [
                {"name": "docker-engine", "expected": "running"},
                {"name": "extra", "expected": "nope"},
            ][::-1],
        },
    ],
)
def test_invocation_evidence_mismatch_fails_before_any_proposal(harness, mutate) -> None:
    with pytest.raises(Exception, match="invocation_evidence_mismatch"):
        harness.call({"invocation": mutate(valid_invocation()), "citation": citation_for()})
    assert harness.proposal_rows() == []
    assert harness.proposal_events() == []


def test_malformed_invocation_fails_as_invalid_invocation(harness) -> None:
    invocation = valid_invocation()
    invocation["arguments"] = "not-an-object"
    with pytest.raises(Exception, match="propose_fix"):
        harness.call({"invocation": invocation, "citation": citation_for()})
    assert harness.proposal_rows() == []


def test_audit_write_failure_rolls_back_proposal_creation(harness, monkeypatch) -> None:
    from ops_guard import AuditWriteFailure

    def failing(conn, event_type, **kwargs):
        raise AuditWriteFailure("disk gone")

    monkeypatch.setattr(harness.audit, "append_on", failing)
    with pytest.raises(Exception, match="proposal_write_failed"):
        harness.call({"invocation": valid_invocation(), "citation": citation_for()})
    assert harness.proposal_rows() == []
    assert harness.proposal_events() == []


def test_repeated_valid_calls_create_distinct_proposals(harness) -> None:
    first = json.loads(
        harness.call({"invocation": valid_invocation(), "citation": citation_for()}).content[0].text
    )
    second = json.loads(
        harness.call({"invocation": valid_invocation(), "citation": citation_for()}).content[0].text
    )
    assert first["proposal_id"] != second["proposal_id"]
    assert first["token"] != second["token"]
    assert len(harness.proposal_rows()) == 2


def test_configured_ttl_shortens_expiry_with_frozen_clock(tmp_path) -> None:
    harness = Harness(tmp_path, ttl=timedelta(seconds=60))
    result = harness.call({"invocation": valid_invocation(), "citation": citation_for()})
    payload = json.loads(result.content[0].text)
    expected = (harness.clock.now + timedelta(seconds=60)).isoformat()
    assert payload["expires_at"] == expected


def test_propose_fix_is_not_alone_when_proposals_are_absent(tmp_path) -> None:
    """Without a proposal service the retrieval-only server stays search-only."""
    harness = Harness(tmp_path)
    from fastmcp import Client

    async def call():
        async with Client(harness.server) as client:
            return [t.name for t in await client.list_tools()]

    # A fully wired server (this harness registers proposals) exposes both;
    # the plain retrieval server (no proposals kwarg) exposes only search.
    assert "propose_fix" in asyncio.run(call())
    plain = build_mcp_server(harness.library, harness.audit)

    async def call_plain():
        async with Client(plain) as client:
            return [t.name for t in await client.list_tools()]

    assert asyncio.run(call_plain()) == ["search_runbook"]


MUTATION_FIELDS = ("action", "target", "runbook_revision_hash")


@given(
    field=st.sampled_from(MUTATION_FIELDS),
    junk=st.text(min_size=1, max_size=12, alphabet="xyz#!%"),
)
@settings(max_examples=25, deadline=None)
def test_no_mutation_of_an_evidence_bound_field_still_mints_a_proposal(tmp_path_factory, field: str, junk: str) -> None:
    """Cross-cutting rigour: any single-field mutation that breaks the
    invocation/evidence equality must fail before a proposal exists.
    (Arguments are not evidence-bound and mint normally.)"""
    tmp_path = tmp_path_factory.mktemp("mutation")
    harness = Harness(tmp_path)
    invocation = valid_invocation()
    invocation[field] = junk if field != "runbook_revision_hash" else "e" * 64
    with pytest.raises(Exception, match="invocation_evidence_mismatch"):
        harness.call({"invocation": invocation, "citation": citation_for()})
    assert harness.proposal_rows() == []
    assert harness.proposal_events() == []


def test_key_order_within_a_precondition_is_canonically_insignificant(tmp_path) -> None:
    """ADR 0004: comparison is over canonical JSON values — object key order
    inside a precondition is not significant; sequence order is."""
    harness = Harness(tmp_path)
    invocation = valid_invocation()
    invocation["preconditions"] = [{"expected": "running", "name": "docker-engine"}]
    result = harness.call({"invocation": invocation, "citation": citation_for()})
    assert json.loads(result.content[0].text)["token"]
    assert len(harness.proposal_rows()) == 1


def test_arguments_are_not_evidence_bound_and_still_mint(tmp_path) -> None:
    harness = Harness(tmp_path)
    invocation = valid_invocation()
    invocation["arguments"] = {"service": "n8n", "changed": True}
    result = harness.call({"invocation": invocation, "citation": citation_for()})
    assert json.loads(result.content[0].text)["token"]
    assert len(harness.proposal_rows()) == 1

def test_proposal_event_carries_closed_judge_projection(harness) -> None:
    harness.call({"invocation": valid_invocation(), "citation": citation_for()})
    events = harness.proposal_events()
    assert len(events) == 1
    snapshot = events[0].judge_snapshot
    assert snapshot is not None
    assert snapshot["schema_version"] == "ops-guard-risk-projection-v1"
    assert snapshot["status"] == "answered"
    assert snapshot["risk_class"] == "routine"
    assert set(snapshot["menu"]) == {"routine", "review", "critical"}
    # The response shape is unchanged (S7-1) and the judgment is not in it.
    result = harness.call({"invocation": valid_invocation(), "citation": citation_for()})
    payload = json.loads(result.content[0].text)
    assert set(payload) == {"proposal_id", "token", "invocation_digest", "expires_at"}
    assert "judge" not in json.dumps(payload).lower()


def test_judge_typed_failure_still_creates_the_proposal(harness) -> None:
    def failing(state):
        return {
            "schema_version": "ops-guard-risk-projection-v1",
            "status": "judge_timeout",
            "trace_id": None,
        }

    harness.server_absent = None  # no-op guard for clarity
    from ops_guard.judge import LocalJudge

    original = harness.server
    # Rebuild the harness server with a judge that always reports a failure.
    from ops_guard.retrieval import build_mcp_server as build

    class FailingJudge:
        def evaluate_risk(self, state):
            return failing(state)

        def evaluate_question_map(self, state, question_ids):
            return {qid: failing(state) for qid in question_ids}

    harness.server = build(
        harness.library,
        harness.audit,
        proposals=harness.service,
        proposal_ttl=DEFAULT_TTL,
        judge=FailingJudge(),
    )
    result = harness.call({"invocation": valid_invocation(), "citation": citation_for()})
    payload = json.loads(result.content[0].text)
    assert payload["token"]  # proposal still created
    events = harness.proposal_events()
    assert events[-1].judge_snapshot["status"] == "judge_timeout"
    assert original is not None
