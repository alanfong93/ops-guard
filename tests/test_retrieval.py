"""Cited MCP retrieval contract (issue #11)."""

from __future__ import annotations

import asyncio
import copy
import json
import os

import pytest

from ops_guard import (
    AuditLog,
    AuditStore,
    AuditWriteFailure,
    Citation,
    TamperedRunbookError,
    UnverifiedRunbookError,
    resolve_citation,
)
from ops_guard.retrieval import RunbookLibrary, build_mcp_server
from tests_helpers_runbook import VALID_RUNBOOK

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "runbooks")


def _load_fixture(name: str) -> dict:
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as handle:
        return json.load(handle)


def library_with(*documents: dict) -> tuple[RunbookLibrary, list]:
    library, rejections = RunbookLibrary.load(list(documents))
    return library, rejections


def test_search_returns_one_exact_verified_passage_with_full_evidence() -> None:
    library, rejections = library_with(VALID_RUNBOOK)
    assert rejections == []
    results = library.search("how do I restart n8n and verify healthcheck")
    assert results, "matching question must return evidence"
    # Round-trip: EVERY returned result is a citation that resolves against
    # the original document — one exact verified passage each.
    document = _load_fixture("valid-n8n-restart.json")
    for top in results:
        assert top.runbook_id == "n8n-restart"
        assert top.content_hash == VALID_RUNBOOK["content_hash"]
        assert top.verifier == "alan"
        assert top.operation_action == "restart"
        assert top.preconditions == ({"name": "healthcheck", "expected": "passing"},)
        cited = resolve_citation(document, top.citation())
        assert cited.passage.text == top.passage_text
    assert results[0].locator == "restart/steps"


def test_unverified_tampered_and_malformed_documents_never_become_evidence() -> None:
    documents = [
        VALID_RUNBOOK,
        _load_fixture("invalid-unverified.json"),
        _load_fixture("invalid-tampered.json"),
        _load_fixture("invalid-malformed.json"),
    ]
    library, rejections = library_with(*documents)
    assert len(rejections) == 3
    assert {r.error for r in rejections} == {
        "UnverifiedRunbookError",
        "TamperedRunbookError",
        "MalformedRunbookError",
    }
    assert {r.document_index for r in rejections} == {1, 2, 3}
    for result in library.search("restart n8n"):
        assert result.content_hash == VALID_RUNBOOK["content_hash"]


def test_stale_source_content_never_qualifies() -> None:
    document = copy.deepcopy(VALID_RUNBOOK)
    library, _ = library_with(document)
    # The operator edits the stored document after the library loaded it.
    document["passages"][0]["text"] = "edited after loading"
    results = library.search("restart n8n")
    assert results
    # The citation binds to the loaded revision: resolution against the
    # edited document fails closed.
    with pytest.raises(TamperedRunbookError):
        resolve_citation(document, results[0].citation())


def test_mutating_source_preconditions_after_load_cannot_change_results() -> None:
    document = copy.deepcopy(VALID_RUNBOOK)
    library, _ = library_with(document)
    document["preconditions"][0]["expected"] = "mutated"
    for result in library.search("restart n8n healthcheck"):
        assert result.preconditions == ({"name": "healthcheck", "expected": "passing"},)


def test_mutating_a_returned_result_cannot_change_the_library_or_later_results() -> None:
    library, _ = library_with(VALID_RUNBOOK)
    first = library.search("restart n8n healthcheck")
    assert first, "matching question must return evidence"
    first[0].preconditions[0]["expected"] = "mutated"
    again = library.search("restart n8n healthcheck")
    assert again
    for result in again:
        assert result.preconditions == ({"name": "healthcheck", "expected": "passing"},)
        assert result.content_hash == VALID_RUNBOOK["content_hash"]


def test_mcp_conversion_hands_out_detached_preconditions() -> None:
    from ops_guard.retrieval import _result_to_dict

    library, _ = library_with(VALID_RUNBOOK)
    evidence = _result_to_dict(library.search("restart n8n healthcheck")[0])
    evidence["preconditions"][0]["expected"] = "mutated"
    for result in library.search("restart n8n healthcheck"):
        assert result.preconditions == ({"name": "healthcheck", "expected": "passing"},)
        assert _result_to_dict(result)["preconditions"] == [
            {"name": "healthcheck", "expected": "passing"}
        ]


def test_irrelevant_question_returns_no_evidence() -> None:
    library, _ = library_with(VALID_RUNBOOK)
    assert library.search("bake sourdough bread") == []


def test_limit_is_respected() -> None:
    library, _ = library_with(VALID_RUNBOOK)
    assert len(library.search("restart n8n verify healthcheck running", limit=1)) == 1


def test_empty_question_is_rejected() -> None:
    library, _ = library_with(VALID_RUNBOOK)
    with pytest.raises(ValueError):
        library.search("   ")


def test_lone_surrogate_document_is_rejected_not_fatal() -> None:
    poisoned = copy.deepcopy(VALID_RUNBOOK)
    poisoned["passages"][0]["text"] = "token " + chr(0xD800) + " poison"
    library, rejections = library_with(VALID_RUNBOOK, poisoned)
    assert len(rejections) == 1
    assert rejections[0].error == "UnicodeEncodeError"
    assert rejections[0].document_index == 1
    assert len(library.search("restart n8n")) >= 1


def test_limit_below_one_is_rejected() -> None:
    library, _ = library_with(VALID_RUNBOOK)
    with pytest.raises(ValueError):
        library.search("restart n8n", limit=0)


def test_mcp_tool_returns_the_structured_evidence(tmp_path, clock) -> None:
    server, _audit = _wired_library(tmp_path, clock)

    async def call() -> list[dict]:
        from fastmcp import Client

        async with Client(server) as client:
            result = await client.call_tool(
                "search_runbook", {"question": "restart n8n healthcheck"}
            )
            return json.loads(result.content[0].text)

    results = asyncio.run(call())
    assert results, "matching question must return evidence through MCP"
    document = _load_fixture("valid-n8n-restart.json")
    for evidence in results:
        assert evidence["runbook_id"] == "n8n-restart"
        assert evidence["content_hash"] == VALID_RUNBOOK["content_hash"]
        assert evidence["locator"] in ("restart/steps", "restart/verify")
        assert evidence["verification"]["verifier"] == "alan"
        assert evidence["passage_text"]
        cited = resolve_citation(document, Citation(
            runbook_id=evidence["runbook_id"],
            revision=evidence["revision"],
            content_hash=evidence["content_hash"],
            locator=evidence["locator"],
        ))
        assert cited.passage.text == evidence["passage_text"]


def test_mcp_schema_pins_minimum_limit(tmp_path, clock) -> None:
    server, _audit = _wired_library(tmp_path, clock)

    async def call() -> None:
        from fastmcp import Client

        async with Client(server) as client:
            with pytest.raises(Exception):
                await client.call_tool("search_runbook", {"question": "restart", "limit": 0})

    asyncio.run(call())


class _FailingSearchAudit(AuditLog):
    """Audit that accepts construction but refuses every search event."""

    def append_on(self, conn, event_type, **kwargs):
        raise AuditWriteFailure("required audit append failed: injected")


def _wired_library(tmp_path, clock):
    path = str(tmp_path / "ops-guard.db")
    audit = AuditLog(AuditStore(path), fingerprint_key=os.urandom(32), clock=clock)
    library, _ = library_with(VALID_RUNBOOK)
    return build_mcp_server(library, audit), audit


def _call(server: object, arguments: dict) -> list[dict]:
    async def call():
        from fastmcp import Client

        async with Client(server) as client:
            result = await client.call_tool("search_runbook", arguments)
            # FastMCP emits no content for an empty result list.
            return json.loads(result.content[0].text) if result.content else []

    return asyncio.run(call())


def test_valid_search_records_correlated_events_without_raw_question(tmp_path, clock) -> None:
    server, audit = _wired_library(tmp_path, clock)
    question = "restart n8n healthcheck secret-password"
    results = _call(server, {"question": question})
    assert results, "matching question must return evidence"
    events = audit.events()
    assert [e.event_type for e in events] == ["request", "guidance"]
    request, guidance = events
    assert request.correlation_id == guidance.correlation_id
    # The raw question is never stored; only the keyed fingerprint is.
    assert question not in json.dumps(request.payload)
    fingerprint = request.payload["question_fingerprint"]
    assert len(fingerprint) == 16 and all(c in "0123456789abcdef" for c in fingerprint)
    assert request.payload["limit"] == 5
    assert len(guidance.payload["results"]) == len(results)
    for ref, evidence in zip(guidance.payload["results"], results):
        assert ref["content_hash"] == evidence["content_hash"]
        assert ref["locator"] == evidence["locator"]
        # The references reconstruct the exact returned guidance from the
        # verified revision — the passage body is not duplicated.
        cited = resolve_citation(VALID_RUNBOOK, Citation(
            runbook_id=ref["runbook_id"],
            revision=ref["revision"],
            content_hash=ref["content_hash"],
            locator=ref["locator"],
        ))
        assert cited.passage.text == evidence["passage_text"]


def test_zero_hit_search_still_records_correlated_events(tmp_path, clock) -> None:
    server, audit = _wired_library(tmp_path, clock)
    results = _call(server, {"question": "bake sourdough bread"})
    assert results == []
    events = audit.events()
    assert [e.event_type for e in events] == ["request", "guidance"]
    assert events[0].correlation_id == events[1].correlation_id
    assert events[1].payload["results"] == []


def test_invalid_search_records_no_events(tmp_path, clock) -> None:
    server, audit = _wired_library(tmp_path, clock)
    with pytest.raises(Exception):
        _call(server, {"question": "   "})
    assert audit.events() == []


def test_failing_search_recording_returns_no_results(tmp_path, clock) -> None:
    path = str(tmp_path / "ops-guard.db")
    audit = _FailingSearchAudit(AuditStore(path), fingerprint_key=os.urandom(32), clock=clock)
    library, _ = library_with(VALID_RUNBOOK)
    server = build_mcp_server(library, audit)
    with pytest.raises(Exception):
        _call(server, {"question": "restart n8n"})
    # Fail-closed: nothing was returned and nothing was half-recorded.
    assert audit.events() == []


def test_second_append_failure_rolls_back_the_whole_pair(tmp_path, clock) -> None:
    """The request event must not survive without its guidance event when the
    second append fails after the first INSERT succeeded (issue #40)."""
    path = str(tmp_path / "ops-guard.db")
    store = AuditStore(path)

    class GuidanceFailsAudit(AuditLog):
        def append_on(self, conn, event_type, **kwargs):
            if event_type == "guidance":
                raise AuditWriteFailure("required audit append failed: injected")
            return super().append_on(conn, event_type, **kwargs)

    audit = GuidanceFailsAudit(store, fingerprint_key=os.urandom(32), clock=clock)
    library, _ = library_with(VALID_RUNBOOK)
    server = build_mcp_server(library, audit)
    with pytest.raises(Exception):
        _call(server, {"question": "restart n8n"})
    # The first INSERT was executed inside the transaction — the rollback
    # must have discarded it: no request event without its guidance pair.
    assert audit.events() == []
