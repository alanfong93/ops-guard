"""Cited MCP retrieval contract (issue #11)."""

from __future__ import annotations

import asyncio
import copy
import json
import os

import pytest

from ops_guard import (
    MalformedRunbookError,
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
    top = results[0]
    assert top.runbook_id == "n8n-restart"
    assert top.content_hash == VALID_RUNBOOK["content_hash"]
    assert top.locator == "restart/steps"
    assert top.verifier == "alan"
    assert top.operation_action == "restart"
    assert top.preconditions == ({"name": "healthcheck", "expected": "passing"},)
    # Round-trip: the returned evidence is a citation that resolves against
    # the original document — one exact verified passage.
    document = _load_fixture("valid-n8n-restart.json")
    cited = resolve_citation(document, top.citation())
    assert cited.passage.text == top.passage_text


def test_unverified_and_tampered_documents_never_become_evidence() -> None:
    documents = [
        VALID_RUNBOOK,
        _load_fixture("invalid-unverified.json"),
        _load_fixture("invalid-tampered.json"),
    ]
    library, rejections = library_with(*documents)
    assert len(rejections) == 2
    assert {r.error for r in rejections} == {
        "UnverifiedRunbookError",
        "TamperedRunbookError",
    }
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


def test_mcp_tool_returns_the_structured_evidence() -> None:
    library, _ = library_with(VALID_RUNBOOK)
    server = build_mcp_server(library)

    async def call() -> list[dict]:
        from fastmcp import Client

        async with Client(server) as client:
            result = await client.call_tool(
                "search_runbook", {"question": "restart n8n healthcheck"}
            )
            return json.loads(result.content[0].text)

    results = asyncio.run(call())
    assert results, "matching question must return evidence through MCP"
    evidence = results[0]
    assert evidence["runbook_id"] == "n8n-restart"
    assert evidence["content_hash"] == VALID_RUNBOOK["content_hash"]
    assert evidence["locator"] in ("restart/steps", "restart/verify")
    assert evidence["verification"]["verifier"] == "alan"
    assert evidence["passage_text"]
    # The MCP result is a resolvable citation against the stored revision.
    document = _load_fixture("valid-n8n-restart.json")
    from ops_guard import Citation

    cited = resolve_citation(document, Citation(
        runbook_id=evidence["runbook_id"],
        revision=evidence["revision"],
        content_hash=evidence["content_hash"],
        locator=evidence["locator"],
    ))
    assert cited.passage.text == evidence["passage_text"]
