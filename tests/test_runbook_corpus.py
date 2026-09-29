"""Public starter-runbook corpus (issue #55; ADR 0007).

The two scrubbed n8n/OpenWebUI update revisions are the public runbook
corpus: operator-verifiable procedure and evidence prose only. Executable
script bytes, local paths, private network names, and standing
authorizations stay operator-local, so the corpus tests also assert their
absence. Assertions are scoped to these two IDs; future corpus additions
must not break them.
"""

from __future__ import annotations

import json
import os

import pytest

from ops_guard import Citation, parse_revision
from ops_guard.retrieval import RunbookLibrary

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNBOOKS_DIR = os.path.join(REPO_ROOT, "runbooks")

CORPUS_IDS = ("n8n-update", "openwebui-update")
REVISION_LABEL = "2026-09-29.1"

# Operator-local material that must never appear in the public corpus:
# absolute paths, script file names, private network names, and local
# configuration values from the source guidance.
FORBIDDEN_SUBSTRINGS = (
    "D:",
    "C:",
    "\\",
    "toUpdateDockerImage",
    "openwebuiollama_default",
    "n8n_n8n_network",
    "Docker Desktop",
    "Cloudflare",
    "localhost:5678",
    "JoJo",
    "models.md",
    "gemma",
    "qwen",
    "7z",
)


def corpus_documents() -> dict[str, dict]:
    """The two corpus documents keyed by runbook id."""
    documents: dict[str, dict] = {}
    for name in sorted(os.listdir(RUNBOOKS_DIR)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(RUNBOOKS_DIR, name), encoding="utf-8") as handle:
            document = json.load(handle)
        if document.get("runbook_id") in CORPUS_IDS:
            documents[document["runbook_id"]] = document
    return documents


def loaded_corpus() -> tuple[RunbookLibrary, dict[str, dict]]:
    """Load the corpus through RunbookLibrary.load(); no document may be
    rejected — a rejected starter runbook is never evidence."""
    documents = corpus_documents()
    library, rejections = RunbookLibrary.load(list(documents.values()))
    assert rejections == [], f"corpus documents rejected at load: {rejections}"
    return library, documents


def test_corpus_contains_both_scrubbed_starter_runbooks() -> None:
    documents = corpus_documents()
    assert set(documents) == set(CORPUS_IDS)


@pytest.mark.parametrize("runbook_id", CORPUS_IDS)
def test_revision_names_the_update_operation_for_its_target(runbook_id: str) -> None:
    documents = corpus_documents()
    revision = parse_revision(documents[runbook_id])
    assert revision.revision == REVISION_LABEL
    assert revision.operation_action == "update"
    assert revision.operation_target == runbook_id.removesuffix("-update")


@pytest.mark.parametrize("runbook_id", CORPUS_IDS)
def test_docker_engine_running_is_a_declared_precondition(runbook_id: str) -> None:
    documents = corpus_documents()
    revision = parse_revision(documents[runbook_id])
    assert {"name": "docker-engine", "expected": "running"} in revision.preconditions


@pytest.mark.parametrize("runbook_id", CORPUS_IDS)
def test_every_corpus_passage_resolves_as_a_citation(runbook_id: str) -> None:
    library, documents = loaded_corpus()
    document = documents[runbook_id]
    revision = parse_revision(document)
    for passage in revision.passages:
        cited = library.resolve_citation(
            Citation(
                runbook_id=runbook_id,
                revision=document["revision"],
                content_hash=document["content_hash"],
                locator=passage.locator,
            )
        )
        assert cited.passage.text == passage.text
        assert (cited.operation_action, cited.operation_target) == ("update", runbook_id.removesuffix("-update"))


def test_canonical_content_hash_recomputes_for_every_corpus_document() -> None:
    for runbook_id, document in corpus_documents().items():
        revision = parse_revision(document)
        assert revision.content_hash == document["content_hash"]
        assert revision.expected_content_hash() == document["content_hash"], runbook_id


@pytest.mark.parametrize("runbook_id", CORPUS_IDS)
def test_n8n_first_ordering_fact_is_preserved(runbook_id: str) -> None:
    documents = corpus_documents()
    revision = parse_revision(documents[runbook_id])
    ordering = [p for p in revision.passages if p.locator == "update/ordering"]
    assert ordering, f"{runbook_id} must carry an update/ordering passage"
    text = ordering[0].text.lower()
    assert "n8n first" in text
    assert "openwebui" in text
    assert "network" in text
    assert "external" in text


@pytest.mark.parametrize("runbook_id", CORPUS_IDS)
def test_post_update_n8n_to_ollama_connectivity_check_is_preserved(runbook_id: str) -> None:
    documents = corpus_documents()
    revision = parse_revision(documents[runbook_id])
    connectivity = [p for p in revision.passages if p.locator == "update/verify-connectivity"]
    assert connectivity, f"{runbook_id} must carry an update/verify-connectivity passage"
    text = connectivity[0].text.lower()
    assert "n8n" in text and "ollama" in text
    assert "wget" in text, "the connectivity check must name the supported wget-based check"


@pytest.mark.parametrize("runbook_id", CORPUS_IDS)
def test_no_operational_script_or_private_material(runbook_id: str) -> None:
    documents = corpus_documents()
    revision = parse_revision(documents[runbook_id])
    prose = [p.text for p in revision.passages]
    prose += [revision.operation_action, revision.operation_target]
    prose += [f"{p['name']}={p['expected']}" for p in revision.preconditions]
    joined = "\n".join(prose)
    for forbidden in FORBIDDEN_SUBSTRINGS:
        assert forbidden.lower() not in joined.lower(), (
            f"{runbook_id} leaks operator-local material: {forbidden!r}"
        )


def test_representative_retrieval_queries_hit_the_corpus() -> None:
    library, _ = loaded_corpus()
    top_n8n = library.search("how do I update the n8n docker image")[0]
    assert top_n8n.runbook_id == "n8n-update"
    top_openwebui = library.search("update openwebui and its ollama runtime")[0]
    assert top_openwebui.runbook_id == "openwebui-update"
    top_connectivity = library.search("verify n8n to ollama connectivity after an update")[0]
    assert top_connectivity.locator == "update/verify-connectivity"
