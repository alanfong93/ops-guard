"""Runbook evidence contract (issue #8; docs/runbook-format.md)."""

from __future__ import annotations

import copy
import json
import os
from datetime import timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ops_guard import (
    Citation,
    MalformedRunbookError,
    TamperedRunbookError,
    UnknownPassageError,
    UnverifiedRunbookError,
    parse_revision,
    resolve_citation,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "runbooks")


def load(name: str) -> dict:
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as handle:
        return json.load(handle)


def citation_for(document: dict, locator: str = "restart/steps") -> Citation:
    return Citation(
        runbook_id=document["runbook_id"],
        revision=document["revision"],
        content_hash=document["content_hash"],
        locator=locator,
    )


def test_valid_fixture_resolves_to_required_procedural_evidence() -> None:
    document = load("valid-n8n-restart.json")
    revision = parse_revision(document)
    assert revision.verification.verifier == "alan"
    cited = resolve_citation(document, citation_for(document))
    assert cited.passage.text.startswith("cd ~/stack")
    assert (cited.operation_action, cited.operation_target) == ("restart", "n8n")
    assert cited.preconditions == ({"name": "healthcheck", "expected": "passing"},)
    assert cited.verifier == "alan"


def test_unverified_revision_cannot_qualify() -> None:
    with pytest.raises(UnverifiedRunbookError):
        parse_revision(load("invalid-unverified.json"))


def test_tampered_body_voids_the_citation() -> None:
    document = load("invalid-tampered.json")
    with pytest.raises(TamperedRunbookError):
        parse_revision(document)
    with pytest.raises(TamperedRunbookError):
        resolve_citation(document, citation_for(document))


def test_malformed_shape_is_rejected() -> None:
    with pytest.raises(MalformedRunbookError):
        parse_revision(load("invalid-malformed.json"))


def test_absent_locator_is_an_unknown_passage() -> None:
    document = load("valid-n8n-restart.json")
    with pytest.raises(UnknownPassageError):
        resolve_citation(document, citation_for(document, locator="nope/steps"))


def test_citation_bound_to_a_different_hash_fails_closed() -> None:
    document = load("valid-n8n-restart.json")
    other = citation_for(document)
    with pytest.raises(TamperedRunbookError):
        resolve_citation(document, Citation(
            runbook_id=other.runbook_id,
            revision=other.revision,
            content_hash="0" * 64,
            locator=other.locator,
        ))
    with pytest.raises(MalformedRunbookError):
        resolve_citation(document, Citation(
            runbook_id="other-runbook",
            revision=other.revision,
            content_hash=other.content_hash,
            locator=other.locator,
        ))


def test_blank_verification_fields_are_unverified() -> None:
    document = load("valid-n8n-restart.json")
    body = {k: v for k, v in document.items() if k != "content_hash"}
    body["verification"]["verifier"] = ""
    from ops_guard.invocation import canonicalize_json
    import hashlib

    document2 = dict(body)
    document2["content_hash"] = hashlib.sha256(canonicalize_json(body)).hexdigest()
    with pytest.raises(UnverifiedRunbookError):
        parse_revision(document2)


def _mutations(document: dict) -> list[dict]:
    out = []
    for path, value in (
        (("runbook_id",), "other-id"),
        (("revision",), "other-rev"),
        (("operation", "action"), "destroy"),
        (("passages", 0, "text"), "changed text"),
        (("preconditions", 0, "expected"), "failing"),
        (("verification", "verifier"), "mallory"),
    ):
        mutant = copy.deepcopy(document)
        node = mutant
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
        out.append(mutant)
    return out


mutation_index = st.integers(min_value=0, max_value=5)


@given(mutation_index)
@settings(max_examples=10)
def test_any_body_change_voids_stale_citations(index: int) -> None:
    document = load("valid-n8n-restart.json")
    stale = citation_for(document)
    mutant = _mutations(document)[index]
    with pytest.raises(TamperedRunbookError):
        resolve_citation(mutant, stale)


def test_rehashed_mutation_is_a_new_revision_that_qualifies() -> None:
    document = load("valid-n8n-restart.json")
    mutant = _mutations(document)[0]
    from ops_guard.invocation import canonicalize_json
    import hashlib

    body = {k: v for k, v in mutant.items() if k != "content_hash"}
    mutant["content_hash"] = hashlib.sha256(canonicalize_json(body)).hexdigest()
    cited = resolve_citation(mutant, citation_for(mutant))
    assert cited.passage.locator == "restart/steps"


def test_verification_timestamp_must_be_aware() -> None:
    document = load("valid-n8n-restart.json")
    body = {k: v for k, v in document.items() if k != "content_hash"}
    body["verification"]["verified_at"] = "2026-09-23T09:00:00"  # naive
    from ops_guard.invocation import canonicalize_json
    import hashlib

    document2 = dict(body)
    document2["content_hash"] = hashlib.sha256(canonicalize_json(body)).hexdigest()
    with pytest.raises(UnverifiedRunbookError):
        parse_revision(document2)
