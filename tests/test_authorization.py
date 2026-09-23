"""Exact complete-invocation standing authorization (issue #13; ADR 0004)."""

from __future__ import annotations

import copy

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ops_guard import (
    Invocation,
    MalformedAuthorizationError,
    MatchResult,
    ScriptIdentity,
    StandingAuthorization,
    match,
    parse_authorization,
)
from helpers import make_invocation

SCRIPT = ScriptIdentity(path="/opt/scripts/restart-n8n.sh", sha256="a" * 64)


def authorization_document(**overrides):
    document = {
        "authorization_id": "auth-restart-n8n",
        "script_path": "/opt/scripts/restart-n8n.sh",
        "script_sha256": "a" * 64,
        "action": "restart",
        "target": "n8n",
        "arguments": {"service": "n8n", "timeout_seconds": 30},
        "preconditions": [{"name": "healthcheck", "expected": "passing"}],
        "runbook_revision_hash": "b" * 64,
    }
    document.update(overrides)
    return document


def matching_setup(**invocation_overrides) -> tuple[StandingAuthorization, Invocation]:
    authorization = parse_authorization(authorization_document())
    invocation = make_invocation(**invocation_overrides)
    return authorization, invocation


def test_exact_match_permits_unattended_authorization() -> None:
    authorization, invocation = matching_setup()
    result = match(authorization, invocation, SCRIPT)
    assert isinstance(result, MatchResult) and result.matched
    assert result.authorization_id == "auth-restart-n8n"


def test_missing_field_never_matches() -> None:
    authorization = parse_authorization(authorization_document())
    invocation = make_invocation()
    truncated = ScriptIdentity(path=SCRIPT.path, sha256="")
    result = match(authorization, invocation, truncated)
    assert not result.matched


FIELD_MUTATIONS = {
    "script_path": {"script": ScriptIdentity(path="/opt/scripts/other.sh", sha256="a" * 64)},
    "script_sha256": {"script": ScriptIdentity(path=SCRIPT.path, sha256="b" * 64)},
    "action": {"invocation": {"action": "stop"}},
    "target": {"invocation": {"target": "openwebui"}},
    "arguments": {"invocation": {"arguments": {"service": "n8n", "timeout_seconds": 31}}},
    "arguments_missing": {"invocation": {"arguments": {"service": "n8n"}}},
    "arguments_extra": {"invocation": {"arguments": {"service": "n8n", "timeout_seconds": 30, "force": True}}},
    "preconditions": {"invocation": {"preconditions": [{"name": "healthcheck", "expected": "failing"}]}},
    "preconditions_order": {
        "invocation": {
            "preconditions": [
                {"name": "disk-space", "expected": "ok"},
                {"name": "healthcheck", "expected": "passing"},
            ]
        }
    },
    "runbook_revision_hash": {"invocation": {"runbook_revision_hash": "c" * 64}},
}
mutation_names = st.sampled_from(sorted(FIELD_MUTATIONS))


@given(mutation_names)
@settings(max_examples=20)
def test_each_altered_field_fails_closed(mutation: str) -> None:
    overrides = FIELD_MUTATIONS[mutation]
    invocation_overrides = overrides.get("invocation", {})
    authorization, invocation = matching_setup(**invocation_overrides)
    script = overrides.get("script", SCRIPT)
    result = match(authorization, invocation, script)
    assert not result.matched
    assert result.reason


def test_precondition_order_is_significant() -> None:
    document = authorization_document(
        preconditions=[
            {"name": "disk-space", "expected": "ok"},
            {"name": "healthcheck", "expected": "passing"},
        ]
    )
    authorization = parse_authorization(document)
    invocation = make_invocation(
        preconditions=[
            {"name": "healthcheck", "expected": "passing"},
            {"name": "disk-space", "expected": "ok"},
        ]
    )
    assert not match(authorization, invocation, SCRIPT).matched


def test_canonically_equal_arguments_match() -> None:
    authorization, invocation = matching_setup(arguments={"service": "n8n", "timeout_seconds": 30.0})
    invocation = make_invocation(arguments={"timeout_seconds": 30, "service": "n8n"})
    assert match(authorization, invocation, SCRIPT).matched


def test_malformed_authorizations_are_rejected() -> None:
    base = authorization_document()
    for mutation in (
        {"authorization_id": " "},
        {"script_sha256": "short"},
        {"runbook_revision_hash": None},
        {"arguments": [{"not": "a mapping"}]},
        {"preconditions": "not-a-list"},
        {"unexpected": True},
    ):
        broken = dict(base)
        broken.update(mutation)
        with pytest.raises(MalformedAuthorizationError):
            parse_authorization(broken)
    with pytest.raises(MalformedAuthorizationError):
        parse_authorization({k: v for k, v in base.items() if k != "preconditions"})


def test_partial_arguments_never_match_a_complete_rule() -> None:
    authorization, invocation = matching_setup(
        arguments={"service": "n8n", "timeout_seconds": 30, "extra": "x"}
    )
    result = match(authorization, invocation, SCRIPT)
    assert not result.matched
