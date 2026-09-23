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


def test_empty_script_hash_never_matches() -> None:
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


@pytest.mark.parametrize("mutation", sorted(FIELD_MUTATIONS))
def test_each_altered_field_fails_closed(mutation: str) -> None:
    overrides = FIELD_MUTATIONS[mutation]
    invocation_overrides = overrides.get("invocation", {})
    authorization, invocation = matching_setup(**invocation_overrides)
    script = overrides.get("script", SCRIPT)
    result = match(authorization, invocation, script)
    assert not result.matched
    assert result.reason


def test_json_true_and_one_are_distinct_permitted_values() -> None:
    authorization = parse_authorization(authorization_document(arguments={"force": True}))
    same_bool = make_invocation(arguments={"force": True})
    assert match(authorization, same_bool, SCRIPT).matched
    number_one = make_invocation(arguments={"force": 1})
    assert not match(authorization, number_one, SCRIPT).matched


def test_non_representable_integer_arguments_are_malformed() -> None:
    with pytest.raises(MalformedAuthorizationError):
        parse_authorization(authorization_document(arguments={"n": 9007199254740993}))
    # The exact neighbour the collision attack relied on is rejected at parse.
    with pytest.raises(MalformedAuthorizationError):
        parse_authorization(authorization_document(arguments={"n": 10**17 + 1}))
    # Representable values remain loadable.
    parse_authorization(authorization_document(arguments={"n": 2**53}))


@given(
    st.dictionaries(
        st.text(min_size=1, max_size=8),
        st.one_of(st.booleans(), st.text(min_size=1, max_size=8), st.integers(min_value=0, max_value=1000)),
        max_size=4,
    ),
    st.dictionaries(
        st.text(min_size=1, max_size=8),
        st.one_of(st.booleans(), st.text(min_size=1, max_size=8), st.integers(min_value=0, max_value=1000)),
        max_size=4,
    ),
)
@settings(max_examples=75)
def test_unequal_arguments_never_match(left: dict, right: dict) -> None:
    from ops_guard.invocation import canonicalize_json

    authorization = parse_authorization(authorization_document(arguments=left))
    invocation = make_invocation(arguments=right)
    result = match(authorization, invocation, SCRIPT)
    canonically_equal = canonicalize_json(dict(left)) == canonicalize_json(dict(right))
    assert result.matched == canonically_equal


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
        {"script_sha256": "g" * 64},
        {"runbook_revision_hash": None},
        {"arguments": [{"not": "a mapping"}]},
        {"arguments": {"n": float("nan")}},
        {"arguments": {1: "non-string-key"}},
        {"preconditions": "not-a-list"},
        {"unexpected": True},
    ):
        broken = dict(base)
        broken.update(mutation)
        with pytest.raises(MalformedAuthorizationError):
            parse_authorization(broken)
    with pytest.raises(MalformedAuthorizationError):
        parse_authorization({k: v for k, v in base.items() if k != "preconditions"})


def test_stored_arguments_are_the_validated_snapshot() -> None:
    """Pins the single-snapshot parse: a Mapping that returns clean values
    during validation but hostile values afterwards must store the clean
    values it validated — never the hostile ones."""
    from collections.abc import Mapping as MappingABC

    class ShiftingMapping(MappingABC):
        reads = 0

        def __init__(self, inner: dict) -> None:
            self._inner = dict(inner)

        def __getitem__(self, key):
            ShiftingMapping.reads += 1
            if ShiftingMapping.reads > 2:
                return 10**400
            return self._inner[key]

        def __iter__(self):
            return iter(self._inner)

        def __len__(self):
            return len(self._inner)

    authorization = parse_authorization(authorization_document(
        arguments=ShiftingMapping({"service": "n8n"})
    ))
    # The stored record canonicalizes cleanly and matches the clean values.
    assert authorization.canonical_arguments() == b'{"service":"n8n"}'
    invocation = make_invocation(arguments={"service": "n8n"})
    assert match(authorization, invocation, SCRIPT).matched


def test_match_never_raises_on_hostile_invocation_values() -> None:
    """ADR 0004 rule 2: one result object reports matched or not. Hostile
    values that cannot canonicalize report no-match instead of raising."""
    authorization = parse_authorization(authorization_document())
    for hostile in (
        make_invocation(arguments={"n": float("inf")}),
        make_invocation(arguments={"n": 10**400}),
        make_invocation(arguments={"nested": {"deep": [1, {"deeper": [2]}] * 500}}),
    ):
        result = match(authorization, hostile, SCRIPT)
        assert result.matched is False
        assert result.reason


def test_partial_arguments_never_match_a_complete_rule() -> None:
    authorization, invocation = matching_setup(
        arguments={"service": "n8n", "timeout_seconds": 30, "extra": "x"}
    )
    result = match(authorization, invocation, SCRIPT)
    assert not result.matched
