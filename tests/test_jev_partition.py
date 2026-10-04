"""Terminal-leaf partition, approved-only projection, and exact wire
serialization (issue #91; ADR 0014).

Property-based: for arbitrary JSON-safe invocations, a full-approval grant
must partition exactly, the outbound state must carry every approved leaf
and no omitted one, and the serialized bytes must round-trip.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ops_guard.jev import (
    PartitionError,
    _json_equal,
    project_jev_state,
    serialize_exact,
    terminal_leaves,
    validate_partition,
    _tokens_to_pointer,
)
from jev_fixtures import (
    PASSAGE_TEXT,
    demo_grant,
    synthetic_invocation_json,
)

json_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53), max_value=2**53),
    st.floats(allow_nan=False, allow_infinity=False, min_value=-(2.0**52), max_value=2.0**52),
    st.text(max_size=24),
)


def invocations(max_leaves: int = 12):
    """Freezable invocation shapes: ``arguments`` is a mapping (the MCP
    schema enforces that), scalars stay inside the IEEE-754 freeze
    contract, and integer magnitudes survive the JCS round-trip."""
    arguments = st.recursive(
        json_scalars,
        lambda children: st.one_of(
            st.lists(children, max_size=3),
            st.dictionaries(st.text(min_size=1, max_size=8), children, max_size=3),
        ),
        max_leaves=max_leaves,
    )
    preconditions = st.lists(
        st.dictionaries(st.text(min_size=1, max_size=8), json_scalars, max_size=2),
        max_size=2,
    )
    return st.fixed_dictionaries(
        {
            "action": st.sampled_from(["verify", "restart", "update"]),
            "target": st.sampled_from(["n8n", "openwebui"]),
            "arguments": arguments,
            "preconditions": preconditions,
            "runbook_revision_hash": st.just("c" * 64),
        }
    ).map(lambda invocation: {**invocation, "arguments": _as_container(invocation["arguments"])})


def _as_container(arguments):
    """``arguments`` must be a mapping to freeze (the MCP schema enforces
    ``arguments: dict``); anything else is wrapped as a single-key object."""
    if isinstance(arguments, dict):
        return arguments
    return {"value": arguments}


def full_approval_grant(invocation_json: dict):
    """Approve every leaf; omit only ``runbook_revision_hash``."""
    leaves = {
        _tokens_to_pointer(tokens): value for tokens, value in terminal_leaves(invocation_json)
    }
    from jev_fixtures import demo_grant

    return demo_grant(invocation_json=invocation_json)


def _walk_values(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_values(item)
    else:
        yield value


# ---- enumeration ---------------------------------------------------------


def test_terminal_leaves_of_the_synthetic_invocation() -> None:
    pointers = {
        _tokens_to_pointer(tokens)
        for tokens, _ in terminal_leaves(synthetic_invocation_json())
    }
    assert pointers == {
        "/action",
        "/target",
        "/arguments/service",
        "/preconditions/0/name",
        "/preconditions/0/expected",
        "/runbook_revision_hash",
    }


def test_empty_containers_are_terminal_leaves() -> None:
    invocation = {
        "action": "a",
        "target": "t",
        "arguments": {},
        "preconditions": [],
        "runbook_revision_hash": "h",
    }
    pointers = {_tokens_to_pointer(t) for t, _ in terminal_leaves(invocation)}
    assert pointers == {"/action", "/target", "/arguments", "/preconditions", "/runbook_revision_hash"}


def test_numeric_object_keys_are_keys_not_indices() -> None:
    invocation = {
        "action": "a",
        "target": "t",
        "arguments": {"0": {"1": "x"}},
        "preconditions": [],
        "runbook_revision_hash": "h",
    }
    pointers = sorted(_tokens_to_pointer(t) for t, _ in terminal_leaves(invocation))
    assert pointers == [
        "/action",
        "/arguments/0/1",
        "/preconditions",
        "/runbook_revision_hash",
        "/target",
    ]


# ---- type-aware equality -------------------------------------------------


@pytest.mark.parametrize(
    "left,right,equal",
    [
        (True, 1, False),
        (1, True, False),
        (0, False, False),
        (1, 1.0, True),
        ("1", 1, False),
        (None, None, True),
        (None, "", False),
        ({"a": 1}, {"a": 1}, True),
        ({"a": 1}, {"a": True}, False),
        ([1, 2], [1, 2], True),
        ([1, 2], [2, 1], False),
    ],
)
def test_json_equal_is_type_aware(left, right, equal) -> None:
    assert _json_equal(left, right) is equal


# ---- partition validation -------------------------------------------------


def test_full_approval_partition_passes() -> None:
    invocation = synthetic_invocation_json()
    grant = full_approval_grant(invocation)
    validate_partition(invocation, grant)


def test_unknown_leaf_rejected() -> None:
    invocation = synthetic_invocation_json()
    grant = demo_grant(invocation_json=invocation)
    from dataclasses import replace

    grown = replace(
        grant, approved={**grant.approved, "/arguments/ghost": "x"}
    )
    with pytest.raises(PartitionError, match="unknown invocation leaves"):
        validate_partition(invocation, grown)


def test_missing_leaf_rejected() -> None:
    invocation = synthetic_invocation_json()
    grant = demo_grant(invocation_json=invocation)
    from dataclasses import replace

    shrunk = replace(
        grant,
        approved={k: v for k, v in grant.approved.items() if k != "/target"},
    )
    with pytest.raises(PartitionError, match="does not cover"):
        validate_partition(invocation, shrunk)


def test_value_mismatch_rejected() -> None:
    invocation = synthetic_invocation_json()
    grant = demo_grant(invocation_json=invocation)
    from dataclasses import replace

    changed = replace(grant, approved={**grant.approved, "/arguments/service": "other"})
    with pytest.raises(PartitionError, match="does not equal"):
        validate_partition(invocation, changed)


def test_bool_int_confusion_rejected() -> None:
    invocation = synthetic_invocation_json()
    grant = demo_grant(invocation_json=invocation)
    from dataclasses import replace

    forged = replace(grant, approved={**grant.approved, "/preconditions/0/expected": True})
    with pytest.raises(PartitionError):
        validate_partition(invocation, forged)


def test_revision_hash_must_be_omitted_never_approved() -> None:
    invocation = synthetic_invocation_json()
    grant = demo_grant(invocation_json=invocation)
    from dataclasses import replace

    approved_hash = replace(
        grant,
        approved={**grant.approved, "/runbook_revision_hash": "c" * 64},
        omitted={k: v for k, v in grant.omitted.items() if k != "/runbook_revision_hash"},
    )
    with pytest.raises(PartitionError, match="runbook_revision_hash"):
        validate_partition(invocation, approved_hash)
    absent = replace(
        grant,
        approved={k: v for k, v in grant.approved.items() if k != "/runbook_revision_hash"},
        omitted={k: v for k, v in grant.omitted.items() if k != "/runbook_revision_hash"},
    )
    with pytest.raises(PartitionError):
        validate_partition(invocation, absent)


def test_action_target_and_preconditions_must_be_approved() -> None:
    invocation = synthetic_invocation_json()
    grant = demo_grant(invocation_json=invocation)
    from dataclasses import replace

    omitted_target = replace(
        grant,
        approved={k: v for k, v in grant.approved.items() if k != "/target"},
        omitted={**grant.omitted, "/target": "operator omission"},
    )
    with pytest.raises(PartitionError, match="/target must be approved"):
        validate_partition(invocation, omitted_target)
    omitted_precondition = replace(
        grant,
        approved={k: v for k, v in grant.approved.items() if k != "/preconditions/0/expected"},
        omitted={**grant.omitted, "/preconditions/0/expected": "assumed neutral"},
    )
    with pytest.raises(PartitionError, match="precondition"):
        validate_partition(invocation, omitted_precondition)


def test_partial_array_approval_rejected() -> None:
    invocation = synthetic_invocation_json()
    invocation["arguments"] = {"hosts": ["a", "b"]}
    grant = demo_grant(invocation_json=invocation)
    from dataclasses import replace

    mixed = replace(
        grant,
        approved={k: v for k, v in grant.approved.items() if not k.startswith("/arguments/hosts")}
        | {"/arguments/hosts/0": "a"},
        omitted={
            **{k: v for k, v in grant.omitted.items()},
            "/arguments/hosts/1": "second host omitted",
        },
    )
    with pytest.raises(PartitionError, match="mixes approved and omitted"):
        validate_partition(invocation, mixed)


def test_nested_array_uniformity_propagates_upward() -> None:
    invocation = synthetic_invocation_json()
    invocation["arguments"] = {"pairs": [[1, 2], [3, 4]]}
    grant = demo_grant(invocation_json=invocation)
    from dataclasses import replace

    # /arguments/pairs/1 omitted entirely while /arguments/pairs/0 is
    # approved: the outer array mixes sides even though each inner array
    # is individually uniform.
    approved = {k: v for k, v in grant.approved.items() if not k.startswith("/arguments/pairs/1")}
    omitted = {
        **grant.omitted,
        **{f"/arguments/pairs/1/{rest}": "omitted" for rest in ("0", "1")},
    }
    mixed = replace(grant, approved=approved, omitted=omitted)
    with pytest.raises(PartitionError, match="mixes approved and omitted"):
        validate_partition(invocation, mixed)


def test_uniform_array_approval_passes() -> None:
    invocation = synthetic_invocation_json()
    invocation["arguments"] = {"hosts": ["a", "b"]}
    grant = demo_grant(invocation_json=invocation)
    validate_partition(invocation, grant)
    from dataclasses import replace

    all_omitted = replace(
        grant,
        approved={k: v for k, v in grant.approved.items() if not k.startswith("/arguments/hosts")},
        omitted={
            **grant.omitted,
            "/arguments/hosts/0": "no host names egress",
            "/arguments/hosts/1": "no host names egress",
        },
    )
    validate_partition(invocation, all_omitted)


# ---- projection -----------------------------------------------------------


def test_projection_shape_matches_the_adr_example() -> None:
    invocation = synthetic_invocation_json()
    grant = demo_grant(invocation_json=invocation)
    state = project_jev_state(
        invocation_json=invocation, passage_text=PASSAGE_TEXT, grant=grant
    )
    assert set(state) == {"schema_version", "invocation", "evidence"}
    assert state["schema_version"] == "ops-guard-jev-state-v1"
    assert set(state["invocation"]) == {"action", "target", "arguments", "preconditions"}
    assert state["invocation"] == {
        "action": "verify",
        "target": "n8n",
        "arguments": {"service": "n8n"},
        "preconditions": [{"name": "healthcheck", "expected": "passing"}],
    }
    assert state["evidence"] == {"passage_text": PASSAGE_TEXT}


def test_omitted_argument_leaf_never_enters_the_state() -> None:
    invocation = synthetic_invocation_json()
    invocation["arguments"] = {"service": "n8n", "window": "02:00-03:00", "note": {"deep": "v"}}
    grant = demo_grant(
        invocation_json=invocation, omitted_argument_pointer="/arguments/window"
    )
    state = project_jev_state(
        invocation_json=invocation, passage_text=PASSAGE_TEXT, grant=grant
    )
    assert state["invocation"]["arguments"] == {
        "service": "n8n",
        "note": {"deep": "v"},
    }
    raw = serialize_exact(state).decode("utf-8")
    assert "02:00-03:00" not in raw
    assert "window" not in raw
    assert "c" * 64 not in raw
    assert "operator deems" not in raw


def test_fully_omitted_arguments_yield_the_empty_object_constant() -> None:
    invocation = synthetic_invocation_json()
    grant = demo_grant(invocation_json=invocation)
    from dataclasses import replace

    everything_omitted = replace(
        grant,
        approved={k: v for k, v in grant.approved.items() if not k.startswith("/arguments")},
        omitted={
            **grant.omitted,
            "/arguments/service": "no argument values egress",
        },
    )
    state = project_jev_state(
        invocation_json=invocation, passage_text=PASSAGE_TEXT, grant=everything_omitted
    )
    assert state["invocation"]["arguments"] == {}
    assert state["invocation"]["preconditions"] == [
        {"name": "healthcheck", "expected": "passing"}
    ]


def test_serialization_is_exact_once_and_stable() -> None:
    state = {
        "schema_version": "ops-guard-jev-state-v1",
        "invocation": {"action": "vérité", "target": "n8n", "arguments": {"κ": 1}},
    }
    raw = serialize_exact(state)
    assert b"v\xc3\xa9rit\xc3\xa9" in raw  # UTF-8, never \u-escaped
    assert b": " not in raw and b", " not in raw  # compact separators
    assert raw == serialize_exact(json.loads(raw.decode("utf-8")))
    with pytest.raises(ValueError):
        serialize_exact({"x": float("inf")})


# ---- properties ------------------------------------------------------------


@settings(max_examples=60, deadline=None)
@given(invocations())
def test_full_approval_partitions_and_projects_exactly(invocation_json) -> None:
    grant = full_approval_grant(invocation_json)
    validate_partition(invocation_json, grant)
    state = project_jev_state(
        invocation_json=invocation_json, passage_text=PASSAGE_TEXT, grant=grant
    )
    # Every approved leaf survives; the omitted one never appears.
    assert state["invocation"]["action"] == invocation_json["action"]
    assert state["invocation"]["target"] == invocation_json["target"]
    assert state["invocation"]["arguments"] == invocation_json["arguments"]
    assert state["invocation"]["preconditions"] == invocation_json["preconditions"]
    values = list(_walk_values(state))
    assert invocation_json["runbook_revision_hash"] not in values
    assert "runbook_revision_hash" not in values
    # Exact bytes round-trip.
    reparsed = json.loads(serialize_exact(state).decode("utf-8"))
    assert reparsed == json.loads(json.dumps(state))


@settings(max_examples=60, deadline=None)
@given(invocations(), st.data())
def test_whole_subtree_omission_drops_the_key_and_keeps_siblings(invocation_json, data) -> None:
    from dataclasses import replace

    if not isinstance(invocation_json["arguments"], dict) or not invocation_json["arguments"]:
        from hypothesis import assume

        assume(False)
    keys = sorted(invocation_json["arguments"])
    victim = data.draw(st.sampled_from(keys))
    grant = full_approval_grant(invocation_json)
    victim_pointers = [
        pointer
        for pointer in grant.approved
        if pointer.startswith("/arguments/") and pointer.split("/")[2] == victim
    ]
    if not victim_pointers:
        victim_pointers = [f"/arguments/{victim}"] if victim in grant.approved else []
    from hypothesis import assume

    assume(bool(victim_pointers))
    omitted = dict(grant.omitted)
    for pointer in victim_pointers:
        omitted[pointer] = "subtree omission"
        grant.approved.pop(pointer, None)
    shrunk = replace(grant, omitted=omitted)
    validate_partition(invocation_json, shrunk)
    state = project_jev_state(
        invocation_json=invocation_json, passage_text=PASSAGE_TEXT, grant=shrunk
    )
    assert victim not in state["invocation"]["arguments"]
    for key, value in invocation_json["arguments"].items():
        if key != victim:
            assert state["invocation"]["arguments"][key] == value
