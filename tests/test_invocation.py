"""Canonical invocation identity properties (ADR 0002, rule 1)."""

from __future__ import annotations

import hashlib
import json

import jcs
from hypothesis import given, settings
from hypothesis import strategies as st

from ops_guard.invocation import Invocation, canonicalize_json, digest_bytes
from helpers import make_invocation

json_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**31), max_value=2**31),
    # The freezable numeric domain: floats up to 2**53 round-trip ES6
    # serialization exactly; larger values whose digits do not round-trip are
    # rejected at the freeze boundary and encoded as strings (tested below).
    st.floats(allow_nan=False, allow_infinity=False, min_value=-(2**53), max_value=2**53),
    st.text(max_size=24),
)

arguments = st.dictionaries(st.text(min_size=1, max_size=16), json_scalars, max_size=6)
preconditions = st.lists(
    st.fixed_dictionaries({"name": st.text(min_size=1, max_size=16), "expected": json_scalars}),
    max_size=4,
)
identifiers = st.text(min_size=1, max_size=32, alphabet=st.characters(min_codepoint=32, max_codepoint=0x10FFFF, exclude_categories=("Cs", "Cc")))

invocations = st.builds(
    Invocation,
    action=identifiers,
    target=identifiers,
    arguments=arguments,
    preconditions=preconditions,
    runbook_revision_hash=st.text(min_size=1, max_size=64),
)


@given(invocations)
@settings(max_examples=100)
def test_digest_is_sha256_over_jcs_bytes(invocation: Invocation) -> None:
    assert invocation.digest == hashlib.sha256(jcs.canonicalize(invocation.to_json())).hexdigest()


@given(invocations, st.data())
@settings(max_examples=100)
def test_digest_is_stable_under_key_order(invocation: Invocation, data) -> None:
    shuffled = data.draw(st.permutations(list(invocation.arguments.items())))
    reordered = make_invocation(
        action=invocation.action,
        target=invocation.target,
        arguments=dict(shuffled),
        preconditions=invocation.preconditions,
        runbook_revision_hash=invocation.runbook_revision_hash,
    )
    assert invocation.digest == reordered.digest


@given(invocations)
@settings(max_examples=100)
def test_canonicalization_is_idempotent(invocation: Invocation) -> None:
    once = invocation.canonical_bytes()
    reparsed = json.loads(once)
    assert canonicalize_json(reparsed) == once


@given(invocations, identifiers, identifiers)
@settings(max_examples=100)
def test_any_bound_field_change_changes_identity(
    invocation: Invocation, replacement_a: str, replacement_b: str
) -> None:
    replacement = replacement_a + "-" + replacement_b
    mutants = [
        make_invocation(
            action=replacement,
            target=invocation.target,
            arguments=invocation.arguments,
            preconditions=invocation.preconditions,
            runbook_revision_hash=invocation.runbook_revision_hash,
        ),
        make_invocation(
            action=invocation.action,
            target=replacement,
            arguments=invocation.arguments,
            preconditions=invocation.preconditions,
            runbook_revision_hash=invocation.runbook_revision_hash,
        ),
        make_invocation(
            action=invocation.action,
            target=invocation.target,
            arguments=dict(invocation.arguments, marker=replacement),
            preconditions=invocation.preconditions,
            runbook_revision_hash=invocation.runbook_revision_hash,
        ),
        make_invocation(
            action=invocation.action,
            target=invocation.target,
            arguments=invocation.arguments,
            preconditions=[*invocation.preconditions, {"name": "extra", "expected": replacement}],
            runbook_revision_hash=invocation.runbook_revision_hash,
        ),
        make_invocation(
            action=invocation.action,
            target=invocation.target,
            arguments=invocation.arguments,
            preconditions=invocation.preconditions,
            runbook_revision_hash=replacement,
        ),
    ]
    for mutant in mutants:
        assert mutant.digest != invocation.digest


def test_non_string_bound_field_is_rejected() -> None:
    try:
        make_invocation(action=7)
    except TypeError:
        pass
    else:
        raise AssertionError("non-string action must be rejected")


non_representable_ints = st.tuples(
    st.integers(min_value=54, max_value=63), st.integers(min_value=0, max_value=2**30)
).map(lambda pair: 2 ** pair[0] + 2 * pair[1] + 1)  # odd above a power of two: never exactly representable


@given(non_representable_ints)
@settings(max_examples=50)
def test_integers_beyond_double_precision_are_rejected(large: int) -> None:
    try:
        make_invocation(arguments={"n": large}).canonical_bytes()
    except ValueError:
        pass
    else:
        raise AssertionError(f"{large} must be rejected, not silently rounded")


@given(non_representable_ints)
@settings(max_examples=50)
def test_negative_lossy_integers_are_rejected(large: int) -> None:
    try:
        make_invocation(arguments={"n": -large}).canonical_bytes()
    except ValueError:
        pass
    else:
        raise AssertionError(f"-{large} must be rejected, not silently rounded")


@given(st.integers(min_value=-(2**53), max_value=2**53))
@settings(max_examples=50)
def test_integers_within_double_precision_are_accepted(safe: int) -> None:
    invocation = make_invocation(arguments={"n": safe})
    parsed = json.loads(invocation.canonical_bytes())
    assert parsed["arguments"]["n"] == safe


def test_integer_boundary_is_exactly_two_power_53() -> None:
    assert make_invocation(arguments={"n": 9007199254740992}).digest  # 2**53 accepted
    try:
        make_invocation(arguments={"n": 9007199254740993}).canonical_bytes()
    except ValueError:
        pass
    else:
        raise AssertionError("2**53 + 1 must be rejected")


def test_values_that_cannot_round_trip_are_rejected_at_freeze() -> None:
    # 2**60's ES6 fixed-notation form re-parses to a non-representable int,
    # so freezing it would produce bytes no consumer could ever re-verify.
    for value in (2**60, 2.0**60):
        try:
            make_invocation(arguments={"n": value}).canonical_bytes()
        except ValueError:
            pass
        else:
            raise AssertionError(f"{value!r} must be rejected at freeze")


def test_non_string_mapping_keys_are_rejected_as_domain_errors() -> None:
    try:
        make_invocation(arguments={1: "x"}).canonical_bytes()
    except ValueError:
        pass
    else:
        raise AssertionError("non-string mapping keys must raise a domain ValueError")


def test_deep_nesting_and_lone_surrogates_are_domain_errors() -> None:
    deep = current = {}
    for _ in range(3000):
        current["n"] = child = {}
        current = child
    for bad in ({"k": "\ud800"}, deep):
        try:
            make_invocation(arguments=bad).canonical_bytes()
        except ValueError:
            pass
        else:
            raise AssertionError(f"{type(bad)} must raise a domain ValueError at freeze")


def test_digest_matches_digest_bytes_helper() -> None:
    invocation = make_invocation()
    assert digest_bytes(invocation.canonical_bytes()) == invocation.digest
