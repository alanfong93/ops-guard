"""Static bearer-token verifier invariants (issue #54; ADR 0006).

The transport credential is a single shared secret compared in constant
time: the verifier accepts exactly the configured token and nothing else,
and rejects before any tool execution.
"""

from __future__ import annotations

import asyncio

from hypothesis import given, settings
from hypothesis import strategies as st

from ops_guard.service import StaticBearerVerifier


def verify(verifier: StaticBearerVerifier, token: str):
    return asyncio.run(verifier.verify_token(token))


def test_exact_token_is_accepted_with_operator_principal() -> None:
    verifier = StaticBearerVerifier("x" * 40)
    accepted = verify(verifier, "x" * 40)
    assert accepted is not None
    assert accepted.client_id == "operator"


def test_wrong_token_is_rejected() -> None:
    verifier = StaticBearerVerifier("x" * 40)
    assert verify(verifier, "y" * 40) is None


def test_empty_token_is_rejected() -> None:
    verifier = StaticBearerVerifier("x" * 40)
    assert verify(verifier, "") is None


@given(
    expected=st.text(min_size=32, max_size=64),
    candidate=st.text(max_size=64),
)
@settings(max_examples=200)
def test_verifier_accepts_exactly_the_configured_token(expected: str, candidate: str) -> None:
    verifier = StaticBearerVerifier(expected)
    accepted = verify(verifier, candidate)
    if candidate == expected:
        assert accepted is not None and accepted.client_id == "operator"
    else:
        assert accepted is None


@given(
    token=st.text(min_size=32, max_size=48),
    position=st.integers(min_value=0, max_value=31),
)
@settings(max_examples=100)
def test_single_character_change_is_rejected(token: str, position: int) -> None:
    index = position % len(token)
    original = token[index]
    replacement = "A" if original != "A" else "B"
    mutated = token[:index] + replacement + token[index + 1 :]
    if mutated == token:  # replacement collided with the original character
        return
    verifier = StaticBearerVerifier(token)
    assert verify(verifier, token) is not None
    assert verify(verifier, mutated) is None
