"""Shared synthetic fixtures for the hosted Jev advisory tests (issue #91).

Everything here is harmless public fixture data — no real policy, no real
secret, no live network call. The grant covers a fixed synthetic invocation
whose shape follows the ADR 0014 example; production policies are
operator-owned and never enter this repository.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile

from ops_guard.invocation import Invocation
from ops_guard.jev import (
    JEV_MODEL,
    JevConfig,
    DisclosureGrant,
    EgressPolicy,
    terminal_leaves,
    _tokens_to_pointer,
)

PASSAGE_TEXT = "Verify the compose file before restarting the stack."
REVISION_HASH = "c" * 64

SYNTHETIC_CITATION = {
    "runbook_id": "demo-runbook",
    "revision": "2026.10",
    "content_hash": "d" * 64,
    "locator": "verify/stack",
}

ENDPOINT = "https://jev.example/v1/systemone"
ENDPOINT_IDENTITY = "https://jev.example:443/v1/systemone"


def synthetic_invocation() -> Invocation:
    """A fixed synthetic invocation: one argument leaf to approve, one
    precondition leaf, and the revision hash that must always be omitted."""
    return Invocation(
        action="verify",
        target="n8n",
        arguments={"service": "n8n"},
        preconditions=[{"name": "healthcheck", "expected": "passing"}],
        runbook_revision_hash=REVISION_HASH,
    )


def synthetic_invocation_json() -> dict:
    return synthetic_invocation().to_json()


def demo_grant(
    *,
    invocation_json: dict | None = None,
    passage_text: str = PASSAGE_TEXT,
    omitted_argument_pointer: str | None = None,
) -> DisclosureGrant:
    """A grant that approves every leaf of the synthetic invocation except
    ``runbook_revision_hash`` (and optionally one named argument leaf)."""
    invocation_json = invocation_json or synthetic_invocation_json()
    leaves = {
        _tokens_to_pointer(tokens): value for tokens, value in terminal_leaves(invocation_json)
    }
    omitted = {"/runbook_revision_hash": "binding retained locally"}
    approved = {}
    for pointer, value in leaves.items():
        if pointer == "/runbook_revision_hash":
            continue
        if omitted_argument_pointer is not None and pointer == omitted_argument_pointer:
            omitted[pointer] = "operator deems this value risk-neutral for measurement"
            continue
        approved[pointer] = value
    return DisclosureGrant(
        profile_id="fixture-profile-1",
        invocation_sha256=hashlib.sha256(
            Invocation.from_frozen_json(invocation_json).canonical_bytes()
        ).hexdigest(),
        citation=dict(SYNTHETIC_CITATION),
        passage_sha256=hashlib.sha256(passage_text.encode("utf-8")).hexdigest(),
        approved=approved,
        omitted=omitted,
    )


def demo_policy(grant: DisclosureGrant | None = None, sha256: str = "0" * 64) -> EgressPolicy:
    return EgressPolicy(grants=(grant or demo_grant(),), sha256=sha256)


def demo_config(
    *,
    grant: DisclosureGrant | None = None,
    endpoint: str = ENDPOINT,
    endpoint_identity_value: str = ENDPOINT_IDENTITY,
    sha256: str = "0" * 64,
) -> JevConfig:
    return JevConfig(
        endpoint=endpoint_identity_value if endpoint == ENDPOINT else endpoint,
        allowed_endpoints=(endpoint_identity_value if endpoint == ENDPOINT else endpoint,),
        bearer_token="fixture-token-" + "x" * 24,
        policy=demo_policy(grant, sha256),
    )


def write_policy_file(grant: DisclosureGrant, directory: str) -> str:
    """Serialize one grant into the closed policy file shape."""
    document = {
        "schema_version": "ops-guard-jev-egress-v1",
        "profiles": [
            {
                "profile_id": grant.profile_id,
                "invocation_sha256": grant.invocation_sha256,
                "citation": dict(grant.citation),
                "passage_sha256": grant.passage_sha256,
                "approved_leaves": [
                    {"pointer": pointer, "value": value}
                    for pointer, value in grant.approved.items()
                ],
                "omitted_leaves": [
                    {"pointer": pointer, "reason": reason}
                    for pointer, reason in grant.omitted.items()
                ],
            }
        ],
    }
    handle_fd, path = tempfile.mkstemp(suffix=".json", dir=directory)
    with os.fdopen(handle_fd, "w", encoding="utf-8") as handle:
        json.dump(document, handle)
    return path


def jev_state(state_cls: str = "ops-guard-risk-state-v1") -> dict:
    """The composed judge state exactly as ``judge_state`` builds it for the
    synthetic invocation — the value ``propose_fix`` hands the judge."""
    return {
        "schema_version": state_cls,
        "invocation": synthetic_invocation_json(),
        "evidence": {
            "runbook_id": SYNTHETIC_CITATION["runbook_id"],
            "revision": SYNTHETIC_CITATION["revision"],
            "content_hash": SYNTHETIC_CITATION["content_hash"],
            "locator": SYNTHETIC_CITATION["locator"],
            "operation": {"action": "verify", "target": "n8n"},
            "preconditions": [{"name": "healthcheck", "expected": "passing"}],
            "passage_text": PASSAGE_TEXT,
        },
    }


def native_body(
    question_ids: list[str],
    *,
    choices: dict[str, str] | None = None,
    model: str = JEV_MODEL,
    confidence: float = 0.42,
    probabilities: dict[str, float] | None = None,
    usage: dict | None = None,
) -> bytes:
    """A fully valid native response body for the given questions."""
    from ops_guard.judge import MENU

    default_distribution = {"routine": 0.6, "review": 0.3, "critical": 0.1}
    answers = {}
    for question_id in question_ids:
        choice = (choices or {}).get(question_id, "routine")
        distribution = dict(probabilities or default_distribution)
        if choice != "routine" and probabilities is None:
            distribution = {"routine": 0.1, "review": 0.2, "critical": 0.7}
            distribution[choice] = 0.7
            distribution = {
                option: distribution.get(option, 0.0) for option in MENU
            }
            total = sum(distribution.values())
            distribution = {option: value / total for option, value in distribution.items()}
        answers[question_id] = {
            "type": "choice",
            "choice": choice,
            "probabilities": distribution,
            "confidence": confidence,
        }
    body = {
        "model": model,
        "answers": answers,
        "usage": usage or {"input_tokens": 120, "output_tokens": 8},
    }
    return json.dumps(body).encode("utf-8")


class ScriptedJevTransport:
    """Records every attempted request body and replays a per-sample script
    of raw body bytes, or ``TransportFailure`` instances for faults."""

    def __init__(self, script) -> None:
        self._script = list(script)
        self.request_bodies: list[bytes] = []
        self.calls = 0

    def post_sample(self, body: bytes) -> bytes:
        self.calls += 1
        self.request_bodies.append(body)
        if self.calls > len(self._script):
            raise AssertionError("script exhausted: more samples than scripted")
        outcome = self._script[self.calls - 1]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome
