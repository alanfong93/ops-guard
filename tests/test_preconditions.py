"""Operator-configured precondition observers (issue #62; ADR 0011).

Policy parsing is strict; observations come from server-owned adapters;
every refusal happens before token consumption; no caller-supplied value
can influence the result.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ops_guard import (
    ApprovalStore,
    ApprovalVerifier,
    AuditLog,
    AuditStore,
    ProposalService,
    ProposalStore,
)
from ops_guard.errors import ProposalError
from ops_guard.gate import ExecutionGate, ExecutionRequest
from ops_guard.preconditions import (
    POLICY_SCHEMA_VERSION,
    ObserverError,
    ObserverRegistry,
    PolicyError,
    load_policy,
    policy_digest,
)
from ops_guard.retrieval import RunbookLibrary
from helpers import FakeClock, make_invocation, make_observer_registry, make_policy_document, load_test_policy
from tests_helpers_runbook import VALID_RUNBOOK

OPERATOR = "alan"
SCRIPT_PATH = "/opt/scripts/restart-n8n.sh"
SCRIPT_BYTES = b"#!/bin/sh\necho ok\n"


class Harness:
    def __init__(self, tmp_path, *, with_bindings: bool = True):
        self.clock = FakeClock()
        self.db = str(tmp_path / "s74.db")
        self.audit = AuditLog(AuditStore(self.db), fingerprint_key=os.urandom(32), clock=self.clock)
        self.service = ProposalService(
            ProposalStore(self.db), token_key=os.urandom(32), clock=self.clock, audit=self.audit
        )
        self.verifier = ApprovalVerifier(
            ApprovalStore(self.db), self.service, operator_identity=OPERATOR, clock=self.clock
        )
        self.library, _ = RunbookLibrary.load([VALID_RUNBOOK])
        self.scripts: dict[str, bytes] = {SCRIPT_PATH: SCRIPT_BYTES}
        self.registry = make_observer_registry({"static_test": "passing"})
        self.policy = load_test_policy(
            make_policy_document(
                runbook_id=VALID_RUNBOOK["runbook_id"],
                revision=VALID_RUNBOOK["revision"],
                content_hash=VALID_RUNBOOK["content_hash"],
                bindings=with_bindings,
            ),
            self.registry,
        )
        self.gate = self._gate()

    def _gate(self) -> ExecutionGate:
        return ExecutionGate(
            self.service,
            self.verifier,
            self.audit,
            runbooks=self.library,
            script_source=self.scripts.__getitem__,
            clock=self.clock,
            observer_registry=self.registry,
            authorization_catalog=self.policy,
            operator_identity=OPERATOR,
        )

    def issue(self):
        invocation = make_invocation(runbook_revision_hash=VALID_RUNBOOK["content_hash"])
        return self.service.open_proposal(invocation, ttl=timedelta(minutes=10))

    def request(self, token: str) -> ExecutionRequest:
        return ExecutionRequest(
            token=token,
            script_path=SCRIPT_PATH,
            citation=__import__(
                "ops_guard", fromlist=["Citation"]
            ).Citation(
                runbook_id=VALID_RUNBOOK["runbook_id"],
                revision=VALID_RUNBOOK["revision"],
                content_hash=VALID_RUNBOOK["content_hash"],
                locator="restart/steps",
            ),
        )


@pytest.fixture()
def harness(tmp_path):
    return Harness(tmp_path)


# ---- strict policy parsing ---------------------------------------------


def test_valid_policy_loads_with_digest() -> None:
    document = make_policy_document(
        runbook_id=VALID_RUNBOOK["runbook_id"],
        revision=VALID_RUNBOOK["revision"],
        content_hash=VALID_RUNBOOK["content_hash"],
    )
    registry = make_observer_registry()
    policy = load_policy(document, registry)
    assert policy.digest == policy_digest(document)
    assert len(policy.digest) == 64
    assert len(policy.bindings) == 1


def test_unknown_schema_version_is_rejected() -> None:
    document = make_policy_document(
        runbook_id="r", revision="v", content_hash="a" * 64
    )
    document["schema_version"] = "ops-guard-policy-v99"
    with pytest.raises(PolicyError):
        load_policy(document, make_observer_registry())


def test_unknown_top_level_field_is_rejected() -> None:
    document = make_policy_document(
        runbook_id="r", revision="v", content_hash="a" * 64
    )
    document["extra"] = True
    with pytest.raises(PolicyError):
        load_policy(document, make_observer_registry())


def test_unknown_observer_id_is_rejected() -> None:
    document = make_policy_document(
        runbook_id="r", revision="v", content_hash="a" * 64
    )
    document["observer_bindings"][0]["observer_id"] = "shell_exec_arbitrary"
    with pytest.raises(PolicyError):
        load_policy(document, make_observer_registry())


def test_duplicate_binding_is_rejected() -> None:
    document = make_policy_document(
        runbook_id="r", revision="v", content_hash="a" * 64
    )
    document["observer_bindings"].append(dict(document["observer_bindings"][0]))
    with pytest.raises(PolicyError):
        load_policy(document, make_observer_registry())


def test_invalid_adapter_settings_are_rejected() -> None:
    document = make_policy_document(
        runbook_id="r", revision="v", content_hash="a" * 64
    )
    document["observer_bindings"][0]["observer_id"] = "docker_engine_running"
    document["observer_bindings"][0]["settings"] = {"timeout_seconds": 0}
    from ops_guard.preconditions import default_registry

    with pytest.raises(PolicyError):
        load_policy(document, default_registry())


def test_policy_cannot_carry_commands_or_urls() -> None:
    """The binding schema has no field a command, URL, or callable could
    hide in — the strict key check rejects any attempt."""
    document = make_policy_document(
        runbook_id="r", revision="v", content_hash="a" * 64
    )
    document["observer_bindings"][0]["command"] = "rm -rf /"
    with pytest.raises(PolicyError):
        load_policy(document, make_observer_registry())


# ---- gate observations --------------------------------------------------


def test_observation_from_the_operator_observer_dispatches(harness) -> None:
    issued = harness.issue()
    harness.verifier.record_approval(issued.token, operator_identity=OPERATOR)
    outcome = harness.gate.execute(harness.request(issued.token), lambda i, s: "success")
    assert outcome.dispatched and outcome.authorization_path == "proposal-bound"


def test_unmapped_precondition_refuses_before_consumption(harness) -> None:
    harness.policy = load_test_policy(
        make_policy_document(
            runbook_id=VALID_RUNBOOK["runbook_id"],
            revision=VALID_RUNBOOK["revision"],
            content_hash=VALID_RUNBOOK["content_hash"],
            bindings=False,
        ),
        harness.registry,
    )
    harness.gate = harness._gate()
    issued = harness.issue()
    outcome = harness.gate.execute(harness.request(issued.token), lambda i, s: "success")
    assert not outcome.dispatched
    assert "no operator-configured observer" in outcome.refusal
    frozen = harness.service.resolve(issued.token)
    assert not frozen.consumed


def test_observer_mismatch_refuses_without_raw_value_leak(harness) -> None:
    harness.registry._test_state["value"] = "failing"
    issued = harness.issue()
    outcome = harness.gate.execute(harness.request(issued.token), lambda i, s: "success")
    assert not outcome.dispatched
    assert "did not match" in outcome.refusal
    assert "failing" not in outcome.refusal  # raw observed value never echoed


def test_adapter_error_is_a_typed_refusal(harness) -> None:
    def broken(settings):
        raise RuntimeError("boom")

    harness.registry.register("broken", broken, lambda s: None)
    document = make_policy_document(
        runbook_id=VALID_RUNBOOK["runbook_id"],
        revision=VALID_RUNBOOK["revision"],
        content_hash=VALID_RUNBOOK["content_hash"],
    )
    document["observer_bindings"][0]["observer_id"] = "broken"
    harness.policy = load_policy(document, harness.registry)
    harness.gate = harness._gate()
    issued = harness.issue()
    outcome = harness.gate.execute(harness.request(issued.token), lambda i, s: "success")
    assert not outcome.dispatched
    assert "observation failed" in outcome.refusal
    assert "boom" not in outcome.refusal  # arbitrary exception text never stored


def test_observer_timeout_refuses(tmp_path) -> None:
    import time as time_module

    harness = Harness(tmp_path)
    harness.registry.register(
        "slow", lambda settings: time_module.sleep(5) or "passing", lambda s: None
    )
    document = make_policy_document(
        runbook_id=VALID_RUNBOOK["runbook_id"],
        revision=VALID_RUNBOOK["revision"],
        content_hash=VALID_RUNBOOK["content_hash"],
    )
    document["observer_bindings"][0]["observer_id"] = "slow"
    document["observer_bindings"][0]["settings"] = {"timeout_seconds": 1}
    harness.policy = load_policy(document, harness.registry)
    harness.gate = harness._gate()
    issued = harness.issue()
    outcome = harness.gate.execute(harness.request(issued.token), lambda i, s: "success")
    assert not outcome.dispatched
    assert "timed out" in outcome.refusal
    frozen = harness.service.resolve(issued.token)
    assert not frozen.consumed


def test_observation_provenance_recorded_in_execution_start(harness) -> None:
    issued = harness.issue()
    harness.verifier.record_approval(issued.token, operator_identity=OPERATOR)
    harness.gate.execute(harness.request(issued.token), lambda i, s: "success")
    starts = [e for e in harness.audit.events() if e.event_type == "execution_start"]
    observations = starts[-1].payload["observations"]
    assert len(observations) == 1
    entry = observations[0]
    assert entry["runbook_id"] == VALID_RUNBOOK["runbook_id"]
    assert entry["revision"] == VALID_RUNBOOK["revision"]
    assert entry["precondition_index"] == 0
    assert entry["observer_id"] == "static_test"
    assert entry["policy_digest"] == harness.policy.digest
    assert entry["outcome"] == "matched"
    assert "value" not in entry  # raw observation values are never persisted


def test_changed_policy_produces_a_different_digest(harness) -> None:
    document_a = make_policy_document(
        runbook_id="r", revision="v", content_hash="a" * 64
    )
    document_b = make_policy_document(
        runbook_id="r", revision="v", content_hash="b" * 64
    )
    assert policy_digest(document_a) != policy_digest(document_b)


def test_caller_supplied_fields_no_longer_exist_on_the_request() -> None:
    import inspect as inspect_module

    fields = inspect_module.signature(ExecutionRequest).parameters
    assert "observed_preconditions" not in fields
    assert "standing" not in fields
    assert "operator_identity" not in fields


@given(value=st.text(min_size=1, max_size=24))
@settings(max_examples=30, deadline=None)
def test_observation_returns_exactly_the_adapter_value(value: str) -> None:
    """The registry returns the adapter's value verbatim; the gate compares
    it exactly against the frozen expected string — no coercion, no caller
    input anywhere in the path."""
    registry = make_observer_registry({"static_test": value})
    document = make_policy_document(
        runbook_id="r", revision="v", content_hash="a" * 64
    )
    policy = load_policy(document, registry)
    binding = policy.bindings[("r", "v", "a" * 64, 0)]
    observation = registry.observe(
        binding.observer_id, binding.settings, timeout_seconds=2
    )
    assert observation.value == value
    # exact comparison: anything but the expected string is a mismatch
    assert (observation.value == "passing") == (value == "passing")
