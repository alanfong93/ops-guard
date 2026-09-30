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
from ops_guard.execution_binding import load_execution_catalog
from ops_guard.preconditions import (
    POLICY_SCHEMA_VERSION,
    ObserverError,
    ObserverRegistry,
    PolicyError,
    load_policy,
    policy_digest,
)
from ops_guard.retrieval import RunbookLibrary
from ops_guard.service import ServiceConfig
from helpers import FakeClock, make_invocation, make_observer_registry, make_policy_document, load_test_policy
from tests_helpers_runbook import VALID_RUNBOOK
import hashlib as _hl
from ops_guard.invocation import canonicalize_json as _cj
SCRIPT_SHA256 = _hl.sha256(b"#!/bin/sh\necho ok\n").hexdigest()


OPERATOR = "alan"
SCRIPT_PATH = "/opt/scripts/restart-n8n.sh"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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
        from helpers import make_execution_catalog

        self.catalog = make_execution_catalog(VALID_RUNBOOK, SCRIPT_PATH, SCRIPT_SHA256)
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
            execution_catalog=self.catalog,
        )

    def issue(self):
        from helpers import binding_template

        invocation = make_invocation(runbook_revision_hash=VALID_RUNBOOK["content_hash"])
        template = binding_template(VALID_RUNBOOK, SCRIPT_PATH, SCRIPT_SHA256, invocation)
        return self.service.open_proposal(
            invocation, ttl=timedelta(minutes=10), execution_binding=template
        )

    def request(self, token: str) -> ExecutionRequest:
        return ExecutionRequest(
            token=token,
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
        "slow",
        lambda settings: time_module.sleep(5) or "passing",
        lambda s: None,
        timeout_getter=lambda s: float(s["timeout_seconds"]),
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

# ---- pass-1 review fixes (refusal provenance, liveness, startup) --------


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("missing-observation", "precondition-unmapped"),
        ("wrong-observation", "precondition-mismatch"),
    ],
)
def test_precondition_refusals_carry_safe_provenance(tmp_path, mutation, code) -> None:
    harness = Harness(tmp_path)
    issued = harness.issue()
    if mutation == "wrong-observation":
        harness.registry._test_state["value"] = "failing"
    else:
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
    outcome = harness.gate.execute(harness.request(issued.token), lambda i, s: "success")
    assert not outcome.dispatched
    refusals = [e for e in harness.audit.events() if e.event_type == "refusal"]
    payload = refusals[-1].payload
    assert payload["failure_code"] == code
    observation = payload["observation"]
    assert observation["runbook_id"] == VALID_RUNBOOK["runbook_id"]
    assert observation["precondition_index"] == 0
    assert observation["policy_digest"] == harness.policy.digest
    assert observation["outcome"] == ("mismatch" if code == "precondition-mismatch" else "unmapped")
    assert "value" not in observation  # raw observed value never persisted


def test_timeout_refusal_records_code_and_provenance(tmp_path) -> None:
    import time as time_module

    harness = Harness(tmp_path)
    harness.registry.register(
        "slow",
        lambda settings: time_module.sleep(5) or "passing",
        lambda s: None,
        timeout_getter=lambda s: float(s["timeout_seconds"]),
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
    refusals = [e for e in harness.audit.events() if e.event_type == "refusal"]
    assert refusals[-1].payload["failure_code"] == "precondition-timeout"
    assert refusals[-1].payload["observation"]["observer_id"] == "slow"
    frozen = harness.service.resolve(issued.token)
    assert not frozen.consumed


def test_timed_out_worker_does_not_block_the_gate(tmp_path) -> None:
    """Liveness: execute returns promptly even when the adapter would sleep
    far past its timeout; the late result is discarded."""
    import time as time_module

    harness = Harness(tmp_path)
    harness.registry.register(
        "slow",
        lambda settings: time_module.sleep(30) or "passing",
        lambda s: None,
        timeout_getter=lambda s: float(s["timeout_seconds"]),
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
    started = time_module.monotonic()
    outcome = harness.gate.execute(harness.request(issued.token), lambda i, s: "success")
    elapsed = time_module.monotonic() - started
    assert not outcome.dispatched
    assert elapsed < 5, f"gate blocked {elapsed:.1f}s past the timeout"


def test_proposal_error_from_adapter_becomes_typed_refusal(tmp_path) -> None:
    """A ProposalError escaping an adapter must still be audited as a typed
    refusal, never propagate unaudited with its message text."""
    harness = Harness(tmp_path)

    def raising(settings):
        raise PolicyError("secret-ish detail")

    harness.registry.register("raising", raising, lambda s: None)
    document = make_policy_document(
        runbook_id=VALID_RUNBOOK["runbook_id"],
        revision=VALID_RUNBOOK["revision"],
        content_hash=VALID_RUNBOOK["content_hash"],
    )
    document["observer_bindings"][0]["observer_id"] = "raising"
    harness.policy = load_policy(document, harness.registry)
    harness.gate = harness._gate()
    issued = harness.issue()
    outcome = harness.gate.execute(harness.request(issued.token), lambda i, s: "success")
    assert not outcome.dispatched
    refusals = [e for e in harness.audit.events() if e.event_type == "refusal"]
    assert refusals, "the failed check must be audit-recorded"
    assert "secret-ish detail" not in refusals[-1].payload["reason"]


def test_docker_engine_running_adapter_branches(monkeypatch) -> None:
    import subprocess as sp

    from ops_guard.preconditions import _docker_engine_running

    class Completed:
        def __init__(self, returncode, stdout):
            self.returncode = returncode
            self.stdout = stdout

    monkeypatch.setattr(sp, "run", lambda *a, **k: Completed(0, "27.0.1"))
    assert _docker_engine_running({"timeout_seconds": 2}) == "running"
    monkeypatch.setattr(sp, "run", lambda *a, **k: Completed(1, ""))
    assert _docker_engine_running({"timeout_seconds": 2}) == "stopped"

    def timeout_out(*a, **k):
        raise sp.TimeoutExpired(cmd="docker", timeout=2)

    monkeypatch.setattr(sp, "run", timeout_out)
    assert _docker_engine_running({"timeout_seconds": 2}) == "stopped"

    def no_engine(*a, **k):
        raise OSError("no docker binary")

    monkeypatch.setattr(sp, "run", no_engine)
    assert _docker_engine_running({"timeout_seconds": 2}) == "stopped"


def test_real_corpus_revision_with_docker_observer(tmp_path, monkeypatch) -> None:
    """The shipped #55 revisions bind their docker-engine precondition to the
    real docker observer: a running engine dispatches; a stopped engine
    refuses with precondition-mismatch even when an approval exists."""
    import subprocess as sp
    from ops_guard.preconditions import (
        _docker_engine_running,
        _validate_timeout_seconds,
    )

    harness = Harness(tmp_path)
    harness.registry.register(
        "docker_engine_running",
        _docker_engine_running,
        _validate_timeout_seconds,
        timeout_getter=lambda s: float(s["timeout_seconds"]),
    )
    calls = {"count": 0}
    real_adapter = harness.registry._adapters["docker_engine_running"][0]

    def counting(settings):
        calls["count"] += 1
        return real_adapter(settings)

    harness.registry._adapters["docker_engine_running"] = (
        counting,
        harness.registry._adapters["docker_engine_running"][1],
        harness.registry._adapters["docker_engine_running"][2],
    )

    # Bind BOTH shipped corpus revisions' precondition index 0 (the
    # docker-engine precondition each declares) to the real observer.
    bindings = []
    corpus_dir = os.path.join(REPO_ROOT, "runbooks")
    corpus: dict[str, dict] = {}
    for name in sorted(os.listdir(corpus_dir)):
        with open(os.path.join(corpus_dir, name), encoding="utf-8") as handle:
            revision = json.load(handle)
        corpus[revision["runbook_id"]] = revision
        bindings.append(
            {
                "runbook_id": revision["runbook_id"],
                "revision": revision["revision"],
                "content_hash": revision["content_hash"],
                "precondition_index": 0,
                "observer_id": "docker_engine_running",
                "settings": {"timeout_seconds": 2},
            }
        )
    document = make_policy_document(
        runbook_id="unused",
        revision="unused",
        content_hash="unused",
        bindings=False,
    )
    document["observer_bindings"] = bindings
    harness.library, _ = RunbookLibrary.load(list(corpus.values()))
    harness.policy = load_policy(document, harness.registry)
    harness.catalog = load_execution_catalog(
        {
            "schema_version": "ops-guard-execution-catalog-v1",
            "runner_profile": {
                "profile_id": "test-runner",
                "executable": "python3",
                "executable_sha256": "e" * 64,
                "argv": ["python3", "-c", "pass"],
                "working_directory": ".",
                "env_allowlist": ["PATH"],
                "timeout_seconds": 10,
                "output_limit": 65536,
            },
            "entries": [
                {
                    "runbook_id": revision["runbook_id"],
                    "revision": revision["revision"],
                    "content_hash": revision["content_hash"],
                    "action": "update",
                    "target": "n8n",
                    "script_id": f"docker-script-{index}",
                    "script_path": SCRIPT_PATH,
                    "script_sha256": SCRIPT_SHA256,
                }
                for index, revision in enumerate(corpus.values())
            ],
        }
    )
    harness.gate = harness._gate()

    from ops_guard.invocation import Invocation

    def corpus_issue() -> tuple[object, Invocation]:
        revision = corpus["n8n-update"]
        invocation = Invocation(
            action=revision["operation"]["action"],
            target=revision["operation"]["target"],
            arguments={"mode": "check"},
            preconditions=[dict(item) for item in revision["preconditions"]],
            runbook_revision_hash=revision["content_hash"],
        )
        from ops_guard.execution_binding import ExecutionBindingTemplate

        from helpers import make_runner_profile

        profile = make_runner_profile()
        entry_document = {
            "runbook_id": revision["runbook_id"],
            "revision": revision["revision"],
            "content_hash": revision["content_hash"],
            "action": "update",
            "target": "n8n",
            "script_id": "docker-script",
            "script_path": SCRIPT_PATH,
            "script_sha256": SCRIPT_SHA256,
        }
        template = ExecutionBindingTemplate(
            runbook_id=revision["runbook_id"],
            runbook_revision=revision["revision"],
            runbook_content_hash=revision["content_hash"],
            script_id="docker-script",
            script_path=SCRIPT_PATH,
            script_sha256=SCRIPT_SHA256,
            catalog_entry_digest=_hl.sha256(_cj(entry_document)).hexdigest(),
            runner_profile_id=profile.profile_id,
            runner_profile_digest=profile.digest(),
        )
        issued = harness.service.open_proposal(
            invocation, ttl=timedelta(minutes=10), execution_binding=template
        )
        request = ExecutionRequest(
            token=issued.token,
            citation=__import__(
                "ops_guard", fromlist=["Citation"]
            ).Citation(
                runbook_id=revision["runbook_id"],
                revision=revision["revision"],
                content_hash=revision["content_hash"],
                locator="update/ordering",
            ),
        )
        return issued, request

    class Completed:
        def __init__(self, returncode, stdout):
            self.returncode = returncode
            self.stdout = stdout

    # A running engine satisfies docker-engine == running: dispatch.
    monkeypatch.setattr(sp, "run", lambda *a, **k: Completed(0, "27.0.1"))
    issued, request = corpus_issue()
    harness.verifier.record_approval(issued.token, operator_identity=OPERATOR)
    outcome = harness.gate.execute(request, lambda i, s: "success")
    assert outcome.dispatched
    assert calls["count"] == 1

    # A stopped engine mismatches docker-engine == running: refusal with the
    # typed failure code, the real observer id, and no token consumption —
    # even though an approval was recorded.
    monkeypatch.setattr(sp, "run", lambda *a, **k: Completed(1, ""))
    issued2, request2 = corpus_issue()
    harness.verifier.record_approval(issued2.token, operator_identity=OPERATOR)
    outcome = harness.gate.execute(request2, lambda i, s: "success")
    assert not outcome.dispatched
    refusals = [e for e in harness.audit.events() if e.event_type == "refusal"]
    assert refusals[-1].payload["failure_code"] == "precondition-mismatch"
    assert refusals[-1].payload["observation"]["observer_id"] == "docker_engine_running"
    frozen = harness.service.resolve(issued2.token)
    assert not frozen.consumed


def test_policy_file_startup_fail_closed(tmp_path, monkeypatch) -> None:
    """main() exits 2 on a missing/malformed policy file before a listener."""
    import ops_guard.service as service_module

    config = ServiceConfig(
        bearer_token="x" * 40,
        proposal_token_key=b"\xaa" * 32,
        audit_fingerprint_key=b"\xbb" * 32,
        db_path=str(tmp_path / "db.sqlite3"),
        runbook_dir=str(tmp_path),
        bind_host="127.0.0.1",
        port=1,
        tls_certfile="c",
        tls_keyfile="k",
        allowed_hosts=("localhost",),
        allowed_origins=("https://x",),
        proposal_ttl_seconds=900,
    )
    monkeypatch.setattr(service_module, "load_config", lambda env: config)
    monkeypatch.setattr(
        service_module, "build_http_server", lambda cfg: (object(), None, None)
    )

    missing = str(tmp_path / "absent-policy.json")
    code = service_module.main(environ={"OPS_GUARD_POLICY_FILE": missing})
    assert code == 2

    malformed = tmp_path / "bad-policy.json"
    malformed.write_text('{"schema_version": "ops-guard-policy-v1"}', encoding="utf-8")
    code = service_module.main(environ={"OPS_GUARD_POLICY_FILE": str(malformed)})
    assert code == 2


def test_policy_file_rejects_duplicate_json_keys(tmp_path) -> None:
    from ops_guard.preconditions import PolicyError, default_registry, load_policy_file

    path = tmp_path / "policy.json"
    path.write_text(
        '{"schema_version": "ops-guard-policy-v1", "schema_version": "ops-guard-policy-v1",'
        ' "standing_authorizations": [], "observer_bindings": []}',
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="duplicate JSON key"):
        load_policy_file(str(path), default_registry())


def test_policy_settings_are_frozen_against_source_mutation() -> None:
    document = make_policy_document(
        runbook_id="r", revision="v", content_hash="a" * 64
    )
    registry = make_observer_registry()
    policy = load_policy(document, registry)
    document["observer_bindings"][0]["settings"]["timeout_seconds"] = 999
    binding = policy.bindings[("r", "v", "a" * 64, 0)]
    assert "timeout_seconds" not in dict(binding.settings)
