"""Proposal-bound execution artifacts (issue #64; ADR 0012).

The server resolves one immutable binding per proposal from the operator
catalog; approvals and standing authorization bind to the binding digest;
the host can never choose or see script identity.
"""

from __future__ import annotations

import json
import os
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
    TokenExpiredError,
)
from ops_guard.execution_binding import (
    BindingResolutionError,
    ExecutionBindingTemplate,
    load_execution_catalog,
    resolve_binding,
)
from ops_guard.retrieval import RunbookLibrary, build_mcp_server
from helpers import FakeClock, make_execution_catalog, make_invocation, make_runner_profile
from tests_helpers_runbook import VALID_RUNBOOK

OPERATOR = "alan"
SCRIPT_PATH = "/opt/scripts/restart-n8n.sh"
SCRIPT_BYTES = b"#!/bin/sh\necho ok\n"
import hashlib as _hl

SCRIPT_SHA256 = _hl.sha256(SCRIPT_BYTES).hexdigest()


def catalog_document(**overrides):
    document = {
        "schema_version": "ops-guard-execution-catalog-v1",
        "runner_profile": {
            "profile_id": "prod-runner",
            "executable": "/usr/bin/python3",
            "executable_sha256": "e" * 64,
            "argv": ["/usr/bin/python3", "-c", "pass"],
            "working_directory": "/opt",
            "env_allowlist": ["PATH"],
            "timeout_seconds": 10,
            "output_limit": 65536,
        },
        "entries": [
            {
                "runbook_id": VALID_RUNBOOK["runbook_id"],
                "revision": VALID_RUNBOOK["revision"],
                "content_hash": VALID_RUNBOOK["content_hash"],
                "action": "restart",
                "target": "n8n",
                "script_id": "restart-n8n-script",
                "script_path": SCRIPT_PATH,
                "script_sha256": SCRIPT_SHA256,
            }
        ],
    }
    document.update(overrides)
    return document


def test_valid_catalog_loads_with_unique_entry() -> None:
    entries, profiles = load_execution_catalog(catalog_document())
    key = (VALID_RUNBOOK["runbook_id"], VALID_RUNBOOK["revision"], VALID_RUNBOOK["content_hash"], "restart", "n8n")
    assert key in entries
    assert list(profiles) == ["prod-runner"]


def test_ambiguous_catalog_entries_are_rejected() -> None:
    document = catalog_document()
    document["entries"].append(dict(document["entries"][0], script_id="second-script"))
    with pytest.raises(Exception, match="duplicates"):
        load_execution_catalog(document)


def test_missing_catalog_entry_never_resolves() -> None:
    entries, profiles = load_execution_catalog(catalog_document())
    with pytest.raises(BindingResolutionError, match="no execution catalog entry"):
        resolve_binding(
            entries,
            profiles,
            runbook_id="unknown-runbook",
            revision="v",
            content_hash="a" * 64,
            action="restart",
            target="n8n",
        )


def test_proposal_write_failure_rolls_back_binding(tmp_path, monkeypatch) -> None:
    from ops_guard import AuditWriteFailure
    from ops_guard.execution_binding import resolve_binding as rb

    clock = FakeClock()
    db = str(tmp_path / "x.db")
    audit = AuditLog(AuditStore(db), fingerprint_key=os.urandom(32), clock=clock)
    service = ProposalService(ProposalStore(db), token_key=os.urandom(32), clock=clock, audit=audit)
    entries, profiles = load_execution_catalog(catalog_document())
    template = rb(
        entries,
        profiles,
        runbook_id=VALID_RUNBOOK["runbook_id"],
        revision=VALID_RUNBOOK["revision"],
        content_hash=VALID_RUNBOOK["content_hash"],
        action="restart",
        target="n8n",
    )
    invocation = make_invocation(runbook_revision_hash=VALID_RUNBOOK["content_hash"])

    def failing(conn, event_type, **kwargs):
        if event_type == "proposal":
            raise AuditWriteFailure("audit gone")
        raise AssertionError("unreachable")

    monkeypatch.setattr(audit, "append_on", failing)
    with pytest.raises(AuditWriteFailure):
        service.open_proposal(
            invocation, ttl=timedelta(minutes=10), execution_binding=template
        )
    with service.store.read() as conn:
        count = conn.execute("SELECT COUNT(*) FROM execution_bindings").fetchone()[0]
        proposals = conn.execute("SELECT COUNT(*) FROM proposals").fetchone()[0]
    assert count == 0 and proposals == 0  # atomic rollback: no binding, no row


def test_legacy_proposal_cannot_be_approved_or_executed(tmp_path) -> None:
    clock = FakeClock()
    db = str(tmp_path / "x.db")
    audit = AuditLog(AuditStore(db), fingerprint_key=os.urandom(32), clock=clock)
    service = ProposalService(ProposalStore(db), token_key=os.urandom(32), clock=clock, audit=audit)
    invocation = make_invocation(runbook_revision_hash=VALID_RUNBOOK["content_hash"])
    issued = service.open_proposal(invocation, ttl=timedelta(minutes=10))  # no binding
    verifier = ApprovalVerifier(
        ApprovalStore(db), service, operator_identity=OPERATOR, clock=clock
    )
    with pytest.raises(Exception, match="predates execution binding"):
        verifier.record_approval_by_proposal_id(
            issued.proposal_id, operator_identity=OPERATOR
        )
    with service.store.read() as conn:
        row = service.fetch_binding_on(conn, issued.proposal_id)
    assert row is None
    from ops_guard.errors import TokenAlreadyConsumedError  # noqa: F401

    # and the gate side: binding missing -> refusal (covered via gate tests)


def test_approve_by_proposal_id_binds_execution_binding_digest(tmp_path) -> None:
    clock = FakeClock()
    db = str(tmp_path / "x.db")
    audit = AuditLog(AuditStore(db), fingerprint_key=os.urandom(32), clock=clock)
    service = ProposalService(ProposalStore(db), token_key=os.urandom(32), clock=clock, audit=audit)
    verifier = ApprovalVerifier(
        ApprovalStore(db), service, operator_identity=OPERATOR, clock=clock
    )
    entries, profiles = load_execution_catalog(catalog_document())
    template = resolve_binding(
        entries,
        profiles,
        runbook_id=VALID_RUNBOOK["runbook_id"],
        revision=VALID_RUNBOOK["revision"],
        content_hash=VALID_RUNBOOK["content_hash"],
        action="restart",
        target="n8n",
    )
    invocation = make_invocation(runbook_revision_hash=VALID_RUNBOOK["content_hash"])
    issued = service.open_proposal(
        invocation, ttl=timedelta(minutes=10), execution_binding=template
    )
    record = verifier.record_approval_by_proposal_id(
        issued.proposal_id, operator_identity=OPERATOR
    )
    binding = template.finalize(issued.proposal_id, issued.invocation_digest)
    assert record.execution_binding_digest == binding.digest()
    decision = verifier.verify(issued.token, operator_identity=OPERATOR)
    assert decision.allowed

def test_relative_executable_is_rejected() -> None:
    """ADR 0012: the profile executable must be an absolute path."""
    document = catalog_document()
    document["runner_profile"]["executable"] = "python3"
    document["runner_profile"]["argv"] = ["python3", "-c", "pass"]
    with pytest.raises(Exception, match="absolute path"):
        load_execution_catalog(document)


def test_argv0_mismatch_is_rejected() -> None:
    """argv[0] must name the profile executable (ADR 0012)."""
    document = catalog_document()
    document["runner_profile"]["argv"] = ["/usr/bin/other", "-c", "pass"]
    with pytest.raises(Exception, match="argv"):
        load_execution_catalog(document)
