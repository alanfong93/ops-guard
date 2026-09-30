"""The `propose_fix` MCP tool (issue #57; ADR 0008).

Registers on the existing authenticated FastMCP server: the host submits a
complete structured `Invocation` and a `Citation` — nothing else is
accepted. The server resolves the citation through its verified
`RunbookLibrary`, matches the invocation against the resolved evidence
(revision hash, action, target, ordered preconditions), and then calls the
existing `ProposalService.open_proposal()` exactly once with the
server-configured TTL. The raw token is returned in this one response and
never stored; the proposal audit event carries the proposal-time citation
as provenance-only `evidence_refs`.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any, Mapping

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, ConfigDict, Field

from ops_guard.errors import ProposalError
from ops_guard.gate import ExecutionRequest as _GateRequest
from ops_guard.invocation import Invocation
from ops_guard.audit import AuditWriteFailure
from ops_guard.runbooks import (
    MalformedRunbookError,
    TamperedRunbookError,
    UnknownPassageError,
    UnverifiedRunbookError,
)

DEFAULT_PROPOSAL_TTL_SECONDS = 900


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProposalInvocationInput(_StrictModel):
    """The complete structured invocation; every field is required."""

    action: str = Field(min_length=1)
    target: str = Field(min_length=1)
    arguments: dict[str, Any]
    preconditions: list[dict[str, Any]]
    runbook_revision_hash: str = Field(min_length=1)


class ProposalCitationInput(_StrictModel):
    """The evidence reference, resolved against the verified library only.

    Field emptiness is deliberately not constrained here: the citation
    resolver raises the typed malformed-citation error, which maps to
    ``invalid_citation`` (ADR 0008) instead of a generic schema error."""

    runbook_id: str
    revision: str
    content_hash: str
    locator: str


def _canonical(value: Any) -> bytes:
    from ops_guard.invocation import canonicalize_json

    return canonicalize_json(value)


def register_propose_fix(
    server,
    *,
    library,
    proposals,
    ttl: timedelta,
    judge,
    execution_catalog=None,
) -> None:
    """Register `propose_fix` on the shared authenticated FastMCP server.

    ``judge`` is required (issue #58): every call records an advisory
    result or typed failure on the proposal audit event, before the
    proposal transaction opens. It never raises past the tool boundary and
    its outcome never changes what this tool returns."""

    @server.tool
    def propose_fix(
        invocation: ProposalInvocationInput,
        citation: ProposalCitationInput,
    ) -> dict:
        """Submit a complete proposed operation with its evidence citation.

        Returns proposal_id, invocation_digest, expires_at, and the raw
        one-time token (this response only). No approval, judgment,
        observation, or execution happens here.
        """
        citation_ref = (
            f"{citation.runbook_id}@{citation.revision}",
            citation.content_hash,
            citation.locator,
        )
        try:
            cited = library.resolve_citation(_build_citation(citation))
        except (
            MalformedRunbookError,
            UnverifiedRunbookError,
            TamperedRunbookError,
            UnknownPassageError,
        ) as error:
            raise ToolError(f"invalid_citation: {error}") from error
        if (
            invocation.runbook_revision_hash != cited.citation.content_hash
            or invocation.action != cited.operation_action
            or invocation.target != cited.operation_target
            or _canonical(list(invocation.preconditions)) != _canonical(list(cited.preconditions))
        ):
            raise ToolError(
                "invocation_evidence_mismatch: the invocation does not equal the "
                "resolved verified evidence (revision hash, action, target, or "
                "ordered preconditions differ)"
            )
        try:
            frozen = Invocation(
                action=invocation.action,
                target=invocation.target,
                arguments=dict(invocation.arguments),
                preconditions=list(invocation.preconditions),
                runbook_revision_hash=invocation.runbook_revision_hash,
            )
            frozen.canonical_bytes()
        except (TypeError, ValueError) as error:
            raise ToolError(f"invalid_invocation: {error}") from error
        # Advisory local risk judgment (issue #58; ADR 0009): composed from
        # the validated invocation and the resolved verified citation only.
        # Audit-only — never returned, never read by the gate; any judge
        # outcome (including every failure code) still creates the proposal.
        from ops_guard.judge import judge_state

        snapshot = judge.evaluate_risk(
            judge_state(
                invocation_json=frozen.to_json(),
                cited_passage=cited,
            )
        )
        binding = None
        if execution_catalog is not None:
            # The server resolves the execution binding (issue #64; ADR 0012)
            # — the host never names a script. Zero or ambiguous matches
            # create no proposal and no token.
            from ops_guard.execution_binding import resolve_binding

            try:
                binding = resolve_binding(
                    execution_catalog[0],
                    execution_catalog[1],
                    runbook_id=citation.runbook_id,
                    revision=citation.revision,
                    content_hash=citation.content_hash,
                    action=frozen.action,
                    target=frozen.target,
                )
            except ProposalError as error:
                raise ToolError(f"execution_binding_unresolved: {error}") from error
        try:
            issued = proposals.open_proposal(
                frozen,
                ttl=ttl,
                evidence_refs=citation_ref,
                judge_snapshot=snapshot,
                execution_binding=binding,
            )
        except (ProposalError, AuditWriteFailure, ValueError) as error:
            raise ToolError(f"proposal_write_failed: {error}") from error
        return {
            "proposal_id": issued.proposal_id,
            "invocation_digest": issued.invocation_digest,
            "expires_at": issued.expires_at.isoformat(),
            "token": issued.token,
        }


def _build_citation(citation: ProposalCitationInput):
    from ops_guard.runbooks import Citation

    return Citation(**citation.model_dump())

def register_execute_fix(server, *, library, gate) -> None:
    """Register `execute_fix` (issue #64; ADR 0012).

    The host supplies a one-time token and a verified Citation — never a
    script path, bytes, runner, standing record, operator identity, or
    observed preconditions. The gate re-resolves the citation against the
    frozen invocation, verifies the stored execution binding and the
    catalog/profile/source digests, and dispatches the staged copy."""

    @server.tool
    def execute_fix(token: str, citation: ProposalCitationInput) -> dict:
        """Execute the operation frozen in the proposal this token was
        issued for. Returns the outcome and authorization path; consumes
        the one-time token atomically with the execution-start record."""
        from ops_guard.runbooks import (
            MalformedRunbookError,
            TamperedRunbookError,
            UnknownPassageError,
            UnverifiedRunbookError,
        )

        try:
            library.resolve_citation(_build_citation(citation))
        except (
            MalformedRunbookError,
            UnverifiedRunbookError,
            TamperedRunbookError,
            UnknownPassageError,
        ) as error:
            raise ToolError(f"invalid_citation: {error}") from error
        outcome = gate.execute(
            _GateRequest(token=token, citation=_build_citation(citation))
        )
        return {
            "dispatched": outcome.dispatched,
            "proposal_id": outcome.proposal_id,
            "authorization_path": outcome.authorization_path,
            "outcome": outcome.outcome,
            "refusal": outcome.refusal,
        }

