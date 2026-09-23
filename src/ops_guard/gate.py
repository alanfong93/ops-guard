"""The sole pre-side-effect execution gate (issue #14).

Composes the five delivered contracts in the order docs/system_flow.md
fixes: evidence, preconditions, token validity, one valid authorization
path (standing, else proposal-bound approval), then — in one durable
transaction — the token consumption (ADR 0002), the pre-execution audit
append (issue #9), and the approval flip (ADR 0003). Only after that
transaction commits does the executor run; its outcome is recorded
afterwards (success, failure, or an explicitly unknown completion).

Every failed check records a refusal audit event before any side effect,
and the executor is never called on a refusal. Judge advice has no input
to this module: it cannot authorize execution.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime

from ops_guard.approvals import ApprovalVerifier
from ops_guard.audit import AuditLog, AuditWriteFailure
from ops_guard.authorization import ScriptIdentity, StandingAuthorization, match
from ops_guard.errors import (
    ApprovalError,
    ProposalError,
    TokenAlreadyConsumedError,
    TokenExpiredError,
    UnknownTokenError,
)
from ops_guard.invocation import Invocation, canonicalize_json
from ops_guard.proposals import ProposalService
from ops_guard.runbooks import (
    Citation,
    MalformedRunbookError,
    TamperedRunbookError,
    UnknownPassageError,
    UnverifiedRunbookError,
    resolve_citation,
)
from ops_guard.store import AuditAppend

_OUTCOMES = {"success", "unknown"}


@dataclass(frozen=True)
class ExecutionRequest:
    token: str
    script: ScriptIdentity
    runbook_document: Mapping
    citation: Citation
    observed_preconditions: Mapping[str, str]
    operator_identity: str
    standing: StandingAuthorization | None = None
    expected_digest: str | None = None


@dataclass(frozen=True)
class GateOutcome:
    dispatched: bool
    refusal: str | None
    proposal_id: str | None
    authorization_path: str | None
    outcome: str | None


class ExecutionGate:
    def __init__(
        self,
        proposals: ProposalService,
        approvals: ApprovalVerifier,
        audit: AuditLog,
        *,
        clock: Callable[[], datetime],
    ) -> None:
        self._proposals = proposals
        self._approvals = approvals
        self._audit = audit
        self._clock = clock

    def execute(
        self,
        request: ExecutionRequest,
        executor: Callable[[Invocation], str],
    ) -> GateOutcome:
        """Run every gate; dispatch only after the durable transaction commits.

        ``executor`` receives the frozen invocation and returns "success" or
        "unknown"; a raised exception is recorded as "failure".
        """
        proposal_id: str | None = None

        def refuse(reason: str) -> GateOutcome:
            self._audit.append(
                "refusal",
                payload={"reason": reason, "gate": "execution"},
                proposal_ref=proposal_id,
                invocation_digest=request.expected_digest,
            )
            return GateOutcome(
                dispatched=False,
                refusal=reason,
                proposal_id=proposal_id,
                authorization_path=None,
                outcome="refused",
            )

        # 1. Evidence: the cited passage must resolve against an intact,
        #    human-verified revision.
        try:
            evidence = resolve_citation(request.runbook_document, request.citation)
        except (MalformedRunbookError, UnverifiedRunbookError, TamperedRunbookError, UnknownPassageError) as error:
            return refuse(f"evidence rejected: {error}")

        # 2. Token validity and frozen-invocation revalidation.
        try:
            frozen = self._proposals.resolve(request.token, expected_digest=request.expected_digest)
        except UnknownTokenError as error:
            return refuse(f"token unknown: {error}")
        except TokenExpiredError as error:
            return refuse(f"token expired: {error}")
        except TokenAlreadyConsumedError as error:
            return refuse(f"token already consumed: {error}")
        except ProposalError as error:
            return refuse(f"token rejected: {error}")
        proposal_id = frozen.proposal_id

        # 3. The frozen invocation must be the one the evidence describes.
        if (
            frozen.invocation.action != evidence.operation_action
            or frozen.invocation.target != evidence.operation_target
            or canonicalize_json(list(frozen.invocation.preconditions))
            != canonicalize_json([dict(p) for p in evidence.preconditions])
        ):
            return refuse("evidence does not describe the frozen invocation")

        # 4. Preconditions must be observed as the frozen invocation requires.
        for precondition in frozen.invocation.preconditions:
            observed = request.observed_preconditions.get(precondition["name"])
            if observed is None:
                return refuse(
                    f"precondition {precondition['name']!r} was not observed"
                )
            if observed != precondition["expected"]:
                return refuse(
                    f"precondition {precondition['name']!r} is "
                    f"{observed!r}, required {precondition['expected']!r}"
                )

        # 5. Exactly one valid authorization path: standing match, else
        #    proposal-bound approval.
        path: str | None = None
        refusal_bits: list[str] = []
        if request.standing is not None:
            standing_result = match(request.standing, frozen.invocation, request.script)
            if standing_result.matched:
                path = "standing"
            else:
                refusal_bits.append(f"standing: {standing_result.reason}")
        if path is None:
            try:
                self._approvals.verify(request.token, operator_identity=request.operator_identity)
                path = "proposal-bound"
            except ApprovalError as error:
                refusal_bits.append(f"approval: {error}")
            except (UnknownTokenError, TokenExpiredError, TokenAlreadyConsumedError) as error:
                refusal_bits.append(f"approval: {error}")
        if path is None:
            return refuse("no authorization path: " + "; ".join(refusal_bits))

        # 6. Dispatch atomically: consume the token, append the
        #    execution-start audit record, and (proposal-bound path) spend
        #    the approval — one durable transaction.
        callbacks: list[AuditAppend] = [
            lambda conn: self._audit.append_on(
                conn,
                "execution_start",
                payload={
                    "phase": "pre-execution",
                    "authorization_path": path,
                    "script_path": request.script.path,
                },
                correlation_id=frozen.proposal_id,
                proposal_ref=frozen.proposal_id,
                invocation_digest=frozen.invocation_digest,
                evidence_refs=[request.citation.locator],
                authorization_path=path,
            )
        ]
        if path == "proposal-bound":
            callbacks.append(self._approvals.mark_used_append(request.token))

        def composed(conn: sqlite3.Connection) -> None:
            for callback in callbacks:
                callback(conn)

        try:
            consumed = self._proposals.consume(
                request.token,
                expected_digest=request.expected_digest,
                same_transaction=composed,
            )
        except (ProposalError, ApprovalError, AuditWriteFailure) as error:
            return refuse(f"dispatch refused: {error}")

        # 7. Side effect, then the outcome record.
        try:
            reported = executor(consumed.invocation)
            if reported not in _OUTCOMES:
                raise ValueError(
                    f"executor must report success or unknown, got {reported!r}"
                )
        except Exception as error:  # noqa: BLE001 - failure is an outcome
            self._audit.append(
                "execution_outcome",
                payload={"outcome": "failure", "error": str(error)},
                correlation_id=frozen.proposal_id,
                proposal_ref=frozen.proposal_id,
                invocation_digest=frozen.invocation_digest,
                authorization_path=path,
                outcome="failure",
                failure_code="executor-error",
            )
            raise

        self._audit.append(
            "execution_outcome",
            payload={"outcome": reported},
            correlation_id=frozen.proposal_id,
            proposal_ref=frozen.proposal_id,
            invocation_digest=frozen.invocation_digest,
            authorization_path=path,
            outcome=reported,
        )
        return GateOutcome(
            dispatched=True,
            refusal=None,
            proposal_id=frozen.proposal_id,
            authorization_path=path,
            outcome=reported,
        )
