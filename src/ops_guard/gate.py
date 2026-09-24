"""The sole pre-side-effect execution gate (issue #14).

Composes the five delivered contracts in the order docs/system_flow.md
fixes: evidence, preconditions, token validity, one valid authorization
path (standing, else proposal-bound approval), then — in one durable
transaction — the token consumption (ADR 0002), the pre-execution audit
append (issue #9), and the approval flip (ADR 0003). Only after that
transaction commits does the executor run; its outcome is recorded
afterwards (success, failure, or an explicitly unknown completion).

Every failed check records a refusal audit event before any side effect,
and the executor is never called on a refusal. Two failure windows escape
as exceptions by design, both after the refusal-recording capability is
gone: if the refusal append itself cannot persist (``AuditWriteFailure``),
and if the outcome append fails after the executor has already run. A dead
store surfaces as a raw sqlite error. Judge advice has no input to this
module: it cannot authorize execution.
"""

from __future__ import annotations

import sqlite3
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime

from ops_guard.approvals import ApprovalVerifier
from ops_guard.audit import AuditLog, AuditWriteFailure
from ops_guard.authorization import ScriptIdentity, StandingAuthorization, match
from ops_guard.errors import (
    ApprovalError,
    GateConfigurationError,
    InvocationMismatchError,
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
from ops_guard.store import AuditAppend, same_database

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
        # One durable transaction boundary (issue #36): the execution-start
        # append joins the token-consume transaction on the proposal store's
        # connection, so a split audit database can never be configured.
        # Validation runs here, at initialization — a mismatched gate is
        # rejected before any operation can be dispatched.
        if not same_database(proposals.store.path, audit.store.path):
            raise GateConfigurationError(
                "audit store must share the proposal database: "
                f"proposals={proposals.store.path!r}, audit={audit.store.path!r}"
            )
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
        "unknown". Any exception raised while it runs is recorded as
        "failure" with code ``executor-error``: this includes the
        ``ValueError`` raised here when it reports anything else, and
        ``BaseException`` subclasses such as ``KeyboardInterrupt`` and
        ``SystemExit``. A timeout (``TimeoutError``,
        ``subprocess.TimeoutExpired``) is the one exception class recorded
        differently: it leaves completion unconfirmed and is recorded as
        explicitly "unknown" with code ``executor-timeout``. The classified
        exception propagates; if the outcome append itself cannot persist,
        ``AuditWriteFailure`` escapes in its place (see the module
        docstring).
        """
        proposal_id: str | None = None

        def refuse(reason: str, *, digest: str | None = None) -> GateOutcome:
            self._audit.append(
                "refusal",
                payload={"reason": reason, "gate": "execution"},
                proposal_ref=proposal_id,
                invocation_digest=digest or request.expected_digest,
                outcome="refused",
            )
            return GateOutcome(
                dispatched=False,
                refusal=reason,
                proposal_id=proposal_id,
                authorization_path=None,
                outcome="refused",
            )

        # 1. Evidence: the cited passage must resolve against an intact,
        #    human-verified revision. A refusal-append failure here escapes
        #    as AuditWriteFailure — fail-closed by design (the audit store
        #    being down must not look like a clean refusal).
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

        # 3. The frozen invocation must be the one the evidence describes —
        #    including the runbook revision binding (runbook-format.md: the
        #    gate binds proposals to the revision content hash).
        if (
            frozen.invocation.action != evidence.operation_action
            or frozen.invocation.target != evidence.operation_target
            or frozen.invocation.runbook_revision_hash != request.citation.content_hash
            or canonicalize_json(list(frozen.invocation.preconditions))
            != canonicalize_json([dict(p) for p in evidence.preconditions])
        ):
            return refuse(
                "evidence does not describe the frozen invocation",
                digest=frozen.invocation_digest,
            )

        # 4. Preconditions must be observed as the frozen invocation requires.
        for precondition in frozen.invocation.preconditions:
            observed = request.observed_preconditions.get(precondition["name"])
            if observed is None:
                return refuse(
                    f"precondition {precondition['name']!r} was not observed",
                    digest=frozen.invocation_digest,
                )
            if observed != precondition["expected"]:
                return refuse(
                    f"precondition {precondition['name']!r} is "
                    f"{observed!r}, required {precondition['expected']!r}",
                    digest=frozen.invocation_digest,
                )

        # 5. Exactly one valid authorization path: standing match, else
        #    proposal-bound approval. On the approval path, request.script is
        #    recorded as supplied — the MCP layer (#16) must resolve and
        #    verify the script actually executed against it.
        path: str | None = None
        refusal_bits: list[str] = []
        if request.standing is not None:
            try:
                standing_result = match(request.standing, frozen.invocation, request.script)
            except ProposalError as error:
                standing_result = None
                refusal_bits.append(f"standing: {error}")
            if standing_result is not None and standing_result.matched:
                path = "standing"
            elif standing_result is not None:
                refusal_bits.append(f"standing: {standing_result.reason}")
        if path is None:
            try:
                self._approvals.verify(request.token, operator_identity=request.operator_identity)
                path = "proposal-bound"
            except ApprovalError as error:
                refusal_bits.append(f"approval: {error}")
            except InvocationMismatchError as error:
                refusal_bits.append(f"approval: {error}")
            except (UnknownTokenError, TokenExpiredError, TokenAlreadyConsumedError) as error:
                refusal_bits.append(f"approval: {error}")
        if path is None:
            return refuse(
                "no authorization path: " + "; ".join(refusal_bits),
                digest=frozen.invocation_digest,
            )

        # 6. Dispatch atomically: consume the token, append the
        #    execution-start audit record, and spend any recorded approval —
        #    one durable transaction. Spending is conditional: the standing
        #    path with no recorded approval leaves nothing to flip, while a
        #    used approval still fails the transaction (replay).
        callbacks: list[AuditAppend] = [
            lambda conn: self._audit.append_on(
                conn,
                "execution_start",
                payload={
                    "phase": "pre-execution",
                    "script_path": request.script.path,
                    "script_sha256": request.script.sha256,
                },
                correlation_id=frozen.proposal_id,
                proposal_ref=frozen.proposal_id,
                invocation_digest=frozen.invocation_digest,
                evidence_refs=[
                    f"{request.citation.runbook_id}@{request.citation.revision}",
                    request.citation.content_hash,
                    request.citation.locator,
                ],
                authorization_path=path,
            ),
            self._approvals.spend_approval_append(request.token),
        ]

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

        # 7. Side effect, then the outcome record. A BaseException (e.g.
        #    SystemExit) is recorded as a failure before it propagates so the
        #    execution never ends without an outcome attempt.
        try:
            reported = executor(consumed.invocation)
            if reported not in _OUTCOMES:
                raise ValueError(
                    f"executor must report success or unknown, got {reported!r}"
                )
        except (TimeoutError, subprocess.TimeoutExpired):
            # A timeout leaves completion unconfirmed: explicitly unknown,
            # never a known failure (issue #38).
            self._audit.append(
                "execution_outcome",
                payload={"outcome": "unknown"},
                correlation_id=frozen.proposal_id,
                proposal_ref=frozen.proposal_id,
                invocation_digest=frozen.invocation_digest,
                authorization_path=path,
                outcome="unknown",
                failure_code="executor-timeout",
            )
            raise
        except BaseException:  # noqa: BLE001 - failure is an outcome
            self._audit.append(
                "execution_outcome",
                payload={"outcome": "failure"},
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
