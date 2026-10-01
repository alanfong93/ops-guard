"""The sole pre-side-effect execution gate (issue #14).

Composes the five delivered contracts in the order docs/system_flow.md
fixes: evidence, preconditions, token validity, one valid authorization
path (standing, else proposal-bound approval), then — in one durable
transaction — the token consumption (ADR 0002), the pre-execution audit
append (issue #9), and the approval flip (ADR 0003). Only after that
transaction commits does the executor run; its outcome is recorded
afterwards (success, failure, or an explicitly unknown completion).

The gate resolves its own artifacts (issue #34; ADR 0004): the cited
runbook revision comes from the verified runbook library by content hash,
and the script bytes come from the authoritative configured source, whose
exact bytes are hashed for the standing-authorization match, recorded as
provenance, and passed unchanged to the executor. Caller-supplied
documents, verification metadata, and script digests are never trusted.

Every failed check records a refusal audit event before any side effect,
and the executor is never called on a refusal. Two failure windows escape
as exceptions by design, both after the refusal-recording capability is
gone: if the refusal append itself cannot persist (``AuditWriteFailure``),
and if the outcome append fails after the executor has already run. A dead
store surfaces as a raw sqlite error. Judge advice has no input to this
module: it cannot authorize execution.
"""

from __future__ import annotations

import hashlib
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
from ops_guard.owner import ExecutionOwner, owners_dir_for
from ops_guard.proposals import ProposalService
from ops_guard.retrieval import RunbookLibrary
from ops_guard.runbooks import (
    Citation,
    MalformedRunbookError,
    UnknownPassageError,
)
from ops_guard.proposals import format_timestamp
from ops_guard.execution_binding import canonical_binding_digest
from ops_guard.preconditions import (
        ObserverError,
        ObserverRegistry,
        ObserverTimeout,
        OperatorPolicy,
    )
from ops_guard.store import AuditAppend, same_database
import time

_OUTCOMES = {"success", "unknown"}


@dataclass(frozen=True)
class ExecutionRequest:
    """What the MCP/server composition may tell the gate: which token and
    which citation — nothing else. The script identity comes from the
    proposal's immutable ExecutionBinding, observations and authorization
    from the server (issues #62 and #64; ADR 0011/0012)."""

    token: str
    citation: Citation
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
        runbooks: RunbookLibrary,
        script_source: Callable[[str], bytes],
        clock: Callable[[], datetime],
        observer_registry: "ObserverRegistry",
        authorization_catalog: "OperatorPolicy",
        operator_identity: str,
        execution_catalog: "tuple[dict, dict] | None" = None,
        owner: ExecutionOwner | None = None,
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
        if not isinstance(runbooks, RunbookLibrary):
            raise GateConfigurationError(
                "the gate resolves evidence from a verified RunbookLibrary"
            )
        if not callable(script_source):
            raise GateConfigurationError(
                "script_source must resolve a script path to its exact bytes"
            )
        if observer_registry is None or authorization_catalog is None:
            raise GateConfigurationError(
                "the gate resolves preconditions through an ObserverRegistry "
                "and standing authorization through the operator policy (issue #62)"
            )
        if not isinstance(operator_identity, str) or not operator_identity:
            raise GateConfigurationError("operator_identity must be the configured operator identity")
        self._catalog = execution_catalog  # (entries, profiles) from ADR 0012
        self._runner_profiles = execution_catalog[1] if execution_catalog else None
        self._observers = observer_registry
        self._policy = authorization_catalog
        self._operator_identity = operator_identity

        self._proposals = proposals
        self._approvals = approvals
        self._audit = audit
        self._runbooks = runbooks
        self._script_source = script_source
        # Owner identity for crash recovery (issue #39; ADR 0005): every
        # execution-start record names the gate process instance that
        # dispatched it, and that instance holds its lock for its lifetime.
        self._owner = owner if owner is not None else ExecutionOwner(
            owners_dir_for(audit.store.path)
        )
        self._clock = clock

    def execute(
        self,
        request: ExecutionRequest,
        executor: Callable[[Invocation, bytes], str] | None = None,
    ) -> GateOutcome:
        """Run every gate; dispatch only after the durable transaction commits.

        The gate resolves the cited revision from the verified runbook
        library and the script bytes from the authoritative source before
        anything is consumed; ``executor`` receives the frozen invocation
        and exactly those resolved bytes, and returns "success" or
        "unknown". An exception from the executor run or its report
        validation is recorded as follows: timeouts (``TimeoutError``,
        ``subprocess.TimeoutExpired``) leave completion unconfirmed and are
        recorded as explicitly "unknown" with code ``executor-timeout``;
        every other exception is recorded as "failure" with code
        ``executor-error``, including the ``ValueError`` raised here when
        the report is neither "success" nor "unknown" and ``BaseException``
        subclasses such as ``KeyboardInterrupt`` and ``SystemExit``. The
        classified exception then propagates unchanged; if the outcome
        append cannot persist, ``AuditWriteFailure`` propagates instead,
        carrying the original exception as ``__context__`` (the module
        docstring documents this window).
        """
        proposal_id: str | None = None

        def refuse(
            reason: str,
            *,
            digest: str | None = None,
            failure_code: str | None = None,
            observation: Mapping | None = None,
        ) -> GateOutcome:
            payload: dict = {"reason": reason, "gate": "execution"}
            if failure_code:
                payload["failure_code"] = failure_code
            if observation:
                # Safe provenance: revision/index/observer/policy-digest and
                # the match outcome — never a raw observed value.
                payload["observation"] = dict(observation)
            self._audit.append(
                "refusal",
                payload=payload,
                proposal_ref=proposal_id,
                invocation_digest=digest or request.expected_digest,
                failure_code=failure_code,
                outcome="refused",
            )
            return GateOutcome(
                dispatched=False,
                refusal=reason,
                proposal_id=proposal_id,
                authorization_path=None,
                outcome="refused",
            )

        # 1. Evidence: the cited passage must resolve against a revision the
        #    verified runbook library holds — never against caller-supplied
        #    document content or verification metadata (issue #34). A
        #    refusal-append failure here escapes as AuditWriteFailure —
        #    fail-closed by design (the audit store being down must not look
        #    like a clean refusal).
        try:
            evidence = self._runbooks.resolve_citation(request.citation)
        except (MalformedRunbookError, UnknownPassageError) as error:
            return refuse(f"evidence rejected: {error}")

        # 3. Token validity and frozen-invocation revalidation.
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

        # 3b. The immutable execution binding (issue #64; ADR 0012) names
        #     the script this proposal may ever run. Legacy proposals
        #     without a binding can never dispatch through this gate.
        with self._proposals.store.read() as conn:
            binding_document = self._proposals.fetch_binding_on(conn, proposal_id)
        if binding_document is None:
            return refuse(
                "proposal carries no execution binding",
                digest=frozen.invocation_digest,
                failure_code="binding-missing",
            )
        execution_binding = binding_document["document"]
        if binding_document["digest"] != canonical_binding_digest(execution_binding):
            return refuse(
                "the stored execution binding is corrupt",
                digest=frozen.invocation_digest,
                failure_code="binding-corrupt",
            )
        if execution_binding["invocation_digest"] != frozen.invocation_digest:
            return refuse(
                "the execution binding diverges from the frozen invocation",
                digest=frozen.invocation_digest,
                failure_code="binding-mismatch",
            )

        # 4. Script resolution: the path comes from the binding, never from
        #    the caller; the resolved bytes must hash exactly to the bound
        #    script_sha256 (issue #34; ADR 0012).
        script_path = execution_binding["script_path"]
        try:
            script_bytes = self._script_source(script_path)
            if not isinstance(script_bytes, bytes):
                raise TypeError("script_source must resolve a path to bytes")
            resolved_sha256 = hashlib.sha256(script_bytes).hexdigest()
        except (OSError, LookupError, ValueError, TypeError) as error:
            return refuse(
                f"script could not be resolved: {error}",
                digest=frozen.invocation_digest,
                failure_code="binding-script-unresolved",
            )
        resolved_script = ScriptIdentity(path=script_path, sha256=resolved_sha256)
        if resolved_script.sha256 != execution_binding["script_sha256"]:
            return refuse(
                "the resolved script bytes do not match the bound script digest",
                digest=frozen.invocation_digest,
                failure_code="binding-script-mismatch",
            )
        if self._catalog is not None:
            catalog_entries, catalog_profiles = self._catalog
            entry = catalog_entries.get(
                (
                    execution_binding["runbook_id"],
                    execution_binding["runbook_revision"],
                    execution_binding["runbook_content_hash"],
                    frozen.invocation.action,
                    frozen.invocation.target,
                )
            )
            entry_document = (
                {
                    "runbook_id": entry.runbook_id,
                    "revision": entry.revision,
                    "content_hash": entry.content_hash,
                    "action": entry.action,
                    "target": entry.target,
                    "script_id": entry.script_id,
                    "script_path": entry.script_path,
                    "script_sha256": entry.script_sha256,
                }
                if entry is not None
                else None
            )
            entry_digest = (
                canonical_binding_digest(entry_document)
                if entry_document is not None
                else None
            )
            if (
                entry is None
                or entry_digest != execution_binding["catalog_entry_digest"]
                or entry.script_sha256 != execution_binding["script_sha256"]
                or entry.script_path != script_path
            ):
                return refuse(
                    "the catalog no longer maps this proposal's bound script",
                    digest=frozen.invocation_digest,
                    failure_code="binding-catalog-changed",
                )
            profile = catalog_profiles.get(execution_binding["runner_profile_id"])
            if (
                profile is None
                or profile.digest() != execution_binding["runner_profile_digest"]
            ):
                return refuse(
                    "the runner profile has changed since this proposal was bound",
                    digest=frozen.invocation_digest,
                    failure_code="binding-profile-changed",
                )

        # 4. The frozen invocation must be the one the evidence describes —
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

        # 4. Preconditions are observed fresh through the operator's fixed
        #    observer bindings (issue #62; ADR 0011) — never accepted from
        #    the caller. Each binding is keyed to the exact verified revision
        #    and zero-based precondition index; missing, unknown, timed-out,
        #    errored, or mismatched observations refuse before authorization.
        observation_provenance: list[dict] = []
        deadline = time.monotonic() + self._observers.deadline_seconds
        for index, precondition in enumerate(frozen.invocation.preconditions):
            binding = self._policy.bindings.get(
                (
                    request.citation.runbook_id,
                    request.citation.revision,
                    request.citation.content_hash,
                    index,
                )
            )

            def provenance(outcome: str, observer_id: str | None) -> dict:
                return {
                    "runbook_id": request.citation.runbook_id,
                    "revision": request.citation.revision,
                    "content_hash": request.citation.content_hash,
                    "precondition_index": index,
                    "precondition_name": precondition["name"],
                    "observer_id": observer_id,
                    "policy_digest": self._policy.digest,
                    "observed_at": format_timestamp(self._clock()),
                    "outcome": outcome,
                }

            if binding is None:
                return refuse(
                    f"precondition {index} ({precondition['name']!r}) has no "
                    "operator-configured observer for this revision",
                    digest=frozen.invocation_digest,
                    failure_code="precondition-unmapped",
                    observation=provenance("unmapped", None),
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return refuse(
                    "total observation deadline exceeded",
                    digest=frozen.invocation_digest,
                    failure_code="precondition-deadline",
                    observation=provenance("deadline-exceeded", binding.observer_id),
                )
            timeout = min(self._observers.timeout_for(binding.observer_id, dict(binding.settings)), remaining)
            try:
                observation = self._observers.observe(
                    binding.observer_id,
                    binding.settings,
                    timeout_seconds=timeout,
                    observed_at=self._clock().timestamp(),
                )
            except ObserverError as error:
                code = (
                    "precondition-timeout"
                    if isinstance(error, ObserverTimeout)
                    else "precondition-observer-error"
                )
                return refuse(
                    f"precondition {index} ({precondition['name']!r}) observation "
                    f"failed: {error}",
                    digest=frozen.invocation_digest,
                    failure_code=code,
                    observation=provenance("failed", binding.observer_id),
                )
            matched = observation.value == precondition["expected"]
            observation_provenance.append(
                {
                    "runbook_id": request.citation.runbook_id,
                    "revision": request.citation.revision,
                    "content_hash": request.citation.content_hash,
                    "precondition_index": index,
                    "precondition_name": precondition["name"],
                    "observer_id": observation.observer_id,
                    "policy_digest": self._policy.digest,
                    "observed_at": format_timestamp(self._clock()),
                    "outcome": "matched" if matched else "mismatch",
                }
            )
            if not matched:
                return refuse(
                    f"precondition {index} ({precondition['name']!r}) did not "
                    "match the required state",
                    digest=frozen.invocation_digest,
                    failure_code="precondition-mismatch",
                    observation=observation_provenance[-1],
                )

        # 5. Exactly one valid authorization path: standing match, else
        #    proposal-bound approval. The match compares the RESOLVED script
        #    identity — digest of the exact source bytes — against the
        #    authorization (issue #34); both paths dispatch only the
        #    resolved bytes, and their provenance is what gets recorded.
        path: str | None = None
        refusal_bits: list[str] = []
        for standing in self._policy.standing:
            try:
                standing_result = match(
                standing,
                frozen.invocation,
                resolved_script,
                runner_profile_digest=execution_binding["runner_profile_digest"],
            )
            except ProposalError as error:
                refusal_bits.append(f"standing: {error}")
                continue
            if standing_result.matched:
                path = "standing"
                break
            refusal_bits.append(f"standing: {standing_result.reason}")
        if path is None:
            try:
                self._approvals.verify(request.token, operator_identity=self._operator_identity)
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
            lambda conn, _consumed_digest: self._audit.append_on(
                conn,
                "execution_start",
                payload={
                    "phase": "pre-execution",
                    "script_path": resolved_script.path,
                    "script_sha256": resolved_script.sha256,
                    "execution_binding_digest": binding_document["digest"],
                    "runner_profile_id": execution_binding["runner_profile_id"],
                    "owner_id": self._owner.id,
                    "observations": observation_provenance,
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

        def composed(conn: sqlite3.Connection, consumed_digest: str) -> None:
            for callback in callbacks:
                callback(conn, consumed_digest)

        try:
            consumed = self._proposals.consume(
                request.token,
                expected_digest=request.expected_digest,
                same_transaction=composed,
            )
        except (ProposalError, ApprovalError, AuditWriteFailure) as error:
            return refuse(f"dispatch refused: {error}")

        # 7. Side effect, then the outcome record. The executor runs on the
        #    exact bytes the gate resolved and hashed — never a re-read of
        #    the path (issue #34, no TOCTOU gap). A BaseException (e.g.
        #    SystemExit) is recorded as a failure before it propagates so the
        #    execution never ends without an outcome attempt.
        failure_code: str | None = None
        if executor is None:
            # Production dispatch (issue #64): the staged runner bound to the
            # proposal's runner profile. The staged bytes are already
            # hash-verified above. The runner reports all three outcomes
            # (success / failure / unknown) and never raises past this
            # point; an unexpected crash is still recorded as a failure
            # before it propagates.
            from ops_guard.execution_binding import run_staged

            profile = self._runner_profiles[execution_binding["runner_profile_id"]]
            try:
                runner_result = run_staged(
                    profile,
                    script_path=script_path,
                    script_bytes=script_bytes,
                    script_sha256=resolved_sha256,
                    invocation=consumed.invocation.to_json(),
                )
            except BaseException as error:  # noqa: BLE001 - recorded as failure
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
            reported = runner_result.outcome
            failure_code = runner_result.failure_code
            if reported not in ("success", "failure", "unknown"):
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
                raise ValueError(
                    f"runner must report success, failure or unknown, got {reported!r}"
                )
        else:
            # Test/injected executor: timeouts leave completion unconfirmed
            # (explicitly unknown, never a known failure, issue #38); every
            # other exception is a recorded failure that still propagates.
            try:
                reported = executor(consumed.invocation, script_bytes)
                if reported not in _OUTCOMES:
                    raise ValueError(
                        f"executor must report success or unknown, got {reported!r}"
                    )
            except (TimeoutError, subprocess.TimeoutExpired):
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
            failure_code=failure_code,
            outcome=reported,
        )
        return GateOutcome(
            dispatched=True,
            refusal=None,
            proposal_id=frozen.proposal_id,
            authorization_path=path,
            outcome=reported,
        )
