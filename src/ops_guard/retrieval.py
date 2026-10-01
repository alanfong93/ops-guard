"""Cited runbook retrieval exposed through MCP (issue #11).

``RunbookLibrary`` loads parsed, human-verified runbook revisions only —
unverified, tampered, or malformed documents are excluded at load time and
never become evidence. ``search_runbook`` ranks passages against the question
with naive keyword scoring (the declared baseline comparator for #15) and
returns structured evidence: runbook id, revision, content hash, locator,
passage text, and verification metadata. Every successful result identifies
one exact verified passage; citations it yields resolve through the #8
contract (docs/runbook-format.md), so stale content never qualifies.

``build_mcp_server`` exposes ``search_runbook`` as an MCP tool. No execution,
authorization, or judgment lives here.
"""

from __future__ import annotations

import copy
import hmac
import re
import sqlite3
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from fastmcp import FastMCP
from fastmcp.server.auth import AuthProvider
from pydantic import Field

from ops_guard.audit import AuditWriteFailure
from ops_guard.errors import ProposalError
from ops_guard.runbooks import (
    Citation,
    CitedPassage,
    MalformedRunbookError,
    Passage,
    RunbookRevision,
    UnknownPassageError,
    parse_revision,
)

if TYPE_CHECKING:
    from ops_guard.audit import AuditLog
    from ops_guard.judge import LocalJudge
    from ops_guard.proposals import ProposalService

_TOKEN = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class RetrievalRejection:
    document_index: int
    reason: str
    error: str


@dataclass(frozen=True)
class SearchResult:
    runbook_id: str
    revision: str
    content_hash: str
    locator: str
    passage_text: str
    operation_action: str
    operation_target: str
    preconditions: tuple[dict, ...]
    verifier: str
    verified_at: datetime
    applicability: str
    score: int

    def citation(self) -> Citation:
        return Citation(
            runbook_id=self.runbook_id,
            revision=self.revision,
            content_hash=self.content_hash,
            locator=self.locator,
        )


def _terms(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


def _snapshot_preconditions(preconditions: tuple[dict, ...]) -> tuple[dict, ...]:
    """Detached copies per return: caller mutation of a result, an MCP
    dictionary, or the source document can never reach library state and
    the verified hash keeps describing what is served (issue #37)."""
    return tuple(copy.deepcopy(item) for item in preconditions)


class RunbookLibrary:
    """Immutable set of verified revisions; the only source of evidence."""

    def __init__(self, revisions: Iterable[RunbookRevision]) -> None:
        self._revisions: tuple[RunbookRevision, ...] = tuple(revisions)
        self._entries: list[tuple[RunbookRevision, Passage]] = []
        for revision in self._revisions:
            for passage in revision.passages:
                self._entries.append((revision, passage))

    @classmethod
    def load(cls, documents: Iterable[Mapping]) -> tuple["RunbookLibrary", list[RetrievalRejection]]:
        """Load documents; invalid ones are excluded and reported, never served."""
        revisions: list[RunbookRevision] = []
        rejections: list[RetrievalRejection] = []
        for index, document in enumerate(documents):
            try:
                revisions.append(parse_revision(document))
            except (ProposalError, TypeError, ValueError, AttributeError,
                    UnicodeEncodeError, RecursionError, OverflowError) as error:
                rejections.append(
                    RetrievalRejection(
                        document_index=index,
                        reason=str(error),
                        error=type(error).__name__,
                    )
                )
        return cls(revisions), rejections

    def resolve_citation(self, citation: Citation) -> CitedPassage:
        """Resolve a citation against the verified revisions only (issue #34).

        The caller never supplies a revision document: the citation's content
        hash must name a revision this library verified at load time, or the
        resolution refuses. Checks mirror ``resolve_citation`` — hash, then
        runbook id and revision label, then the locator. Served preconditions
        are detached copies: library state cannot be mutated through the
        evidence (issue #37 convention).
        """
        if not isinstance(citation, Citation) or not all(
            isinstance(getattr(citation, field), str) and getattr(citation, field)
            for field in ("runbook_id", "revision", "content_hash", "locator")
        ):
            raise MalformedRunbookError("citation fields must be non-empty strings")
        for revision in self._revisions:
            if hmac.compare_digest(revision.content_hash, citation.content_hash):
                break
        else:
            raise UnknownPassageError(
                "no verified revision carries this content hash"
            )
        if citation.runbook_id != revision.runbook_id or citation.revision != revision.revision:
            raise MalformedRunbookError("citation names a different revision")
        for passage in revision.passages:
            if passage.locator == citation.locator:
                return CitedPassage(
                    citation=citation,
                    passage=passage,
                    operation_action=revision.operation_action,
                    operation_target=revision.operation_target,
                    preconditions=tuple(
                        copy.deepcopy(item) for item in revision.preconditions
                    ),
                    verifier=revision.verification.verifier,
                )
        raise UnknownPassageError(f"locator {citation.locator!r} does not exist in the revision")

    def search(self, question: str, *, limit: int = 5) -> list[SearchResult]:
        """Rank passages against the question; every hit is verified evidence."""
        if not isinstance(question, str) or not question.strip():
            raise ValueError("question must be a non-empty string")
        if limit < 1:
            raise ValueError("limit must be at least 1")
        wanted = set(_terms(question))
        scored: list[SearchResult] = []
        for revision, passage in self._entries:
            haystack = _terms(passage.text) + _terms(
                f"{revision.operation_action} {revision.operation_target}"
            )
            score = sum(1 for term in haystack if term in wanted)
            if score == 0:
                continue
            scored.append(
                SearchResult(
                    runbook_id=revision.runbook_id,
                    revision=revision.revision,
                    content_hash=revision.content_hash,
                    locator=passage.locator,
                    passage_text=passage.text,
                    operation_action=revision.operation_action,
                    operation_target=revision.operation_target,
                    preconditions=_snapshot_preconditions(revision.preconditions),
                    verifier=revision.verification.verifier,
                    verified_at=revision.verification.verified_at,
                    applicability=revision.verification.applicability,
                    score=score,
                )
            )
        scored.sort(key=lambda r: (-r.score, r.runbook_id, r.locator))
        return scored[:limit]


def _result_to_dict(result: SearchResult) -> dict:
    return {
        "runbook_id": result.runbook_id,
        "revision": result.revision,
        "content_hash": result.content_hash,
        "locator": result.locator,
        "passage_text": result.passage_text,
        "operation": {
            "action": result.operation_action,
            "target": result.operation_target,
        },
        "preconditions": [copy.deepcopy(item) for item in result.preconditions],
        "verification": {
            "verifier": result.verifier,
            "verified_at": result.verified_at.isoformat(timespec="microseconds"),
            "applicability": result.applicability,
        },
    }


def build_mcp_server(
    library: RunbookLibrary,
    audit: "AuditLog",
    auth: "AuthProvider | None" = None,
    proposals: "ProposalService | None" = None,
    proposal_ttl: "timedelta | None" = None,
    judge: "LocalJudge | None" = None,
    execution_catalog: "tuple[dict, dict] | None" = None,
    gate: "ExecutionGate | None" = None,
) -> FastMCP:
    """MCP server exposing ``search_runbook`` — and, when a proposal service
    is wired (issue #57), ``propose_fix``.

    ``audit`` is required (issue #40): every valid search records correlated
    ``request`` and ``guidance`` events atomically before results are
    returned, fail-closed on recording failure. ``auth`` optionally attaches
    a FastMCP auth provider (issue #54 wires a static bearer verifier).
    ``proposals``/``proposal_ttl`` add the host-composed proposal tool on
    this same server and database — never a second server or store.
    ``judge`` (issue #58) is required whenever ``proposals`` is wired: the
    propose_fix path always records an advisory result or typed failure on
    the proposal audit event.
    """
    server: FastMCP = FastMCP("ops-guard-retrieval", auth=auth)

    if proposals is not None:
        from ops_guard.proposal_tool import register_propose_fix

        if proposal_ttl is None:
            proposal_ttl = timedelta(minutes=15)
        if judge is None:
            raise ValueError(
                "a judge must be wired with the proposal service: every "
                "propose_fix call records an advisory result or typed failure"
            )
        register_propose_fix(
            server,
            library=library,
            proposals=proposals,
            ttl=proposal_ttl,
            judge=judge,
            execution_catalog=execution_catalog,
        )
        if gate is not None:
            from ops_guard.proposal_tool import register_execute_fix

            register_execute_fix(server, library=library, gate=gate)

    @server.tool
    def search_runbook(
        question: str,
        limit: int = Field(default=5, ge=1),
    ) -> list[dict]:
        """Cited runbook guidance: every result identifies one exact verified
        passage (runbook id, revision, content hash, locator, verification
        metadata) bound to the operation it evidences."""
        # Invalid input raises here, before any event is written.
        results = library.search(question, limit=limit)
        references = [
            {
                "runbook_id": result.runbook_id,
                "revision": result.revision,
                "content_hash": result.content_hash,
                "locator": result.locator,
                "operation": {
                    "action": result.operation_action,
                    "target": result.operation_target,
                },
            }
            for result in results
        ]
        correlation_id = uuid.uuid4().hex
        try:
            with audit.store.transaction() as conn:
                audit.append_on(
                    conn,
                    "request",
                    payload={
                        "question_fingerprint": audit.fingerprint(question),
                        "limit": limit,
                    },
                    correlation_id=correlation_id,
                )
                audit.append_on(
                    conn,
                    "guidance",
                    payload={"results": references},
                    correlation_id=correlation_id,
                )
        except AuditWriteFailure:
            raise
        except sqlite3.Error as error:
            raise AuditWriteFailure(f"required search audit failed: {error}") from error
        # Only a fully recorded search returns results.
        return [_result_to_dict(result) for result in results]

    return server
