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

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime

from fastmcp import FastMCP
from pydantic import Field

from ops_guard.errors import ProposalError
from ops_guard.runbooks import Citation, Passage, RunbookRevision, parse_revision

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
                    preconditions=revision.preconditions,
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
        "preconditions": list(result.preconditions),
        "verification": {
            "verifier": result.verifier,
            "verified_at": result.verified_at.isoformat(timespec="microseconds"),
            "applicability": result.applicability,
        },
    }


def build_mcp_server(library: RunbookLibrary) -> FastMCP:
    """MCP server exposing ``search_runbook`` — no other surface."""
    server: FastMCP = FastMCP("ops-guard-retrieval")

    @server.tool
    def search_runbook(
        question: str,
        limit: int = Field(default=5, ge=1),
    ) -> list[dict]:
        """Cited runbook guidance: every result identifies one exact verified
        passage (runbook id, revision, content hash, locator, verification
        metadata) bound to the operation it evidences."""
        return [_result_to_dict(result) for result in library.search(question, limit=limit)]

    return server
