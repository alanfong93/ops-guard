"""Runbook revisions and cited-passage evidence (issue #8; docs/runbook-format.md).

A runbook revision is immutable and human-verified. A citation qualifies as
required procedural evidence only when the revision parses to the canonical
shape, carries verification metadata, its content hash recomputes exactly
(a changed hash voids the citation), and the cited locator exists.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from ops_guard.errors import ProposalError
from ops_guard.invocation import canonicalize_json

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class MalformedRunbookError(ProposalError):
    """The document does not match the canonical revision shape."""


class UnverifiedRunbookError(ProposalError):
    """The revision carries no complete human-verification metadata."""


class TamperedRunbookError(ProposalError):
    """The stored content hash does not match the revision body."""


class UnknownPassageError(ProposalError):
    """The cited locator does not exist in the revision."""


def _aware(moment: datetime) -> datetime:
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("verified_at must be timezone-aware")
    return moment


def _require_str(document: Mapping, key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value.strip():
        raise MalformedRunbookError(f"{key} must be a non-blank string")
    return value


def _require_str_in(mapping: Mapping, key: str, where: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise MalformedRunbookError(f"{where}.{key} must be a non-blank string")
    return value


@dataclass(frozen=True)
class Passage:
    locator: str
    text: str


@dataclass(frozen=True)
class Verification:
    verifier: str
    verified_at: datetime
    applicability: str


@dataclass(frozen=True)
class RunbookRevision:
    runbook_id: str
    revision: str
    operation_action: str
    operation_target: str
    preconditions: tuple[dict, ...]
    passages: tuple[Passage, ...]
    verification: Verification
    content_hash: str
    body: dict

    def canonical_bytes(self) -> bytes:
        """JCS canonicalization of the literal stored document minus the
        content-hash key — exactly what the contract hashes."""
        return canonicalize_json(self.body)

    def expected_content_hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


def _parse_passages(raw: Any) -> tuple[Passage, ...]:
    if not isinstance(raw, list) or not raw:
        raise MalformedRunbookError("passages must be a non-empty list")
    passages = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, Mapping) or set(item) != {"locator", "text"}:
            raise MalformedRunbookError("each passage must have exactly locator and text")
        locator = _require_str_in(item, "locator", "passage")
        text = _require_str_in(item, "text", "passage")
        if locator in seen:
            raise MalformedRunbookError(f"duplicate passage locator {locator!r}")
        seen.add(locator)
        passages.append(Passage(locator=locator, text=text))
    return tuple(passages)


def _parse_preconditions(raw: Any) -> tuple[dict, ...]:
    if not isinstance(raw, list):
        raise MalformedRunbookError("preconditions must be a list")
    out = []
    for item in raw:
        if not isinstance(item, Mapping) or set(item) != {"name", "expected"}:
            raise MalformedRunbookError("each precondition must have exactly name and expected")
        out.append(
            {
                "name": _require_str_in(item, "name", "precondition"),
                "expected": _require_str_in(item, "expected", "precondition"),
            }
        )
    return tuple(out)


def _parse_verification(raw: Any) -> Verification:
    if not isinstance(raw, Mapping) or not set(raw) == {"verifier", "verified_at", "applicability"}:
        raise UnverifiedRunbookError(
            "verification must have exactly verifier, verified_at, applicability"
        )

    def verified_string(key: str) -> str:
        value = raw.get(key)
        if not isinstance(value, str) or not value.strip():
            raise UnverifiedRunbookError(f"verification.{key} must be a non-blank string")
        return value

    verifier = verified_string("verifier")
    applicability = verified_string("applicability")
    raw_when = raw.get("verified_at")
    if not isinstance(raw_when, str) or not raw_when:
        raise UnverifiedRunbookError("verification.verified_at must be a non-empty string")
    try:
        moment = datetime.fromisoformat(raw_when)
    except ValueError as error:
        raise UnverifiedRunbookError("verification.verified_at is not an ISO timestamp") from error
    try:
        _aware(moment)
    except ValueError as error:
        raise UnverifiedRunbookError(str(error)) from error
    return Verification(verifier=verifier, verified_at=moment, applicability=applicability)


def parse_revision(document: Mapping) -> RunbookRevision:
    """Parse and validate a revision document; content hash must recompute.

    The hash is over the **literal stored document** minus the content-hash
    key (JCS canonicalization): timestamp spelling and every other byte of
    semantic content is significant, exactly as docs/runbook-format.md
    specifies.
    """
    if not isinstance(document, Mapping):
        raise MalformedRunbookError("revision must be a JSON object")
    expected_keys = {
        "runbook_id", "revision", "operation", "preconditions",
        "passages", "verification", "content_hash",
    }
    if set(document) != expected_keys:
        missing = {"verification"} - set(document)
        if missing:
            raise UnverifiedRunbookError(
                "revision carries no verification metadata; it can never qualify"
            )
        raise MalformedRunbookError("revision keys do not match the canonical shape")
    operation = document.get("operation")
    if not isinstance(operation, Mapping) or set(operation) != {"action", "target"}:
        raise MalformedRunbookError("operation must have exactly action and target")
    content_hash = _require_str(document, "content_hash")
    if not _HEX64.fullmatch(content_hash):
        raise MalformedRunbookError("content_hash must be 64 hexadecimal characters")
    literal_body = {key: value for key, value in document.items() if key != "content_hash"}
    revision = RunbookRevision(
        runbook_id=_require_str(document, "runbook_id"),
        revision=_require_str(document, "revision"),
        operation_action=_require_str_in(operation, "action", "operation"),
        operation_target=_require_str_in(operation, "target", "operation"),
        preconditions=_parse_preconditions(document.get("preconditions")),
        passages=_parse_passages(document.get("passages")),
        verification=_parse_verification(document.get("verification")),
        content_hash=content_hash,
        body=literal_body,
    )
    if not hmac.compare_digest(revision.expected_content_hash(), content_hash):
        raise TamperedRunbookError("content hash does not match the revision body")
    return revision


@dataclass(frozen=True)
class Citation:
    runbook_id: str
    revision: str
    content_hash: str
    locator: str


@dataclass(frozen=True)
class CitedPassage:
    citation: Citation
    passage: Passage
    operation_action: str
    operation_target: str
    preconditions: tuple[dict, ...]
    verifier: str


def resolve_citation(document: Mapping, citation: Citation) -> CitedPassage:
    """All-or-nothing citation resolution (docs/runbook-format.md, Citations).

    Returns the cited passage bound to the operation and its preconditions —
    required procedural evidence — or raises a typed rejection.
    """
    if not isinstance(citation, Citation) or not all(
        isinstance(getattr(citation, field), str) and getattr(citation, field)
        for field in ("runbook_id", "revision", "content_hash", "locator")
    ):
        raise MalformedRunbookError("citation fields must be non-empty strings")
    revision = parse_revision(document)  # malformed / unverified / tampered
    if citation.content_hash != revision.content_hash:
        raise TamperedRunbookError(
            "citation is bound to a different revision content hash"
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
                preconditions=revision.preconditions,
                verifier=revision.verification.verifier,
            )
    raise UnknownPassageError(f"locator {citation.locator!r} does not exist in the revision")
