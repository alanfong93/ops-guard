"""Exact complete-invocation standing authorization (issue #13; ADR 0004).

A standing authorization declares the complete permitted invocation —
verified script identity (path and SHA-256), action, target, typed
arguments, preconditions, and the runbook revision content hash — as exact
literal values. Matching is all-or-nothing equality over canonical JSON
values (``1`` and ``1.0`` are the same value; precondition order is
significant). Missing or unequal fields never match; there are no wildcards,
prefixes, templates, defaults, or partial credit (ADR 0004).

Authorization records are operator-curated configuration: unauthenticated
data whose authority comes from the operator's control of the configuration
store, like runbook verification metadata.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

import json

from ops_guard.errors import ProposalError
from ops_guard.invocation import Invocation, canonicalize_json, ensure_json_representable

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

_FIELDS = (
    "script_path", "script_sha256", "action", "target",
    "arguments", "preconditions", "runbook_revision_hash",
)


class MalformedAuthorizationError(ProposalError):
    """The standing-authorization record is missing or invalid a field."""


@dataclass(frozen=True)
class StandingAuthorization:
    authorization_id: str
    script_path: str
    script_sha256: str
    action: str
    target: str
    arguments: Mapping[str, Any]
    preconditions: tuple[dict, ...]
    runbook_revision_hash: str

    def canonical_arguments(self) -> bytes:
        return canonicalize_json(dict(self.arguments))

    def canonical_preconditions(self) -> bytes:
        return canonicalize_json(list(self.preconditions))


@dataclass(frozen=True)
class ScriptIdentity:
    """The verified script the caller intends to execute (ADR 0004, rule 1)."""

    path: str
    sha256: str


@dataclass(frozen=True)
class MatchResult:
    matched: bool
    authorization_id: str
    reason: str


def parse_authorization(document: Mapping) -> StandingAuthorization:
    """Validate an operator-authored authorization record; malformed never matches."""
    if not isinstance(document, Mapping):
        raise MalformedAuthorizationError("authorization must be a JSON object")
    if set(document) != set(_FIELDS) | {"authorization_id"}:
        raise MalformedAuthorizationError(
            "authorization keys must be exactly authorization_id plus "
            + ", ".join(_FIELDS)
        )
    strings = {}
    for field in ("authorization_id", "script_path", "action", "target", "runbook_revision_hash"):
        value = document.get(field)
        if not isinstance(value, str) or not value.strip():
            raise MalformedAuthorizationError(f"{field} must be a non-blank string")
        strings[field] = value
    script_sha256 = document.get("script_sha256")
    if not isinstance(script_sha256, str) or not script_sha256.strip():
        raise MalformedAuthorizationError("script_sha256 must be a non-blank string")
    if not _HEX64.fullmatch(script_sha256):
        raise MalformedAuthorizationError("script_sha256 must be 64 hexadecimal characters")
    if not _HEX64.fullmatch(strings["runbook_revision_hash"]):
        raise MalformedAuthorizationError("runbook_revision_hash must be 64 hexadecimal characters")
    arguments = document.get("arguments")
    if not isinstance(arguments, Mapping):
        raise MalformedAuthorizationError("arguments must be a mapping")
    # One snapshot, deep-frozen through the canonical serialization: the
    # frozen values are validated and stored, so a hostile or mutating
    # Mapping cannot pass validation with different values than the record
    # will carry — including nested containers.
    arguments = document.get("arguments")
    if not isinstance(arguments, Mapping):
        raise MalformedAuthorizationError("arguments must be a mapping")
    arguments = dict(arguments)
    try:
        # Raw-side guard: a literal the freeze contract cannot represent
        # exactly (ADR 0004) is malformed, not silently rounded.
        ensure_json_representable(arguments)
        # Freeze, then validate exactly the frozen values that get stored —
        # a hostile dual-read container cannot pass validation with values
        # the record does not carry — and confirm the freeze is idempotent.
        arguments = json.loads(canonicalize_json(arguments))
        ensure_json_representable(arguments)
        canonicalize_json(arguments)
    except (TypeError, ValueError, AttributeError, UnicodeEncodeError,
            RecursionError, OverflowError) as error:
        raise MalformedAuthorizationError(
            f"arguments are not exactly representable: {error}"
        ) from error
    preconditions_raw = document.get("preconditions")
    if not isinstance(preconditions_raw, list):
        raise MalformedAuthorizationError("preconditions must be a list")
    preconditions = []
    for item in preconditions_raw:
        if not isinstance(item, Mapping) or set(item) != {"name", "expected"}:
            raise MalformedAuthorizationError(
                "each precondition must have exactly name and expected"
            )
        name, expected = item["name"], item["expected"]
        if not isinstance(name, str) or not name.strip():
            raise MalformedAuthorizationError("precondition.name must be a non-blank string")
        if not isinstance(expected, str) or not expected.strip():
            raise MalformedAuthorizationError("precondition.expected must be a non-blank string")
        preconditions.append({"name": name, "expected": expected})
    return StandingAuthorization(
        authorization_id=strings["authorization_id"],
        script_path=strings["script_path"],
        script_sha256=script_sha256,
        action=strings["action"],
        target=strings["target"],
        arguments=dict(arguments),
        preconditions=tuple(preconditions),
        runbook_revision_hash=strings["runbook_revision_hash"],
    )


def match(
    authorization: StandingAuthorization,
    invocation: Invocation,
    script: ScriptIdentity,
) -> MatchResult:
    """All-or-nothing equality between the declared permitted invocation and
    the frozen invocation plus the presented script identity (ADR 0004)."""
    if not isinstance(authorization, StandingAuthorization):
        raise MalformedAuthorizationError(
            "authorization must be a parsed StandingAuthorization (use parse_authorization)"
        )
    if not isinstance(script, ScriptIdentity):
        raise MalformedAuthorizationError("script identity required for matching")
    if not isinstance(invocation, Invocation):
        raise MalformedAuthorizationError("an invocation is required for matching")

    try:
        arguments_equal = (
            canonicalize_json(dict(invocation.arguments))
            == authorization.canonical_arguments()
        )
        preconditions_equal = (
            canonicalize_json(list(invocation.preconditions))
            == authorization.canonical_preconditions()
        )
    except (TypeError, ValueError, AttributeError, UnicodeEncodeError,
            RecursionError, OverflowError) as error:
        # ADR 0004 rule 2: the match reports matched or not. A side that
        # cannot be canonicalized under the freeze contract never matches.
        return MatchResult(
            matched=False,
            authorization_id=authorization.authorization_id,
            reason=f"canonicalization failed on one side: {error}",
        )
    checks = (
        ("script_path", script.path == authorization.script_path),
        ("script_sha256", hmac_eq(script.sha256, authorization.script_sha256)),
        ("action", invocation.action == authorization.action),
        ("target", invocation.target == authorization.target),
        ("arguments", arguments_equal),
        ("preconditions", preconditions_equal),
        (
            "runbook_revision_hash",
            hmac_eq(invocation.runbook_revision_hash, authorization.runbook_revision_hash),
        ),
    )
    for field, equal in checks:
        if not equal:
            return MatchResult(
                matched=False,
                authorization_id=authorization.authorization_id,
                reason=f"{field} differs from the permitted invocation",
            )
    return MatchResult(
        matched=True,
        authorization_id=authorization.authorization_id,
        reason="exact complete-invocation match",
    )


def hmac_eq(left: str, right: str) -> bool:
    import hmac

    try:
        return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
    except (AttributeError, UnicodeEncodeError):
        return False
