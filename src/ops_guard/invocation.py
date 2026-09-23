"""Canonical invocation identity (ADR 0002, rule 1).

The complete invocation is serialized with JCS (RFC 8785) and identified by
the SHA-256 digest of the canonical bytes. Any difference in any bound field
yields a different identity. Sequence order inside the invocation is
significant; callers must sort unordered collections before freezing.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

import jcs

_INVOCATION_KEYS = frozenset(
    {"action", "target", "arguments", "preconditions", "runbook_revision_hash"}
)


@dataclass(frozen=True)
class Invocation:
    """A complete invocation bound into a frozen proposal."""

    action: str
    target: str
    arguments: Mapping[str, Any]
    preconditions: Sequence[Mapping[str, Any]]
    runbook_revision_hash: str

    def __post_init__(self) -> None:
        for name in ("action", "target", "runbook_revision_hash"):
            if not isinstance(getattr(self, name), str):
                raise TypeError(f"{name} must be a string")

    def to_json(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "target": self.target,
            "arguments": dict(self.arguments),
            "preconditions": list(self.preconditions),
            "runbook_revision_hash": self.runbook_revision_hash,
        }

    def canonical_bytes(self) -> bytes:
        """RFC 8785 (JCS) canonical serialization of the complete invocation.

        This is the freeze boundary. The bytes must round-trip: re-parsing
        them must yield a value that passes the numeric-domain guard and
        re-canonicalizes byte-identically. A value whose serialization cannot
        survive that cycle (e.g. large doubles whose ES6 digit-padding
        re-parses to a non-representable integer) is rejected here rather
        than being frozen into a proposal that consumers could never
        re-verify — encode such values as strings.
        """
        value = self.to_json()
        try:
            _reject_unrepresentable_numbers(value)
            frozen = canonicalize_json(value)
            reparsed = json.loads(frozen)
        except (AttributeError, TypeError, UnicodeEncodeError, RecursionError) as error:
            raise ValueError(
                "invocation contains values that are not JSON-representable "
                f"({type(error).__name__}: {error}); mapping keys must be strings "
                "and nesting must stay within reasonable depth"
            ) from error
        try:
            _reject_unrepresentable_numbers(reparsed)
            if canonicalize_json(reparsed) != frozen:
                raise ValueError(
                    "invocation does not round-trip canonical serialization; "
                    "encode the affected values as strings"
                )
        except RecursionError as error:
            raise ValueError(
                "invocation nesting is too deep to re-verify; flatten it"
            ) from error
        return frozen

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_frozen_json(cls, payload: Mapping[str, Any]) -> "Invocation":
        """Rebuild an invocation from previously frozen canonical bytes."""
        if not isinstance(payload, Mapping) or set(payload) != _INVOCATION_KEYS:
            raise ValueError("frozen payload does not match the invocation shape")
        return cls(
            action=payload["action"],
            target=payload["target"],
            arguments=payload["arguments"],
            preconditions=payload["preconditions"],
            runbook_revision_hash=payload["runbook_revision_hash"],
        )


def canonicalize_json(value: Any) -> bytes:
    """JCS-canonicalize a JSON-compatible value; raises on non-serializable input.

    Pure canonicalization: no argument-domain validation. The freeze boundary
    (``Invocation.canonical_bytes``) rejects integer arguments that would lose
    precision as IEEE-754 doubles.
    """
    return jcs.canonicalize(value)


def _reject_unrepresentable_numbers(value: Any) -> None:
    if isinstance(value, dict):
        for item in value.values():
            _reject_unrepresentable_numbers(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_unrepresentable_numbers(item)
    elif isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 2**53 and float(value) != value:
            raise ValueError(
                f"integer {value} is not exactly representable as an IEEE-754 "
                "double; encode it as a string or it could collide with another invocation"
            )


def digest_bytes(canonical: bytes) -> str:
    return hashlib.sha256(canonical).hexdigest()


def parse_frozen_invocation(raw: bytes) -> Invocation:
    """Parse stored canonical bytes back into an Invocation."""
    return Invocation.from_frozen_json(json.loads(raw))
