"""Operator-owned policy and trusted precondition observers (issue #62; ADR 0011).

The server loads one local, operator-owned JSON policy at startup:

- ``standing_authorizations`` — exact ``StandingAuthorization`` records
  (ADR 0004 semantics, parsed by the existing ``parse_authorization``).
- ``observer_bindings`` — maps one exact verified revision and zero-based
  precondition index to a fixed, code-defined read-only adapter id and its
  strictly typed settings. Runbooks and callers cannot select probes,
  endpoints, or credentials; adapters own their bounded I/O.

The whole document is validated strictly at startup (unknown fields,
duplicate/conflicting bindings, unknown adapters, invalid settings all fail
closed) and identified by the SHA-256 of its JCS-canonical form. The gate
resolves every precondition through this registry immediately before
authorization and refuses on any missing, unknown, timed-out, errored, or
mismatched observation — caller-supplied values can never influence the
result.
"""

from __future__ import annotations

import concurrent.futures
import copy
import hashlib
from types import MappingProxyType
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from ops_guard.authorization import StandingAuthorization, parse_authorization
from ops_guard.errors import ProposalError
from ops_guard.invocation import canonicalize_json

POLICY_SCHEMA_VERSION = "ops-guard-policy-v1"
OBSERVATION_DEADLINE_SECONDS = 30.0


class PolicyError(ProposalError):
    """The operator policy file is missing, malformed, or ambiguous."""


class ObserverError(ProposalError):
    """A trusted observation failed, timed out, or was malformed."""


def policy_digest(document: Mapping[str, Any]) -> str:
    """SHA-256 over the JCS-canonicalized policy document."""
    return hashlib.sha256(canonicalize_json(document)).hexdigest()


@dataclass(frozen=True)
class ObserverBinding:
    """One exact precondition → adapter mapping (ADR 0011)."""

    runbook_id: str
    revision: str
    content_hash: str
    precondition_index: int
    observer_id: str
    settings: Mapping[str, Any]

    def key(self) -> tuple[str, str, str, int]:
        return (self.runbook_id, self.revision, self.content_hash, self.precondition_index)


@dataclass(frozen=True)
class OperatorPolicy:
    """The validated, immutable startup policy."""

    digest: str
    standing: tuple[StandingAuthorization, ...]
    bindings: Mapping[tuple[str, str, str, int], ObserverBinding]


@dataclass(frozen=True)
class Observation:
    """The safe snapshot of one precondition observation."""

    observer_id: str
    observed_at: float
    value: str | None  # raw value never persisted; used for exact comparison only
    failure_code: str | None


Adapter = Callable[[Mapping[str, Any]], str]


class ObserverRegistry:
    """Fixed, code-defined read-only observers (ADR 0011).

    Adapters are registered in server code only; the policy selects among
    them by id and may supply only strictly typed settings. Each adapter
    owns its bounded I/O; the registry enforces the per-observation timeout
    at the adapter boundary (a timed-out worker is cancelled without
    waiting, its late result discarded, so it can never authorize) and a
    total observation deadline is available to the gate."""

    def __init__(self, *, deadline_seconds: float = OBSERVATION_DEADLINE_SECONDS) -> None:
        self._adapters: dict[
            str,
            tuple[
                Adapter,
                Callable[[Mapping[str, Any]], None],
                Callable[[Mapping[str, Any]], float],
            ],
        ] = {}
        self._deadline = deadline_seconds
        self._lock = threading.Lock()
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)

    @property
    def deadline_seconds(self) -> float:
        """The total observation deadline the gate enforces."""
        return self._deadline

    def register(
        self,
        observer_id: str,
        adapter: Adapter,
        settings_validator: Callable[[Mapping[str, Any]], None],
        timeout_getter: Callable[[Mapping[str, Any]], float] | None = None,
    ) -> None:
        with self._lock:
            if observer_id in self._adapters:
                raise PolicyError(f"observer {observer_id!r} is already registered")
            self._adapters[observer_id] = (
                adapter,
                settings_validator,
                timeout_getter or (lambda settings: OBSERVATION_DEADLINE_SECONDS),
            )

    def validate_settings(self, observer_id: str, settings: Mapping[str, Any]) -> None:
        try:
            _adapter, validator, _timeout = self._adapters[observer_id]
        except KeyError:
            raise PolicyError(
                f"unknown observer id {observer_id!r}: policy may only select registered adapters"
            ) from None
        validator(settings)

    def timeout_for(self, observer_id: str, settings: Mapping[str, Any]) -> float:
        """The adapter's own bounded per-observation timeout."""
        try:
            _adapter, _validator, timeout_getter = self._adapters[observer_id]
        except KeyError:
            raise ObserverError(f"observer {observer_id!r} is not registered") from None
        return float(timeout_getter(settings))

    def observe(
        self,
        observer_id: str,
        settings: Mapping[str, Any],
        *,
        timeout_seconds: float | None = None,
        observed_at: float | None = None,
    ) -> Observation:
        """One fresh observation through the named adapter.

        The adapter runs in a shared worker pool bounded by its own
        timeout; on timeout the worker is cancelled without waiting: the
        gate returns promptly and the late result is discarded (it can
        never authorize). ``observed_at`` lets the gate stamp the snapshot
        with the same injected clock the audit uses."""
        try:
            adapter, _validator, timeout_getter = self._adapters[observer_id]
        except KeyError:
            raise ObserverError(f"observer {observer_id!r} is not registered") from None
        effective_timeout = (
            timeout_seconds if timeout_seconds is not None else timeout_getter(settings)
        )
        started = time.monotonic()
        future = self._executor.submit(adapter, settings)
        try:
            value = future.result(timeout=effective_timeout)
        except concurrent.futures.TimeoutError:
            future.cancel()
            raise ObserverError(
                f"observer {observer_id!r} timed out after {effective_timeout}s"
            ) from None
        except ObserverError:
            raise
        except Exception as error:  # noqa: BLE001 - adapter failure is a typed refusal
            raise ObserverError(
                f"observer {observer_id!r} failed ({type(error).__name__})"
            ) from None
        if not isinstance(value, str) or not value:
            raise ObserverError(f"observer {observer_id!r} returned a malformed observation")
        if time.monotonic() - started > self._deadline:
            raise ObserverError("total observation deadline exceeded")
        return Observation(
            observer_id=observer_id,
            observed_at=observed_at if observed_at is not None else time.time(),
            value=value,
            failure_code=None,
        )


def _validate_timeout_seconds(settings: Mapping[str, Any]) -> None:
    if not isinstance(settings, Mapping) or set(settings) != {"timeout_seconds"}:
        raise PolicyError("docker_engine_running settings must be exactly {timeout_seconds}")
    value = settings["timeout_seconds"]
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 30:
        raise PolicyError("timeout_seconds must be an integer from 1 through 30")


def _docker_engine_running(settings: Mapping[str, Any]) -> str:
    """Fixed read-only probe: the Docker engine answers ``docker info``.

    The command is code-defined — settings carry only the bounded timeout.
    Returns 'running' when the engine responds, 'stopped' otherwise."""
    timeout = settings["timeout_seconds"]
    try:
        completed = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "stopped"
    if completed.returncode == 0 and completed.stdout.strip():
        return "running"
    return "stopped"


def default_registry() -> ObserverRegistry:
    """The server's fixed observer set (ADR 0011): code-defined adapters only."""
    registry = ObserverRegistry()
    registry.register(
        "docker_engine_running",
        _docker_engine_running,
        _validate_timeout_seconds,
        timeout_getter=lambda settings: float(settings["timeout_seconds"]),
    )
    return registry


def load_policy(document: Any, registry: ObserverRegistry) -> OperatorPolicy:
    """Strictly validate the operator policy document (fail closed).

    Unknown top-level fields, a wrong schema version, malformed
    authorization records, duplicate or conflicting bindings, unknown
    adapter ids, and invalid adapter settings are all rejections — nothing
    is silently ignored."""
    if not isinstance(document, Mapping):
        raise PolicyError("policy must be a JSON object")
    if set(document) != {"schema_version", "standing_authorizations", "observer_bindings"}:
        raise PolicyError("policy keys do not match the operator-policy schema")
    if document["schema_version"] != POLICY_SCHEMA_VERSION:
        raise PolicyError(
            f"policy schema_version must be {POLICY_SCHEMA_VERSION!r}"
        )
    standing_raw = document["standing_authorizations"]
    bindings_raw = document["observer_bindings"]
    if not isinstance(standing_raw, list) or not isinstance(bindings_raw, list):
        raise PolicyError("standing_authorizations and observer_bindings must be lists")

    standing: list[StandingAuthorization] = []
    for index, record in enumerate(standing_raw):
        try:
            standing.append(parse_authorization(record))
        except ProposalError as error:
            raise PolicyError(f"standing_authorizations[{index}]: {error}") from error

    bindings: dict[tuple[str, str, str, int], ObserverBinding] = {}
    for index, raw in enumerate(bindings_raw):
        if not isinstance(raw, Mapping):
            raise PolicyError(f"observer_bindings[{index}] must be an object")
        if set(raw) != {
            "runbook_id",
            "revision",
            "content_hash",
            "precondition_index",
            "observer_id",
            "settings",
        }:
            raise PolicyError(
                f"observer_bindings[{index}] keys do not match the binding schema"
            )
        for text_field in ("runbook_id", "revision", "content_hash", "observer_id"):
            if not isinstance(raw[text_field], str) or not raw[text_field]:
                raise PolicyError(f"observer_bindings[{index}].{text_field} must be a non-empty string")
        precondition_index = raw["precondition_index"]
        if not isinstance(precondition_index, int) or isinstance(precondition_index, bool) or precondition_index < 0:
            raise PolicyError(f"observer_bindings[{index}].precondition_index must be a non-negative integer")
        binding = ObserverBinding(
            runbook_id=raw["runbook_id"],
            revision=raw["revision"],
            content_hash=raw["content_hash"],
            precondition_index=precondition_index,
            observer_id=raw["observer_id"],
            settings=MappingProxyType(copy.deepcopy(dict(raw["settings"]))),
        )
        key = binding.key()
        if key in bindings:
            raise PolicyError(
                f"observer_bindings[{index}] duplicates the binding for "
                f"{binding.runbook_id}@{binding.revision}[{binding.precondition_index}]"
            )
        registry.validate_settings(binding.observer_id, dict(binding.settings))
        bindings[key] = binding

    return OperatorPolicy(
        digest=policy_digest(document),
        standing=tuple(standing),
        bindings=bindings,
    )


def load_policy_file(path: str, registry: ObserverRegistry) -> OperatorPolicy:
    """Read and validate the policy file; startup fails closed on any error."""
    import json
    import os

    if not os.path.isfile(path):
        raise PolicyError(f"policy file does not exist: {path}")
    def _reject_duplicate_keys(pairs):
        seen = {}
        for key, value in pairs:
            if key in seen:
                raise PolicyError(f"duplicate JSON key {key!r} in the policy file")
            seen[key] = value
        return seen

    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle, object_pairs_hook=_reject_duplicate_keys)
    except PolicyError:
        raise
    except (OSError, ValueError) as error:
        raise PolicyError(f"policy file is unreadable as JSON ({type(error).__name__})") from error
    return load_policy(document, registry)
