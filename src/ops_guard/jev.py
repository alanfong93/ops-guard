"""The opt-in native hosted Jev advisory (issue #91; ADR 0014).

One internal module owns the whole hosted path: the operator egress
policy, the approved-field projection, the native wire serializer, the
bounded HTTPS transport, the strict native response parser, the sample
aggregator, the closed audit projection, and the serving fingerprint.
``propose_fix`` and the audit transaction are untouched — the tool calls
``judge.evaluate_risk(judge_state(...))`` exactly as before; only the
judge object behind that call changes when the operator opts in with
``OPS_GUARD_JUDGE_BACKEND=jev``.

The disclosure boundary is exact records, never scrubbing: an operator
policy (``ops-guard-jev-egress-v1``) grants one profile per complete
invocation hash plus citation tuple, partitioning the invocation's
terminal leaves into explicitly approved values and explicitly reasoned
omissions. Anything unsupported — missing or ambiguous profile, changed
invocation, unknown leaf, mismatched value, drifted passage, oversized
request — is ``judge_input_rejected`` before any byte leaves the process.
The outbound state (``ops-guard-jev-state-v1``) is reconstructed from
approved values only; omitted values, keys, reasons, citations, tokens
and audit data never enter it.

Native transport talks HTTPS only, to an exact operator allowlist, with
certificate verification, no proxies, no redirects, no retries, a 64 KiB
request/response cap, and three sequential samples under a total
monotonic 10-second deadline each; the first failed sample stops the
assessment. Native confidence and probabilities are validated and then
dropped — never voted with, persisted, or exposed.

The only output is the closed ``ops-guard-jev-projection-v1`` snapshot
with the same six failure codes as the local judge. Raw state, passages,
native outputs, credentials, confidence, and arbitrary error text never
cross into runtime audit.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping

from ops_guard.invocation import Invocation, canonicalize_json
from ops_guard.judge import MENU, PROMPT_VERSION, RUBRIC_VERSION, risk_question

JEV_MODEL = "jev-1.13.0"
JEV_PROVIDER = "typesafe"
JEV_SAMPLE_COUNT = 3
JEV_TIMEOUT_MS = 10000
REQUEST_CAP_BYTES = 64 * 1024
RESPONSE_CAP_BYTES = 64 * 1024
POLICY_CAP_BYTES = 1024 * 1024
POLICY_MAX_PROFILES = 256

JEV_STATE_SCHEMA_VERSION = "ops-guard-jev-state-v1"
JEV_EGRESS_POLICY_SCHEMA = "ops-guard-jev-egress-v1"
JEV_PROJECTION_SCHEMA_VERSION = "ops-guard-jev-projection-v1"
ADAPTER_VERSION = "ops-guard-jev-adapter-v1"
PARSER_VERSION = "ops-guard-jev-parser-v1"
AGGREGATION_VERSION = "ops-guard-jev-aggregation-v1"

RISK_QUESTION_ID = "risk_class"
COMPANION_QUESTION_IDS = ("companion_safety", "companion_scope")
ALLOWED_QUESTION_IDS = frozenset({RISK_QUESTION_ID, *COMPANION_QUESTION_IDS})

# The six closed failure codes (ADR 0009/0014).
INPUT_REJECTED = "judge_input_rejected"
JUDGE_TIMEOUT = "judge_timeout"
JUDGE_UNAVAILABLE = "judge_unavailable"
INVALID_OUTPUT = "judge_invalid_output"
JUDGE_INABILITY = "judge_inability"
JUDGE_ERROR = "judge_error"

_PROFILE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

_CITATION_FIELDS = ("runbook_id", "revision", "content_hash", "locator")


class JevConfigError(ValueError):
    """The enabled hosted-judge configuration is missing, empty, or invalid.

    Messages name the environment variable, never its value."""


class EgressPolicyError(ValueError):
    """The operator egress policy file violates the closed schema."""


class NativeResponseError(ValueError):
    """A native response violated the closed wire contract."""


# --------------------------------------------------------------------------
# Endpoint identity
# --------------------------------------------------------------------------


def endpoint_identity(raw: str) -> str:
    """The canonical HTTPS endpoint identity: scheme, lowercase hostname,
    effective port, exact path (ADR 0014).

    Returns ``https://host:port/path``; rejects userinfo, query, fragment,
    empty hostnames, malformed ports, and any control or whitespace
    character anywhere in the URL. The identity is the allowlist unit and
    the only endpoint field recorded in runtime audit."""
    if not isinstance(raw, str) or not raw:
        raise JevConfigError("endpoint must be a non-empty URL string")
    if any(ch.isspace() or ord(ch) < 0x21 or ord(ch) == 0x7F for ch in raw):
        raise JevConfigError("endpoint must not contain whitespace or control characters")
    parts = urllib.request.urlsplit(raw)
    if parts.scheme != "https":
        raise JevConfigError("endpoint scheme must be https")
    if parts.username is not None or parts.password is not None:
        raise JevConfigError("endpoint must not carry userinfo")
    if parts.query or parts.fragment:
        raise JevConfigError("endpoint must not carry a query or fragment")
    hostname = parts.hostname
    if not hostname:
        raise JevConfigError("endpoint hostname must be non-empty")
    try:
        port = parts.port if parts.port is not None else 443
    except ValueError as error:
        raise JevConfigError("endpoint port is malformed") from error
    if not 1 <= port <= 65535:
        raise JevConfigError("endpoint port must be between 1 and 65535")
    path = parts.path or "/"
    if not path.startswith("/"):
        raise JevConfigError("endpoint path must be empty or start with /")
    host = f"[{hostname}]" if ":" in hostname else hostname
    return f"https://{host}:{port}{path}"


# --------------------------------------------------------------------------
# Operator configuration
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class JevConfig:
    """The loaded hosted-mode configuration; secrets stay in the caller's
    process and never enter snapshots or logs."""

    endpoint: str
    allowed_endpoints: tuple[str, ...]
    bearer_token: str
    policy: "EgressPolicy"


def _env_value(environ: Mapping[str, str], name: str) -> str:
    value = environ.get(name)
    if value is None or not value.strip():
        raise JevConfigError(f"{name} must be set to a non-blank value when the jev backend is enabled")
    return value.strip()


def load_jev_config(environ: Mapping[str, str]) -> JevConfig:
    """Load and validate the hosted configuration once, at startup (ADR 0014).

    Every failure names the offending variable, never its value. The
    serving endpoint must appear on the independently configured exact
    allowlist, and the egress policy must parse under the closed schema."""
    raw_endpoint = _env_value(environ, "OPS_GUARD_JEV_ENDPOINT")
    endpoint = endpoint_identity(raw_endpoint)
    allowed_raw = _env_value(environ, "OPS_GUARD_JEV_ALLOWED_ENDPOINTS")
    allowed: list[str] = []
    for entry in allowed_raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        identity = endpoint_identity(entry)
        if identity not in allowed:
            allowed.append(identity)
    if not allowed:
        raise JevConfigError(
            "OPS_GUARD_JEV_ALLOWED_ENDPOINTS must contain at least one exact https endpoint identity"
        )
    if endpoint not in allowed:
        raise JevConfigError(
            "OPS_GUARD_JEV_ENDPOINT must exactly match one OPS_GUARD_JEV_ALLOWED_ENDPOINTS entry"
        )
    token = _env_value(environ, "OPS_GUARD_JEV_BEARER_TOKEN")
    if len(token) < 32:
        raise JevConfigError(
            "OPS_GUARD_JEV_BEARER_TOKEN must be at least 32 characters (32 random bytes)"
        )
    policy_path = _env_value(environ, "OPS_GUARD_JEV_EGRESS_POLICY_FILE")
    try:
        with open(policy_path, "rb") as handle:
            policy_bytes = handle.read()
    except OSError as error:
        raise JevConfigError(
            f"OPS_GUARD_JEV_EGRESS_POLICY_FILE must be a readable file ({type(error).__name__})"
        ) from error
    try:
        policy = parse_egress_policy(policy_bytes)
    except EgressPolicyError as error:
        raise JevConfigError(f"OPS_GUARD_JEV_EGRESS_POLICY_FILE: {error}") from error
    return JevConfig(
        endpoint=endpoint,
        allowed_endpoints=tuple(allowed),
        bearer_token=token,
        policy=policy,
    )


# --------------------------------------------------------------------------
# Egress policy: closed exact-record disclosure grants
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class DisclosureGrant:
    """One operator disclosure profile: exactly which invocation leaves may
    egress, and which are omitted with an explicit reason."""

    profile_id: str
    invocation_sha256: str
    citation: Mapping[str, str]
    passage_sha256: str
    approved: Mapping[str, Any]
    omitted: Mapping[str, str]

    @property
    def citation_tuple(self) -> tuple[str, str, str, str]:
        return tuple(self.citation[field] for field in _CITATION_FIELDS)


@dataclass(frozen=True)
class EgressPolicy:
    """The parsed policy; ``sha256`` covers the exact file bytes."""

    grants: tuple[DisclosureGrant, ...]
    sha256: str

    def select(self, invocation_sha256: str, citation: tuple[str, str, str, str]) -> DisclosureGrant | None:
        """The unique grant for an exact complete-invocation hash and exact
        citation tuple; zero or multiple matches select nothing."""
        matches = [
            grant
            for grant in self.grants
            if grant.invocation_sha256 == invocation_sha256 and grant.citation_tuple == citation
        ]
        return matches[0] if len(matches) == 1 else None


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise EgressPolicyError(f"duplicate JSON key: {key!r}")
        out[key] = value
    return out


def _reject_json_constant(name: str):
    raise EgressPolicyError(f"nonfinite JSON constant not allowed: {name}")


def _reject_nonfinite(value: Any) -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        raise EgressPolicyError("nonfinite numbers are not allowed")
    if isinstance(value, dict):
        for item in value.values():
            _reject_nonfinite(item)
    elif isinstance(value, list):
        for item in value:
            _reject_nonfinite(item)


def parse_pointer(pointer: str) -> tuple[str, ...]:
    """Validate a canonical RFC 6901 pointer and return its unescaped tokens.

    Root pointers are rejected (a grant never covers the whole invocation);
    ``~`` must always escape as ``~0`` or ``~1``."""
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise EgressPolicyError(f"pointer must be a non-root RFC 6901 path: {pointer!r}")
    tokens: list[str] = []
    for raw in pointer.split("/")[1:]:
        token = ""
        index = 0
        while index < len(raw):
            ch = raw[index]
            if ch == "~":
                if index + 1 >= len(raw) or raw[index + 1] not in "01":
                    raise EgressPolicyError(f"invalid ~ escape in pointer: {pointer!r}")
                token += "~" if raw[index + 1] == "0" else "/"
                index += 2
            else:
                token += ch
                index += 1
        tokens.append(token)
    return tuple(tokens)


def _reject_pointer_conflicts(pointers) -> None:
    """Duplicate paths and ancestor conflicts are both ambiguous partitions."""
    seen: list[tuple[str, ...]] = []
    for pointer in pointers:
        tokens = parse_pointer(pointer)
        for other in seen:
            # Symmetric ancestor check: whichever pointer came first, one
            # must not be a strict segment-boundary prefix of the other.
            if tokens == other or other[: len(tokens)] == tokens or tokens[: len(other)] == other:
                raise EgressPolicyError(
                    f"pointer {pointer!r} duplicates or nests under an existing pointer"
                )
        seen.append(tokens)


def _require_exact_keys(obj: Mapping, expected: set[str], what: str) -> None:
    if not isinstance(obj, Mapping):
        raise EgressPolicyError(f"{what} must be a JSON object")
    keys = set(obj)
    if keys != expected:
        missing = sorted(expected - keys)
        unknown = sorted(keys - expected)
        raise EgressPolicyError(
            f"{what} has wrong keys (missing={missing}, unknown={unknown})"
        )


def _parse_grant(raw: Any, index: int) -> DisclosureGrant:
    what = f"profile[{index}]"
    _require_exact_keys(
        raw,
        {"profile_id", "invocation_sha256", "citation", "passage_sha256", "approved_leaves", "omitted_leaves"},
        what,
    )
    profile_id = raw["profile_id"]
    if not isinstance(profile_id, str) or not _PROFILE_ID_RE.fullmatch(profile_id):
        raise EgressPolicyError(f"{what}.profile_id must match [A-Za-z0-9_-]{{1,64}}")
    for field in ("invocation_sha256", "passage_sha256"):
        value = raw[field]
        if not isinstance(value, str) or not _HEX64_RE.fullmatch(value):
            raise EgressPolicyError(f"{what}.{field} must be lowercase 64-hex")
    citation = raw["citation"]
    _require_exact_keys(citation, set(_CITATION_FIELDS), f"{what}.citation")
    for field in _CITATION_FIELDS:
        if not isinstance(citation[field], str) or not citation[field]:
            raise EgressPolicyError(f"{what}.citation.{field} must be a non-empty string")
    approved = _parse_leaf_records(raw["approved_leaves"], f"{what}.approved_leaves", with_value=True)
    omitted = _parse_leaf_records(raw["omitted_leaves"], f"{what}.omitted_leaves", with_value=False)
    _reject_pointer_conflicts(list(approved) + list(omitted))
    return DisclosureGrant(
        profile_id=profile_id,
        invocation_sha256=raw["invocation_sha256"],
        citation=dict(citation),
        passage_sha256=raw["passage_sha256"],
        approved=approved,
        omitted=omitted,
    )


def _parse_leaf_records(raw: Any, what: str, *, with_value: bool) -> dict:
    if not isinstance(raw, list):
        raise EgressPolicyError(f"{what} must be an array")
    out: dict = {}
    for record in raw:
        expected = {"pointer", "value"} if with_value else {"pointer", "reason"}
        _require_exact_keys(record, expected, what)
        pointer = record["pointer"]
        if not isinstance(pointer, str):
            raise EgressPolicyError(f"{what}.pointer must be a string")
        if pointer in out:
            raise EgressPolicyError(f"{what} repeats pointer {pointer!r}")
        if with_value:
            out[pointer] = record["value"]
        else:
            reason = record["reason"]
            if not isinstance(reason, str) or not reason.strip():
                raise EgressPolicyError(f"{what}.reason must be a non-blank string")
            if len(reason) > 256:
                raise EgressPolicyError(f"{what}.reason must be at most 256 characters")
            out[pointer] = reason
    return out


def parse_egress_policy(raw_bytes: bytes) -> EgressPolicy:
    """Parse the closed ``ops-guard-jev-egress-v1`` policy document.

    An empty ``profiles`` array is valid and deny-all. Caps: 1 MiB of
    policy bytes, 256 profiles. Duplicate JSON keys, profile ids, selector
    pairs, unknown keys, nonfinite numbers, and invalid pointers are all
    rejected."""
    if len(raw_bytes) > POLICY_CAP_BYTES:
        raise EgressPolicyError(f"policy exceeds the {POLICY_CAP_BYTES}-byte cap")
    try:
        document = json.loads(
            raw_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError) as error:
        if isinstance(error, EgressPolicyError):
            raise
        raise EgressPolicyError(f"policy is not valid strict JSON ({type(error).__name__})") from error
    _require_exact_keys(document, {"schema_version", "profiles"}, "policy")
    if document["schema_version"] != JEV_EGRESS_POLICY_SCHEMA:
        raise EgressPolicyError(
            f"policy schema_version must be {JEV_EGRESS_POLICY_SCHEMA!r}"
        )
    profiles = document["profiles"]
    if not isinstance(profiles, list):
        raise EgressPolicyError("policy profiles must be an array")
    if len(profiles) > POLICY_MAX_PROFILES:
        raise EgressPolicyError(f"policy exceeds the {POLICY_MAX_PROFILES}-profile cap")
    grants = tuple(_parse_grant(profile, index) for index, profile in enumerate(profiles))
    ids = [grant.profile_id for grant in grants]
    if len(set(ids)) != len(ids):
        raise EgressPolicyError("duplicate profile_id in policy")
    selectors = [(grant.invocation_sha256, grant.citation_tuple) for grant in grants]
    if len(set(selectors)) != len(selectors):
        raise EgressPolicyError("duplicate (invocation_sha256, citation) selector pair in policy")
    return EgressPolicy(grants=grants, sha256=hashlib.sha256(raw_bytes).hexdigest())


# --------------------------------------------------------------------------
# Terminal-leaf partition of the invocation
# --------------------------------------------------------------------------


def _is_terminal(value: Any) -> bool:
    """A terminal is a scalar string/bool/null/finite JSON number or an
    empty object/array (ADR 0014)."""
    if value is None or isinstance(value, (str, bool)):
        return True
    if isinstance(value, float):
        return value == value and value not in (float("inf"), float("-inf"))
    if isinstance(value, int):
        return True
    if isinstance(value, dict):
        return len(value) == 0
    if isinstance(value, list):
        return len(value) == 0
    return False


def terminal_leaves(value: Any, tokens: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], Any]]:
    """Enumerate the invocation's terminal leaves as ``(tokens, value)``
    pairs with canonical zero-based array indices (RFC 6901)."""
    if _is_terminal(value):
        return [(tokens, value)]
    out: list[tuple[tuple[str, ...], Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            out.extend(terminal_leaves(item, tokens + (str(key),)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            out.extend(terminal_leaves(item, tokens + (str(index),)))
    else:
        raise EgressPolicyError(f"unsupported invocation value at /{'/'.join(tokens)}")
    return out


def _tokens_to_pointer(tokens: tuple[str, ...]) -> str:
    return "/" + "/".join(token.replace("~", "~0").replace("/", "~1") for token in tokens)


def _json_equal(left: Any, right: Any) -> bool:
    """Canonical, type-aware JSON equality: ``true`` is not ``1``; numbers
    compare numerically; objects compare as unordered exact-key maps;
    arrays compare in order."""
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, str) or isinstance(right, str):
        return isinstance(left, str) and isinstance(right, str) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if isinstance(left, dict) and isinstance(right, dict):
        return set(left) == set(right) and all(_json_equal(left[k], right[k]) for k in left)
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(_json_equal(a, b) for a, b in zip(left, right))
    return False


class PartitionError(ValueError):
    """The grant does not partition this invocation exactly (ADR 0014)."""


def validate_partition(invocation_json: Mapping[str, Any], grant: DisclosureGrant) -> dict[str, Any]:
    """Check the grant partitions this invocation exactly; return the
    approved values keyed by unescaped token path.

    Rejections (all ``judge_input_rejected`` at the judge boundary):
    unknown leaves, missing leaves, mismatched approved values, partial
    arrays, non-uniform array approval/omission, approved or absent
    ``runbook_revision_hash``, and unapproved action/target/precondition
    leaves."""
    leaves = terminal_leaves(dict(invocation_json))
    leaf_values = {_tokens_to_pointer(tokens): value for tokens, value in leaves}
    if len(leaf_values) != len(leaves):
        raise PartitionError("pointer emission collided; keys must not escape ambiguously")
    approved_pointers = set(grant.approved)
    omitted_pointers = set(grant.omitted)
    if approved_pointers & omitted_pointers:
        raise PartitionError("a pointer appears in both approved_leaves and omitted_leaves")
    unknown = (approved_pointers | omitted_pointers) - set(leaf_values)
    if unknown:
        raise PartitionError(f"grant names unknown invocation leaves: {sorted(unknown)[:3]}")
    missing = set(leaf_values) - (approved_pointers | omitted_pointers)
    if missing:
        raise PartitionError(f"grant does not cover invocation leaves: {sorted(missing)[:3]}")
    for pointer, value in grant.approved.items():
        if not _json_equal(leaf_values[pointer], value):
            raise PartitionError(f"approved value at {pointer} does not equal the invocation leaf")
    # Nonempty arrays are all-or-nothing: every terminal descendant of each
    # nonempty array must sit on the same side (nested arrays propagate the
    # constraint upward — a mixed inner array fails the outer one too).
    stack = [((token,), item) for token, item in dict(invocation_json).items()]
    while stack:
        tokens, node = stack.pop()
        if isinstance(node, dict) and node:
            stack.extend((tokens + (str(key),), item) for key, item in node.items())
        elif isinstance(node, list) and node:
            prefix = _tokens_to_pointer(tokens)
            sides = {
                pointer in approved_pointers
                for pointer in leaf_values
                if pointer.startswith(prefix + "/")
            }
            if len(sides) > 1:
                raise PartitionError(
                    f"nonempty array at {prefix} mixes approved and omitted descendants"
                )
            stack.extend((tokens + (str(index),), item) for index, item in enumerate(node))
    for required in ("/action", "/target"):
        if required not in approved_pointers:
            raise PartitionError(f"{required} must be approved")
    precondition_leaves = [
        pointer
        for pointer in leaf_values
        if pointer == "/preconditions" or pointer.startswith("/preconditions/")
    ]
    if any(pointer not in approved_pointers for pointer in precondition_leaves):
        raise PartitionError("every precondition leaf must be approved")
    if "/runbook_revision_hash" in approved_pointers:
        raise PartitionError("runbook_revision_hash must never be approved for egress")
    if "/runbook_revision_hash" not in omitted_pointers:
        raise PartitionError("runbook_revision_hash must be explicitly omitted")
    return {parse_pointer(pointer): value for pointer, value in grant.approved.items()}


_DROP = object()


def _prune_to_approved(
    value: Any,
    tokens: tuple[str, ...],
    approved_pointers: set[str],
    leaf_values: Mapping[str, Any],
):
    """Copy the invocation keeping only approved leaves; dropped branches
    disappear entirely (omitted keys never appear in the outbound state).

    Source values are used: the partition check already proved each grant
    value equals its source leaf under canonical type-aware equality, and
    the source is the freeze-boundary authority."""
    pointer = _tokens_to_pointer(tokens)
    if pointer in approved_pointers:
        return leaf_values[pointer]
    if isinstance(value, dict) and value:
        out = {}
        for key, item in value.items():
            pruned = _prune_to_approved(item, tokens + (str(key),), approved_pointers, leaf_values)
            if pruned is not _DROP:
                out[key] = pruned
        return out if out else _DROP
    if isinstance(value, list) and value:
        out = []
        for index, item in enumerate(value):
            pruned = _prune_to_approved(item, tokens + (str(index),), approved_pointers, leaf_values)
            if pruned is not _DROP:
                out.append(pruned)
        return out if out else _DROP
    return _DROP


def project_jev_state(
    *,
    invocation_json: Mapping[str, Any],
    passage_text: str,
    grant: DisclosureGrant,
) -> dict:
    """Build ``ops-guard-jev-state-v1`` from approved values only (ADR 0014).

    The outbound shape is fixed: ``action``/``target`` scalars, the
    ``arguments`` object (the empty object is the structural constant when
    every argument leaf is omitted), the fully approved ``preconditions``
    array, and the exact approved passage text. Omitted values and keys,
    omission reasons, citation identifiers, hashes, tokens, and audit data
    never enter the state."""
    leaves = terminal_leaves(dict(invocation_json))
    leaf_values = {_tokens_to_pointer(tokens): value for tokens, value in leaves}
    approved = validate_partition(invocation_json, grant)
    pruned = _prune_to_approved(
        dict(invocation_json), (), set(grant.approved), leaf_values
    )
    if not isinstance(pruned, dict):
        raise PartitionError("projection did not yield the invocation object shape")
    return {
        "schema_version": JEV_STATE_SCHEMA_VERSION,
        "invocation": {
            "action": pruned["action"],
            "target": pruned["target"],
            "arguments": pruned.get("arguments", {}),
            "preconditions": pruned.get("preconditions", []),
        },
        "evidence": {"passage_text": passage_text},
    }


def serialize_exact(value: Any) -> bytes:
    """The one wire serialization (ADR 0014): compact separators, UTF-8,
    no ASCII escaping, dictionary order preserved, nonfinite rejected.
    These exact bytes feed the request cap, the audit HMACs, and every
    attempted sample."""
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def native_request_bytes(state: Mapping[str, Any], question_ids: list[str]) -> bytes:
    """The closed native request: exactly ``model``, ``state``, and
    ``questions`` — no inference overrides, no other fields."""
    body = {
        "model": JEV_MODEL,
        "state": state,
        "questions": {question_id: risk_question() for question_id in question_ids},
    }
    return serialize_exact(body)


# --------------------------------------------------------------------------
# Bounded native transport
# --------------------------------------------------------------------------


class TransportFailure(Exception):
    """One sample failed at the transport boundary; ``failure_code`` is one
    of the closed judge codes. No exception text ever escapes this module."""

    def __init__(self, failure_code: str) -> None:
        super().__init__(failure_code)
        self.failure_code = failure_code


_JEV_USER_AGENT = "ops-guard-jev/1.0"
_READ_CHUNK = 8192


class JevTransport:
    """One HTTPS POST per sample over raw ``http.client``: direct connection
    (environment proxies are never consulted), normal certificate
    verification, and no redirect logic at all — a 3xx is just a non-200
    status. Each sample runs under a total monotonic deadline covering the
    write, the response headers, and bounded incremental reads, so a
    slow-drip body cannot extend it. Credentials are attached only to the
    configured endpoint, which must sit on the operator allowlist."""

    def __init__(
        self,
        *,
        endpoint: str,
        allowed_endpoints: tuple[str, ...],
        bearer_token: str,
        timeout_ms: int = JEV_TIMEOUT_MS,
        response_cap_bytes: int = RESPONSE_CAP_BYTES,
        connection_factory=None,
    ) -> None:
        self._endpoint = endpoint_identity(endpoint)
        if self._endpoint not in allowed_endpoints:
            raise JevConfigError("transport endpoint must appear on the exact allowlist")
        self._token = bearer_token
        self._timeout_ms = timeout_ms
        self._response_cap = response_cap_bytes
        self._connection_factory = connection_factory or self._connect

    @staticmethod
    def _connect(host: str, port: int, timeout: float):
        import http.client
        import ssl

        return http.client.HTTPSConnection(
            host, port, timeout=timeout, context=ssl.create_default_context()
        )

    def post_sample(self, body: bytes) -> bytes:
        """Send one sample and return the response body bytes.

        Raises ``TransportFailure`` with ``judge_timeout`` (total deadline
        exceeded), ``judge_unavailable`` (TLS/transport/HTTP/provider
        failure, non-200 status, oversized body), or ``judge_input_rejected``
        (an oversized request can never be sent)."""
        import http.client
        import ssl

        if len(body) > REQUEST_CAP_BYTES:
            raise TransportFailure(INPUT_REJECTED)
        deadline = time.monotonic() + self._timeout_ms / 1000.0
        parts = urllib.request.urlsplit(self._endpoint)
        connection = None
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransportFailure(JUDGE_TIMEOUT)
            connection = self._connection_factory(parts.hostname, parts.port, remaining)
            connection.putrequest("POST", parts.path, skip_accept_encoding=True)
            connection.putheader("Authorization", f"Bearer {self._token}")
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", str(len(body)))
            connection.putheader("User-Agent", _JEV_USER_AGENT)
            connection.endheaders(message_body=body)
            response = connection.getresponse()
            if response.status != 200:
                raise TransportFailure(JUDGE_UNAVAILABLE)
            chunks: list[bytes] = []
            total = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TransportFailure(JUDGE_TIMEOUT)
                if connection.sock is not None:
                    connection.sock.settimeout(remaining)
                try:
                    chunk = response.read(_READ_CHUNK)
                except TimeoutError:
                    raise TransportFailure(JUDGE_TIMEOUT) from None
                except (OSError, http.client.HTTPException, ssl.SSLError):
                    raise TransportFailure(JUDGE_UNAVAILABLE) from None
                if not chunk:
                    break
                total += len(chunk)
                if total > self._response_cap:
                    raise TransportFailure(JUDGE_UNAVAILABLE)
                chunks.append(chunk)
            return b"".join(chunks)
        except TransportFailure:
            raise
        except TimeoutError:
            raise TransportFailure(JUDGE_TIMEOUT) from None
        except (OSError, http.client.HTTPException, ssl.SSLError):
            raise TransportFailure(JUDGE_UNAVAILABLE) from None
        finally:
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass


# --------------------------------------------------------------------------
# Strict native response parser
# --------------------------------------------------------------------------


def _response_duplicate_keys(pairs):
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise NativeResponseError(f"duplicate JSON key in native response: {key!r}")
        out[key] = value
    return out


def _response_constant(name: str):
    raise NativeResponseError(f"nonfinite constant in native response: {name}")


def _finite_number(value, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise NativeResponseError(f"{what} must be a number")
    number = float(value)
    if number != number or number in (float("inf"), float("-inf")):
        raise NativeResponseError(f"{what} must be finite")
    return number


def _closed_object(value, expected: set[str], what: str) -> Mapping:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise NativeResponseError(f"{what} must be an object with exactly {sorted(expected)}")
    return value


def parse_native_response(raw: bytes, question_ids: list[str]) -> dict:
    """Validate one native sample against the closed wire contract.

    Returns ``{"model", "answers": {qid: {"choice", "probabilities",
    "confidence"}}, "usage"}``; anything else — wrong model, wrong question
    map, duplicate keys, bad probabilities or confidence — raises
    ``NativeResponseError`` (→ ``judge_invalid_output``). Confidence and
    probabilities are validated and returned only so the judge can prove
    they are never persisted: nothing here is voted with or stored."""
    import math

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise NativeResponseError("native response is not valid UTF-8") from error
    try:
        body = json.loads(
            text, object_pairs_hook=_response_duplicate_keys, parse_constant=_response_constant
        )
    except NativeResponseError:
        raise
    except ValueError as error:
        raise NativeResponseError(f"native response is not strict JSON ({type(error).__name__})") from error
    _closed_object(body, {"model", "answers", "usage"}, "native response")
    if body["model"] != JEV_MODEL:
        raise NativeResponseError("native response model mismatch")
    answers = _closed_object(body["answers"], set(question_ids), "native answers")
    usage = _closed_object(body["usage"], {"input_tokens", "output_tokens"}, "native usage")
    for field in ("input_tokens", "output_tokens"):
        value = usage[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise NativeResponseError(f"native usage.{field} must be a nonnegative integer")
    validated: dict[str, dict] = {}
    for question_id in question_ids:
        answer = _closed_object(
            body["answers"][question_id],
            {"type", "choice", "probabilities", "confidence"},
            f"native answer {question_id!r}",
        )
        if answer["type"] != "choice":
            raise NativeResponseError(f"native answer {question_id!r} type must be 'choice'")
        choice = answer["choice"]
        if not isinstance(choice, str) or choice not in MENU:
            raise NativeResponseError(f"native answer {question_id!r} choice is outside the menu")
        probabilities = _closed_object(
            answer["probabilities"], set(MENU), f"native answer {question_id!r} probabilities"
        )
        values = {}
        for option, raw_value in probabilities.items():
            number = _finite_number(raw_value, f"probability {option!r}")
            if not 0.0 <= number <= 1.0:
                raise NativeResponseError(f"probability {option!r} outside [0,1]")
            values[option] = number
        if abs(math.fsum(values.values()) - 1.0) > 1e-6:
            raise NativeResponseError("probabilities must sum to 1 within 1e-6")
        top = max(values.values())
        if values[choice] < top:
            raise NativeResponseError("selected choice must attain a maximum probability")
        confidence = _finite_number(answer["confidence"], "confidence")
        if not 0.0 <= confidence <= 1.0:
            raise NativeResponseError("confidence outside [0,1]")
        validated[question_id] = {
            "choice": choice,
            "probabilities": values,
            "confidence": confidence,
        }
    return {
        "model": body["model"],
        "answers": validated,
        "usage": dict(usage),
    }


# --------------------------------------------------------------------------
# Sample aggregation
# --------------------------------------------------------------------------


def aggregate_native_samples(
    answers_per_sample: list[Mapping[str, str]], question_ids: list[str]
) -> dict[str, dict]:
    """Aggregate the validated per-sample labels independently per question.

    A unique majority answers with ``vote_share`` counts/3 and ``agreement``
    winning count/3; a three-way tie is ``judge_inability`` for that
    question. Native confidence and probabilities never enter here."""
    if len(answers_per_sample) != JEV_SAMPLE_COUNT:
        raise ValueError("aggregation requires all three validated samples")
    out: dict[str, dict] = {}
    for question_id in question_ids:
        labels = [sample[question_id] for sample in answers_per_sample]
        counts = {option: labels.count(option) for option in MENU}
        top = max(counts.values())
        winners = [option for option, count in counts.items() if count == top]
        if len(winners) > 1:
            out[question_id] = {"failure": JUDGE_INABILITY}
        else:
            out[question_id] = {
                "choice": winners[0],
                "vote_share": {option: counts[option] / JEV_SAMPLE_COUNT for option in MENU},
                "agreement": top / JEV_SAMPLE_COUNT,
            }
    return out


# --------------------------------------------------------------------------
# Serving fingerprint (ADR 0014: actual installed artifact hashes)
# --------------------------------------------------------------------------

LOCAL_JUDGE_PINNED_COMMIT = "fca3fbde28312e7a1fa18940b8738ae406714f43"

_FINGERPRINT_ARTIFACTS = (
    "ops_guard/jev.py",
    "ops_guard/judge.py",
    "ops_guard/service.py",
    "ops_guard/invocation.py",
)


def _installed_artifact_hashes() -> dict[str, str] | None:
    """Raw SHA-256 of the actually installed serving sources; ``None`` when
    any artifact's identity is missing (never a made-up digest)."""
    import importlib

    out: dict[str, str] = {}
    for name in _FINGERPRINT_ARTIFACTS:
        module_name = name[:-3].replace("/", ".")
        path = getattr(importlib.import_module(module_name), "__file__", None)
        if not path:
            return None
        try:
            with open(path, "rb") as handle:
                out[name] = hashlib.sha256(handle.read()).hexdigest()
        except OSError:
            return None
    return out


def compute_serving_fingerprint(config: JevConfig) -> str | None:
    """SHA-256 over the canonical serving-identity manifest: endpoint/model,
    policy digest, schema and rubric versions, parser/transport bounds,
    sampling rules, installed artifact hashes, and pinned dependency
    metadata. Versions alone and Git HEAD do not identify running code."""
    import importlib.metadata

    artifacts = _installed_artifact_hashes()
    if artifacts is None:
        return None
    try:
        ops_guard_version = importlib.metadata.version("ops-guard")
    except importlib.metadata.PackageNotFoundError:
        ops_guard_version = None
    if not ops_guard_version:
        return None
    manifest = {
        "endpoint": config.endpoint,
        "model": JEV_MODEL,
        "policy_sha256": config.policy.sha256,
        "projection_schema_version": JEV_PROJECTION_SCHEMA_VERSION,
        "state_schema_version": JEV_STATE_SCHEMA_VERSION,
        "prompt_version": PROMPT_VERSION,
        "rubric_version": RUBRIC_VERSION,
        "menu": dict(MENU),
        "adapter_version": ADAPTER_VERSION,
        "parser_version": PARSER_VERSION,
        "aggregation_version": AGGREGATION_VERSION,
        "bounds": {
            "request_cap_bytes": REQUEST_CAP_BYTES,
            "response_cap_bytes": RESPONSE_CAP_BYTES,
            "sample_count": JEV_SAMPLE_COUNT,
            "timeout_ms": JEV_TIMEOUT_MS,
        },
        "artifacts": dict(sorted(artifacts.items())),
        "dependencies": {
            "local_judge_pinned_commit": LOCAL_JUDGE_PINNED_COMMIT,
            "ops_guard_version": ops_guard_version,
        },
    }
    return hashlib.sha256(canonicalize_json(manifest)).hexdigest()


# --------------------------------------------------------------------------
# The hosted judge
# --------------------------------------------------------------------------


class _InputRejected(Exception):
    """Internal: the assessment stops before egress with ``judge_input_rejected``."""


class JevJudge:
    """The opt-in hosted advisory judge (ADR 0014).

    Same interface and audit-only role as ``LocalJudge``: ``evaluate_risk``
    never raises, its outcome never changes proposal issuance, and every
    result is a closed ``ops-guard-jev-projection-v1`` snapshot. Rejected
    inputs make zero network requests; the first failed native sample stops
    the assessment. ``evaluate_question_map`` with companion ids is the
    private evaluation helper (issue #92's measurement path) — it is not an
    MCP tool."""

    def __init__(
        self,
        *,
        config: JevConfig,
        hmac_key: bytes,
        fingerprint: Any | None = None,
        transport: JevTransport | None = None,
        serving_fingerprint: str | None = None,
        timeout_ms: int = JEV_TIMEOUT_MS,
    ) -> None:
        if not hmac_key:
            raise ValueError("hmac_key must be a non-empty secret")
        self._config = config
        self._hmac_key = hmac_key
        self._fingerprint = fingerprint
        self._serving_fingerprint = serving_fingerprint
        self._timeout_ms = timeout_ms
        self._transport = transport or JevTransport(
            endpoint=config.endpoint,
            allowed_endpoints=config.allowed_endpoints,
            bearer_token=config.bearer_token,
            timeout_ms=timeout_ms,
        )

    def evaluate_risk(self, state: Mapping[str, Any]) -> dict:
        """The propose_fix path: exactly one fixed question ID."""
        results = self.evaluate_question_map(state, [RISK_QUESTION_ID])
        return results[RISK_QUESTION_ID]

    def evaluate_question_map(
        self, state: Mapping[str, Any], question_ids: list[str]
    ) -> dict[str, dict]:
        """Run the hosted assessment for a nonempty unique subset of the
        fixed question ids, in requested order. Never raises."""
        question_ids = list(question_ids)
        try:
            return self._assess(state, question_ids)
        except Exception:  # noqa: BLE001 — the worst case is a typed failure
            return {
                question_id: self._projection(
                    status="unavailable",
                    failure_code=JUDGE_ERROR,
                    question_id=question_id,
                    response_models=[],
                    profile_id=None,
                    attempted_samples=0,
                    completed_samples=0,
                    request_hmacs=[],
                    citation_refs=self._citation_refs_of(state),
                )
                for question_id in question_ids
            }

    # -- assessment ----------------------------------------------------

    def _assess(self, state: Mapping[str, Any], question_ids: list[str]) -> dict[str, dict]:
        if (
            not question_ids
            or len(set(question_ids)) != len(question_ids)
            or any(q not in ALLOWED_QUESTION_IDS for q in question_ids)
        ):
            raise ValueError("question ids must be a nonempty unique subset of the fixed rubric")
        citation_refs = self._citation_refs_of(state)
        profile_id: str | None = None
        attempted = 0
        completed = 0
        request_hmacs: list[str] = []
        response_models: list[str] = []
        answers: list[Mapping[str, str]] = []
        try:
            invocation_json, passage_text, citation = _extract_invocation_and_passage(state)
            invocation_sha256 = _invocation_digest(invocation_json)
            grant = self._config.policy.select(
                invocation_sha256,
                tuple(citation[field] for field in _CITATION_FIELDS),
            )
            if grant is None:
                raise _InputRejected()
            profile_id = grant.profile_id
            if (
                hashlib.sha256(passage_text.encode("utf-8")).hexdigest()
                != grant.passage_sha256
            ):
                raise _InputRejected()
            jev_state = project_jev_state(
                invocation_json=invocation_json, passage_text=passage_text, grant=grant
            )
            request = native_request_bytes(jev_state, question_ids)
            if len(request) > REQUEST_CAP_BYTES:
                raise _InputRejected()
        except (_InputRejected, PartitionError, EgressPolicyError):
            return self._all_unavailable(
                INPUT_REJECTED, question_ids, citation_refs, profile_id, 0, 0, [], []
            )
        request_hmac = self._request_hmac(request)
        for _sample in range(JEV_SAMPLE_COUNT):
            attempted += 1
            request_hmacs.append(request_hmac)
            try:
                raw = self._transport.post_sample(request)
            except TransportFailure as failure:
                return self._all_unavailable(
                    failure.failure_code,
                    question_ids,
                    citation_refs,
                    profile_id,
                    attempted,
                    completed,
                    request_hmacs,
                    response_models,
                )
            try:
                parsed = parse_native_response(raw, question_ids)
            except NativeResponseError:
                return self._all_unavailable(
                    INVALID_OUTPUT,
                    question_ids,
                    citation_refs,
                    profile_id,
                    attempted,
                    completed,
                    request_hmacs,
                    response_models,
                )
            completed += 1
            response_models.append(parsed["model"])
            answers.append({qid: answer["choice"] for qid, answer in parsed["answers"].items()})
        aggregates = aggregate_native_samples(answers, question_ids)
        projections: dict[str, dict] = {}
        for question_id in question_ids:
            outcome = aggregates[question_id]
            if "failure" in outcome:
                projections[question_id] = self._projection(
                    status="unavailable",
                    failure_code=JUDGE_INABILITY,
                    question_id=question_id,
                    response_models=response_models,
                    profile_id=profile_id,
                    attempted_samples=attempted,
                    completed_samples=completed,
                    request_hmacs=request_hmacs,
                    citation_refs=citation_refs,
                )
            else:
                projections[question_id] = self._projection(
                    status="answered",
                    question_id=question_id,
                    response_models=response_models,
                    profile_id=profile_id,
                    attempted_samples=attempted,
                    completed_samples=completed,
                    request_hmacs=request_hmacs,
                    citation_refs=citation_refs,
                    risk_class=outcome["choice"],
                    vote_share=dict(outcome["vote_share"]),
                    agreement=outcome["agreement"],
                )
        return projections

    def _all_unavailable(
        self,
        failure_code: str,
        question_ids: list[str],
        citation_refs: list[str],
        profile_id: str | None,
        attempted: int,
        completed: int,
        request_hmacs: list[str],
        response_models: list[str],
    ) -> dict[str, dict]:
        return {
            question_id: self._projection(
                status="unavailable",
                question_id=question_id,
                failure_code=failure_code,
                response_models=response_models,
                profile_id=profile_id,
                attempted_samples=attempted,
                completed_samples=completed,
                request_hmacs=request_hmacs,
                citation_refs=citation_refs,
            )
            for question_id in question_ids
        }

    def _request_hmac(self, request: bytes) -> str:
        """Keyed HMAC of the exact attempted request bytes plus the
        policy/config reference, using the existing audit key. Provenance
        for correlation — never proof of vendor receipt."""
        message = b"\n".join(
            [
                request,
                self._config.policy.sha256.encode("ascii"),
                self._config.endpoint.encode("utf-8"),
                JEV_MODEL.encode("utf-8"),
            ]
        )
        return hmac.new(self._hmac_key, message, hashlib.sha256).hexdigest()

    def _citation_refs_of(self, state: Mapping[str, Any]) -> list[str]:
        """The same immutable citation reference shape the local judge
        records; extracted without retaining any other state content."""
        evidence = state.get("evidence") if isinstance(state, Mapping) else None
        if not isinstance(evidence, Mapping):
            return []
        return [
            f"{evidence.get('runbook_id')}@{evidence.get('revision')}",
            evidence.get("content_hash"),
            evidence.get("locator"),
        ]

    def _projection(
        self,
        *,
        status: str,
        question_id: str,
        response_models: list[str],
        profile_id: str | None,
        attempted_samples: int,
        completed_samples: int,
        request_hmacs: list[str],
        citation_refs: list[str],
        failure_code: str | None = None,
        **answered: Any,
    ) -> dict:
        if status == "answered":
            common: dict[str, Any] = {
                "schema_version": JEV_PROJECTION_SCHEMA_VERSION,
                "status": status,
            }
        else:
            if failure_code is None or failure_code not in {
                INPUT_REJECTED, JUDGE_TIMEOUT, JUDGE_UNAVAILABLE, INVALID_OUTPUT,
                JUDGE_INABILITY, JUDGE_ERROR,
            }:
                raise ValueError("unavailable projections carry exactly one closed failure code")
            common = {
                "schema_version": JEV_PROJECTION_SCHEMA_VERSION,
                "status": status,
                "failure_code": failure_code,
            }
        if not 0 <= completed_samples <= attempted_samples <= JEV_SAMPLE_COUNT:
            raise ValueError("sample counters violate the closed invariant")
        if len(response_models) != completed_samples:
            raise ValueError("response-model count must equal completed samples")
        if len(request_hmacs) != attempted_samples:
            raise ValueError("request-HMAC count must equal attempted samples")
        if status == "answered" and completed_samples != JEV_SAMPLE_COUNT:
            raise ValueError("answered requires all three validated samples")
        projection = {
            **common,
            "provider": JEV_PROVIDER,
            "model": JEV_MODEL,
            "response_models": list(response_models),
            "endpoint": self._config.endpoint,
            "policy_sha256": self._config.policy.sha256,
            "profile_id": profile_id,
            "serving_fingerprint": self._serving_fingerprint,
            "sample_count": JEV_SAMPLE_COUNT,
            "timeout_ms": self._timeout_ms,
            "attempted_samples": attempted_samples,
            "completed_samples": completed_samples,
            "request_hmacs": list(request_hmacs),
            "question_id": question_id,
            "citation_refs": list(citation_refs),
            "state_schema_version": JEV_STATE_SCHEMA_VERSION,
            "rubric_version": RUBRIC_VERSION,
            "prompt_version": PROMPT_VERSION,
            "menu": dict(MENU),
            "adapter_version": ADAPTER_VERSION,
            "parser_version": PARSER_VERSION,
            "aggregation_version": AGGREGATION_VERSION,
        }
        projection.update(answered)
        return projection


def _extract_invocation_and_passage(
    state: Mapping[str, Any],
) -> tuple[dict[str, Any], str, Mapping[str, str]]:
    """Pull the validated invocation, exact passage text, and citation out
    of the composed judge state; any shape problem is input rejection."""
    if not isinstance(state, Mapping):
        raise _InputRejected()
    invocation_json = state.get("invocation")
    if not isinstance(invocation_json, Mapping):
        raise _InputRejected()
    try:
        invocation = Invocation.from_frozen_json(dict(invocation_json))
    except (TypeError, ValueError) as error:
        raise _InputRejected() from error
    evidence = state.get("evidence")
    if not isinstance(evidence, Mapping):
        raise _InputRejected()
    passage_text = evidence.get("passage_text")
    if not isinstance(passage_text, str):
        raise _InputRejected()
    citation = {field: evidence.get(field) for field in _CITATION_FIELDS}
    if any(not isinstance(value, str) or not value for value in citation.values()):
        raise _InputRejected()
    return invocation.to_json(), passage_text, citation


def _invocation_digest(invocation_json: Mapping[str, Any]) -> str:
    """The SHA-256 of the complete invocation's canonical bytes; any
    non-freezable invocation is input rejection, not a made-up identity."""
    try:
        invocation = Invocation.from_frozen_json(dict(invocation_json))
        invocation.canonical_bytes()
    except (TypeError, ValueError) as error:
        raise _InputRejected() from error
    return invocation.digest
