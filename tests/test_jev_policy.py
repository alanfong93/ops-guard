"""Closed egress-policy schema, endpoint identity, and operator config
(issue #91; ADR 0014).

Hermetic: everything parses in-process; the policy file lives in tmp_path.
"""

from __future__ import annotations

import json

import pytest

from ops_guard.jev import (
    POLICY_CAP_BYTES,
    POLICY_MAX_PROFILES,
    EgressPolicyError,
    JevConfigError,
    endpoint_identity,
    load_jev_config,
    parse_egress_policy,
    parse_pointer,
)
from jev_fixtures import (
    ENDPOINT,
    ENDPOINT_IDENTITY,
    demo_grant,
    synthetic_invocation_json,
    write_policy_file,
)

VALID_POLICY = {
    "schema_version": "ops-guard-jev-egress-v1",
    "profiles": [],
}


def policy_bytes(document) -> bytes:
    return json.dumps(document).encode("utf-8")


def grant_document(**overrides) -> dict:
    grant = demo_grant()
    document = {
        "profile_id": grant.profile_id,
        "invocation_sha256": grant.invocation_sha256,
        "citation": dict(grant.citation),
        "passage_sha256": grant.passage_sha256,
        "approved_leaves": [
            {"pointer": pointer, "value": value} for pointer, value in grant.approved.items()
        ],
        "omitted_leaves": [
            {"pointer": pointer, "reason": reason} for pointer, reason in grant.omitted.items()
        ],
    }
    document.update(overrides)
    return document


def full_policy(**profile_overrides) -> dict:
    return {
        "schema_version": "ops-guard-jev-egress-v1",
        "profiles": [grant_document(**profile_overrides)],
    }


# ---- closed schema -------------------------------------------------------


def test_empty_policy_is_valid_and_denies_all() -> None:
    policy = parse_egress_policy(policy_bytes(VALID_POLICY))
    assert policy.grants == ()
    assert policy.select("0" * 64, ("a", "b", "c", "d")) is None


def test_valid_single_profile_round_trips() -> None:
    policy = parse_egress_policy(policy_bytes(full_policy()))
    grant = policy.grants[0]
    assert grant.profile_id == "fixture-profile-1"
    assert grant.invocation_sha256 == demo_grant().invocation_sha256
    assert policy.select(grant.invocation_sha256, grant.citation_tuple) is grant


@pytest.mark.parametrize(
    "document",
    [
        {"schema_version": "ops-guard-jev-egress-v1", "profiles": [], "extra": {}},
        {"schema_version": "ops-guard-jev-egress-v1"},
        {"profiles": []},
        {"schema_version": "ops-guard-jev-egress-v2", "profiles": []},
        {"schema_version": "ops-guard-jev-egress-v1", "profiles": {}},
    ],
)
def test_policy_top_level_closure(document) -> None:
    with pytest.raises(EgressPolicyError):
        parse_egress_policy(policy_bytes(document))


def test_profile_rejects_unknown_and_missing_keys() -> None:
    with pytest.raises(EgressPolicyError):
        parse_egress_policy(policy_bytes(full_policy(extra_field=1)))
    broken = grant_document()
    del broken["passage_sha256"]
    with pytest.raises(EgressPolicyError):
        parse_egress_policy(policy_bytes({"schema_version": "ops-guard-jev-egress-v1", "profiles": [broken]}))


@pytest.mark.parametrize(
    "override",
    [
        {"profile_id": ""},
        {"profile_id": "has space"},
        {"profile_id": "x" * 65},
        {"profile_id": 7},
        {"invocation_sha256": "A" * 64},
        {"invocation_sha256": "z" * 64},
        {"invocation_sha256": "a" * 63},
        {"passage_sha256": "a" * 64 + "b"},
    ],
)
def test_profile_field_formats(override) -> None:
    with pytest.raises(EgressPolicyError):
        parse_egress_policy(policy_bytes(full_policy(**override)))


def test_citation_is_exactly_four_nonempty_strings() -> None:
    with pytest.raises(EgressPolicyError):
        parse_egress_policy(policy_bytes(full_policy(citation={**demo_grant().citation, "extra": "x"})))
    short = dict(demo_grant().citation)
    short["locator"] = ""
    with pytest.raises(EgressPolicyError):
        parse_egress_policy(policy_bytes(full_policy(citation=short)))


def test_duplicate_json_keys_rejected_at_any_depth() -> None:
    raw = (
        '{"schema_version":"ops-guard-jev-egress-v1","profiles":[],'
        '"schema_version":"ops-guard-jev-egress-v1"}'
    )
    with pytest.raises(EgressPolicyError, match="duplicate"):
        parse_egress_policy(raw.encode("utf-8"))


def test_nonfinite_numbers_rejected() -> None:
    with pytest.raises(EgressPolicyError):
        parse_egress_policy(
            policy_bytes(
                {
                    "schema_version": "ops-guard-jev-egress-v1",
                    "profiles": [grant_document(approved_leaves=[
                        {"pointer": "/arguments/x", "value": float("inf")}
                    ])],
                }
            )
        )
    with pytest.raises(EgressPolicyError):
        parse_egress_policy(b'{"schema_version":"ops-guard-jev-egress-v1","profiles":[],"x":NaN}')
    with pytest.raises(EgressPolicyError):
        parse_egress_policy(b'{"schema_version":"ops-guard-jev-egress-v1","profiles":[],"x":1e999}')


def test_policy_byte_and_profile_caps() -> None:
    oversized = b'{"schema_version":"ops-guard-jev-egress-v1","profiles":[],"pad":"' + b"a" * POLICY_CAP_BYTES + b'"}'
    with pytest.raises(EgressPolicyError, match="cap"):
        parse_egress_policy(oversized)
    document = {
        "schema_version": "ops-guard-jev-egress-v1",
        "profiles": [grant_document(profile_id=f"p{index}") for index in range(POLICY_MAX_PROFILES + 1)],
    }
    with pytest.raises(EgressPolicyError, match="profile cap"):
        parse_egress_policy(policy_bytes(document))


def test_duplicate_profile_ids_and_selector_pairs_rejected() -> None:
    with pytest.raises(EgressPolicyError, match="profile_id"):
        parse_egress_policy(
            policy_bytes(
                {
                    "schema_version": "ops-guard-jev-egress-v1",
                    "profiles": [grant_document(), grant_document()],
                }
            )
        )
    same_selector = [
        grant_document(profile_id="one"),
        grant_document(profile_id="two"),
    ]
    with pytest.raises(EgressPolicyError, match="selector"):
        parse_egress_policy(
            policy_bytes({"schema_version": "ops-guard-jev-egress-v1", "profiles": same_selector})
        )


def test_omission_reason_bounds() -> None:
    with pytest.raises(EgressPolicyError):
        parse_egress_policy(
            policy_bytes(full_policy(omitted_leaves=[{"pointer": "/runbook_revision_hash", "reason": "   "}]))
        )
    with pytest.raises(EgressPolicyError):
        parse_egress_policy(
            policy_bytes(
                full_policy(omitted_leaves=[{"pointer": "/runbook_revision_hash", "reason": "x" * 257}])
            )
        )
    parsed = parse_egress_policy(
        policy_bytes(full_policy(omitted_leaves=[{"pointer": "/runbook_revision_hash", "reason": "x" * 256}]))
    )
    assert parsed.grants[0].omitted["/runbook_revision_hash"] == "x" * 256


def test_approved_records_are_closed_pointer_value_pairs() -> None:
    with pytest.raises(EgressPolicyError):
        parse_egress_policy(
            policy_bytes(full_policy(approved_leaves=[{"pointer": "/action", "value": "v", "why": 1}]))
        )
    with pytest.raises(EgressPolicyError):
        parse_egress_policy(policy_bytes(full_policy(approved_leaves=[{"pointer": "/action"}])))


# ---- RFC 6901 pointers ---------------------------------------------------


@pytest.mark.parametrize(
    "pointer",
    ["", "action", "/action", "/arguments/a~1b", "/arguments/a~0b", "/preconditions/0/name"],
)
def test_pointer_parsing(pointer) -> None:
    if pointer in ("", "action"):
        with pytest.raises(EgressPolicyError):
            parse_pointer(pointer)
    else:
        parse_pointer(pointer)


def test_root_and_relative_pointers_rejected() -> None:
    with pytest.raises(EgressPolicyError):
        parse_pointer("")
    with pytest.raises(EgressPolicyError):
        parse_pointer("arguments")


@pytest.mark.parametrize("pointer", ["/a~", "/a~2", "/~"])
def test_invalid_escapes_rejected(pointer) -> None:
    with pytest.raises(EgressPolicyError):
        parse_pointer(pointer)


def test_duplicate_and_ancestor_pointer_conflicts() -> None:
    grant = demo_grant()
    approved = [
        {"pointer": pointer, "value": value}
        for pointer, value in grant.approved.items()
        if pointer != "/preconditions/0/name"
    ] + [{"pointer": "/preconditions/0", "value": {"name": "healthcheck", "expected": "passing"}}]
    conflict = grant_document(approved_leaves=approved)
    with pytest.raises(EgressPolicyError, match="nests|duplicates"):
        parse_egress_policy(
            policy_bytes({"schema_version": "ops-guard-jev-egress-v1", "profiles": [conflict]})
        )
    duplicated = grant_document(approved_leaves=[
        {"pointer": "/action", "value": "verify"},
        {"pointer": "/action", "value": "verify"},
    ])
    with pytest.raises(EgressPolicyError):
        parse_egress_policy(
            policy_bytes({"schema_version": "ops-guard-jev-egress-v1", "profiles": [duplicated]})
        )


@pytest.mark.parametrize("ancestor_first", [True, False])
def test_ancestor_conflict_detected_regardless_of_order(ancestor_first) -> None:
    ancestor, descendant = "/arguments", "/arguments/x"
    pair = [
        {"pointer": ancestor, "value": {}},
        {"pointer": descendant, "value": 1},
    ]
    if not ancestor_first:
        pair.reverse()
    document = grant_document(approved_leaves=pair)
    with pytest.raises(EgressPolicyError, match="nests|duplicates"):
        parse_egress_policy(
            policy_bytes({"schema_version": "ops-guard-jev-egress-v1", "profiles": [document]})
        )


def test_duplicate_pointer_across_approved_and_omitted_rejected() -> None:
    grant = demo_grant()
    approved = [
        {"pointer": pointer, "value": value} for pointer, value in grant.approved.items()
    ]  # /arguments/service stays approved ...
    omitted = [
        {"pointer": pointer, "reason": reason} for pointer, reason in grant.omitted.items()
    ] + [{"pointer": "/arguments/service", "reason": "double-booked"}]  # ... and is omitted too
    document = grant_document(approved_leaves=approved, omitted_leaves=omitted)
    with pytest.raises(EgressPolicyError):
        parse_egress_policy(
            policy_bytes({"schema_version": "ops-guard-jev-egress-v1", "profiles": [document]})
        )


# ---- endpoint identity ---------------------------------------------------


def test_endpoint_identity_canonicalizes() -> None:
    assert endpoint_identity("https://jev.example/v1/systemone") == ENDPOINT_IDENTITY
    assert endpoint_identity("HTTPS://JEV.Example/v1/systemone") == ENDPOINT_IDENTITY
    assert endpoint_identity("https://jev.example:443/v1/systemone") == ENDPOINT_IDENTITY
    assert endpoint_identity("https://jev.example") == "https://jev.example:443/"
    assert endpoint_identity("https://jev.example:8443/v1") == "https://jev.example:8443/v1"
    assert endpoint_identity("https://[2001:db8::1]/v1") == "https://[2001:db8::1]:443/v1"


@pytest.mark.parametrize(
    "raw",
    [
        "http://jev.example/v1",
        "ftp://jev.example/v1",
        "https://user:pass@jev.example/v1",
        "https://jev.example/v1?x=1",
        "https://jev.example/v1#frag",
        "https:///v1",
        "https://jev.example:port/v1",
        "https://jev.example:70000/v1",
        "https://jev.example/v1 sys",
        "https://jev.exa\x01mple/v1",
        "",
    ],
)
def test_endpoint_identity_rejections(raw) -> None:
    with pytest.raises(JevConfigError):
        endpoint_identity(raw)


# ---- operator configuration ----------------------------------------------


def base_environ(tmp_path, **overrides) -> dict:
    grant = demo_grant()
    environ = {
        "OPS_GUARD_JUDGE_BACKEND": "jev",
        "OPS_GUARD_JEV_ENDPOINT": ENDPOINT,
        "OPS_GUARD_JEV_ALLOWED_ENDPOINTS": ENDPOINT_IDENTITY,
        "OPS_GUARD_JEV_BEARER_TOKEN": "b" * 32,
        "OPS_GUARD_JEV_EGRESS_POLICY_FILE": write_policy_file(grant, str(tmp_path)),
    }
    environ.update(overrides)
    return environ


def test_load_jev_config_happy_path(tmp_path) -> None:
    config = load_jev_config(base_environ(tmp_path))
    assert config.endpoint == ENDPOINT_IDENTITY
    assert config.allowed_endpoints == (ENDPOINT_IDENTITY,)
    assert len(config.bearer_token) >= 32
    assert config.policy.grants[0].invocation_sha256 == demo_grant().invocation_sha256


def test_load_jev_config_names_the_missing_variable_without_its_value(tmp_path) -> None:
    for name in (
        "OPS_GUARD_JEV_ENDPOINT",
        "OPS_GUARD_JEV_ALLOWED_ENDPOINTS",
        "OPS_GUARD_JEV_BEARER_TOKEN",
        "OPS_GUARD_JEV_EGRESS_POLICY_FILE",
    ):
        environ = base_environ(tmp_path)
        del environ[name]
        with pytest.raises(JevConfigError, match=name):
            load_jev_config(environ)
        environ = base_environ(tmp_path)
        environ[name] = "   "
        with pytest.raises(JevConfigError, match=name):
            load_jev_config(environ)


def test_short_bearer_token_rejected(tmp_path) -> None:
    with pytest.raises(JevConfigError, match="OPS_GUARD_JEV_BEARER_TOKEN"):
        load_jev_config(base_environ(tmp_path, OPS_GUARD_JEV_BEARER_TOKEN="short"))


def test_endpoint_must_sit_on_the_exact_allowlist(tmp_path) -> None:
    with pytest.raises(JevConfigError, match="OPS_GUARD_JEV_ENDPOINT"):
        load_jev_config(
            base_environ(tmp_path, OPS_GUARD_JEV_ALLOWED_ENDPOINTS="https://other.example:443/x")
        )


def test_allowlist_entries_are_canonicalized_for_comparison(tmp_path) -> None:
    config = load_jev_config(
        base_environ(tmp_path, OPS_GUARD_JEV_ALLOWED_ENDPOINTS="HTTPS://JEV.Example/v1/systemone")
    )
    assert config.endpoint in config.allowed_endpoints


def test_missing_policy_file_named_without_values(tmp_path) -> None:
    with pytest.raises(JevConfigError, match="OPS_GUARD_JEV_EGRESS_POLICY_FILE"):
        load_jev_config(
            base_environ(
                tmp_path, OPS_GUARD_JEV_EGRESS_POLICY_FILE=str(tmp_path / "absent.json")
            )
        )


def test_invalid_policy_file_fails_startup_config(tmp_path) -> None:
    path = tmp_path / "broken.json"
    path.write_text('{"schema_version":"ops-guard-jev-egress-v1","profiles":[],"pad":1}', encoding="utf-8")
    with pytest.raises(JevConfigError):
        load_jev_config(base_environ(tmp_path, OPS_GUARD_JEV_EGRESS_POLICY_FILE=str(path)))
