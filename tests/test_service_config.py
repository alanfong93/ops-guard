"""Service environment-config contract (issue #54; ADR 0006).

Fail-fast rules: every required variable must be present, well-formed, and
loadable; any problem exits before a listener opens, naming the variable
and never a secret value.
"""

from __future__ import annotations

import ssl
from hypothesis import given, settings
from hypothesis import strategies as st
import pytest

from ops_guard.service import (
    ConfigurationError,
    parse_allowlist,
    validate_tls_pair,
)

REQUIRED_VARS = {
    "OPS_GUARD_HTTP_BEARER_TOKEN": "h" * 40,
    "OPS_GUARD_PROPOSAL_TOKEN_KEY": "a" * 64,
    "OPS_GUARD_AUDIT_FINGERPRINT_KEY": "b" * 64,
    "OPS_GUARD_DB_PATH": "proposals.db",
    "OPS_GUARD_RUNBOOK_DIR": "runbooks",
    "OPS_GUARD_BIND_HOST": "192.168.1.10",
    "OPS_GUARD_PORT": "8443",
    "OPS_GUARD_TLS_CERTFILE": "cert.pem",
    "OPS_GUARD_TLS_KEYFILE": "key.pem",
    "OPS_GUARD_ALLOWED_HOSTS": "ops-guard.lan,localhost",
    "OPS_GUARD_ALLOWED_ORIGINS": "https://ops-guard.lan",
}

SECRET_VARS = (
    "OPS_GUARD_HTTP_BEARER_TOKEN",
    "OPS_GUARD_PROPOSAL_TOKEN_KEY",
    "OPS_GUARD_AUDIT_FINGERPRINT_KEY",
)


def environ_without(*names: str) -> dict[str, str]:
    return {k: v for k, v in REQUIRED_VARS.items() if k not in names}


def test_every_required_variable_is_present_and_parsed() -> None:
    from ops_guard.service import load_config

    config = load_config(REQUIRED_VARS)
    assert config.bearer_token == "h" * 40
    assert config.proposal_token_key == b"\xaa" * 32
    assert config.audit_fingerprint_key == b"\xbb" * 32
    assert config.db_path == "proposals.db"
    assert config.runbook_dir == "runbooks"
    assert config.bind_host == "192.168.1.10"
    assert config.port == 8443
    assert config.tls_certfile == "cert.pem"
    assert config.tls_keyfile == "key.pem"
    assert config.allowed_hosts == ("ops-guard.lan", "localhost")
    assert config.allowed_origins == ("https://ops-guard.lan",)


@pytest.mark.parametrize("name", sorted(REQUIRED_VARS))
def test_missing_variable_fails_fast_naming_it(name: str) -> None:
    from ops_guard.service import load_config

    with pytest.raises(ConfigurationError) as raised:
        load_config(environ_without(name))
    assert name in str(raised.value)


@pytest.mark.parametrize("name", sorted(REQUIRED_VARS))
def test_empty_variable_fails_fast_naming_it(name: str) -> None:
    from ops_guard.service import load_config

    environ = dict(REQUIRED_VARS)
    environ[name] = ""
    with pytest.raises(ConfigurationError) as raised:
        load_config(environ)
    assert name in str(raised.value)


def test_whitespace_only_variable_fails_fast() -> None:
    from ops_guard.service import load_config

    environ = dict(REQUIRED_VARS)
    environ["OPS_GUARD_HTTP_BEARER_TOKEN"] = "   "
    with pytest.raises(ConfigurationError):
        load_config(environ)


@given(token=st.text(min_size=33, max_size=64), missing=st.sampled_from(sorted(REQUIRED_VARS)))
@settings(max_examples=40)
def test_error_messages_never_leak_supplied_secret_values(token: str, missing: str) -> None:
    from ops_guard.service import load_config

    environ = environ_without(missing)
    environ["OPS_GUARD_HTTP_BEARER_TOKEN"] = token
    try:
        load_config(environ)
    except ConfigurationError as error:
        message = str(error)
        assert token not in message
        assert "a" * 64 not in message
        assert "b" * 64 not in message


def test_short_bearer_token_is_rejected() -> None:
    from ops_guard.service import load_config

    environ = dict(REQUIRED_VARS)
    environ["OPS_GUARD_HTTP_BEARER_TOKEN"] = "h" * 31
    with pytest.raises(ConfigurationError) as raised:
        load_config(environ)
    assert "OPS_GUARD_HTTP_BEARER_TOKEN" in str(raised.value)


def test_32_character_bearer_token_is_accepted() -> None:
    from ops_guard.service import load_config

    environ = dict(REQUIRED_VARS)
    environ["OPS_GUARD_HTTP_BEARER_TOKEN"] = "h" * 32
    assert load_config(environ).bearer_token == "h" * 32


@pytest.mark.parametrize("name", ["OPS_GUARD_PROPOSAL_TOKEN_KEY", "OPS_GUARD_AUDIT_FINGERPRINT_KEY"])
def test_keys_must_be_64_hex_characters(name: str) -> None:
    from ops_guard.service import load_config

    for bad in ("z" * 64, "a" * 63, "a" * 65, ""):
        environ = dict(REQUIRED_VARS)
        environ[name] = bad
        with pytest.raises(ConfigurationError) as raised:
            load_config(environ)
        assert name in str(raised.value)


def test_port_must_be_in_range() -> None:
    from ops_guard.service import load_config

    for bad in ("0", "65536", "-1", "8443.0", "http"):
        environ = dict(REQUIRED_VARS)
        environ["OPS_GUARD_PORT"] = bad
        with pytest.raises(ConfigurationError):
            load_config(environ)


def test_proposal_ttl_defaults_to_900_seconds_when_absent() -> None:
    from ops_guard.service import load_config

    assert load_config(REQUIRED_VARS).proposal_ttl_seconds == 900


@pytest.mark.parametrize("bad", ["", "   ", "abc", "8443.0", "0", "-5", "900.5"])
def test_invalid_proposal_ttl_override_fails_startup(bad: str) -> None:
    from ops_guard.service import load_config

    environ = dict(REQUIRED_VARS)
    environ["OPS_GUARD_PROPOSAL_TTL_SECONDS"] = bad
    with pytest.raises(ConfigurationError) as raised:
        load_config(environ)
    assert "OPS_GUARD_PROPOSAL_TTL_SECONDS" in str(raised.value)


def test_valid_proposal_ttl_override_is_parsed() -> None:
    from ops_guard.service import load_config

    environ = dict(REQUIRED_VARS)
    environ["OPS_GUARD_PROPOSAL_TTL_SECONDS"] = "60"
    assert load_config(environ).proposal_ttl_seconds == 60


def test_allowlist_parsing_drops_empties_and_strips_whitespace() -> None:
    assert parse_allowlist(" ops-guard.lan , , localhost ,,", variable="V") == ("ops-guard.lan", "localhost")


def test_empty_allowlist_is_rejected_naming_the_variable() -> None:
    with pytest.raises(ConfigurationError) as raised:
        parse_allowlist(" , ,", variable="OPS_GUARD_ALLOWED_HOSTS")
    assert "OPS_GUARD_ALLOWED_HOSTS" in str(raised.value)


def test_missing_tls_files_fail_validation(tmp_path) -> None:
    from ops_guard.service import StartupError

    with pytest.raises(StartupError):
        validate_tls_pair(str(tmp_path / "absent.pem"), str(tmp_path / "absent-key.pem"))


def _write_pem(tmp_path, *, name: str, **kwargs) -> tuple[str, str]:
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    common = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(common)
        .issuer_name(common)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / f"{name}.pem"
    key_path = tmp_path / f"{name}-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


def test_valid_tls_pair_loads(tmp_path) -> None:
    from ops_guard.service import StartupError  # noqa: F401  (contract: typed startup errors)

    cert_path, key_path = _write_pem(tmp_path, name="pair")
    context = validate_tls_pair(cert_path, key_path)
    assert isinstance(context, ssl.SSLContext)


def test_mismatched_certificate_and_key_fail_validation(tmp_path) -> None:
    from ops_guard.service import StartupError

    cert_a, key_a = _write_pem(tmp_path, name="a")
    cert_b, key_b = _write_pem(tmp_path, name="b")
    with pytest.raises(StartupError):
        validate_tls_pair(cert_a, key_b)
