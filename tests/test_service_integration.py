"""Real-socket LAN HTTPS service integration (issue #54; ADR 0006).

These tests run the actual uvicorn TLS listener in a thread and speak
MCP over it with a real client: the verified-citation path, and the
fail-closed paths (wrong bearer token, disallowed Host, disallowed
Origin, certificate mismatch) — each rejection before any audited
result is returned.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import ssl
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import uvicorn

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC_CORPUS = os.path.join(REPO_ROOT, "runbooks")
N8N_RUNBOOK = os.path.join(PUBLIC_CORPUS, "n8n-update.json")
SEARCH_PATH = "/mcp"

BEARER_TOKEN = "integration-bearer-" + "x" * 32


def _write_test_certificate(tmp_path) -> tuple[str, str]:
    """Self-signed certificate whose SAN covers localhost + 127.0.0.1."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ops-guard-test")])
    now = datetime.now(timezone.utc)
    san = x509.SubjectAlternativeName(
        [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


def _trusting_context(cert_path: str) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=cert_path)
    context.check_hostname = True
    return context


class ServiceHandle:
    """A running service on an ephemeral port, plus direct access to its
    audit database so tests can prove what was and was not recorded."""

    def __init__(self, tmp_path, *, allowed_hosts: tuple[str, ...] = ("localhost", "127.0.0.1")):
        from ops_guard.service import ServiceConfig

        cert_path, key_path = _write_test_certificate(tmp_path)
        self.cert_path = cert_path
        self.db_path = str(tmp_path / "service.db")
        # Port 0 (ephemeral) is a test-harness need; the strict env contract
        # requires a concrete port, so build the config directly here.
        self.config = ServiceConfig(
            bearer_token=BEARER_TOKEN,
            proposal_token_key=bytes.fromhex("a" * 64),
            audit_fingerprint_key=bytes.fromhex("b" * 64),
            db_path=self.db_path,
            runbook_dir=PUBLIC_CORPUS,
            bind_host="127.0.0.1",
            port=0,
            tls_certfile=cert_path,
            tls_keyfile=key_path,
            allowed_hosts=allowed_hosts,
            allowed_origins=("https://ops-guard.lan",),
            proposal_ttl_seconds=900,
        )
        self._thread: threading.Thread | None = None
        self._server: uvicorn.Server | None = None
        self.port: int | None = None

    def start(self) -> "ServiceHandle":
        from ops_guard.service import build_http_server

        app, audit, _proposals = build_http_server(self.config)
        self.audit = audit
        uvicorn_config = uvicorn.Config(
            app,
            host=self.config.bind_host,
            port=self.config.port,
            ssl_certfile=self.config.tls_certfile,
            ssl_keyfile=self.config.tls_keyfile,
            log_level="warning",
        )
        self._server = uvicorn.Server(uvicorn_config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self._server.started:
                break
            if getattr(self._server, "exit_code", None) not in (None, 0):
                raise RuntimeError("service failed to start")
            time.sleep(0.05)
        else:
            raise RuntimeError("service did not start in time")
        self.port = self._server.servers[0].sockets[0].getsockname()[1]
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=10)

    @property
    def url(self) -> str:
        return f"https://localhost:{self.port}{SEARCH_PATH}"

    def audit_event_count(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]


@pytest.fixture()
def service(tmp_path):
    handle = ServiceHandle(tmp_path).start()
    yield handle
    handle.stop()


def _client(service: ServiceHandle, *, token: str = BEARER_TOKEN) -> httpx.Client:
    return httpx.Client(
        verify=_trusting_context(service.cert_path),
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )


def test_valid_client_discovers_only_search_runbook_and_retrieves_the_expected_citation(service) -> None:
    from fastmcp import Client
    from fastmcp.client.transports import StreamableHttpTransport

    transport = StreamableHttpTransport(
        url=service.url,
        auth=BEARER_TOKEN,
        verify=_trusting_context(service.cert_path),
    )

    async def scenario() -> tuple[list[str], dict]:
        async with Client(transport) as client:
            tools = await client.list_tools()
            result = await client.call_tool(
                "search_runbook",
                {"question": "how do I update the n8n docker image", "limit": 3},
            )
        return [tool.name for tool in tools], json.loads(result.content[0].text)

    tool_names, payload = asyncio.run(scenario())
    # S7-1 (issue #57): the proposal tool joins the same authenticated server.
    assert sorted(tool_names) == ["propose_fix", "search_runbook"]
    assert payload, "expected at least one cited result"
    top = payload[0]
    with open(N8N_RUNBOOK, encoding="utf-8") as handle:
        expected = json.load(handle)
    assert top["runbook_id"] == "n8n-update"
    assert top["revision"] == expected["revision"]
    assert top["content_hash"] == expected["content_hash"]
    assert top["verification"]["verifier"] == expected["verification"]["verifier"]
    assert top["passage_text"]
    assert top["operation"] == {"action": "update", "target": "n8n"}
    # The valid search is durably recorded before results are returned.
    assert service.audit_event_count() > 0


def test_wrong_bearer_token_is_rejected_with_no_recorded_result(service) -> None:
    before = service.audit_event_count()
    with _client(service, token="wrong-" + "y" * 32) as client:
        response = client.post(
            service.url,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "reject-test", "version": "0"},
                },
            },
        )
        assert response.status_code >= 400
    assert service.audit_event_count() == before


def test_missing_bearer_token_is_rejected_with_no_recorded_result(service) -> None:
    before = service.audit_event_count()
    with httpx.Client(verify=_trusting_context(service.cert_path), timeout=15) as client:
        response = client.post(service.url, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert response.status_code >= 400
    assert service.audit_event_count() == before


def test_disallowed_host_header_is_rejected_with_no_recorded_result(service) -> None:
    before = service.audit_event_count()
    with _client(service) as client:
        response = client.post(
            service.url,
            headers={"Host": "evil.example"},
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert response.status_code >= 400
    assert service.audit_event_count() == before


def test_disallowed_origin_header_is_rejected_with_no_recorded_result(service) -> None:
    before = service.audit_event_count()
    with _client(service) as client:
        response = client.post(
            service.url,
            headers={"Origin": "https://evil.example"},
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert response.status_code >= 400
    assert service.audit_event_count() == before


def test_client_mistrusting_the_certificate_cannot_connect(service) -> None:
    with httpx.Client(verify=ssl.create_default_context(), timeout=5) as client:
        with pytest.raises(Exception):
            client.post(service.url, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})


def test_reconciliation_runs_before_the_listener(tmp_path, capsys) -> None:
    """build_http_server completes recovery before any socket exists, and
    reports only counts."""
    handle = ServiceHandle(tmp_path)
    assert handle.port is None  # nothing bound yet
    from ops_guard.service import build_http_server

    app, audit, _proposals = build_http_server(handle.config)
    captured = capsys.readouterr().out
    assert app is not None
    # A fresh database recovers nothing; the report is counts only.
    assert "[ops-guard] recovery complete: 0 recovered, 0 alive, 0 indeterminate" in captured


def test_reconciliation_failure_aborts_startup_before_binding(tmp_path) -> None:
    from unittest import mock

    import ops_guard.service as service_module

    handle = ServiceHandle(tmp_path)
    with mock.patch.object(
        service_module, "reconcile_interrupted_executions", side_effect=RuntimeError("db broken")
    ):
        with pytest.raises(RuntimeError, match="db broken"):
            service_module.build_http_server(handle.config)
    assert handle.port is None


def test_unusable_database_path_fails_startup_as_typed_error(tmp_path) -> None:
    from ops_guard.service import ServiceConfig, StartupError, build_http_server

    cert_path, key_path = _write_test_certificate(tmp_path)
    config = ServiceConfig(
        bearer_token=BEARER_TOKEN,
        proposal_token_key=bytes.fromhex("a" * 64),
        audit_fingerprint_key=bytes.fromhex("b" * 64),
        db_path=str(tmp_path / "missing-dir" / "service.db"),
        runbook_dir=PUBLIC_CORPUS,
        bind_host="127.0.0.1",
        port=0,
        tls_certfile=cert_path,
        tls_keyfile=key_path,
        allowed_hosts=("localhost",),
        allowed_origins=("https://ops-guard.lan",),
        proposal_ttl_seconds=900,
    )
    with pytest.raises(StartupError) as raised:
        build_http_server(config)
    assert "OPS_GUARD_DB_PATH" in str(raised.value)


def test_startup_error_text_carries_underlying_message(tmp_path) -> None:
    """The store wrapper's StartupError includes the underlying error
    text, not just its type name (#69)."""
    from ops_guard.service import ServiceConfig, StartupError, build_http_server

    cert_path, key_path = _write_test_certificate(tmp_path)
    db_path = tmp_path / "corrupt"
    db_path.mkdir()
    (db_path / "service.db").write_text("not a database", encoding="utf-8")
    config = ServiceConfig(
        bearer_token=BEARER_TOKEN,
        proposal_token_key=bytes.fromhex("a" * 64),
        audit_fingerprint_key=bytes.fromhex("b" * 64),
        db_path=str(db_path / "service.db"),
        runbook_dir=PUBLIC_CORPUS,
        bind_host="127.0.0.1",
        port=0,
        tls_certfile=cert_path,
        tls_keyfile=key_path,
        allowed_hosts=("localhost",),
        allowed_origins=("https://ops-guard.lan",),
        proposal_ttl_seconds=900,
    )
    with pytest.raises(StartupError) as raised:
        build_http_server(config)
    message = str(raised.value)
    assert "OPS_GUARD_DB_PATH" in message
    assert "not a database" in message
    assert type(raised.value.__cause__).__name__ in message


def test_tls_startup_error_text_carries_underlying_message(tmp_path) -> None:
    """The TLS wrapper's StartupError includes the underlying error text
    (#69)."""
    from ops_guard.service import ServiceConfig, StartupError, validate_tls_pair

    certfile = str(tmp_path / "absent.pem")
    with pytest.raises(StartupError) as raised:
        validate_tls_pair(certfile, str(tmp_path / "absent-key.pem"))
    message = str(raised.value)
    assert "OPS_GUARD_TLS_CERTFILE / OPS_GUARD_TLS_KEYFILE" in message
    assert "No such file or directory" in message
    assert type(raised.value.__cause__).__name__ in message


def test_startup_does_not_log_secret_values(service, capsys) -> None:
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert BEARER_TOKEN not in out
    assert "a" * 64 not in out
    assert "b" * 64 not in out
