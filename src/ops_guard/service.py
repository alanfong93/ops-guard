"""Runnable LAN MCP service (issue #54; ADR 0006).

``python -m ops_guard`` serves the existing retrieval-only MCP surface —
``search_runbook`` and nothing else — over FastMCP Streamable HTTP with
native Uvicorn TLS at the configured LAN endpoint. Environment
configuration is fail-fast: missing, empty, or invalid values exit before
a listener opens, naming the variable and never a secret value. The
static bearer credential is compared in constant time by a custom
``TokenVerifier``; Host and Origin headers are validated against explicit
allowlists. Owner-based crash reconciliation completes before the
listener opens; only recovery counts are logged.
"""

from __future__ import annotations

import hmac
import json
import os
import socket
import sqlite3
import ssl
import sys
import threading
from dataclasses import dataclass
from datetime import timedelta
from typing import Mapping

from fastmcp.server.auth import AccessToken, TokenVerifier
from local_judge.ollama import UrllibOllamaTransport

from ops_guard.audit import AuditLog, AuditStore
from ops_guard.errors import ProposalError
from ops_guard.proposal_tool import DEFAULT_PROPOSAL_TTL_SECONDS
from ops_guard.telegram_approval import ApprovalConfigError
from ops_guard.proposals import ProposalService, default_clock
from ops_guard.recovery import reconcile_interrupted_executions
from ops_guard.retrieval import RunbookLibrary, build_mcp_server
from ops_guard.store import ProposalStore

_HEX64_RE = __import__("re").compile(r"^[0-9a-f]{64}$")


class ConfigurationError(Exception):
    """The environment configuration is missing, empty, or invalid."""


class StartupError(Exception):
    """Startup could not complete (bad paths, unreadable inputs, TLS)."""


def parse_allowlist(raw: str, *, variable: str) -> tuple[str, ...]:
    entries = tuple(entry.strip() for entry in raw.split(",") if entry.strip())
    if not entries:
        raise ConfigurationError(
            f"{variable} must contain at least one non-blank comma-separated entry"
        )
    return entries


@dataclass(frozen=True)
class ServiceConfig:
    bearer_token: str
    proposal_token_key: bytes
    audit_fingerprint_key: bytes
    db_path: str
    runbook_dir: str
    bind_host: str
    port: int
    tls_certfile: str
    tls_keyfile: str
    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...]
    proposal_ttl_seconds: int


def _required(environ: Mapping[str, str], name: str) -> str:
    value = environ.get(name)
    if value is None or not value.strip():
        raise ConfigurationError(f"{name} must be set to a non-blank value")
    return value


def load_config(environ: Mapping[str, str]) -> ServiceConfig:
    """Fail-fast environment configuration (ADR 0006)."""
    bearer_token = _required(environ, "OPS_GUARD_HTTP_BEARER_TOKEN")
    if len(bearer_token) < 32:
        raise ConfigurationError(
            "OPS_GUARD_HTTP_BEARER_TOKEN must be at least 32 characters (32 random bytes)"
        )

    def hex_key(name: str) -> bytes:
        raw = _required(environ, name)
        if not _HEX64_RE.fullmatch(raw):
            raise ConfigurationError(f"{name} must be 64 hexadecimal characters (32 bytes)")
        return bytes.fromhex(raw)

    proposal_token_key = hex_key("OPS_GUARD_PROPOSAL_TOKEN_KEY")
    audit_fingerprint_key = hex_key("OPS_GUARD_AUDIT_FINGERPRINT_KEY")
    db_path = _required(environ, "OPS_GUARD_DB_PATH")
    runbook_dir = _required(environ, "OPS_GUARD_RUNBOOK_DIR")
    if not os.path.isdir(runbook_dir):
        raise ConfigurationError(f"OPS_GUARD_RUNBOOK_DIR must be an existing directory")
    bind_host = _required(environ, "OPS_GUARD_BIND_HOST")
    try:
        socket.getaddrinfo(bind_host, None)
    except socket.gaierror as error:
        raise ConfigurationError(f"OPS_GUARD_BIND_HOST is not a resolvable address") from error
    raw_port = _required(environ, "OPS_GUARD_PORT")
    try:
        port = int(raw_port)
    except ValueError as error:
        raise ConfigurationError("OPS_GUARD_PORT must be an integer between 1 and 65535") from error
    if not 1 <= port <= 65535:
        raise ConfigurationError("OPS_GUARD_PORT must be an integer between 1 and 65535")
    tls_certfile = _required(environ, "OPS_GUARD_TLS_CERTFILE")
    tls_keyfile = _required(environ, "OPS_GUARD_TLS_KEYFILE")
    allowed_hosts = parse_allowlist(
        _required(environ, "OPS_GUARD_ALLOWED_HOSTS"), variable="OPS_GUARD_ALLOWED_HOSTS"
    )
    allowed_origins = parse_allowlist(
        _required(environ, "OPS_GUARD_ALLOWED_ORIGINS"), variable="OPS_GUARD_ALLOWED_ORIGINS"
    )
    raw_ttl = environ.get("OPS_GUARD_PROPOSAL_TTL_SECONDS")
    if raw_ttl is None:
        proposal_ttl_seconds = DEFAULT_PROPOSAL_TTL_SECONDS
    else:
        try:
            proposal_ttl_seconds = int(raw_ttl.strip())
        except ValueError as error:
            raise ConfigurationError(
                "OPS_GUARD_PROPOSAL_TTL_SECONDS must be a positive integer number of seconds"
            ) from error
        if proposal_ttl_seconds <= 0:
            raise ConfigurationError(
                "OPS_GUARD_PROPOSAL_TTL_SECONDS must be a positive integer number of seconds"
            )
    return ServiceConfig(
        bearer_token=bearer_token,
        proposal_token_key=proposal_token_key,
        audit_fingerprint_key=audit_fingerprint_key,
        db_path=db_path,
        runbook_dir=runbook_dir,
        bind_host=bind_host,
        port=port,
        tls_certfile=tls_certfile,
        tls_keyfile=tls_keyfile,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
        proposal_ttl_seconds=proposal_ttl_seconds,
    )


def validate_tls_pair(certfile: str, keyfile: str) -> ssl.SSLContext:
    """Load the certificate chain and key together; any problem fails startup
    with the typed startup error, never a raw traceback."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certfile, keyfile)
    except (ssl.SSLError, OSError) as error:
        raise StartupError(
            "OPS_GUARD_TLS_CERTFILE / OPS_GUARD_TLS_KEYFILE: "
            f"certificate and key must be a loadable PEM pair ({type(error).__name__})"
        ) from error
    return context


class StaticBearerVerifier(TokenVerifier):
    """Constant-time comparison against the one configured service token.

    The token is transport authentication only — never proposal-bound
    approval or execution authorization (ADR 0006, accepted limits).
    """

    def __init__(self, expected_token: str) -> None:
        super().__init__()
        if not expected_token:
            raise ValueError("expected token must be non-empty")
        self._expected = expected_token.encode("utf-8")

    async def verify_token(self, token: str) -> AccessToken | None:
        if not isinstance(token, str) or not token:
            return None
        if hmac.compare_digest(token.encode("utf-8"), self._expected):
            return AccessToken(token=token, client_id="operator", scopes=[])
        return None


def load_runbook_documents(
    directory: str,
) -> tuple[list[dict], list[tuple[str, str, str]]]:
    """Read JSON revisions from ``directory`` for RunbookLibrary.load.

    Returns the parseable documents plus ``(file, error, reason)`` rows
    for everything excluded — file name and error type only, never
    document content. A missing or unreadable directory fails startup.
    """
    if not os.path.isdir(directory):
        raise StartupError(f"runbook directory does not exist: {directory}")
    try:
        names = sorted(n for n in os.listdir(directory) if n.endswith(".json"))
    except OSError as error:
        raise StartupError(f"runbook directory is unreadable: {directory}") from error
    documents: list[dict] = []
    names_of: list[str] = []
    rejections: list[tuple[str, str, str]] = []
    for name in names:
        path = os.path.join(directory, name)
        try:
            with open(path, encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, ValueError) as error:
            rejections.append((name, "json", f"not readable as JSON: {type(error).__name__}"))
            continue
        documents.append(document)
        names_of.append(name)
    _, parsed_rejections = RunbookLibrary.load(documents)
    for rejection in parsed_rejections:
        rejections.append(
            (names_of[rejection.document_index], rejection.error, rejection.reason)
        )
    kept = {names_of[r.document_index] for r in parsed_rejections}
    documents = [doc for doc, name in zip(documents, names_of) if name not in kept]
    return documents, rejections


def build_http_server(config: ServiceConfig) -> tuple[object, AuditLog]:
    """Assemble the service: runbooks, audit/proposal initialization on the
    shared database, crash reconciliation, then the retrieval-only MCP app
    behind bearer auth and Host/Origin protection. Nothing binds here."""
    documents, rejections = load_runbook_documents(config.runbook_dir)
    library, _ = RunbookLibrary.load(documents)
    for name, error, reason in rejections:
        print(f"[ops-guard] excluded runbook revision {name}: {error} ({reason})", flush=True)
    print(f"[ops-guard] serving {len(documents)} runbook revision(s) from {config.runbook_dir}", flush=True)

    clock = default_clock
    try:
        audit = AuditLog(
            AuditStore(config.db_path),
            fingerprint_key=config.audit_fingerprint_key,
            clock=clock,
        )
        proposals = ProposalService(
            ProposalStore(config.db_path),
            token_key=config.proposal_token_key,
            clock=clock,
            audit=audit,
        )
        reconciliations = reconcile_interrupted_executions(audit)
    except (sqlite3.Error, OSError) as error:
        raise StartupError(
            f"OPS_GUARD_DB_PATH: audit/proposal store must be initializable at "
            f"{config.db_path} ({type(error).__name__})"
        ) from error
    counts: dict[str, int] = {}
    for reconciliation in reconciliations:
        counts[reconciliation.action] = counts.get(reconciliation.action, 0) + 1
    print(
        "[ops-guard] recovery complete: "
        f"{counts.get('recovered', 0)} recovered, "
        f"{counts.get('alive', 0)} alive, "
        f"{counts.get('indeterminate', 0)} indeterminate",
        flush=True,
    )

    verifier = StaticBearerVerifier(config.bearer_token)
    from ops_guard.judge import LocalJudge

    judge = LocalJudge(transport=UrllibOllamaTransport(), fingerprint=audit.fingerprint)
    server = build_mcp_server(
        library,
        audit,
        auth=verifier,
        proposals=proposals,
        proposal_ttl=timedelta(seconds=config.proposal_ttl_seconds),
        judge=judge,
    )
    tls_context = validate_tls_pair(config.tls_certfile, config.tls_keyfile)
    app = server.http_app(
        transport="streamable-http",
        host_origin_protection=True,
        allowed_hosts=list(config.allowed_hosts),
        allowed_origins=list(config.allowed_origins),
    )
    return app, audit, proposals


class _ApprovalRuntime:
    """Started approval loops with a shared stop event (ADR 0010)."""

    def __init__(self, *, notifier, poller) -> None:
        self.stop_event = threading.Event()
        self.notifier = notifier
        self.poller = poller
        self.notifier._stop = self.stop_event
        self.poller._stop = self.stop_event
        self.threads = [
            threading.Thread(target=notifier.run, daemon=True),
            threading.Thread(target=poller.run, daemon=True),
        ]

    def start(self) -> None:
        for thread in self.threads:
            thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        for thread in self.threads:
            thread.join(timeout=10)


def build_approval_runtime(environment: Mapping[str, str], audit, proposals, clock):
    """Opt-in Telegram approval runtime (issue #61; ADR 0010).

    Returns None when approvals are disabled; otherwise the poller and
    notifier, not yet started. Malformed enabled-configuration fails here,
    before a listener opens."""
    from ops_guard.approvals import ApprovalStore, ApprovalVerifier
    from ops_guard.telegram_approval import (
        ApprovalConfigError,
        ApprovalNotifier,
        ApprovalPoller,
        TelegramBotClient,
        load_approval_config,
    )

    approval_config = load_approval_config(environment)
    if approval_config is None:
        return None
    verifier = ApprovalVerifier(
        ApprovalStore(proposals.store.path),
        proposals,
        operator_identity=approval_config.operator_identity,
        clock=clock,
    )
    client = TelegramBotClient(approval_config.bot_token)
    notifier = ApprovalNotifier(
        client,
        proposals,
        audit=audit,
        operator_chat_id=approval_config.operator_chat_id,
        clock=clock,
    )
    poller = ApprovalPoller(
        client,
        verifier,
        operator_user_id=approval_config.operator_user_id,
        operator_chat_id=approval_config.operator_chat_id,
        operator_identity=approval_config.operator_identity,
        clock=clock,
    )
    return _ApprovalRuntime(notifier=notifier, poller=poller)


def main(argv: list[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    """Entry point for ``python -m ops_guard`` (ADR 0006, ADR 0010)."""
    import uvicorn

    environment = os.environ if environ is None else environ
    try:
        config = load_config(environment)
        app, audit, proposals = build_http_server(config)
    except (ConfigurationError, StartupError) as error:
        print(f"[ops-guard] startup failed: {error}", file=sys.stderr)
        return 2
    try:
        runtime = build_approval_runtime(environment, audit, proposals, default_clock)
    except ApprovalConfigError as error:
        print(f"[ops-guard] startup failed: {error}", file=sys.stderr)
        return 2
    # Operator policy (issue #62; ADR 0011): validated once per server
    # start, fail-closed on any error. The execution gate consumes it when
    # the execute surface is wired (issue #64).
    policy_path = environment.get("OPS_GUARD_POLICY_FILE")
    if policy_path:
        from ops_guard.preconditions import default_registry, load_policy_file

        try:
            policy = load_policy_file(policy_path, default_registry())
        except ProposalError as error:
            print(f"[ops-guard] startup failed: {error}", file=sys.stderr)
            return 2
        print(
            f"[ops-guard] operator policy loaded (digest {policy.digest[:16]}...)", flush=True
        )
    if runtime is not None:
        runtime.start()
        print("[ops-guard] approval transport enabled (Telegram, private operator DM)", flush=True)
    try:
        uvicorn.run(
            app,
            host=config.bind_host,
            port=config.port,
            ssl_certfile=config.tls_certfile,
            ssl_keyfile=config.tls_keyfile,
            log_level="info",
        )
    finally:
        if runtime is not None:
            runtime.stop()
    return 0
    print(
        f"[ops-guard] serving search_runbook on https://{config.bind_host}:{config.port}"
        " (bearer-authenticated, Host/Origin allowlisted)",
        flush=True,
    )
    uvicorn.run(
        app,
        host=config.bind_host,
        port=config.port,
        ssl_certfile=config.tls_certfile,
        ssl_keyfile=config.tls_keyfile,
        log_level="info",
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
