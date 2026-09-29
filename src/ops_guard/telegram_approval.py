"""Telegram approval transport (issue #61; ADR 0010).

Opt-in operator approval over a fresh dedicated Telegram bot: the server
long-polls ``getUpdates`` for callback queries from the configured
operator in the configured private chat, and records approvals through
the internal verifier by proposal id — the raw proposal token is never
carried, recovered, sent, or logged. A notifier delivers plain-text
proposal previews (key-based redaction applied) to the same chat.

Everything here is fail-closed: when approvals are disabled or the
transport is unavailable, no approval can be recorded and gated execution
is unaffected. All Bot API access goes through an injectable requester so
tests are fully hermetic.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Mapping

from ops_guard.audit import redact
from ops_guard.approvals import ApprovalVerifier
from ops_guard.errors import (
    ApprovalAlreadyRecordedError,
    ProposalError,
    TokenExpiredError,
)
from ops_guard.proposals import FrozenProposal, ProposalService, format_timestamp

TELEGRAM_MESSAGE_LIMIT = 4096
PREVIEW_PART_LIMIT = 4096
MAX_PREVIEW_PARTS = 5
CALLBACK_DATA_LIMIT = 64
APPROVE_PREFIX = "approve:"
LONG_POLL_SECONDS = 30
PROPOSAL_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")


class ApprovalConfigError(Exception):
    """Approval transport configuration is enabled but invalid."""


class TelegramTransportError(Exception):
    """Sanitized transport failure: never carries the bot token or URLs."""


class TelegramRetryAfter(TelegramTransportError):
    def __init__(self, retry_after: float) -> None:
        super().__init__(f"telegram asked to retry after {retry_after}s")
        self.retry_after = retry_after


@dataclass(frozen=True)
class ApprovalConfig:
    bot_token: str
    operator_user_id: int
    operator_chat_id: int
    operator_identity: str


def load_approval_config(environ: Mapping[str, str]) -> ApprovalConfig | None:
    """Opt-in approval configuration (ADR 0010).

    Returns None when the transport is disabled — no approval can be
    recorded and gated execution remains fail-closed. When enabled, every
    setting is required and well-formed; a failure names the variable and
    never a secret value."""
    raw_enabled = environ.get("OPS_GUARD_APPROVALS_ENABLED", "")
    enabled = raw_enabled.strip().lower() in ("1", "true", "yes", "on")
    if not enabled:
        return None

    def required(name: str) -> str:
        value = environ.get(name)
        if value is None or not value.strip():
            raise ApprovalConfigError(f"{name} must be set when approvals are enabled")
        return value

    bot_token = required("OPS_GUARD_TELEGRAM_BOT_TOKEN")
    if not re.fullmatch(r"[0-9]{6,20}:[A-Za-z0-9_-]{20,}", bot_token):
        raise ApprovalConfigError(
            "OPS_GUARD_TELEGRAM_BOT_TOKEN is malformed (expected <bot id>:<secret>)"
        )

    def numeric(name: str) -> int:
        raw = required(name)
        if not re.fullmatch(r"-?[0-9]{1,20}", raw.strip()):
            raise ApprovalConfigError(f"{name} must be a numeric Telegram id")
        return int(raw.strip())

    operator_user_id = numeric("OPS_GUARD_TELEGRAM_OPERATOR_USER_ID")
    operator_chat_id = numeric("OPS_GUARD_TELEGRAM_OPERATOR_CHAT_ID")
    operator_identity = required("OPS_GUARD_APPROVAL_OPERATOR_IDENTITY")
    return ApprovalConfig(
        bot_token=bot_token,
        operator_user_id=operator_user_id,
        operator_chat_id=operator_chat_id,
        operator_identity=operator_identity,
    )


class TelegramBotClient:
    """Stdlib HTTPS Bot API client; the requester is injectable for tests.

    All failures surface as sanitized TelegramTransportError subclasses:
    the bot token appears in the API request path, so no error text, URL,
    or response body is ever echoed verbatim."""

    def __init__(self, bot_token: str, requester: Callable[[str, str, Mapping[str, Any], int], dict] | None = None) -> None:
        self._token = bot_token
        self._request = requester or self._stdlib_request

    def _stdlib_request(self, method: str, token: str, payload: Mapping[str, Any], timeout: int) -> dict:
        url = f"https://api.telegram.org/bot{token}/{method}"
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            if error.code == 429:
                try:
                    document = json.loads(error.read().decode("utf-8"))
                    retry_after = (document.get("parameters") or {}).get("retry_after")
                except Exception:  # noqa: BLE001 — sanitization over detail
                    retry_after = None
                if retry_after is not None:
                    raise TelegramRetryAfter(float(retry_after)) from None
            raise TelegramTransportError(
                f"telegram API returned HTTP {error.code}"
            ) from None
        except (urllib.error.URLError, OSError, ValueError) as error:
            raise TelegramTransportError(
                f"telegram transport failure ({type(error).__name__})"
            ) from None
        return body

    def _call(self, method: str, payload: Mapping[str, Any], timeout: int) -> Any:
        try:
            body = self._request(method, self._token, payload, timeout)
        except TelegramRetryAfter:
            raise
        except TelegramTransportError:
            raise
        except Exception as error:  # noqa: BLE001 — sanitize everything else
            raise TelegramTransportError(
                f"telegram transport failure ({type(error).__name__})"
            ) from None
        if not isinstance(body, dict) or body.get("ok") is not True:
            raise TelegramTransportError(f"telegram API rejected {method}")
        return body.get("result")

    def get_me(self) -> dict:
        me = self._call("getMe", {}, 10)
        if not isinstance(me, dict) or not isinstance(me.get("id"), int):
            raise TelegramTransportError("getMe returned no bot identity")
        return me

    def get_updates(self, offset: int | None, timeout_s: int = LONG_POLL_SECONDS) -> list[dict]:
        updates = self._call(
            "getUpdates",
            {
                "offset": offset,
                "timeout": timeout_s,
                "allowed_updates": ["callback_query"],
            },
            timeout_s + 10,
        )
        return updates if isinstance(updates, list) else []

    def send_message(self, chat_id: int, text: str, reply_markup: Mapping[str, Any] | None = None) -> dict:
        payload: dict[str, Any] = {"chat_id": chat_id, "text": text}
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        return self._call("sendMessage", payload, 15)

    def answer_callback_query(self, callback_query_id: str, text: str | None = None) -> None:
        payload: dict[str, Any] = {"callback_query_id": callback_query_id}
        if text:
            payload["text"] = text
        self._call("answerCallbackQuery", payload, 10)


def build_preview_parts(
    frozen: FrozenProposal,
    evidence_refs,
    *,
    redactor: Callable[[Any], Any] = redact,
    part_limit: int = PREVIEW_PART_LIMIT - 64,
    max_parts: int = MAX_PREVIEW_PARTS,
) -> list[str]:
    """Plain-text approval preview, split into complete numbered parts.

    No raw proposal token or bot token ever enters the text; argument
    values pass the key-based audit redaction. Approval-relevant fields are
    never truncated: an oversized preview raises rather than dropping
    fields, and the caller sends no actionable button."""

    def header(index: int, total: int) -> str:
        return f"[ops-guard approval {index}/{total}]"

    body = (
        "Proposal: " + frozen.proposal_id + "\n"
        "Invocation digest: " + frozen.invocation_digest + "\n"
        "Expires at: " + format_timestamp(frozen.expires_at) + "\n"
        "Action: " + frozen.invocation.action + "\n"
        "Target: " + frozen.invocation.target + "\n"
        "Arguments: " + json.dumps(redactor(dict(frozen.invocation.arguments)), sort_keys=True, default=str)
        + "\n"
        "Preconditions: "
        + json.dumps(redactor(list(frozen.invocation.preconditions)), default=str)
        + "\n"
    )
    if evidence_refs:
        body += "Evidence: " + " | ".join(str(ref) for ref in evidence_refs) + "\n"
    body += "Approving records one proposal-bound operator approval; the proposal expires unapproved otherwise."

    chunks: list[str] = []
    remaining = body
    while remaining:
        chunks.append(remaining[:part_limit])
        remaining = remaining[part_limit:]
        if len(chunks) > max_parts:
            raise ValueError("proposal preview exceeds the maximum number of parts")
    total = len(chunks)
    return [f"{header(i + 1, total)}\n{chunk}" for i, chunk in enumerate(chunks)]


def callback_data_for(proposal_id: str) -> str:
    """The Approve callback payload: action prefix + proposal id, nothing else."""
    data = APPROVE_PREFIX + proposal_id
    if not PROPOSAL_ID_PATTERN.fullmatch(proposal_id):
        raise ValueError("proposal id must be 32 hexadecimal characters")
    if len(data) > CALLBACK_DATA_LIMIT:
        raise ValueError("callback data exceeds the Telegram limit")
    return data


def parse_callback_data(data: str) -> str | None:
    """Return the proposal id for a well-formed Approve payload, else None."""
    if not isinstance(data, str) or not data.startswith(APPROVE_PREFIX):
        return None
    proposal_id = data[len(APPROVE_PREFIX) :]
    if not PROPOSAL_ID_PATTERN.fullmatch(proposal_id):
        return None
    return proposal_id


class ApprovalNotifier:
    """Delivers previews for active unapproved proposals to the operator DM.

    Startup and periodic scans retry transient delivery errors with capped
    backoff while a proposal stays unexpired; a process-local sent set
    prevents repeats during normal operation. The Approve button goes only
    on the final part after every part has succeeded."""

    def __init__(
        self,
        client: TelegramBotClient,
        service: ProposalService,
        *,
        audit,
        operator_chat_id: int,
        clock: Callable[[], datetime],
        poll_interval: float = 30.0,
        stop_event: threading.Event | None = None,
        backoff_cap: float = 60.0,
    ) -> None:
        self._client = client
        self._service = service
        self._audit = audit
        self._chat_id = operator_chat_id
        self._clock = clock
        self._poll_interval = poll_interval
        self._stop = stop_event or threading.Event()
        self._backoff_cap = backoff_cap
        self._sent: set[str] = set()

    def active_unapproved(self) -> list[FrozenProposal]:
        now = format_timestamp(self._clock())
        with self._service.store.read() as conn:
            rows = conn.execute(
                """
                SELECT p.* FROM proposals p
                 WHERE p.state = 'active' AND p.expires_at > ?
                   AND NOT EXISTS (
                       SELECT 1 FROM approvals a WHERE a.token_digest = p.token_digest
                   )
                """,
                (now,),
            ).fetchall()
        from ops_guard.proposals import _row_to_proposal

        return [_row_to_proposal(row) for row in rows]

    def evidence_refs_for(self, proposal_id: str):
        for event in self._audit.events():
            if event.event_type == "proposal" and event.proposal_ref == proposal_id:
                return tuple(event.evidence_refs)
        return ()

    def deliver(self, frozen: FrozenProposal) -> bool:
        """Send the complete preview; True when every part plus the button
        succeeded. A failed part leaves no actionable button behind."""
        refs = self.evidence_refs_for(frozen.proposal_id)
        parts = build_preview_parts(frozen, refs)
        keyboard = {
            "inline_keyboard": [
                [{"text": "Approve", "callback_data": callback_data_for(frozen.proposal_id)}]
            ]
        }
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            self._client.send_message(
                self._chat_id, part, reply_markup=keyboard if final else None
            )
        return True

    def scan_once(self) -> list[str]:
        try:
            candidates = self.active_unapproved()
        except sqlite3.Error:
            # transient storage failure: survive and retry next scan
            self._sleep(min(5.0, self._backoff_cap))
            return []
        delivered: list[str] = []
        for frozen in candidates:
            if frozen.proposal_id in self._sent:
                continue
            try:
                self.deliver(frozen)
            except TelegramRetryAfter as error:
                # Telegram's own value is authoritative: never capped
                self._sleep(error.retry_after)
                continue
            except TelegramTransportError:
                self._sleep(min(5.0, self._backoff_cap))
                continue
            except sqlite3.Error:
                # evidence read or other storage failure: transient, survive
                self._sleep(min(5.0, self._backoff_cap))
                continue
            except ValueError:
                # Oversized preview: no actionable button is sent; the
                # proposal expires unapproved (fail-closed).
                continue
            self._sent.add(frozen.proposal_id)
            delivered.append(frozen.proposal_id)
        return delivered

    def _sleep(self, seconds: float) -> None:
        self._stop.wait(seconds)

    def run(self) -> None:
        while not self._stop.is_set():
            self.scan_once()
            self._stop.wait(self._poll_interval)


class ApprovalPoller:
    """Sequential getUpdates loop with conservative offset advancement.

    The offset advances after a committed approval or a terminal safe
    no-op rejection; a transient storage error holds the offset so the
    update is redelivered (safe: approval insertion is unique)."""

    def __init__(
        self,
        client: TelegramBotClient,
        verifier: ApprovalVerifier,
        *,
        operator_user_id: int,
        operator_chat_id: int,
        operator_identity: str,
        clock: Callable[[], datetime] | None = None,
        stop_event: threading.Event | None = None,
        backoff_cap: float = 60.0,
    ) -> None:
        self._client = client
        self._verifier = verifier
        self._user_id = operator_user_id
        self._chat_id = operator_chat_id
        self._operator_identity = operator_identity
        self._stop = stop_event or threading.Event()
        self._backoff_cap = backoff_cap
        self._offset: int | None = None
        self._bot_id: int | None = None

    @property
    def offset(self) -> int | None:
        return self._offset

    def bind_bot_identity(self) -> None:
        me = self._client.get_me()
        self._bot_id = me["id"]

    def classify_update(self, update: Mapping[str, Any]) -> tuple[str, str | None]:
        """Return (disposition, proposal_id): 'approve', 'discard', or
        'hold'. Discard is a terminal safe no-op (advance); hold means a
        transient storage failure (do not advance)."""
        callback = update.get("callback_query")
        if not isinstance(callback, dict):
            return "discard", None
        message = callback.get("message")
        sender = callback.get("from")
        if not isinstance(message, dict) or not isinstance(sender, dict):
            return "discard", None
        if message.get("from", {}).get("id") != self._bot_id:
            return "discard", None  # a callback on a message this bot did not send
        if sender.get("id") != self._user_id:
            return "discard", None  # not the configured operator
        if message.get("chat", {}).get("id") != self._chat_id:
            return "discard", None  # not the configured private chat
        proposal_id = parse_callback_data(callback.get("data", ""))
        if proposal_id is None:
            return "discard", None
        return "approve", proposal_id

    def approve(self, proposal_id: str) -> str:
        """Record one approval by proposal id; returns the outcome string."""
        try:
            self._verifier.record_approval_by_proposal_id(
                proposal_id, operator_identity=self._operator_identity
            )
            return "approved"
        except ApprovalAlreadyRecordedError:
            return "already-approved"
        except TokenExpiredError:
            return "expired"
        except ProposalError:
            return "rejected"
        except sqlite3.Error:
            return "hold"  # transient storage failure: do not advance

    def process_update(self, update: Mapping[str, Any]) -> str:
        disposition, proposal_id = self.classify_update(update)
        if disposition == "discard":
            return "discarded"
        assert proposal_id is not None
        return self.approve(proposal_id)

    def run_once(self) -> None:
        try:
            updates = self._client.get_updates(self._offset)
        except TelegramRetryAfter as error:
            self._stop.wait(error.retry_after)  # Telegram's value: authoritative
            return
        except TelegramTransportError:
            self._stop.wait(min(5.0, self._backoff_cap))
            return
        for update in updates:
            update_id = update.get("update_id")
            outcome = self.process_update(update)
            if outcome == "hold":
                return  # keep the offset: the update will be redelivered
            if isinstance(update_id, int):
                self._offset = update_id + 1
            callback_id = (update.get("callback_query") or {}).get("id")
            if callback_id:
                try:
                    self._client.answer_callback_query(
                        callback_id,
                        None if outcome == "discarded" else outcome,
                    )
                except TelegramTransportError:
                    pass  # best effort: the durable outcome stands

    def run(self) -> None:
        try:
            self.bind_bot_identity()
        except TelegramTransportError:
            return  # webhook conflict or outage: approval stays unavailable
        while not self._stop.is_set():
            self.run_once()
