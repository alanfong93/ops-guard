# 0010 — Telegram approval transport

- Status: Accepted
- Date: 2026-09-29
- Decided by: plan-loop design (issue #61); implemented with this issue
- Consumers: #64 (proposal-bound script execution demonstration)

## Context

ADR 0003 fixes the internal approval-verifier boundary and leaves transport open. ops-guard exposes proposal tokens once to the MCP host and never persists the raw token. The current OpenCode session exposes n8n workflow-management tools, while the deployed proposal runtime's exact n8n permissions are unverified. A live `pc-enforcer` container polls Telegram. n8n currently uses existing Telegram credentials for outbound workflows.

## Decision

Deliver approvals with a fresh dedicated Telegram bot polled by the ops-guard server through Telegram Bot API `getUpdates` (long poll, `allowed_updates=["callback_query"]`, never a webhook). Only a callback from the configured numeric operator identity in the configured private chat can record approval. Callback data carries a proposal ID, never the raw proposal token; the internal verifier resolves and revalidates the frozen proposal by ID inside its existing transaction and keys the approval by the stored token digest. The server does not expose an approval MCP tool or public HTTP endpoint. The bot token and approval authority are not made available through the proposing MCP tool/configuration surface; deployments that cannot establish this boundary keep approval unavailable and execution fail-closed. A proposal preview is delivered to the configured private Telegram chat, contains the approval-relevant frozen invocation and evidence reference, applies the current key-based redaction policy, and contains no raw token. Callers must not place credentials in invocation arguments.

The transport is opt-in (`OPS_GUARD_APPROVALS_ENABLED`): when disabled, no approval can be recorded and gated execution remains fail-closed; when enabled, missing or malformed settings fail startup without printing secrets. If Telegram reports a webhook already set for the bot, the poller stays unavailable and the webhook is left untouched. Updates are processed sequentially; the offset advances after a committed approval or a terminal safe no-op rejection, never after a transient storage error — duplicate delivery is safe because approval insertion is unique and replay cannot create another approval. A proposal without approval simply expires; no rejection state exists and no callback can extend a proposal's expiry.

## Rejected alternatives

- Reuse an existing bot — it is already used by active systems, including a live poller.
- n8n callback before proving the proposing runtime cannot edit or execute that workflow.
- Webhooks — adds an inbound endpoint and competes with `getUpdates` for the same bot.
- Host-supplied approval claims — contradicts ADR 0003.

## Consequences

A Telegram outage, missing configuration, webhook conflict, or expired proposal leaves no approval; no automatic renewal or alternate approval route exists. Telegram update retention is at most 24 hours, but the proposal's 15-minute expiry controls authorization. Duplicate notifications and redelivered updates may occur; one-approval and replay rules make them non-authorizing. Telegram receives the operator-facing proposal preview, so secret values must remain outside invocation arguments. Exact Telegram Bot API behavior is documented at https://core.telegram.org/bots/api.
