# ops-guard

**An MCP server that makes an AI agent safe enough to point at production.**

Cited answers from your runbooks. A two-step approval gate before anything destructive runs. An audit log of everything it did. And a published accuracy score, so the claim is checkable rather than asserted.

Works with any MCP-speaking host: Claude Code, OpenClaw, Hermes Agent, and anything else that adopts the protocol.

**Status: design stage. Nothing is built yet.**

---

## The problem

Agents like OpenClaw and Hermes can already act on your machine. What they cannot do is convince anyone to let them near production, because there is no way to answer three questions:

1. **Was it right?** The agent asserts an answer. Nothing shows where it came from or how often it is wrong.
2. **What if it is wrong?** Nothing stands between "the model decided to restart the database" and the database restarting.
3. **What did it actually do?** No durable record of the action, the reasoning, or the authorisation.

Until those are answered, the honest advice stays what it is today: keep the agent in tightly scoped, well-observed environments. That is a polite way of saying do not let it near anything that matters.

`ops-guard` is an attempt at the missing layer, not another agent.

## What it does

### 1. Cited retrieval

```
search_runbook(question) -> answer + the source passage it came from
```

The answer arrives with its evidence attached, so a human can check the reasoning instead of trusting the output. Same principle throughout: **show the working, never just the verdict.**

### 2. A two-step approval gate

```
propose_fix(problem)          -> { plan, token }     # changes nothing
execute_fix(token, approval)  -> refuses without a human approval
```

Proposing and executing are separate calls. The first is always safe to run. The second will not proceed without an approval a human supplied.

**The gate lives in the server, not in the host.** That is the design decision this project exists to test. Approval is normally a client concern, which means it disappears the moment you swap agents. Here it survives whatever is driving.

### 3. An audit log

Append-only. Every call: what was asked, what came back, what executed, which approval authorised it.

### 4. An eval harness

Not an MCP tool. A test suite in this repo: a fixed question set with known-correct answers, scored against the retrieval, with a naive keyword-search baseline for comparison.

**The MCP server is the product. The eval harness is the evidence.** A safety claim with no number behind it is decoration.

## Why MCP rather than a plugin

A plugin works in one host. A skill works in one host. The Model Context Protocol works across all of them, and is the nearest thing the agent ecosystem has to a shared standard.

Given that agent tooling is churning fast, and users are already migrating between hosts, anything written against a single host's plugin API is a bet on which host wins. This is deliberately not that bet.

## Scope

**In:** retrieval with citations, the propose/execute split, approval enforcement, audit logging, the eval harness and its baseline.

**Out, for now:** being an agent, model hosting or fine-tuning, a UI, multi-tenancy, anything resembling a full ITSM tool.

## Licence

Not yet chosen.
