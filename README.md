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

## How it sits between the agent and production

The agent has no direct line to the systems it operates — no shell shortcut. Every operation passes through the gate, whatever agent is driving.

```mermaid
flowchart TD
    ALAN["Alan"] -->|'update n8n'| AGENT{{"Agent<br>OpenCode · OpenClaw · Hermes · any MCP host"}}

    subgraph OPSGUARD["ops-guard MCP server — the only path to production"]
        direction TB
        SR["search_runbook(question)<br>→ answer + source passage"]
        RB[("runbooks/<br>verified procedures only")]
        PF["propose_fix(problem)<br>→ plan + one-time token<br>changes NOTHING")]
        JD{"Judge<br>local LLM via Ollama<br>risk class + confidence"}
        GATE{"Gate check"}
        AL[("allowlist<br>verified script paths")]
        AUD[("append-only audit log")]
    end

    subgraph PROD["Production systems"]
        SYS1[n8n]
        SYS2[OpenWebUI / Ollama]
        SYS3[Docker / backups]
    end

    AGENT -->|1. asks| SR
    RB --- SR
    SR -->|2. cited steps| AGENT
    AGENT -->|3. 'do it'| PF
    PF -->|4. label this| JD
    JD -->|5. safe / review / critical| GATE
    AL --- GATE

    GATE -->|allowlisted script<br>auto-runs, always logged| EF["execute_fix(token)"]
    GATE -->|model-composed fix<br>needs approval| ALAN
    ALAN -->|approve| EF
    ALAN -->|deny| NO["refused — nothing ran"]

    EF -->|6. the only door| SYS1
    EF --> SYS2
    EF --> SYS3

    SR -.->|every call| AUD
    PF -.-> AUD
    EF -.->|asked · returned · executed · who approved| AUD

    style ALAN fill:#fef3c7,stroke:#92400e,color:#000
    style AGENT fill:#dbeafe,stroke:#1e40af,color:#000
    style OPSGUARD fill:#dcfce7,stroke:#166534,color:#000
    style PROD fill:#fee2e2,stroke:#991b1b,color:#000
    style NO fill:#fecaca,stroke:#991b1b,color:#000
    style EF fill:#bbf7d0,stroke:#166534,color:#000
```

**Design decisions from the 2026-09-19 session** (Python + FastMCP; judge in v1):

1. **Fixes come in two kinds.** A fix that maps to an *allowlisted, human-verified script* auto-executes (always logged) — the model generates nothing, it invokes a known procedure. A *model-composed* fix requires human approval before execution.
2. **The judge is advisory in v1.** It labels every proposal with a risk class and confidence; those labels are logged but never veto a standing human decision. The audit trail of label-vs-decision is the evidence that would justify auto-execution of low-risk novel fixes later.
3. **The allowlist anchors to the script itself** (exact path/content), not to the model's description of it — a model cannot get arbitrary commands through by naming them "update n8n".
 4. **Agent-agnostic server; OpenCode is the first host** (dogfooded daily). OpenClaw/Hermes compatibility is free via MCP.

## Why MCP rather than a plugin

A plugin works in one host. A skill works in one host. The Model Context Protocol works across all of them, and is the nearest thing the agent ecosystem has to a shared standard.

Given that agent tooling is churning fast, and users are already migrating between hosts, anything written against a single host's plugin API is a bet on which host wins. This is deliberately not that bet.

## Scope

**In:** retrieval with citations, the propose/execute split, approval enforcement, audit logging, the eval harness and its baseline.

**Out, for now:** being an agent, model hosting or fine-tuning, a UI, multi-tenancy, anything resembling a full ITSM tool.

## Licence

Not yet chosen.
