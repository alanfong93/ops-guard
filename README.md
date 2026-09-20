# ops-guard

**An MCP server for cited runbook guidance, controlled execution, and durable audit records.**

Cited answers from your runbooks. Standing authorization for permitted invocations, fresh approval for model-composed fixes, and an audit log of what happened. Retrieval results are published as evidence, not as a claim of operational safety.

Works with any MCP-speaking host: Claude Code, OpenClaw, Hermes Agent, and anything else that adopts the protocol.

**Status: project definition complete. Nothing is built yet.**

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

### 2. Authorization for submitted operations

```
propose_fix(problem) -> { plan, token }  # changes nothing
execute_fix(token)   -> runs only under standing authorization or proposal-bound approval
```

Proposing and executing are separate calls. An invocation covered by standing authorization may run unattended. A model-composed fix or invocation outside that authorization requires fresh human approval bound to the specific proposal; the proposing agent cannot supply or manufacture that approval.

**The gate lives in the server, not in the host.** That is the design decision this project exists to test. Approval is normally a client concern, which means it disappears the moment you swap agents. Here it survives whatever is driving.

### 3. An audit log

Append-only. Every call: what was asked, what came back, what executed, which approval authorised it.

### 4. An eval harness

Not an MCP tool. A test suite in this repo: a documented assessment set with reference retrieval results, scored against a declared retrieval baseline. Retrieval evidence is separate from judgment, authorization, and execution evidence.

**The MCP server is the product. The eval harness is the evidence.** A safety claim with no number behind it is decoration.

## How it sits between the agent and production

For operations submitted through ops-guard, the server applies the gate before execution. Preventing an agent from using an independent path to the systems requires deployment controls outside this server.

```mermaid
flowchart TD
    ALAN["Alan"] -->|'update n8n'| AGENT{{"Agent<br>OpenCode · OpenClaw · Hermes · any MCP host"}}

    subgraph OPSGUARD["ops-guard MCP server — checks submitted operations"]
        direction TB
        SR["search_runbook(question)<br>→ answer + source passage"]
        RB[("runbooks/<br>verified procedures only")]
        PF["propose_fix(problem)<br>→ plan + one-time token<br>changes NOTHING")]
        JD{"Judge<br>local LLM via Ollama<br>risk class + confidence"}
        GATE{"Gate check"}
    AL[("standing authorization<br>script + action + target + args + preconditions")]
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

    GATE -->|authorized invocation<br>may run unattended, always logged| EF["execute_fix(token)"]
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

**Design decisions from the 2026-09-19 project-definition session** (Python + FastMCP; judge included in the current design):

1. **Fixes come in two authorization paths.** An invocation covered by standing authorization for an *allowlisted, human-verified script* may run unattended (always logged). A *model-composed* fix or invocation outside that authorization requires fresh human approval.
2. **The judge is advisory in the current design.** It labels every proposal with a risk class and confidence; those labels are logged but never grant or withdraw authorization. Judge unavailability does not grant authorization.
3. **The allowlist anchors to the script itself** (exact path/content), not to the model's description of it — a model cannot get arbitrary commands through by naming them "update n8n".
 4. **Agent-agnostic server; OpenCode is the first host** (dogfooded daily). OpenClaw/Hermes compatibility is free via MCP.

**Adversarial-review amendments (GPT-6 Astra + DeepSeek cross-check, 2026-09-19):**

 5. **An allowlisted script authorizes the *invocation*, not just the content.** The allowlist binds action, target, arguments, and preconditions — verified content run at the wrong moment or with wrong arguments is still a failure.
 6. **Approval cannot be agent-supplied.** Human approval arrives through a separate channel, bound to the frozen proposal; tokens are consumed atomically. The proposing agent can never manufacture the permission the gate exists to require.
 7. **Model consensus escalates; it never clears.** Reviewer models may force human review (veto-side only). Only a standing rule the operator wrote, or a click the operator made, authorizes execution. Whether and when tribunal-as-triage belongs is left for stage-loop to determine from audit agreement data.
 8. **Judge authority is explicit.** Its assessment and unavailability never grant authorization. Required audit recording and authorization checks remain server controls; detailed mechanics are left for stage-loop.

Also recorded for stage-loop to assess: a durable execution state machine (`proposed → authorized → started → succeeded/failed/outcome-unknown`), BM25 alongside the naive keyword baseline, four separated evidence layers in the eval (retrieval / judgment / authorization / execution), and public example runbooks that stay executable — placeholders only in machine-specific config.

## Why MCP rather than a plugin

A plugin works in one host. A skill works in one host. The Model Context Protocol works across all of them, and is the nearest thing the agent ecosystem has to a shared standard.

Given that agent tooling is churning fast, and users are already migrating between hosts, anything written against a single host's plugin API is a bet on which host wins. This is deliberately not that bet.

## Scope

**In:** retrieval with citations, the propose/execute split, approval enforcement, audit logging, the eval harness and its baseline.

**Out, for now:** being an agent, model hosting or fine-tuning, a UI, multi-tenancy, anything resembling a full ITSM tool.

## Licence

Not yet chosen.
