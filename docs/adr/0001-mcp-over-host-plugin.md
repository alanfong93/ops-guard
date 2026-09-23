# 0001 — MCP server over host plugin or skill

- Status: Accepted
- Date: 2026-09-23
- Decided by: project definition (2026-09-19 session), recorded via issue #6

## Context

ops-guard must stay available and enforce the same trust boundary no matter
which MCP-speaking agent host the operator drives. Two host-specific
integration shapes were considered alongside an MCP server: a plugin for a
specific host, or a skill loaded by an agent.

## Decision

Expose ops-guard as an MCP server. The MCP protocol is the integration
surface — `search_runbook` is served over it today, and execution tools,
when added, will reach execution only through the gate — so the trust layer
lives in the server, and for operations submitted through it the approval
records, standing-authorization matching, execution gate, and audit log
survive a host swap.

## Rejected alternatives

- **A host plugin** (e.g. a plugin for one agent product). The boundary
  would be reimplemented or re-trusted per host, and porting hosts means
  porting (or losing) the enforcement layer.
- **A host skill** (prompt-side instructions). A skill advises the model; it
  is not enforcement and disappears with the prompt. The gate exists
  precisely because model-side advice cannot be the boundary.
- **In-process library embedding.** Enforcement inside the host's process is
  subject to the host's own controls and cannot guarantee the durable,
  transactional audit and approval records across host swaps.

## Consequences

- An MCP-speaking host that also holds separate system credentials can
  bypass ops-guard entirely. MCP portability does not stop independent
  access; preventing it requires deployment controls outside this project.
- Host-specific plugins or skills may *consume* the server's tools, but they
  never become the trust boundary.
- Tool schemas stay host-neutral; compatibility layers for non-MCP clients
  are out of scope.
