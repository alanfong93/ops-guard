# Who
Alan, driving an AI agent — OpenCode today, any MCP-speaking agent (OpenClaw, Hermes) tomorrow — against his self-hosted production systems.

# What
An MCP server that provides cited runbook guidance and enforces human-defined authorization for operations submitted through it.

# Problem
An agent's proposed operational action needs traceable procedural evidence, enforceable permission, and a durable record; the agent's own assertions are insufficient.

# How
Retrieve guidance from human-verified runbooks with supporting passages. Execute only under applicable standing authorization or fresh human approval, and record the evidence, authorization, and observed outcome.

# Required capabilities and constraints

- A **human-verified runbook** is a curated procedure whose guidance and referenced operation have been reviewed for this project.
- **Standing authorization** binds a permitted invocation to the verified script, action, target, arguments, and preconditions; it is the basis for unattended execution.
- A **declared baseline** is the named retrieval comparator and assessment method recorded with the published result.
- An **observed outcome** is the execution result recorded after the operation, including an explicitly unknown outcome when completion cannot be confirmed.
- **Required procedural evidence** is a cited passage from a human-verified runbook sufficient to identify the intended operation and its conditions; without it, fresh approval alone is not enough to execute.
- **Judge confidence** is an advisory estimate attached to the judge's risk assessment; it is not authorization or a safety guarantee.
- Return cited runbook guidance; absent required procedural evidence, refuse execution.
- Bind standing authorization to the verified script and complete permitted invocation: action, target, arguments, and preconditions. Matching invocations may run unattended.
- Require fresh human approval for model-composed fixes and invocations outside standing authorization. Approval must bind to the specific proposal and cannot be supplied or manufactured by the proposing agent.
- Enforce authorization in the server. Judge assessments are advisory: neither an assessment nor judge unavailability grants or withdraws authorization.
- Keep durable audit records of requests, returned guidance, proposals, authorization used, execution, and observed outcomes. Refuse execution if required audit recording fails.
- Publish retrieval-quality evidence against a declared baseline, without treating that score as proof of operational safety.
- Make the protection boundary explicit: ops-guard governs calls through its server; preventing independent agent access requires deployment controls.

# Done when

An agent can obtain cited guidance, execute an invocation covered by standing authorization without fresh approval, and execute other permitted proposals only with genuine proposal-bound human approval. Missing evidence, missing authorization, and audit-recording failure prevent execution. Judge advice cannot authorize execution. These behaviours and their audit records are demonstrated, and retrieval outperforms the declared baseline on a documented assessment.

# Not this project

Being an agent. Model hosting or fine-tuning. A UI. Multi-tenancy. A full ITSM tool. Guaranteeing arbitrary agent behaviour outside the server's control.
