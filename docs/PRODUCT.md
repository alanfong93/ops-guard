# Who
The operator of one self-hosted environment, using an MCP-speaking agent such as OpenCode, OpenClaw, or Hermes. Alan's systems are the initial deployment; this is not a shared-operator or multi-tenant service.

# What
An MCP server that provides cited runbook guidance and enforces human-defined authorization for operations submitted through it.

# Problem
An agent's proposed operational action needs traceable procedural evidence, enforceable permission, and a durable record; the agent's own assertions are insufficient.

# How
Retrieve guidance from human-verified runbooks with supporting passages. Execute only when required procedural evidence, preconditions, audit recording, and applicable standing authorization or fresh human approval all pass; record the evidence, authorization, and observed outcome.

# Required capabilities and constraints

- A **human-verified runbook** is a curated procedure whose guidance and referenced operation have been reviewed for this project.
- **Standing authorization** binds a permitted invocation to the verified script, action, target, arguments, and preconditions; it is the basis for unattended execution.
- A **declared baseline** is the named retrieval comparator and assessment method recorded with the published result.
- An **observed outcome** is the execution result recorded after the operation, including an explicitly unknown outcome when completion cannot be confirmed.
- **Required procedural evidence** is a cited passage from a human-verified runbook sufficient to identify the intended operation and its conditions; without it, fresh approval alone is not enough to execute.
- **Proposal-bound approval** is a one-time permission from a configured operator identity through an approval channel independent of the proposing MCP host. It binds the frozen proposal and expiry, and is consumed atomically.
- A **judge advisory signal** is an estimate attached to the judge's risk assessment. Its meaning and derivation are recorded; it is not authorization, a safety guarantee, or evidence that the assessment is correct.
- Return cited runbook guidance; absent required procedural evidence, refuse execution.
- Bind standing authorization to the verified script and complete permitted invocation: action, target, arguments, and preconditions. Matching invocations may run unattended.
- Require fresh human approval for model-composed fixes and invocations outside standing authorization. Approval must bind to the specific proposal and cannot be supplied or manufactured by the proposing agent.
- Enforce authorization in the server. Required procedural evidence and preconditions are checked independently of model judgment; neither an assessment nor judge unavailability grants or withdraws authorization. A favorable assessment cannot substitute for missing evidence, an unmet precondition, or an independently observed failure.
- Keep append-only durable audit records of requests, returned guidance, proposals, authorization used, execution, and observed outcomes. The audit log is operational history, not a tamper-evident ledger or protection against storage-level deletion. Where an advisory judgment is used, retain the evidence snapshot, model identity and relevant inference settings, versioned rubric and state schema, exact candidate menu where applicable, thresholds, and result or failure. Refuse execution if required audit recording fails.
- Publish retrieval-quality evidence against a declared baseline, without treating that score as proof of operational safety.
- Make the protection boundary explicit: ops-guard governs calls through its server; preventing independent agent access requires deployment controls.

# Done when

An agent can obtain cited guidance, execute an invocation covered by standing authorization without fresh approval, and execute other permitted proposals only with genuine proposal-bound human approval. Missing evidence, unmet preconditions, missing authorization, and audit-recording failure prevent execution. Judge advice cannot authorize execution. These behaviours and their audit records are demonstrated, and retrieval outperforms the declared baseline on a documented assessment.

# Not this project

Being an agent. Model hosting or fine-tuning. A UI. Multi-tenancy. A full ITSM tool. Guaranteeing arbitrary agent behaviour outside the server's control.
