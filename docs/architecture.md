# Architecture

ops-guard is a single-operator trust layer for operations submitted by an MCP-speaking agent. It applies evidence, authorization, precondition, and audit gates before an operation reaches a managed self-hosted system. It does not prevent an agent that already has separate system access from bypassing the server.

```mermaid
C4Context
    title ops-guard system context
    Person(operator, "Operator", "Owns the self-hosted environment and grants approvals.")
    System_Ext(host, "MCP-speaking host", "An agent host that requests guidance and submits operations.")
    System(guard, "ops-guard", "Single-operator MCP trust layer for cited guidance, execution gates, and audit records.")
    System_Ext(runbooks, "Verified runbooks", "Operator-reviewed operational procedures.")
    System_Ext(approval, "Approval channel", "Independent channel that authenticates the configured operator's proposal-bound approval.")
    System_Ext(audit, "Audit storage", "Durable operational history managed by ops-guard.")
    System_Ext(systems, "Managed systems", "Self-hosted production systems reached only through approved ops-guard operations.")

    Rel(operator, host, "Directs operational work")
    Rel(host, guard, "Uses MCP")
    Rel(guard, runbooks, "Retrieves cited procedures")
    Rel(guard, approval, "Verifies proposal-bound approval")
    Rel(guard, audit, "Records requests and outcomes")
    Rel(guard, systems, "Executes gated operations")
```

The audit record is append-only operational history. It is not a tamper-evident ledger and does not itself protect against storage-level deletion; deployments needing that assurance must retain audit records independently.

The server persists the following logical records. This describes the required relationships, not a storage implementation.

```mermaid
erDiagram
    PROPOSAL ||--o| AUTHORIZATION : "uses"
    PROPOSAL ||--o{ AUDIT_RECORD : "creates"
    AUTHORIZATION ||--o{ AUDIT_RECORD : "is recorded in"
    PROPOSAL {
        string proposal_id
        blob invocation_bytes "canonical JCS bytes, immutable"
        string invocation_digest "SHA-256 of the canonical bytes"
        string token_digest "HMAC-SHA-256 of the one-time token"
        datetime created_at
        datetime expires_at "absolute"
        string state "active or consumed"
        datetime consumed_at
    }
    AUTHORIZATION {
        string type
        string operator_identity
        string invocation_binding
    }
    AUDIT_RECORD {
        string event_type
        string cited_evidence
        string observed_outcome
        datetime recorded_at
    }
```

The proposal store is transactional (SQLite today) so that token consumption can commit atomically with the pre-execution audit append; the frozen-invocation and token contract is recorded in [ADR 0002](adr/0002-frozen-invocation-audit-contract.md).
