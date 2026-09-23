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
    RUNBOOK_REVISION ||--|{ PASSAGE : "contains"
    STANDING_AUTHORIZATION }o--|| RUNBOOK_REVISION : "draws evidence from"
    PROPOSAL }o--|| RUNBOOK_REVISION : "cites evidence from"
    PROPOSAL ||--o| APPROVAL : "is authorized by"
    PROPOSAL ||--o| AUTHORIZATION : "uses"
    PROPOSAL ||--o{ AUDIT_RECORD : "creates"
    AUTHORIZATION ||--o{ AUDIT_RECORD : "is recorded in"
    STANDING_AUTHORIZATION {
        string authorization_id
        string script_path
        string script_sha256 "verified script identity"
        string action
        string target
        string arguments "exact permitted values"
        string preconditions "exact permitted pairs, order significant"
        string runbook_revision_hash
    }
    RUNBOOK_REVISION {
        string runbook_id
        string revision
        string content_hash "SHA-256 of literal canonical body - changed hash voids citations"
        string operation_action
        string operation_target
        string preconditions "JSON name/expected pairs"
        string verification_verifier
        datetime verification_verified_at
        string applicability
    }
    PASSAGE {
        string locator "unique within the revision"
        string text
    }
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
    APPROVAL {
        string approval_id
        string token_digest "unique - one approval per proposal"
        string proposal_id "copied from the frozen proposal"
        string operator_identity "configured operator"
        string invocation_digest "copied from the frozen proposal"
        string runbook_revision_hash "copied from the frozen proposal"
        datetime expires_at "copied from the frozen proposal"
        datetime created_at
        string state "recorded or used"
        datetime used_at
    }
    AUTHORIZATION {
        string type
        string operator_identity
        string invocation_binding
    }
    AUDIT_RECORD {
        integer sequence "globally monotonic, gapless"
        string event_id
        integer schema_version
        datetime recorded_at
        string event_type
        string correlation_id
        string proposal_ref
        string invocation_digest
        string evidence_refs "JSON array of cited references"
        string authorization_path
        string judge_snapshot "redacted, when present"
        string payload "redacted canonical JSON"
        string outcome "success, failure, unknown, or refused"
        string failure_code
    }
```

The proposal store is transactional (SQLite today) so that token consumption can commit atomically with the pre-execution audit append; the frozen-invocation and token contract is recorded in [ADR 0002](adr/0002-frozen-invocation-audit-contract.md). An approval is recorded only on the internal operator path, is single-use, and its recorded-to-used transition joins the token-consumption transaction ([ADR 0003](adr/0003-approval-verifier-boundary.md)). Audit events are insert-only with write-time redaction: sensitive values are replaced by an explicit redaction marker plus a keyed fingerprint; the audit interface exposes append and read only. Runbook revisions are immutable and human-verified ([runbook format](runbook-format.md)): a citation qualifies as required procedural evidence only when it is bound to a revision whose content hash recomputes exactly — a changed hash voids the citation.
