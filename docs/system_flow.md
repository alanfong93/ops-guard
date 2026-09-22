# System Flow

```mermaid
flowchart TD
    HOST["MCP-speaking host"] -->|"search_runbook(question)"| RETRIEVE["Retrieve cited guidance"]
    RUNBOOKS[("Human-verified runbooks")] --> RETRIEVE
    RETRIEVE -->|"answer + supporting passage"| HOST
    RETRIEVE -.-> AUDIT_LOG[("Durable audit record")]

    HOST -->|"propose_fix(problem)"| PROPOSE["Freeze proposal and issue one-time token"]
    PROPOSE --> EVIDENCE{"Required procedural evidence?"}
    EVIDENCE -->|"No"| REFUSE["Refuse execution and record reason"]
    EVIDENCE -->|"Yes"| PRECONDITIONS{"Preconditions met?"}
    PRECONDITIONS -->|"No"| REFUSE
    PRECONDITIONS -->|"Yes"| AUTH{"Standing authorization applies?"}
    AUTH -->|"Yes"| AUDIT{"Audit record available?"}
    AUTH -->|"No"| APPROVAL{"Genuine proposal-bound approval?"}
    APPROVAL -->|"No or expired"| REFUSE
    APPROVAL -->|"Yes"| AUDIT
    AUDIT -->|"No"| REFUSE
    AUDIT -->|"Yes"| EXECUTE["Execute submitted operation"]
    EXECUTE --> OUTCOME["Record observed or unknown outcome"]
    PROPOSE -.-> AUDIT_LOG
    REFUSE --> AUDIT_LOG
    OUTCOME --> AUDIT_LOG

    style REFUSE fill:#fecaca,stroke:#991b1b,color:#000
    style EXECUTE fill:#bbf7d0,stroke:#166534,color:#000
    style AUDIT_LOG fill:#e0e7ff,stroke:#3730a3,color:#000
```

The judge may attach an advisory risk assessment to a proposal, but it does not alter any gate in this flow and cannot authorize execution.
