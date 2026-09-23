"""ops-guard proposal lifecycle and approval verification.

Implements the frozen-invocation and one-time-token contract recorded in
docs/adr/0002-frozen-invocation-audit-contract.md and the approval verifier
boundary in docs/adr/0003-approval-verifier-boundary.md. The execution token
is a capability handle for one frozen invocation; it is not itself
authorization — authorization is standing authorization or proposal-bound
approval, verified separately.
"""

from ops_guard.approvals import (
    ApprovalDecision,
    ApprovalRecord,
    ApprovalStore,
    ApprovalVerifier,
)
from ops_guard.audit import (
    AUDIT_SCHEMA_VERSION,
    DEFAULT_SENSITIVE_KEYS,
    AuditEvent,
    AuditLog,
    AuditStore,
    AuditWriteFailure,
    redact,
)
from ops_guard.errors import (
    ApprovalAlreadyRecordedError,
    ApprovalError,
    ApprovalOperatorMismatchError,
    ApprovalReplayedError,
    HostSuppliedApprovalError,
    InvocationMismatchError,
    ProposalError,
    TokenAlreadyConsumedError,
    TokenExpiredError,
    UnknownTokenError,
)
from ops_guard.invocation import Invocation
from ops_guard.proposals import FrozenProposal, IssuedProposal, ProposalService
from ops_guard.store import ProposalStore

__all__ = [
    "AUDIT_SCHEMA_VERSION",
    "ApprovalAlreadyRecordedError",
    "ApprovalDecision",
    "ApprovalError",
    "ApprovalOperatorMismatchError",
    "ApprovalRecord",
    "ApprovalReplayedError",
    "ApprovalStore",
    "ApprovalVerifier",
    "AuditEvent",
    "AuditLog",
    "AuditStore",
    "AuditWriteFailure",
    "DEFAULT_SENSITIVE_KEYS",
    "FrozenProposal",
    "HostSuppliedApprovalError",
    "Invocation",
    "InvocationMismatchError",
    "IssuedProposal",
    "ProposalError",
    "ProposalService",
    "ProposalStore",
    "TokenAlreadyConsumedError",
    "TokenExpiredError",
    "UnknownTokenError",
    "redact",
]
