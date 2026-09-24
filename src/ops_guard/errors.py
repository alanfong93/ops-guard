"""Typed rejections for the proposal lifecycle (ADR 0002, rule 5).

Every rejection happens before any execution or side effect.
"""


class ProposalError(Exception):
    """Base class for proposal-lifecycle rejections."""


class UnknownTokenError(ProposalError):
    """No proposal is bound to the presented token."""


class InvocationMismatchError(ProposalError):
    """The presented expected invocation digest differs from the frozen one."""


class TokenAlreadyConsumedError(ProposalError):
    """The proposal is in the terminal consumed state; tokens never reset."""


class TokenExpiredError(ProposalError):
    """The current time is at or past the proposal's absolute expiry."""


class ApprovalError(Exception):
    """Base class for approval-verifier rejections (ADR 0003)."""


class HostSuppliedApprovalError(ApprovalError):
    """No server-recorded approval exists for the presented token."""


class ApprovalOperatorMismatchError(ApprovalError):
    """The operator identity is not the configured operator of this record."""


class ApprovalReplayedError(ApprovalError):
    """The approval is already in the terminal used state."""


class ApprovalAlreadyRecordedError(ApprovalError):
    """A proposal carries at most one approval; a correction is a new proposal."""


class GateConfigurationError(ValueError):
    """The gate was configured with stores that cannot form one durable
    transaction boundary; rejected at initialization, before any dispatch."""
