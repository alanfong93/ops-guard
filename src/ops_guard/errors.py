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
