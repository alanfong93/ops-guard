"""ops-guard proposal lifecycle.

Implements the frozen-invocation and one-time-token contract recorded in
docs/adr/0002-frozen-invocation-audit-contract.md. The execution token is a
capability handle for one frozen invocation; it is not itself authorization.
"""

from ops_guard.errors import (
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
    "FrozenProposal",
    "Invocation",
    "InvocationMismatchError",
    "IssuedProposal",
    "ProposalError",
    "ProposalService",
    "ProposalStore",
    "TokenAlreadyConsumedError",
    "TokenExpiredError",
    "UnknownTokenError",
]
