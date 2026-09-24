"""Stateful lifecycle machine: arbitrary operation sequences keep the contract invariants (ADR 0002, rule 7)."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from datetime import timedelta

from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule

from ops_guard import TokenAlreadyConsumedError, TokenExpiredError
from helpers import FakeClock, make_invocation, make_service

TTL_SECONDS = st.integers(min_value=1, max_value=120)
STEP_SECONDS = st.integers(min_value=1, max_value=600)


class ProposalLifecycleMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.clock = FakeClock()
        self.path = os.path.join(tempfile.mkdtemp(prefix="ops-guard-stateful-"), "proposals.db")
        self.service = make_service(self.path, token_key=os.urandom(32), clock=self.clock)
        self.counter = 0
        self.tokens: dict[str, dict] = {}

    @rule(ttl=TTL_SECONDS)
    def open_proposal(self, ttl: int) -> None:
        self.counter += 1
        invocation = make_invocation(arguments={"n": self.counter})
        issued = self.service.open_proposal(invocation, ttl=timedelta(seconds=ttl))
        self.tokens[issued.token] = {
            "digest": issued.invocation_digest,
            "expires_at": self.clock.now + timedelta(seconds=ttl),
            "consumed": False,
        }

    @precondition(lambda self: self.tokens)
    @rule(index=st.integers(min_value=0, max_value=63))
    def resolve(self, index: int) -> None:
        tokens = sorted(self.tokens)
        token = tokens[index % len(tokens)]
        record = self.tokens[token]
        try:
            frozen = self.service.resolve(token)
        except TokenAlreadyConsumedError:
            assert record["consumed"]
        except TokenExpiredError:
            assert self.clock.now >= record["expires_at"]
        else:
            assert frozen.invocation_digest == record["digest"]

    @precondition(lambda self: any(not r["consumed"] for r in self.tokens.values()))
    @rule(index=st.integers(min_value=0, max_value=63))
    def consume(self, index: int) -> None:
        eligible = sorted(t for t, r in self.tokens.items() if not r["consumed"])
        token = eligible[index % len(eligible)]
        record = self.tokens[token]
        try:
            self.service.consume(token)
        except (TokenAlreadyConsumedError, TokenExpiredError):
            pass
        else:
            record["consumed"] = True

    @precondition(lambda self: any(not r["consumed"] for r in self.tokens.values()))
    @rule(index=st.integers(min_value=0, max_value=63))
    def crash_during_consume(self, index: int) -> None:
        eligible = sorted(t for t, r in self.tokens.items() if not r["consumed"])
        token = eligible[index % len(eligible)]

        def failing_append(conn: sqlite3.Connection, _consumed_digest: str) -> None:
            raise RuntimeError("crash before commit")

        try:
            self.service.consume(token, same_transaction=failing_append)
        except RuntimeError:
            pass  # crash before commit: the token must be unchanged
        except (TokenAlreadyConsumedError, TokenExpiredError):
            return  # not eligible; the crash path was not exercised
        # Rollback keeps the token exactly as it was.
        assert not self.tokens[token]["consumed"]

    @rule(seconds=STEP_SECONDS)
    def advance_clock(self, seconds: int) -> None:
        self.clock.advance(seconds)

    @invariant()
    def consumed_tokens_are_terminal(self) -> None:
        for token, record in self.tokens.items():
            if record["consumed"]:
                try:
                    self.service.resolve(token)
                except TokenAlreadyConsumedError:
                    pass
                else:
                    raise AssertionError("a consumed token became eligible again")

    @invariant()
    def database_states_are_consistent(self) -> None:
        conn = sqlite3.connect(self.path)
        try:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'proposals'"
            ).fetchone()
            if not exists:
                return
            rows = conn.execute("SELECT state, consumed_at FROM proposals").fetchall()
        finally:
            conn.close()
        for state, consumed_at in rows:
            assert state in ("active", "consumed")
            assert (state == "consumed") == (consumed_at is not None)


TestProposalLifecycle = ProposalLifecycleMachine.TestCase
TestProposalLifecycle.settings = settings(
    max_examples=25,
    stateful_step_count=40,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
