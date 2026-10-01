"""The staged runner contract (issue #64; ADR 0012).

Harmless fixture scripts only: real python processes executing tiny
scripts through the production run_staged path.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

from datetime import timedelta

from helpers import FakeClock, binding_template, make_invocation

SCRIPT_BYTES = b'#!/bin/sh\necho ok\n'
from helpers import make_observer_registry, make_policy_document, load_test_policy, make_execution_catalog
from ops_guard import ApprovalStore, ApprovalVerifier, AuditLog, AuditStore, ProposalService, ProposalStore
from ops_guard import Citation
from ops_guard.execution_binding import RunnerProfile, run_staged

PROFILE = RunnerProfile(
    profile_id="test-runner",
    executable=sys.executable,
    executable_sha256="placeholder-set-in-fixture",
    argv=(sys.executable,),
    working_directory=".",
    env_allowlist=("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "COMSPEC"),
    timeout_seconds=10,
)


def _with_hash(profile: RunnerProfile) -> RunnerProfile:
    from dataclasses import replace

    digest = __import__("hashlib").sha256(
        open(profile.executable, "rb").read()
    ).hexdigest()
    return replace(profile, executable_sha256=digest)


def _fixture(body: str) -> bytes:
    return body.encode("utf-8")


INVOCATION = {
    "action": "restart",
    "target": "n8n",
    "arguments": {"service": "n8n"},
    "preconditions": [{"name": "docker-engine", "expected": "running"}],
}


def test_success_path(tmp_path) -> None:
    profile = _with_hash(PROFILE)
    result = run_staged(
        profile,
        script_path="fixture.py",
        script_bytes=_fixture("import json,sys; sys.exit(0)"),
        script_sha256=__import__("hashlib").sha256(
            _fixture("import json,sys; sys.exit(0)")
        ).hexdigest(),
        invocation=INVOCATION,
    )
    assert result.outcome == "success"
    assert result.failure_code is None


def test_non_zero_exit_maps_to_failure_with_code(tmp_path) -> None:
    profile = _with_hash(PROFILE)
    body = _fixture("import sys; sys.exit(3)")
    result = run_staged(
        profile,
        script_path="fixture.py",
        script_bytes=body,
        script_sha256=__import__("hashlib").sha256(body).hexdigest(),
        invocation=INVOCATION,
    )
    assert result.outcome == "failure"
    assert result.failure_code == "non-zero-exit"


def test_staged_hash_mismatch_refuses_before_spawn(tmp_path, monkeypatch) -> None:
    import subprocess as sp

    profile = _with_hash(PROFILE)
    spawned = []
    monkeypatch.setattr(sp, "Popen", lambda *a, **k: spawned.append(1))
    result = run_staged(
        profile,
        script_path="fixture.py",
        script_bytes=_fixture("pass"),
        script_sha256="f" * 64,  # does not match the staged bytes
        invocation=INVOCATION,
    )
    assert result.outcome == "failure"
    assert result.failure_code == "staged-hash-mismatch"
    assert spawned == []  # never spawned


def test_runner_executable_mismatch_detected(tmp_path) -> None:
    profile = RunnerProfile(
        profile_id="wrong-hash",
        executable=sys.executable,
        executable_sha256="f" * 64,  # not the real interpreter digest
        argv=(sys.executable,),
        working_directory=".",
        env_allowlist=("PATH",),
        timeout_seconds=10,
    )
    body = _fixture("pass")
    result = run_staged(
        profile,
        script_path="fixture.py",
        script_bytes=body,
        script_sha256=__import__("hashlib").sha256(body).hexdigest(),
        invocation=INVOCATION,
    )
    assert result.outcome == "failure"
    assert result.failure_code == "runner-executable-mismatch"


def test_timeout_maps_to_unknown(tmp_path) -> None:
    from dataclasses import replace

    profile = replace(_with_hash(PROFILE), timeout_seconds=1)
    body = _fixture("import time; time.sleep(10)")
    result = run_staged(
        profile,
        script_path="fixture.py",
        script_bytes=body,
        script_sha256=__import__("hashlib").sha256(body).hexdigest(),
        invocation=INVOCATION,
    )
    assert result.outcome == "unknown"
    assert result.failure_code == "executor-timeout"


def test_temp_directory_is_removed(tmp_path) -> None:
    import glob
    import tempfile as tf

    profile = _with_hash(PROFILE)
    before = set(glob.glob(os.path.join(tf.gettempdir(), "ops-guard-exec-*")))
    body = _fixture("pass")
    run_staged(
        profile,
        script_path="fixture.py",
        script_bytes=body,
        script_sha256=__import__("hashlib").sha256(body).hexdigest(),
        invocation=INVOCATION,
    )
    after = set(glob.glob(os.path.join(tf.gettempdir(), "ops-guard-exec-*")))
    assert after - before == set()  # no leftovers beyond pre-existing ones


def test_stdin_receives_canonical_invocation(tmp_path) -> None:
    """The child's stdin is exactly the canonical JCS invocation bytes."""
    from dataclasses import replace

    from ops_guard.invocation import canonicalize_json

    profile = replace(_with_hash(PROFILE), working_directory=str(tmp_path))
    fixture = _fixture(
        "import hashlib,sys\n"
        "data = sys.stdin.buffer.read()\n"
        "open('stdin-digest', 'wb').write(hashlib.sha256(data).hexdigest().encode())\n"
    )
    result = run_staged(
        profile,
        script_path="fixture.py",
        script_bytes=fixture,
        script_sha256=__import__("hashlib").sha256(fixture).hexdigest(),
        invocation=INVOCATION,
    )
    assert result.outcome == "success"
    with open(tmp_path / "stdin-digest", "rb") as handle:
        assert handle.read().decode() == __import__("hashlib").sha256(
            canonicalize_json(INVOCATION)
        ).hexdigest()


def test_environment_allowlist_strips_host_values(tmp_path) -> None:
    profile = _with_hash(PROFILE)
    os.environ["OPS_GUARD_LEAK_CANARY"] = "secret-value"
    fixture = _fixture(
        "import os,sys\n"
        "print('LEAK' if 'OPS_GUARD_LEAK_CANARY' in os.environ else 'CLEAN')\n"
    )
    result = run_staged(
        profile,
        script_path="fixture.py",
        script_bytes=fixture,
        script_sha256=__import__("hashlib").sha256(fixture).hexdigest(),
        invocation=INVOCATION,
    )
    assert result.outcome == "success"
    # the canary must not have leaked into the child environment
    assert os.environ["OPS_GUARD_LEAK_CANARY"] == "secret-value"  # host intact
    del os.environ["OPS_GUARD_LEAK_CANARY"]


def test_output_limit_enforced(tmp_path) -> None:
    from dataclasses import replace

    profile = replace(_with_hash(PROFILE), output_limit=1024)
    body = _fixture("import sys; sys.stdout.write('x' * 4096); sys.exit(0)")
    result = run_staged(
        profile,
        script_path="fixture.py",
        script_bytes=body,
        script_sha256=__import__("hashlib").sha256(body).hexdigest(),
        invocation=INVOCATION,
    )
    assert result.outcome == "failure"
    assert result.failure_code == "output-limit"

def test_large_stdin_to_quiet_child_times_out(tmp_path) -> None:
    """A child that never reads stdin cannot block the bounded dispatch: a
    payload larger than the pipe buffer with a hung child maps to
    unknown/executor-timeout within the budget."""
    import hashlib as hl
    import time as tm
    from dataclasses import replace

    profile = replace(
        RunnerProfile(
            profile_id="quiet-hung",
            executable=sys.executable,
            executable_sha256=hl.sha256(open(sys.executable, "rb").read()).hexdigest(),
            argv=(sys.executable,),
            working_directory=str(tmp_path),
            env_allowlist=("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "COMSPEC"),
            timeout_seconds=1,
        ),
    )
    big_invocation = {
        "action": "restart",
        "target": "n8n",
        "arguments": {"blob": "x" * 65536},
        "preconditions": [],
    }
    fixture = _fixture("import time; time.sleep(30)")
    started = tm.monotonic()
    result = run_staged(
        profile,
        script_path="fixture.py",
        script_bytes=fixture,
        script_sha256=hl.sha256(fixture).hexdigest(),
        invocation=big_invocation,
    )
    elapsed = tm.monotonic() - started
    assert result.outcome == "unknown"
    assert result.failure_code == "executor-timeout"
    assert elapsed < 10, f"dispatch blocked {elapsed:.1f}s past the budget"


def test_illegal_runner_outcome_records_failure(tmp_path, monkeypatch) -> None:
    """A runner returning an illegal outcome records failure/executor-error
    and consumes the token — never leaves a started-no-outcome gap."""
    import tempfile as tf
    from pathlib import Path

    from ops_guard import (
        ApprovalStore,
        ApprovalVerifier,
        AuditLog,
        AuditStore,
        ExecutionGate,
        ExecutionRequest,
    )
    from ops_guard.retrieval import RunbookLibrary
    from tests_helpers_runbook import VALID_RUNBOOK

    from ops_guard.execution_binding import RunnerResult

    clock = FakeClock()
    db = str(Path(tf.mkdtemp()) / "gate.db")
    audit = AuditLog(AuditStore(db), fingerprint_key=os.urandom(32), clock=clock)
    service = ProposalService(ProposalStore(db), token_key=os.urandom(32), clock=clock, audit=audit)
    verifier = ApprovalVerifier(ApprovalStore(db), service, operator_identity="alan", clock=clock)
    library = RunbookLibrary.load([VALID_RUNBOOK])[0]
    registry = make_observer_registry({"static_test": "passing"})
    policy = load_test_policy(
        make_policy_document(
            runbook_id=VALID_RUNBOOK["runbook_id"],
            revision=VALID_RUNBOOK["revision"],
            content_hash=VALID_RUNBOOK["content_hash"],
        ),
        registry,
    )
    catalog = make_execution_catalog(
        VALID_RUNBOOK,
        "/opt/scripts/restart-n8n.sh",
        __import__("hashlib").sha256(SCRIPT_BYTES).hexdigest(),
    )
    gate = ExecutionGate(
        service, verifier, audit, runbooks=library,
        script_source={"/opt/scripts/restart-n8n.sh": SCRIPT_BYTES}.__getitem__,
        clock=clock, observer_registry=registry, authorization_catalog=policy,
        operator_identity="alan", execution_catalog=catalog,
    )
    import hashlib as hl


    template = binding_template(
        VALID_RUNBOOK,
        "/opt/scripts/restart-n8n.sh",
        __import__("hashlib").sha256(SCRIPT_BYTES).hexdigest(),
        make_invocation(),
    )
    invocation = make_invocation(runbook_revision_hash=VALID_RUNBOOK["content_hash"])
    issued = service.open_proposal(invocation, ttl=timedelta(minutes=10), execution_binding=template)
    verifier.record_approval(issued.token, operator_identity="alan")
    citation = Citation(
        runbook_id=VALID_RUNBOOK["runbook_id"], revision=VALID_RUNBOOK["revision"],
        content_hash=VALID_RUNBOOK["content_hash"], locator="restart/steps",
    )

    import ops_guard.execution_binding as eb_module

    def bogus_runner(*args, **kwargs):
        return RunnerResult(outcome="excellent", failure_code=None)

    monkeypatch.setattr(eb_module, "run_staged", bogus_runner)
    with pytest.raises(ValueError, match="runner must report"):
        gate.execute(ExecutionRequest(token=issued.token, citation=citation), None)
    events = [e for e in audit.events() if e.event_type == "execution_outcome"]
    assert len(events) == 1
    assert events[0].outcome == "failure"
    assert events[0].failure_code == "executor-error"
    events = [e for e in audit.events() if e.event_type == "execution_outcome"]
    assert len(events) == 1
    assert events[0].outcome == "failure"
    assert events[0].failure_code == "executor-error"

# ---- pipe-holding grandchild and taskkill fallback (review cycle 4) ------


@pytest.mark.skipif(
    os.name == "nt",
    reason=(
        "On Windows the grandchild spawned by the middle child does not "
        "deterministically inherit the runner's pipe handles (PEP 446 "
        "non-inheritable handles), so the EOF/pipe-held distinction cannot "
        "be driven from the fixture; the Job Object guarantee is covered by "
        "test_job_object_kills_surviving_grandchild (ADR 0012 amendment)"
    ),
)
def test_pipe_holding_grandchild_maps_to_unknown(tmp_path) -> None:
    """A grandchild that inherits the pipes and outlives the direct child
    maps to explicitly unknown, never success."""
    import hashlib as hl
    import subprocess as sp
    import time as tm
    from dataclasses import replace

    from ops_guard.execution_binding import RunnerProfile, run_staged

    marker = tmp_path / "grandchild-alive"
    marker.write_text("alive")
    profile = replace(
        RunnerProfile(
            profile_id="pipe-holder",
            executable=sys.executable,
            executable_sha256=hl.sha256(open(sys.executable, "rb").read()).hexdigest(),
            argv=(sys.executable,),
            working_directory=str(tmp_path),
            env_allowlist=("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "COMSPEC"),
            timeout_seconds=10,
            output_limit=1024,
        ),
    )
    spawn_line = (
        "import time; time.sleep(30)"
    )
    spawn = (
        "import subprocess, sys\n"
        f"subprocess.Popen([{sys.executable!r}, '-c', {spawn_line!r}])\n"
        "sys.exit(0)\n"
    )
    inner = f"import subprocess, sys; {spawn_line!r}"
    body = (
        "import subprocess, sys\n"
        f"child = subprocess.Popen([{sys.executable!r}, '-c', {inner!r}],\n"
        "    stdout=sys.stdout, stderr=sys.stderr)\n"
        "sys.exit(0)\n"
    ).encode()
    started = tm.monotonic()
    result = run_staged(
        profile,
        script_path="fixture.py",
        script_bytes=body,
        script_sha256=hl.sha256(body).hexdigest(),
        invocation={"action": "restart"},
    )
    elapsed = tm.monotonic() - started
    assert result.outcome == "unknown"  # explicitly unknown, never success
    assert elapsed < 15
    # the tree is terminated: the grandchild dies shortly after
    deadline = tm.monotonic() + 5
    while tm.monotonic() < deadline and marker.exists():
        tm.sleep(0.1)
    assert not marker.exists(), "grandchild survived the tree kill"


def test_taskkill_timeout_still_kills_direct_child(tmp_path, monkeypatch) -> None:
    """If taskkill times out, process.kill still runs as the fallback."""
    import hashlib as hl
    import subprocess as sp
    import time as tm
    from dataclasses import replace

    from ops_guard.execution_binding import RunnerProfile, run_staged

    profile = replace(
        RunnerProfile(
            profile_id="slow-kill",
            executable=sys.executable,
            executable_sha256=hl.sha256(open(sys.executable, "rb").read()).hexdigest(),
            argv=(sys.executable,),
            working_directory=str(tmp_path),
            env_allowlist=("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "COMSPEC"),
            timeout_seconds=1,
        ),
    )
    body = _fixture("import time; time.sleep(10)")
    kill_calls = []

    def fake_run(cmd, **kwargs):
        kill_calls.append(cmd)
        raise sp.TimeoutExpired(cmd=cmd, timeout=10)

    monkeypatch.setattr(sp, "run", fake_run)
    result = run_staged(
        profile,
        script_path="fixture.py",
        script_bytes=_fixture("import time; time.sleep(10)"),
        script_sha256=hl.sha256(_fixture("import time; time.sleep(10)")).hexdigest(),
        invocation={"action": "restart"},
    )
    assert result.outcome == "unknown"
    assert any("taskkill" in str(c) for c in kill_calls)
    # process.kill() ran as the fallback: the direct child is gone
    assert result.failure_code == "executor-timeout"


def test_job_object_kills_surviving_grandchild(tmp_path) -> None:
    """Windows: a grandchild that survives the direct child is terminated by
    the kill-on-close Job Object before run_staged returns (ADR 0012)."""
    import hashlib as hl
    import subprocess as sp
    import time as tm
    from dataclasses import replace

    from ops_guard.execution_binding import RunnerProfile, run_staged

    if os.name != "nt":
        pytest.skip("Job Objects are Windows-specific")
    marker = tmp_path / "grandchild-alive"
    marker.write_text("alive")
    profile = replace(
        RunnerProfile(
            profile_id="jobbed",
            executable=sys.executable,
            executable_sha256=hl.sha256(open(sys.executable, "rb").read()).hexdigest(),
            argv=(sys.executable,),
            working_directory=str(tmp_path),
            env_allowlist=("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "COMSPEC"),
            timeout_seconds=10,
        ),
    )
    # The grandchild inherits the child's stdout (the runner's pipe): the
    # still-open detection fires, the job closes, and the grandchild dies.
    # The grandchild writes its PID so the test can poll its liveness.
    body = (
        "import subprocess, sys\n"
        f"pid_file = {str(marker)!r}\n"
        f"grandchild = subprocess.Popen([{sys.executable!r}, '-c', "
        "'import time; time.sleep(30)'])\n"
        "open(pid_file, 'w').write(str(grandchild.pid))\n"
        "sys.exit(0)\n"
    ).encode()
    result = run_staged(
        profile,
        script_path="fixture.py",
        script_bytes=body,
        script_sha256=hl.sha256(body).hexdigest(),
        invocation={"action": "restart"},
    )
    assert result.outcome in ("unknown", "failure")
    grandchild_pid = int(marker.read_text())
    import ctypes

    deadline = tm.monotonic() + 10
    while tm.monotonic() < deadline:
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, grandchild_pid)
        if not handle:
            break  # process gone
        ctypes.windll.kernel32.CloseHandle(handle)
        tm.sleep(0.1)
    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, grandchild_pid)
    assert not handle, "grandchild survived the Job Object kill"


def test_detached_grandchild_killed_by_job_close(tmp_path) -> None:
    """Windows: kill-on-close (not just TerminateJobObject on the still-open
    path) terminates a detached grandchild that outlives a clean direct
    child exit."""
    import hashlib as hl
    import time as tm
    from ops_guard.execution_binding import RunnerProfile, run_staged

    if os.name != "nt":
        pytest.skip("Job Objects are Windows-specific")
    marker = tmp_path / "grandchild.pid"
    # the MIDDLE child records the detached grandchild's pid, then exits
    spawn_line = "import time; time.sleep(30)"
    inner = (
        "import subprocess, sys\n"
        f"grandchild = subprocess.Popen([{sys.executable!r}, '-c', {spawn_line!r}],\n"
        "    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,\n"
        "    stdin=subprocess.DEVNULL)\n"
        f"open({str(marker)!r}, 'w').write(str(grandchild.pid))\n"
    )
    profile = RunnerProfile(
        profile_id="detached",
        executable=sys.executable,
        executable_sha256=hl.sha256(open(sys.executable, "rb").read()).hexdigest(),
        argv=(sys.executable,),
        working_directory=str(tmp_path),
        env_allowlist=("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "COMSPEC"),
        timeout_seconds=10,
    )
    body = (
        "import subprocess, sys\n"
        f"subprocess.Popen([{sys.executable!r}, '-c', {inner!r}])\n"
        "sys.exit(0)\n"
    ).encode()
    result = run_staged(
        profile,
        script_path="fixture.py",
        script_bytes=body,
        script_sha256=hl.sha256(body).hexdigest(),
        invocation={"action": "restart"},
    )
    # The detached grandchild uses DEVNULL stdio, so the still-open
    # detection does NOT fire: the clean child exit maps to success, and
    # kill-on-close must have terminated the surviving grandchild.
    assert result.outcome == "success"
    import ctypes

    deadline = tm.monotonic() + 10
    while tm.monotonic() < deadline and not marker.exists():
        tm.sleep(0.1)
    grandchild_pid = int(marker.read_text())
    while tm.monotonic() < deadline:
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, grandchild_pid)
        if not handle:
            break  # process gone
        ctypes.windll.kernel32.CloseHandle(handle)
        tm.sleep(0.1)
    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, grandchild_pid)
    assert not handle, "grandchild survived the Job Object kill"
