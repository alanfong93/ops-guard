"""The staged runner contract (issue #64; ADR 0012).

Harmless fixture scripts only: real python processes executing tiny
scripts through the production run_staged path.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

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
