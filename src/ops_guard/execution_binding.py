"""Operator execution catalog, immutable ExecutionBinding, and the local
runner (issue #64; ADR 0012).

The operator-owned execution catalog maps one exact verified runbook key
(id, revision, content hash) plus action/target to exactly one local
script (id, path, expected SHA-256) and names the single runner profile.
The runner profile defines the executable identity/hash, fixed argument
vector, working directory, environment allowlist, stdin input protocol,
timeout, and output bounds — `shell=False`, no host-controlled arguments.

The gate stages the operator-source bytes it already hash-verified into a
per-execution private temporary file, re-verifies the staged copy, and
runs only that copy through the profile. Timeouts and uncertain
completions map to the explicitly `unknown` outcome (ADR 0005); nothing
is retried.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Mapping

from ops_guard.errors import ProposalError
from ops_guard.invocation import canonicalize_json

EXECUTION_CATALOG_SCHEMA_VERSION = "ops-guard-execution-catalog-v1"
RUNNER_PROFILE_SCHEMA_VERSION = "ops-guard-runner-profile-v1"
DEFAULT_OUTPUT_LIMIT = 64 * 1024


class ExecutionCatalogError(ProposalError):
    """The execution catalog is missing, malformed, or ambiguous."""


class BindingResolutionError(ProposalError):
    """No unique catalog entry exists for the proposed invocation."""


def canonical_binding_digest(binding: Mapping[str, Any]) -> str:
    """SHA-256 over the JCS-canonicalized binding document."""
    return hashlib.sha256(canonicalize_json(binding)).hexdigest()


@dataclass(frozen=True)
class CatalogEntry:
    """One operator-approved script mapping (ADR 0012)."""

    runbook_id: str
    revision: str
    content_hash: str
    action: str
    target: str
    script_id: str
    script_path: str
    script_sha256: str

    def key(self) -> tuple[str, str, str, str, str]:
        return (self.runbook_id, self.revision, self.content_hash, self.action, self.target)


@dataclass(frozen=True)
class RunnerProfile:
    """The single operator-configured runner for a service (v1).

    ``argv`` is an explicit argument vector executed with ``shell=False``;
    ``env_allowlist`` names the host environment variables the child may
    inherit (nothing else passes through)."""

    profile_id: str
    executable: str
    executable_sha256: str
    argv: tuple[str, ...]
    working_directory: str
    env_allowlist: tuple[str, ...]
    timeout_seconds: int
    output_limit: int = DEFAULT_OUTPUT_LIMIT

    def digest(self) -> str:
        document = {
            "schema_version": RUNNER_PROFILE_SCHEMA_VERSION,
            "profile_id": self.profile_id,
            "executable": self.executable,
            "executable_sha256": self.executable_sha256,
            "argv": list(self.argv),
            "working_directory": self.working_directory,
            "env_allowlist": list(self.env_allowlist),
            "timeout_seconds": self.timeout_seconds,
            "output_limit": self.output_limit,
        }
        return hashlib.sha256(canonicalize_json(document)).hexdigest()


@dataclass(frozen=True)
class ExecutionBinding:
    """The immutable server-resolved execution sidecar for one proposal."""

    proposal_id: str
    invocation_digest: str
    runbook_id: str
    runbook_revision: str
    runbook_content_hash: str
    script_id: str
    script_path: str
    script_sha256: str
    catalog_entry_digest: str
    runner_profile_id: str
    runner_profile_digest: str

    def to_document(self) -> dict:
        return {
            "proposal_id": self.proposal_id,
            "invocation_digest": self.invocation_digest,
            "runbook_id": self.runbook_id,
            "runbook_revision": self.runbook_revision,
            "runbook_content_hash": self.runbook_content_hash,
            "script_id": self.script_id,
            "script_path": self.script_path,
            "script_sha256": self.script_sha256,
            "catalog_entry_digest": self.catalog_entry_digest,
            "runner_profile_id": self.runner_profile_id,
            "runner_profile_digest": self.runner_profile_digest,
        }

    def digest(self) -> str:
        return canonical_binding_digest(self.to_document())


@dataclass(frozen=True)
class ExecutionBindingTemplate:
    """A resolved binding awaiting its proposal id (ADR 0012).

    ``open_proposal`` finalizes the template with the minted proposal id
    and the frozen invocation digest inside the insert transaction, so the
    binding digest always covers the final persisted document."""

    runbook_id: str
    runbook_revision: str
    runbook_content_hash: str
    script_id: str
    script_path: str
    script_sha256: str
    catalog_entry_digest: str
    runner_profile_id: str
    runner_profile_digest: str

    def finalize(self, proposal_id: str, invocation_digest: str) -> ExecutionBinding:
        return ExecutionBinding(
            proposal_id=proposal_id,
            invocation_digest=invocation_digest,
            runbook_id=self.runbook_id,
            runbook_revision=self.runbook_revision,
            runbook_content_hash=self.runbook_content_hash,
            script_id=self.script_id,
            script_path=self.script_path,
            script_sha256=self.script_sha256,
            catalog_entry_digest=self.catalog_entry_digest,
            runner_profile_id=self.runner_profile_id,
            runner_profile_digest=self.runner_profile_digest,
        )


def load_execution_catalog(document: Any) -> tuple[dict[tuple[str, str, str, str, str], CatalogEntry], dict[str, RunnerProfile]]:
    """Strictly validate the operator execution catalog document.

    Exact top-level keys, unique entries, unique script ids, well-formed
    hashes, and one runner profile; anything else fails closed."""
    if not isinstance(document, Mapping):
        raise ExecutionCatalogError("execution catalog must be a JSON object")
    if set(document) != {
        "schema_version",
        "runner_profile",
        "entries",
    }:
        raise ExecutionCatalogError("execution catalog keys do not match the schema")
    if document["schema_version"] != EXECUTION_CATALOG_SCHEMA_VERSION:
        raise ExecutionCatalogError(
            f"catalog schema_version must be {EXECUTION_CATALOG_SCHEMA_VERSION!r}"
        )
    profile_raw = document["runner_profile"]
    if not isinstance(profile_raw, Mapping) or set(profile_raw) != {
        "profile_id",
        "executable",
        "executable_sha256",
        "argv",
        "working_directory",
        "env_allowlist",
        "timeout_seconds",
        "output_limit",
    }:
        raise ExecutionCatalogError("runner_profile keys do not match the schema")
    import re

    if not isinstance(profile_raw["profile_id"], str) or not profile_raw["profile_id"]:
        raise ExecutionCatalogError("runner_profile.profile_id must be a non-empty string")
    for text_field in ("executable", "working_directory"):
        if not isinstance(profile_raw[text_field], str) or not profile_raw[text_field]:
            raise ExecutionCatalogError(f"runner_profile.{text_field} must be a non-empty string")
    if not isinstance(profile_raw["executable_sha256"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", profile_raw["executable_sha256"]
    ):
        raise ExecutionCatalogError("runner_profile.executable_sha256 must be 64 hex characters")
    argv = profile_raw["argv"]
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
        raise ExecutionCatalogError("runner_profile.argv must be a non-empty list of strings")
    looks_absolute = os.path.isabs(profile_raw["executable"]) or (
        profile_raw["executable"].startswith("/")
    )
    if not looks_absolute:
        raise ExecutionCatalogError("runner_profile.executable must be an absolute path")
    if argv[0] != profile_raw["executable"]:
        raise ExecutionCatalogError(
            "runner_profile.argv[0] must equal the profile executable (ADR 0012)"
        )
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
        raise ExecutionCatalogError("runner_profile.argv must be a non-empty list of strings")
    allowlist = profile_raw["env_allowlist"]
    if not isinstance(allowlist, list) or not all(isinstance(a, str) and a for a in allowlist):
        raise ExecutionCatalogError("runner_profile.env_allowlist must be a list of strings")
    timeout = profile_raw["timeout_seconds"]
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 3600:
        raise ExecutionCatalogError("runner_profile.timeout_seconds must be an integer 1..3600")
    output_limit = profile_raw["output_limit"]
    if not isinstance(output_limit, int) or isinstance(output_limit, bool) or output_limit < 1024:
        raise ExecutionCatalogError("runner_profile.output_limit must be an integer >= 1024")
    profile = RunnerProfile(
        profile_id=profile_raw["profile_id"],
        executable=profile_raw["executable"],
        executable_sha256=profile_raw["executable_sha256"],
        argv=tuple(argv),
        working_directory=profile_raw["working_directory"],
        env_allowlist=tuple(allowlist),
        timeout_seconds=timeout,
        output_limit=output_limit,
    )
    profiles = {profile.profile_id: profile}

    entries_raw = document["entries"]
    if not isinstance(entries_raw, list):
        raise ExecutionCatalogError("entries must be a list")
    entries: dict[tuple[str, str, str, str, str], CatalogEntry] = {}
    script_ids: set[str] = set()
    for index, raw in enumerate(entries_raw):
        if not isinstance(raw, Mapping) or set(raw) != {
            "runbook_id",
            "revision",
            "content_hash",
            "action",
            "target",
            "script_id",
            "script_path",
            "script_sha256",
        }:
            raise ExecutionCatalogError(f"entries[{index}] keys do not match the entry schema")
        for text_field in (
            "runbook_id",
            "revision",
            "content_hash",
            "action",
            "target",
            "script_id",
            "script_path",
            "script_sha256",
        ):
            if not isinstance(raw[text_field], str) or not raw[text_field]:
                raise ExecutionCatalogError(f"entries[{index}].{text_field} must be a non-empty string")
        import re

        for hash_field in ("content_hash", "script_sha256"):
            if not re.fullmatch(r"[0-9a-f]{64}", raw[hash_field]):
                raise ExecutionCatalogError(f"entries[{index}].{hash_field} must be 64 hex characters")
        entry = CatalogEntry(
            runbook_id=raw["runbook_id"],
            revision=raw["revision"],
            content_hash=raw["content_hash"],
            action=raw["action"],
            target=raw["target"],
            script_id=raw["script_id"],
            script_path=raw["script_path"],
            script_sha256=raw["script_sha256"],
        )
        key = entry.key()
        if key in entries:
            raise ExecutionCatalogError(f"entries[{index}] duplicates an existing catalog key")
        if entry.script_id in script_ids:
            raise ExecutionCatalogError(f"entries[{index}] reuses script_id {entry.script_id!r}")
        script_ids.add(entry.script_id)
        entries[key] = entry
    return entries, profiles


def load_execution_catalog_file(path: str) -> tuple[dict, dict]:
    """Read and validate the catalog file; duplicate JSON keys fail closed."""
    import re

    def _reject_duplicate_keys(pairs):
        seen = {}
        for key, value in pairs:
            if key in seen:
                raise ExecutionCatalogError(f"duplicate JSON key {key!r} in the execution catalog")
            seen[key] = value
        return seen

    if not os.path.isfile(path):
        raise ExecutionCatalogError(f"execution catalog does not exist: {path}")
    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle, object_pairs_hook=_reject_duplicate_keys)
    except ExecutionCatalogError:
        raise
    except (OSError, ValueError) as error:
        raise ExecutionCatalogError(
            f"execution catalog is unreadable as JSON ({type(error).__name__})"
        ) from error
    return load_execution_catalog(document)


def resolve_binding(
    catalog_entries: Mapping[tuple[str, str, str, str, str], CatalogEntry],
    profiles: Mapping[str, RunnerProfile],
    *,
    runbook_id: str,
    revision: str,
    content_hash: str,
    action: str,
    target: str,
) -> ExecutionBindingTemplate:
    """Resolve the one catalog entry for the proposed invocation.

    Zero or ambiguous matches raise before any proposal exists. The entry
    digest covers the canonicalized catalog entry so later catalog edits
    invalidate existing bindings."""
    matches = [
        entry
        for key, entry in catalog_entries.items()
        if key[:3] == (runbook_id, revision, content_hash) and key[3] == action and key[4] == target
    ]
    if not matches:
        raise BindingResolutionError(
            f"no execution catalog entry maps {runbook_id}@{revision} {action}/{target}"
        )
    if len(matches) > 1:
        raise BindingResolutionError(
            f"the execution catalog maps {runbook_id}@{revision} {action}/{target} ambiguously"
        )
    entry = matches[0]
    if len(profiles) != 1:
        raise BindingResolutionError(
            "the execution catalog must declare exactly one runner profile"
        )
    profile = next(iter(profiles.values()))
    entry_document = {
        "runbook_id": entry.runbook_id,
        "revision": entry.revision,
        "content_hash": entry.content_hash,
        "action": entry.action,
        "target": entry.target,
        "script_id": entry.script_id,
        "script_path": entry.script_path,
        "script_sha256": entry.script_sha256,
    }
    return ExecutionBindingTemplate(
        runbook_id=entry.runbook_id,
        runbook_revision=entry.revision,
        runbook_content_hash=entry.content_hash,
        script_id=entry.script_id,
        script_path=entry.script_path,
        script_sha256=entry.script_sha256,
        catalog_entry_digest=canonical_binding_digest(entry_document),
        runner_profile_id=profile.profile_id,
        runner_profile_digest=profile.digest(),
    )


@dataclass(frozen=True)
class RunnerResult:
    """The bounded outcome of one staged execution."""

    outcome: str  # "success" | "failure" | "unknown"
    failure_code: str | None


def run_staged(
    profile: RunnerProfile,
    *,
    script_path: str,
    script_bytes: bytes,
    script_sha256: str,
    invocation: Any,
) -> RunnerResult:
    """Stage the verified bytes and execute only the staged copy.

    The gate reads the operator source once and hash-verifies it; this
    runner writes those in-memory bytes to a per-execution private
    temporary file, re-verifies the staged hash, and executes the staged
    path with the profile's fixed argv (`shell=False`), the canonical JCS
    Invocation JSON on stdin, a bounded environment, bounded output, and a
    hard child-process timeout with process-tree termination. Timeouts and
    uncertain completions map to the explicitly `unknown` outcome (ADR
    0005); nothing retries."""
    staged_digest = hashlib.sha256(script_bytes).hexdigest()
    if staged_digest != script_sha256:
        return RunnerResult(outcome="failure", failure_code="staged-hash-mismatch")

    # The runner profile's executable identity is part of the verified
    # binding: hash the resolved binary before spawning it.
    try:
        with open(profile.executable, "rb") as handle:
            executable_digest = hashlib.sha256(handle.read()).hexdigest()
    except OSError:
        return RunnerResult(outcome="failure", failure_code="runner-executable-unreadable")
    if executable_digest != profile.executable_sha256:
        return RunnerResult(outcome="failure", failure_code="runner-executable-mismatch")

    tmp_dir = tempfile.mkdtemp(prefix="ops-guard-exec-")
    try:
        staged_path = os.path.join(tmp_dir, "staged-script")
        with open(staged_path, "wb") as handle:
            handle.write(script_bytes)
        os.chmod(staged_path, 0o700)
        with open(staged_path, "rb") as handle:
            if hashlib.sha256(handle.read()).hexdigest() != script_sha256:
                return RunnerResult(outcome="failure", failure_code="staged-hash-mismatch")
        stdin_payload = canonicalize_json(invocation)
        env = {
            name: os.environ[name]
            for name in profile.env_allowlist
            if name in os.environ
        }
        argv = list(profile.argv) + [staged_path]
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=profile.working_directory,
            env=env,
            shell=False,
            start_new_session=True,  # POSIX: own process group for tree kill
        )
        limit = profile.output_limit
        overflow: dict[str, bool] = {"stdout": False, "stderr": False}

        def _drain(stream, key: str) -> None:
            drained = 0
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    return
                drained += len(chunk)
                if drained > limit:
                    overflow[key] = True
                    _terminate_tree(process)
                    return

        import threading as _threading

        readers = [
            _threading.Thread(target=_drain, args=(process.stdout, "stdout"), daemon=True),
            _threading.Thread(target=_drain, args=(process.stderr, "stderr"), daemon=True),
        ]
        for reader in readers:
            reader.start()

        def _write_stdin() -> None:
            try:
                process.stdin.write(stdin_payload)
                process.stdin.close()
            except OSError:
                pass  # a child that closed stdin early must not crash the runner

        writer = _threading.Thread(target=_write_stdin, daemon=True)
        writer.start()
        try:
            process.wait(timeout=profile.timeout_seconds)
        except subprocess.TimeoutExpired:
            _terminate_tree(process)
            return RunnerResult(outcome="unknown", failure_code="executor-timeout")
        except OSError:
            return RunnerResult(outcome="unknown", failure_code="spawn-failure")
        writer.join(timeout=5)
        for reader in readers:
            reader.join(timeout=5)
        still_open = (
            writer.is_alive() or any(reader.is_alive() for reader in readers)
        )
        if still_open:
            # A descendant holds the inherited stdio pipes: the tree is not
            # done even though the direct child exited. Terminate it and
            # report an explicitly unknown completion (ADR 0005).
            _terminate_tree(process)
            code = "output-limit" if (overflow["stdout"] or overflow["stderr"]) else None
            return RunnerResult(outcome="unknown", failure_code=code)
        if overflow["stdout"] or overflow["stderr"]:
            return RunnerResult(outcome="failure", failure_code="output-limit")
        if process.returncode == 0:
            return RunnerResult(outcome="success", failure_code=None)
        return RunnerResult(outcome="failure", failure_code="non-zero-exit")
    finally:
        import shutil

        shutil.rmtree(tmp_dir, ignore_errors=True)


def _terminate_tree(process: subprocess.Popen) -> None:
    """Kill the child and its whole process tree.

    POSIX: the child runs in its own session (start_new_session), so
    killpg reaches every descendant. Windows: taskkill /F /T walks the
    PID tree; a plain TerminateProcess would orphan grandchildren."""
    import signal

    try:
        if hasattr(os, "killpg") and hasattr(os, "setsid"):
            os.killpg(process.pid, signal.SIGKILL)
        else:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                capture_output=True,
                timeout=10,
            )
            process.kill()
    except OSError:
        process.kill()
    except subprocess.TimeoutExpired:
        process.kill()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass
