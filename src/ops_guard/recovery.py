"""Crash recovery: reconcile owner-proven-dead executions to unknown (issue #39; ADR 0005)
and sweep attributable staging directories of dead owners (issue #81; ADR 0012).

A committed ``execution_start`` without a terminal outcome is ambiguous:
the owning process may have crashed, or the operation may still be running
in another gate process. Recovery resolves the ambiguity by probing the
owner's lock (ADR 0005 rule 3) and appends exactly one ``unknown`` terminal
event — in the same SQLite write transaction that checked for one — only
when the owner is positively proven dead. Live and indeterminate owners
stay unresolved. Recovery never retries, compensates, or re-executes.

The staged runner writes each execution into ``ops-guard-exec-<owner>-*``
in the system temp dir (ADR 0012). A crash leaves the directory behind; the
startup sweep removes a directory only when its owning owner is positively
proven dead. Live and indeterminate owners — and anything not matching the
attributable naming — are left untouched.
"""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ops_guard.audit import AuditLog
from ops_guard.owner import ExecutionOwner, owners_dir_for

_STAGED_DIR_RE = re.compile(r"^ops-guard-exec-([0-9a-f]{32})-.+")


@dataclass(frozen=True)
class Reconciliation:
    """What one sweep saw, for operator reporting."""

    owner: str
    proposal_ref: str | None
    action: str  # "recovered" or the probe verdict for unresolved starts


def reconcile_interrupted_executions(audit: AuditLog) -> list[Reconciliation]:
    """One idempotent recovery sweep over the shared audit database.

    The terminal-outcome check and the recovery append share one
    ``BEGIN IMMEDIATE`` transaction, so the sweep serializes with ordinary
    outcome writes: a terminal outcome that lands first wins, and a sweep
    that lands first makes any ordinary outcome append see an existing
    terminal event (ordinary outcome appends are insert-only; the audit
    never overwrites). Repeating a sweep is safe — a recovered execution
    has a terminal event and is skipped.
    """
    owners_dir = owners_dir_for(audit.store.path)
    reconciliations: list[Reconciliation] = []
    with audit.store.transaction() as conn:
        starts = conn.execute(
            """
            SELECT sequence, correlation_id, proposal_ref, payload
              FROM audit_events
             WHERE event_type = 'execution_start'
            """
        ).fetchall()
        for start in starts:
            proposal_ref = start["proposal_ref"]
            terminal = conn.execute(
                """
                SELECT sequence FROM audit_events
                 WHERE event_type = 'execution_outcome'
                   AND proposal_ref = ?
                   AND outcome IS NOT NULL
                 LIMIT 1
                """,
                (proposal_ref,),
            ).fetchone()
            if terminal is not None:
                continue
            owner_id = _owner_of(start["payload"])
            verdict = ExecutionOwner.probe(owners_dir, owner_id)
            if verdict != "dead":
                reconciliations.append(
                    Reconciliation(owner=owner_id, proposal_ref=proposal_ref, action=verdict)
                )
                continue
            audit.append_on(
                conn,
                "execution_outcome",
                payload={"outcome": "unknown", "recovery": "execution owner proven dead"},
                correlation_id=start["correlation_id"],
                proposal_ref=proposal_ref,
                outcome="unknown",
                failure_code="owner-dead",
            )
            reconciliations.append(
                Reconciliation(owner=owner_id, proposal_ref=proposal_ref, action="recovered")
            )
    return reconciliations


def _owner_of(payload_text: str | None) -> str:
    if not payload_text:
        return ""
    try:
        payload = json.loads(payload_text)
    except (ValueError, TypeError):
        return ""
    owner_id = payload.get("owner_id") if isinstance(payload, dict) else None
    return owner_id if isinstance(owner_id, str) else ""


def sweep_exec_tmp_leftovers(
    owners_dir: str | Path,
    temp_root: str | Path | None = None,
) -> list[str]:
    """Remove crash-leftover staging dirs whose owner is proven dead.

    A staging dir is attributable when its name matches
    ``ops-guard-exec-<32-hex-owner>-<suffix>`` (the staged runner embeds
    the owning gate's owner id, ADR 0012). Only a positively ``dead``
    probe on that owner's lock authorizes removal; a live or
    indeterminate owner's directory, and anything not matching the
    naming, is left untouched. Best effort: filesystem errors never
    block startup. Returns the removed directory paths."""
    root = Path(temp_root) if temp_root is not None else Path(tempfile.gettempdir())
    removed: list[str] = []
    try:
        candidates = sorted(root.glob("ops-guard-exec-*"))
    except OSError:
        return removed
    for candidate in candidates:
        try:
            # Junctions and symlinked dirs are never ours and are never
            # followed: classification does not traverse them, and one
            # unreadable or hostile candidate never aborts the sweep.
            if candidate.is_symlink() or candidate.is_junction():
                continue
            if not candidate.is_dir(follow_symlinks=False):
                continue
            match = _STAGED_DIR_RE.match(candidate.name)
            if match is None:
                continue
            if ExecutionOwner.probe(owners_dir, match.group(1)) != "dead":
                continue
            shutil.rmtree(candidate, ignore_errors=True)
            if not candidate.exists():
                removed.append(str(candidate))
        except OSError:
            continue
    return removed
