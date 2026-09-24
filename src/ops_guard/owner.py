"""Execution owner identity and liveness proof (issue #39; ADR 0005).

A gate process instance is a random ID plus an OS-held exclusive lock file
in a per-database owner directory. The lock is held for the process's
lifetime: the OS releases it when the process dies, so acquiring it later
is positive evidence the owner is gone. Liveness is never inferred from
age, PIDs (which the OS may reuse), or absence of heartbeats.

Probe verdicts are exactly three: ``alive`` (the lock is held),
``dead`` (an existing lock file was lockable — its owner must be gone),
``indeterminate`` (missing or unusable lock state — never treated as dead).
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

_ALIVE = "alive"
_DEAD = "dead"
_INDETERMINATE = "indeterminate"


def owners_dir_for(database_path: str | Path) -> Path:
    """The per-database owner directory: sibling to the database file."""
    path = Path(database_path)
    return path.parent / f"{path.name}.owners"


class ExecutionOwner:
    """A live gate process instance holding its lock file."""

    def __init__(self, owners_dir: str | Path) -> None:
        self._dir = Path(owners_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self.id = uuid.uuid4().hex
        self._lock_path = self._dir / f"{self.id}.lock"
        self._fd = os.open(self._lock_path, os.O_CREAT | os.O_RDWR)
        self._acquire()
        self._closed = False

    @property
    def lock_path(self) -> Path:
        return self._lock_path

    def _acquire(self) -> None:
        os.lseek(self._fd, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def close(self) -> None:
        """Release the lock. The lock file itself is kept: an incomplete
        start may still refer to it, and a kept file only ever probes as
        ``dead`` or ``indeterminate`` — never as a live owner."""
        if self._closed:
            return
        self._closed = True
        try:
            os.lseek(self._fd, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)

    @staticmethod
    def probe(owners_dir: str | Path, owner_id: str) -> str:
        """Non-blocking liveness verdict for an owner id (ADR 0005 rule 3)."""
        if not owner_id or not isinstance(owner_id, str):
            return _INDETERMINATE
        lock_path = Path(owners_dir) / f"{owner_id}.lock"
        if not lock_path.is_file():
            return _INDETERMINATE
        try:
            fd = os.open(lock_path, os.O_RDWR)
        except OSError:
            return _INDETERMINATE
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                except OSError:
                    return _ALIVE
                try:
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            else:
                import fcntl

                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    return _ALIVE
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            return _DEAD
        finally:
            os.close(fd)
