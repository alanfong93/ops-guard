"""Crash-leftover staging-dir sweep (issue #81; ADR 0012).

A staging dir attributable to an owner is removed only when that owner is
positively proven dead; live and indeterminate owners, and anything not
matching the attributable naming, is left untouched.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ops_guard.owner import ExecutionOwner
from ops_guard.recovery import sweep_exec_tmp_leftovers


def _staging_dir(root: Path, owner_id: str) -> Path:
    # mkdtemp suffix shape: 8 random chars, matching the runner's prefix.
    path = root / f"ops-guard-exec-{owner_id}-ab12cd34"
    path.mkdir()
    (path / "staged-script").write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    return path


def test_dead_owner_staging_dir_is_swept(tmp_path) -> None:
    owners = tmp_path / "owners"
    owner = ExecutionOwner(owners)
    owner_id = owner.id
    owner.close()  # lock released: positively dead
    root = tmp_path / "tmp"
    root.mkdir()
    staged = _staging_dir(root, owner_id)
    removed = sweep_exec_tmp_leftovers(owners, temp_root=root)
    assert removed == [str(staged)]
    assert not staged.exists()


def test_live_owner_staging_dir_is_untouched(tmp_path) -> None:
    owners = tmp_path / "owners"
    owner = ExecutionOwner(owners)  # held open for the whole test: alive
    root = tmp_path / "tmp"
    root.mkdir()
    staged = _staging_dir(root, owner.id)
    removed = sweep_exec_tmp_leftovers(owners, temp_root=root)
    assert removed == []
    assert staged.exists()
    owner.close()


def test_indeterminate_owner_staging_dir_is_untouched(tmp_path) -> None:
    owners = tmp_path / "owners"
    owners.mkdir(parents=True, exist_ok=True)
    root = tmp_path / "tmp"
    root.mkdir()
    # A 32-hex owner id with no lock file probes indeterminate.
    staged = _staging_dir(root, "0" * 32)
    removed = sweep_exec_tmp_leftovers(owners, temp_root=root)
    assert removed == []
    assert staged.exists()


def test_unattributable_dirs_are_untouched(tmp_path) -> None:
    owners = tmp_path / "owners"
    owner = ExecutionOwner(owners)
    owner.close()
    root = tmp_path / "tmp"
    root.mkdir()
    anonymous = root / "ops-guard-exec-randomstuff"
    anonymous.mkdir()
    stranger = root / "ops-guard-exec-zzzz-not-hex-suffix"
    stranger.mkdir()
    elsewhere = root / "unrelated-dir"
    elsewhere.mkdir()
    removed = sweep_exec_tmp_leftovers(owners, temp_root=root)
    assert removed == []
    assert anonymous.exists()
    assert stranger.exists()
    assert elsewhere.exists()


def test_missing_files_and_nondirs_are_ignored(tmp_path) -> None:
    owners = tmp_path / "owners"
    owner = ExecutionOwner(owners)
    owner.close()
    root = tmp_path / "tmp"
    root.mkdir()
    (root / "ops-guard-exec-not-a-dir").write_text("x", encoding="utf-8")
    removed = sweep_exec_tmp_leftovers(owners, temp_root=root)
    assert removed == []


def test_junction_is_neither_followed_nor_fatal(tmp_path) -> None:
    """A junction planted in the temp root (even one that raises on
    stat) is skipped without aborting the sweep, and other candidates
    are still processed (#81 hardening; post-merge review of #85)."""
    import _winapi

    if os.name != "nt":
        pytest.skip("junctions are Windows-specific")
    owners = tmp_path / "owners"
    owner = ExecutionOwner(owners)
    owner_id = owner.id
    owner.close()
    root = tmp_path / "tmp"
    root.mkdir()
    # a junction whose name does not even match the attributable pattern,
    # pointing at an unreadable-by-design system directory
    target = tmp_path / "junction-target"
    target.mkdir()
    _winapi.CreateJunction(str(target), str(root / "ops-guard-exec-nothex"))
    staged = _staging_dir(root, owner_id)  # dead owner: must still be swept
    removed = sweep_exec_tmp_leftovers(owners, temp_root=root)
    assert removed == [str(staged)]
    assert not staged.exists()
    assert (root / "ops-guard-exec-nothex").exists()  # untouched
