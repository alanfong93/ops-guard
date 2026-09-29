"""File-backed runbook loading for the service (issue #54; ADR 0006).

Preserves the RunbookLibrary contract: invalid revisions are excluded and
reported without exposing content; a missing or unreadable directory fails
startup; an empty corpus serves empty results.
"""

from __future__ import annotations

import json
import os

import pytest

from ops_guard.service import StartupError, load_runbook_documents

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC_CORPUS = os.path.join(REPO_ROOT, "runbooks")


def _write(path, document) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        if isinstance(document, str):
            handle.write(document)
        else:
            json.dump(document, handle)


def test_public_corpus_directory_loads_both_verified_revisions() -> None:
    documents, rejections = load_runbook_documents(PUBLIC_CORPUS)
    assert rejections == []
    ids = sorted(d["runbook_id"] for d in documents)
    assert ids == ["n8n-update", "openwebui-update"]


def test_invalid_documents_are_excluded_and_reported_by_name(tmp_path) -> None:
    from ops_guard.invocation import canonicalize_json

    good = {
        "runbook_id": "good",
        "revision": "2026-09-29.1",
        "operation": {"action": "update", "target": "t"},
        "preconditions": [],
        "passages": [{"locator": "a", "text": "b"}],
        "verification": {
            "verifier": "v",
            "verified_at": "2026-09-29T00:00:00.000000+00:00",
            "applicability": "a",
        },
    }
    good["content_hash"] = __import__("hashlib").sha256(canonicalize_json(good)).hexdigest()
    _write(tmp_path / "good.json", good)
    _write(tmp_path / "broken.json", "{not json")
    _write(tmp_path / "unverified.json", {"runbook_id": "unverified"})

    documents, rejections = load_runbook_documents(str(tmp_path))
    assert [d["runbook_id"] for d in documents] == ["good"]
    by_name = {name: (error, reason) for name, error, reason in rejections}
    assert set(by_name) == {"broken.json", "unverified.json"}
    assert by_name["broken.json"][0] == "json"
    assert by_name["unverified.json"][0] == "UnverifiedRunbookError"
    # Rejection reasons name the problem, never the document content.
    assert "not json" not in by_name["broken.json"][1]
    for _, _, reason in rejections:
        assert "passage text" not in reason


def test_missing_directory_fails_startup(tmp_path) -> None:
    with pytest.raises(StartupError):
        load_runbook_documents(str(tmp_path / "absent"))


def test_file_path_as_directory_fails_startup(tmp_path) -> None:
    path = tmp_path / "afile"
    path.write_text("x")
    with pytest.raises(StartupError):
        load_runbook_documents(str(path))


def test_empty_directory_yields_no_documents(tmp_path) -> None:
    documents, rejections = load_runbook_documents(str(tmp_path))
    assert documents == []
    assert rejections == []


def test_non_json_files_are_ignored(tmp_path) -> None:
    (tmp_path / "notes.txt").write_text("ignore me", encoding="utf-8")
    (tmp_path / "README.md").write_text("# notes", encoding="utf-8")
    documents, rejections = load_runbook_documents(str(tmp_path))
    assert documents == []
    assert rejections == []
