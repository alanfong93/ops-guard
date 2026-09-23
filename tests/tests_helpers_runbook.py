"""Shared valid-runbook document for gate tests."""

from __future__ import annotations

import json
import os

_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "runbooks", "valid-n8n-restart.json")

with open(_PATH, encoding="utf-8") as _handle:
    VALID_RUNBOOK: dict = json.load(_handle)
