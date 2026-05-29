"""Shared pytest configuration for Zypheron AI tests."""

from __future__ import annotations

import os
from pathlib import Path


os.environ.setdefault(
    "ZYPHERON_STATE_DIR",
    str(Path(__file__).resolve().parent.parent / ".pytest-state"),
)
