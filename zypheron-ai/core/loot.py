"""
Zypheron Loot Manager

Manages the standard loot directory structure:
~/.zypheron/loot/<session-id>/
    session.json
    timeline.log
    ports/
    services/
    hosts/
    creds/
    vulns/
    findings/
    screenshots/
    web/
    cloud/
    ad/
    attack/
    reports/
    raw/
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict
from loguru import logger


LOOT_SUBDIRS = [
    "ports", "services", "hosts", "creds", "vulns",
    "findings", "screenshots", "web", "cloud", "ad",
    "attack", "reports", "raw",
]


@dataclass
class SessionMeta:
    session_id: str
    target: str
    started_at: str = ""
    mode: str = "autopent"
    provider: str = ""
    model: str = ""
    status: str = "in_progress"

    def __post_init__(self):
        if not self.started_at:
            self.started_at = datetime.now(timezone.utc).isoformat()


@dataclass
class TimelineEntry:
    ts: str
    phase: str
    action: str
    tool: str = ""
    detail: str = ""
    status: str = "ok"


def base_loot_dir() -> Path:
    return Path.home() / ".zypheron" / "loot"


class LootManager:
    """Manages loot directory lifecycle for a pentest session."""

    def __init__(self, session_id: Optional[str] = None):
        if not session_id:
            session_id = f"session-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.session_id = session_id
        self.base_dir = base_loot_dir()
        self.session_dir = self.base_dir / session_id

    def init(
        self,
        target: str,
        mode: str = "autopent",
        provider: str = "",
        model: str = "",
    ) -> Path:
        """Create the full directory tree and session.json."""
        for sub in LOOT_SUBDIRS:
            (self.session_dir / sub).mkdir(parents=True, exist_ok=True)

        meta = SessionMeta(
            session_id=self.session_id,
            target=target,
            mode=mode,
            provider=provider,
            model=model,
        )
        self._write_json("session.json", asdict(meta))
        logger.info(f"Loot directory initialized: {self.session_dir}")
        return self.session_dir

    def log_timeline(
        self,
        phase: str,
        action: str,
        tool: str = "",
        detail: str = "",
        status: str = "ok",
    ) -> None:
        """Append a JSONL entry to timeline.log."""
        entry = TimelineEntry(
            ts=datetime.now(timezone.utc).isoformat(),
            phase=phase,
            action=action,
            tool=tool,
            detail=detail,
            status=status,
        )
        timeline_path = self.session_dir / "timeline.log"
        with open(timeline_path, "a") as f:
            f.write(json.dumps(asdict(entry)) + "\n")

    def save_loot(self, category: str, filename: str, data: bytes | str) -> Path:
        """Write data to the appropriate subdirectory."""
        path = self.session_dir / category / filename
        # SECURITY: Resolve and verify path stays within session directory
        resolved = path.resolve()
        real_path = Path(os.path.realpath(resolved))
        session_real = Path(os.path.realpath(self.session_dir))
        if not str(real_path).startswith(str(session_real) + os.sep) and real_path != session_real:
            raise ValueError(
                f"Path traversal detected: '{filename}' resolves outside session directory"
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        # SECURITY: Re-check after mkdir in case of symlink race
        real_path = Path(os.path.realpath(path))
        if not str(real_path).startswith(str(session_real) + os.sep):
            raise ValueError(
                f"Symlink escape detected: '{filename}' resolves outside session directory"
            )
        if isinstance(data, str):
            path.write_text(data)
        else:
            path.write_bytes(data)
        return path

    def save_loot_json(self, category: str, filename: str, obj: Any) -> Path:
        """Marshal obj to JSON and write it."""
        data = json.dumps(obj, indent=2, default=str)
        return self.save_loot(category, filename, data)

    def get_path(self, category: str, filename: str = "") -> Path:
        """Return the full path for a loot file or directory."""
        if filename:
            return self.session_dir / category / filename
        return self.session_dir / category

    def finalize(self, status: str = "completed") -> None:
        """Mark the session as complete."""
        meta_path = self.session_dir / "session.json"
        if meta_path.exists():
            meta = json.loads(meta_path.read_text())
            meta["status"] = status
            meta["finished_at"] = datetime.now(timezone.utc).isoformat()
            self._write_json("session.json", meta)
        self.log_timeline("session", "finalize", status=status)
        logger.info(f"Session {self.session_id} finalized: {status}")

    def _write_json(self, filename: str, obj: Any) -> None:
        path = self.session_dir / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(obj, indent=2, default=str))

    @staticmethod
    def list_sessions() -> List[str]:
        """Return all session IDs in the loot directory."""
        base = base_loot_dir()
        if not base.exists():
            return []
        return sorted(
            [d.name for d in base.iterdir() if d.is_dir()],
            reverse=True,
        )

    @staticmethod
    def load_session_meta(session_id: str) -> Optional[Dict]:
        """Load session.json for a given session."""
        meta_path = base_loot_dir() / session_id / "session.json"
        if meta_path.exists():
            return json.loads(meta_path.read_text())
        return None
