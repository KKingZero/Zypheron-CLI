"""Small helpers for private file creation and safe session paths."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Union


SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class InvalidSessionIdError(ValueError):
    """Raised when a caller supplies an unsafe session_id."""


def validate_session_id(session_id: str) -> str:
    """Return session_id when it is safe to use as a filename stem."""
    if not isinstance(session_id, str) or not SESSION_ID_PATTERN.fullmatch(session_id):
        raise InvalidSessionIdError(
            f"Invalid session_id (must match {SESSION_ID_PATTERN.pattern}): {session_id!r}"
        )
    return session_id


def ensure_private_dir(path: Path) -> Path:
    """Create a directory and make it owner-only where the platform supports it."""
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.chmod(0o700)
    except OSError:
        pass
    return path


def contained_path(base_dir: Path, *parts: str) -> Path:
    """Resolve a child path and require it to stay below base_dir."""
    base_real = base_dir.resolve()
    candidate = base_real.joinpath(*parts).resolve()
    if candidate != base_real and base_real not in candidate.parents:
        raise InvalidSessionIdError(f"Path escapes base directory: {candidate}")
    return candidate


def session_path(base_dir: Path, session_id: str, suffix: str) -> Path:
    """Resolve a validated session file path below base_dir."""
    validated = validate_session_id(session_id)
    return contained_path(base_dir, f"{validated}{suffix}")


def write_private_atomic(path: Path, data: Union[bytes, str]) -> None:
    """Atomically replace path with owner-only content."""
    payload = data.encode("utf-8") if isinstance(data, str) else data
    ensure_private_dir(path.parent)
    fd = None
    tmp_name = ""
    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=str(path.parent),
        )
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "wb") as f:
            fd = None
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
    finally:
        if fd is not None:
            os.close(fd)
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass


def create_private_file(path: Path, data: Union[bytes, str]) -> None:
    """Create path with 0600 permissions, failing if it already exists."""
    payload = data.encode("utf-8") if isinstance(data, str) else data
    ensure_private_dir(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
    finally:
        if fd >= 0:
            os.close(fd)
