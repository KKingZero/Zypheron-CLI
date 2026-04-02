"""Local durable storage for query-engine tasks and audit events."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from contracts.runtime import AuditEvent, TaskRecord, TaskStatus, utc_now_iso


class TaskStore:
    """Persist task state and audit events in a local SQLite database."""

    def __init__(self, db_path: Optional[str] = None):
        default_path = Path.home() / ".zypheron" / "runtime.db"
        self.db_path = str(db_path or default_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._harden_db_permissions()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=30, isolation_level=None)

    def _harden_db_permissions(self) -> None:
        """Restrict the runtime database to the current user where possible."""
        try:
            os.chmod(self.db_path, 0o600)
        except FileNotFoundError:
            pass
        except PermissionError:
            pass

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    input_summary TEXT NOT NULL,
                    provider TEXT,
                    model TEXT,
                    metadata TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_tasks_session ON tasks(session_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_task ON audit_events(task_id)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS session_approvals (
                    session_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (session_id, tool_name)
                )
                """
            )

    def upsert_task(self, task: TaskRecord) -> None:
        """Insert or update a task record."""
        task.updated_at = utc_now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tasks (
                    task_id, kind, status, session_id, input_summary, provider, model,
                    metadata, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    status = excluded.status,
                    session_id = excluded.session_id,
                    input_summary = excluded.input_summary,
                    provider = excluded.provider,
                    model = excluded.model,
                    metadata = excluded.metadata,
                    updated_at = excluded.updated_at
                """
                ,
                (
                    task.task_id,
                    task.kind,
                    task.status.value if isinstance(task.status, TaskStatus) else task.status,
                    task.session_id,
                    task.input_summary,
                    task.provider,
                    task.model,
                    json.dumps(task.metadata or {}),
                    task.created_at,
                    task.updated_at,
                ),
            )

    def get_task(self, task_id: str) -> Optional[TaskRecord]:
        """Fetch a single task record."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT task_id, kind, status, session_id, input_summary, provider, model,
                       metadata, created_at, updated_at
                FROM tasks WHERE task_id = ?
                """,
                (task_id,),
            ).fetchone()
        if not row:
            return None
        return TaskRecord(
            task_id=row[0],
            kind=row[1],
            status=TaskStatus(row[2]),
            session_id=row[3],
            input_summary=row[4],
            provider=row[5] or "",
            model=row[6] or "",
            metadata=json.loads(row[7] or "{}"),
            created_at=row[8],
            updated_at=row[9],
        )

    def list_tasks(
        self,
        limit: int = 50,
        session_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> List[TaskRecord]:
        """Return recent tasks."""
        clauses: List[str] = []
        params: List[Any] = []
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if task_id:
            clauses.append("task_id = ?")
            params.append(task_id)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT task_id, kind, status, session_id, input_summary, provider, model,
                       metadata, created_at, updated_at
                FROM tasks
                {where_sql}
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (*params, limit),
            ).fetchall()
        return [
            TaskRecord(
                task_id=row[0],
                kind=row[1],
                status=TaskStatus(row[2]),
                session_id=row[3],
                input_summary=row[4],
                provider=row[5] or "",
                model=row[6] or "",
                metadata=json.loads(row[7] or "{}"),
                created_at=row[8],
                updated_at=row[9],
            )
            for row in rows
        ]

    def append_event(self, event: AuditEvent) -> None:
        """Append an audit event."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (task_id, event_type, payload, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    event.task_id,
                    event.event_type,
                    json.dumps(event.payload or {}),
                    event.created_at,
                ),
            )

    def list_events(self, task_id: str) -> List[Dict[str, Any]]:
        """Return audit events for a task."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT event_type, payload, created_at
                FROM audit_events
                WHERE task_id = ?
                ORDER BY id ASC
                """,
                (task_id,),
            ).fetchall()
        return [
            {
                "event_type": row[0],
                "payload": json.loads(row[1] or "{}"),
                "created_at": row[2],
            }
            for row in rows
        ]

    def add_session_approval(self, session_id: str, tool_name: str) -> None:
        """Persist a session-wide tool approval."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO session_approvals (session_id, tool_name, created_at)
                VALUES (?, ?, ?)
                """,
                (session_id, tool_name, utc_now_iso()),
            )

    def has_session_approval(self, session_id: str, tool_name: str) -> bool:
        """Check whether a session-wide approval exists for a tool."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT 1
                FROM session_approvals
                WHERE session_id = ? AND tool_name = ?
                """,
                (session_id, tool_name),
            ).fetchone()
        return row is not None

    def claim_pending_approval(self, task_id: str, request_id: str) -> TaskRecord:
        """
        Atomically claim a waiting approval so only one caller can resume it.
        """
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT task_id, kind, status, session_id, input_summary, provider, model,
                       metadata, created_at, updated_at
                FROM tasks
                WHERE task_id = ?
                """,
                (task_id,),
            ).fetchone()
            if not row:
                conn.execute("ROLLBACK")
                raise ValueError(f"Task not found: {task_id}")

            metadata = json.loads(row[7] or "{}")
            if row[2] != TaskStatus.WAITING_APPROVAL.value:
                conn.execute("ROLLBACK")
                raise ValueError(f"Task is not waiting for approval: {task_id}")

            pending_request = metadata.get("pending_approval_request") or {}
            if pending_request.get("request_id") != request_id:
                conn.execute("ROLLBACK")
                raise ValueError("Approval request id does not match pending task")

            if metadata.get("approval_claimed"):
                conn.execute("ROLLBACK")
                raise ValueError("Approval request is already being processed")

            metadata["approval_claimed"] = request_id
            updated_at = utc_now_iso()
            conn.execute(
                """
                UPDATE tasks
                SET status = ?, metadata = ?, updated_at = ?
                WHERE task_id = ?
                """,
                (
                    TaskStatus.RUNNING.value,
                    json.dumps(metadata),
                    updated_at,
                    task_id,
                ),
            )
            conn.execute("COMMIT")

        return TaskRecord(
            task_id=row[0],
            kind=row[1],
            status=TaskStatus.RUNNING,
            session_id=row[3],
            input_summary=row[4],
            provider=row[5] or "",
            model=row[6] or "",
            metadata=metadata,
            created_at=row[8],
            updated_at=updated_at,
        )

    def set_approval_response(self, task_id: str, request_id: str, decision: str) -> None:
        """Persist an external approval response for non-query-engine workflows."""
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT metadata FROM tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            if not row:
                conn.execute("ROLLBACK")
                raise ValueError(f"Task not found: {task_id}")
            metadata = json.loads(row[0] or "{}")
            pending_request = metadata.get("pending_approval_request") or {}
            if pending_request.get("request_id") != request_id:
                conn.execute("ROLLBACK")
                raise ValueError("Approval request id does not match pending task")
            metadata["pending_approval_response"] = {
                "request_id": request_id,
                "decision": decision,
                "decided_at": utc_now_iso(),
            }
            conn.execute(
                """
                UPDATE tasks
                SET metadata = ?, updated_at = ?
                WHERE task_id = ?
                """,
                (json.dumps(metadata), utc_now_iso(), task_id),
            )
            conn.execute("COMMIT")

    def recover_claimed_approvals(self) -> None:
        """
        Return interrupted approval-resume tasks to WAITING_APPROVAL on startup.
        """
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT task_id, metadata
                FROM tasks
                WHERE status = ?
                """,
                (TaskStatus.RUNNING.value,),
            ).fetchall()
            for task_id, raw_metadata in rows:
                metadata = json.loads(raw_metadata or "{}")
                if not metadata.get("pending_tool_call") or not metadata.get("pending_approval_request"):
                    continue
                if not metadata.get("approval_claimed"):
                    continue
                metadata.pop("approval_claimed", None)
                conn.execute(
                    """
                    UPDATE tasks
                    SET status = ?, metadata = ?, updated_at = ?
                    WHERE task_id = ?
                    """,
                    (
                        TaskStatus.WAITING_APPROVAL.value,
                        json.dumps(metadata),
                        utc_now_iso(),
                        task_id,
                    ),
                )
