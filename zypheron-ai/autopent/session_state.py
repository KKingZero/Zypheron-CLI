"""
Session State Manager - Save and resume attack path sessions

Per user requirement: Save on request (manual save/resume)
"""

import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class SessionMetadata:
    """Metadata about a saved session"""
    session_id: str
    objective: str
    initial_target: str
    created_at: datetime
    last_updated: datetime
    status: str  # running, paused, completed, failed
    total_steps: int
    completed_steps: int
    saved_by_user: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            'created_at': self.created_at.isoformat(),
            'last_updated': self.last_updated.isoformat(),
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'SessionMetadata':
        return SessionMetadata(
            session_id=data['session_id'],
            objective=data['objective'],
            initial_target=data['initial_target'],
            created_at=datetime.fromisoformat(data['created_at']),
            last_updated=datetime.fromisoformat(data['last_updated']),
            status=data['status'],
            total_steps=data['total_steps'],
            completed_steps=data['completed_steps'],
            saved_by_user=data.get('saved_by_user', True),
        )


class SessionStateManager:
    """
    Manages session state persistence

    Features:
    - Save attack path graph state
    - Save credentials and approvals
    - Resume from saved state
    - List saved sessions
    - Delete old sessions
    """

    def __init__(self, state_dir: Optional[str] = None):
        if state_dir:
            self.state_dir = Path(state_dir)
        else:
            # Default: ~/.zypheron/sessions/
            home = Path.home()
            self.state_dir = home / '.zypheron' / 'sessions'

        self.state_dir.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Session state directory: {self.state_dir}")

    def save_session(
        self,
        session_id: str,
        attack_graph: Any,  # AttackPathGraph
        credential_vault: Any,  # CredentialVault
        approval_manager: Any,  # ApprovalManager
        metadata: Optional[Dict[str, Any]] = None
    ) -> Path:
        """
        Save current session state

        Args:
            session_id: Unique session identifier
            attack_graph: AttackPathGraph instance
            credential_vault: CredentialVault instance
            approval_manager: ApprovalManager instance
            metadata: Optional additional metadata

        Returns:
            Path to saved session file
        """
        session_file = self.state_dir / f"{session_id}.json"

        # Build session data
        session_data = {
            'metadata': SessionMetadata(
                session_id=session_id,
                objective=attack_graph.objective,
                initial_target=attack_graph.initial_target,
                created_at=datetime.now(),
                last_updated=datetime.now(),
                status='paused',  # Saved sessions are paused
                total_steps=len(attack_graph.edges),
                completed_steps=sum(
                    1 for e in attack_graph.edges.values() if e.successful
                ),
                saved_by_user=True,
            ).to_dict(),

            'attack_graph': attack_graph.to_dict(),

            'credentials': {
                'vault': [cred.to_dict() for cred in credential_vault.credentials.values()],
                'session_auto_approve': list(credential_vault.session_auto_approve),
                'summary': credential_vault.get_vault_summary(),
            },

            'approvals': {
                'session_approvals': approval_manager.get_session_approvals(),
                'denied_actions': list(approval_manager.denied_actions),
                'summary': approval_manager.get_approval_summary(),
            },

            'additional': metadata or {},

            'saved_at': datetime.now().isoformat(),
        }

        # Write to file
        with open(session_file, 'w') as f:
            json.dump(session_data, f, indent=2, default=str)

        logger.info(f"💾 Session saved: {session_id}")
        logger.info(f"   File: {session_file}")

        return session_file

    def load_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Load a saved session

        Args:
            session_id: Session identifier

        Returns:
            Session data dictionary or None if not found
        """
        session_file = self.state_dir / f"{session_id}.json"

        if not session_file.exists():
            logger.error(f"Session not found: {session_id}")
            return None

        try:
            with open(session_file, 'r') as f:
                session_data = json.load(f)

            logger.info(f"📂 Session loaded: {session_id}")
            return session_data

        except Exception as e:
            logger.error(f"Failed to load session {session_id}: {e}")
            return None

    def list_sessions(self) -> List[SessionMetadata]:
        """
        List all saved sessions

        Returns:
            List of SessionMetadata objects
        """
        sessions = []

        for session_file in self.state_dir.glob("*.json"):
            try:
                with open(session_file, 'r') as f:
                    data = json.load(f)

                metadata = SessionMetadata.from_dict(data['metadata'])
                sessions.append(metadata)

            except Exception as e:
                logger.warning(f"Failed to read session file {session_file}: {e}")
                continue

        # Sort by last updated (most recent first)
        sessions.sort(key=lambda s: s.last_updated, reverse=True)

        return sessions

    def delete_session(self, session_id: str) -> bool:
        """
        Delete a saved session

        Args:
            session_id: Session to delete

        Returns:
            True if deleted, False otherwise
        """
        session_file = self.state_dir / f"{session_id}.json"

        if not session_file.exists():
            logger.warning(f"Session not found: {session_id}")
            return False

        try:
            session_file.unlink()
            logger.info(f"🗑️  Session deleted: {session_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete session {session_id}: {e}")
            return False

    def resume_session(
        self,
        session_id: str
    ) -> Optional[tuple]:
        """
        Resume a saved session

        Returns:
            Tuple of (attack_graph_data, credential_vault_data, approval_data, metadata)
            or None if session not found
        """
        session_data = self.load_session(session_id)

        if not session_data:
            return None

        return (
            session_data['attack_graph'],
            session_data['credentials'],
            session_data['approvals'],
            session_data.get('additional', {}),
        )

    def get_session_metadata(self, session_id: str) -> Optional[SessionMetadata]:
        """Get metadata for a specific session"""
        session_data = self.load_session(session_id)

        if not session_data:
            return None

        return SessionMetadata.from_dict(session_data['metadata'])

    def auto_save(
        self,
        session_id: str,
        attack_graph: Any,
        credential_vault: Any,
        approval_manager: Any,
    ):
        """
        Auto-save session (for crash recovery)

        This creates a backup that can be recovered
        """
        backup_file = self.state_dir / f"{session_id}.autosave.json"

        try:
            session_data = {
                'metadata': SessionMetadata(
                    session_id=session_id,
                    objective=attack_graph.objective,
                    initial_target=attack_graph.initial_target,
                    created_at=datetime.now(),
                    last_updated=datetime.now(),
                    status='running',
                    total_steps=len(attack_graph.edges),
                    completed_steps=sum(
                        1 for e in attack_graph.edges.values() if e.successful
                    ),
                    saved_by_user=False,  # Auto-save
                ).to_dict(),

                'attack_graph': attack_graph.to_dict(),

                'credentials': {
                    'vault': [cred.to_dict() for cred in credential_vault.credentials.values()],
                    'session_auto_approve': list(credential_vault.session_auto_approve),
                },

                'approvals': {
                    'session_approvals': approval_manager.get_session_approvals(),
                    'denied_actions': list(approval_manager.denied_actions),
                },

                'saved_at': datetime.now().isoformat(),
            }

            with open(backup_file, 'w') as f:
                json.dump(session_data, f, indent=2, default=str)

            logger.debug(f"Auto-saved session: {session_id}")

        except Exception as e:
            logger.warning(f"Auto-save failed: {e}")

    def format_session_list(self, sessions: List[SessionMetadata]) -> str:
        """
        Format session list for display

        Returns:
            Formatted string for terminal
        """
        if not sessions:
            return "\nNo saved sessions found.\n"

        lines = []
        lines.append("\n" + "="*80)
        lines.append("SAVED SESSIONS")
        lines.append("="*80 + "\n")

        for i, session in enumerate(sessions, 1):
            age = datetime.now() - session.last_updated
            age_str = self._format_timedelta(age)

            progress = (
                f"{session.completed_steps}/{session.total_steps} steps "
                f"({session.completed_steps / session.total_steps * 100:.0f}%)"
                if session.total_steps > 0 else "0 steps"
            )

            status_emoji = {
                'running': '⚡',
                'paused': '⏸️ ',
                'completed': '✓',
                'failed': '✗',
            }.get(session.status, '○')

            lines.append(f"{i}. {status_emoji} {session.session_id}")
            lines.append(f"   Objective: {session.objective}")
            lines.append(f"   Target: {session.initial_target}")
            lines.append(f"   Progress: {progress}")
            lines.append(f"   Last Updated: {age_str} ago")
            lines.append(f"   Status: {session.status}")
            lines.append("")

        lines.append("="*80 + "\n")
        return "\n".join(lines)

    def _format_timedelta(self, delta) -> str:
        """Format timedelta for human-readable display"""
        seconds = int(delta.total_seconds())

        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            return f"{seconds // 60}m"
        elif seconds < 86400:
            return f"{seconds // 3600}h"
        else:
            return f"{seconds // 86400}d"
