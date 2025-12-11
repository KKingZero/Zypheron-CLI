"""
Rollback Manager - State management and rollback capabilities
"""

import logging
import json
import shutil
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
import tempfile

logger = logging.getLogger(__name__)


@dataclass
class Checkpoint:
    """State checkpoint for rollback"""
    checkpoint_id: str
    created_at: datetime
    description: str
    
    # State data
    files_changed: List[Dict[str, Any]] = field(default_factory=list)
    commands_executed: List[str] = field(default_factory=list)
    network_connections: List[str] = field(default_factory=list)
    
    # Backup data
    backup_path: Optional[str] = None
    
    # Metadata
    tags: List[str] = field(default_factory=list)
    rolled_back: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'checkpoint_id': self.checkpoint_id,
            'created_at': self.created_at.isoformat(),
            'description': self.description,
            'files_changed': self.files_changed,
            'commands_executed': self.commands_executed,
            'network_connections': self.network_connections,
            'backup_path': self.backup_path,
            'tags': self.tags,
            'rolled_back': self.rolled_back
        }


class RollbackManager:
    """
    Manage state checkpoints and rollback operations
    
    Features:
    - Create checkpoints before destructive operations
    - Track all changes
    - Rollback to previous state
    - Backup important files
    - Audit trail
    """
    
    def __init__(self, backup_dir: Optional[str] = None):
        if backup_dir:
            self.backup_dir = Path(backup_dir)
        else:
            self.backup_dir = Path(tempfile.gettempdir()) / 'zypheron_backups'
        
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoints: Dict[str, Checkpoint] = {}
    
    def create_checkpoint(
        self,
        description: str,
        tags: Optional[List[str]] = None
    ) -> Checkpoint:
        """
        Create a new checkpoint
        
        Args:
            description: Description of the checkpoint
            tags: Optional tags for categorization
            
        Returns:
            Checkpoint object
        """
        checkpoint_id = f"checkpoint_{int(datetime.now().timestamp())}"
        
        checkpoint = Checkpoint(
            checkpoint_id=checkpoint_id,
            created_at=datetime.now(),
            description=description,
            tags=tags or []
        )
        
        # Create backup directory for this checkpoint
        checkpoint_backup_dir = self.backup_dir / checkpoint_id
        checkpoint_backup_dir.mkdir(parents=True, exist_ok=True)
        checkpoint.backup_path = str(checkpoint_backup_dir)
        
        self.checkpoints[checkpoint_id] = checkpoint
        logger.info(f"Created checkpoint: {checkpoint_id}")
        
        return checkpoint
    
    def record_file_change(
        self,
        checkpoint_id: str,
        file_path: str,
        operation: str,
        backup: bool = True
    ) -> bool:
        """
        Record a file change in checkpoint
        
        Args:
            checkpoint_id: Checkpoint ID
            file_path: Path to file
            operation: Operation (create, modify, delete)
            backup: Whether to backup original file
            
        Returns:
            Success status
        """
        if checkpoint_id not in self.checkpoints:
            logger.error(f"Checkpoint not found: {checkpoint_id}")
            return False
        
        checkpoint = self.checkpoints[checkpoint_id]
        
        # Backup original file if it exists
        backup_path = None
        if backup and Path(file_path).exists():
            try:
                backup_filename = Path(file_path).name + '.bak'
                backup_path = str(Path(checkpoint.backup_path) / backup_filename)
                shutil.copy2(file_path, backup_path)
                logger.debug(f"Backed up {file_path} to {backup_path}")
            except Exception as e:
                logger.error(f"Failed to backup {file_path}: {e}")
                return False
        
        # Record change
        change = {
            'file_path': file_path,
            'operation': operation,
            'timestamp': datetime.now().isoformat(),
            'backup_path': backup_path,
            'original_exists': Path(file_path).exists()
        }
        
        checkpoint.files_changed.append(change)
        return True
    
    def record_command(
        self,
        checkpoint_id: str,
        command: str
    ) -> bool:
        """Record executed command"""
        if checkpoint_id not in self.checkpoints:
            return False
        
        checkpoint = self.checkpoints[checkpoint_id]
        checkpoint.commands_executed.append(command)
        return True
    
    def rollback(self, checkpoint_id: str) -> bool:
        """
        Rollback to checkpoint state
        
        Args:
            checkpoint_id: Checkpoint ID to rollback to
            
        Returns:
            Success status
        """
        if checkpoint_id not in self.checkpoints:
            logger.error(f"Checkpoint not found: {checkpoint_id}")
            return False
        
        checkpoint = self.checkpoints[checkpoint_id]
        
        if checkpoint.rolled_back:
            logger.warning(f"Checkpoint {checkpoint_id} already rolled back")
            return True
        
        logger.info(f"Rolling back checkpoint: {checkpoint_id}")
        success = True
        
        # Rollback file changes in reverse order
        for change in reversed(checkpoint.files_changed):
            try:
                file_path = Path(change['file_path'])
                operation = change['operation']
                backup_path = change.get('backup_path')
                
                if operation == 'create':
                    # Delete created file
                    if file_path.exists():
                        file_path.unlink()
                        logger.debug(f"Deleted created file: {file_path}")
                        
                elif operation == 'modify':
                    # Restore from backup
                    if backup_path and Path(backup_path).exists():
                        shutil.copy2(backup_path, str(file_path))
                        logger.debug(f"Restored {file_path} from backup")
                    else:
                        logger.warning(f"No backup found for {file_path}")
                        success = False
                        
                elif operation == 'delete':
                    # Restore from backup
                    if backup_path and Path(backup_path).exists():
                        shutil.copy2(backup_path, str(file_path))
                        logger.debug(f"Restored deleted file: {file_path}")
                    else:
                        logger.warning(f"Cannot restore deleted file {file_path}")
                        success = False
                        
            except Exception as e:
                logger.error(f"Failed to rollback change: {e}")
                success = False
        
        checkpoint.rolled_back = True
        return success
    
    def get_checkpoint(self, checkpoint_id: str) -> Optional[Checkpoint]:
        """Get checkpoint by ID"""
        return self.checkpoints.get(checkpoint_id)
    
    def list_checkpoints(
        self,
        tags: Optional[List[str]] = None
    ) -> List[Checkpoint]:
        """List all checkpoints, optionally filtered by tags"""
        checkpoints = list(self.checkpoints.values())
        
        if tags:
            checkpoints = [
                cp for cp in checkpoints
                if any(tag in cp.tags for tag in tags)
            ]
        
        return sorted(checkpoints, key=lambda x: x.created_at, reverse=True)
    
    def cleanup_old_checkpoints(self, days: int = 7) -> int:
        """
        Clean up checkpoints older than specified days
        
        Args:
            days: Number of days to keep
            
        Returns:
            Number of checkpoints cleaned up
        """
        cutoff = datetime.now().timestamp() - (days * 86400)
        cleaned = 0
        
        for checkpoint_id in list(self.checkpoints.keys()):
            checkpoint = self.checkpoints[checkpoint_id]
            if checkpoint.created_at.timestamp() < cutoff:
                # Delete backup directory
                if checkpoint.backup_path:
                    try:
                        shutil.rmtree(checkpoint.backup_path)
                    except Exception as e:
                        logger.error(f"Failed to delete backup: {e}")
                
                # Remove checkpoint
                del self.checkpoints[checkpoint_id]
                cleaned += 1
                logger.debug(f"Cleaned up checkpoint: {checkpoint_id}")
        
        logger.info(f"Cleaned up {cleaned} old checkpoints")
        return cleaned
    
    def export_checkpoint(
        self,
        checkpoint_id: str,
        output_file: str
    ) -> bool:
        """Export checkpoint to JSON file"""
        checkpoint = self.get_checkpoint(checkpoint_id)
        if not checkpoint:
            return False
        
        try:
            with open(output_file, 'w') as f:
                json.dump(checkpoint.to_dict(), f, indent=2)
            logger.info(f"Exported checkpoint to {output_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to export checkpoint: {e}")
            return False

