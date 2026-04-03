"""
Zypheron AI Memory Manager
Handles tiered contextual memory (Working, Session, Campaign, Organizational) with SQLite persistence and encryption.
"""

import sqlite3
import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from enum import Enum
from cryptography.fernet import Fernet
from loguru import logger
from core.config import config

class MemoryTier(str, Enum):
    WORKING = "working"
    SESSION = "session"
    CAMPAIGN = "campaign"
    ORGANIZATION = "organization"

class MemoryManager:
    """Manages secure, persistent, tiered memory"""

    def __init__(self, db_path: str = None, encryption_key: bytes = None):
        self.db_path = db_path or str(Path.home() / ".zypheron" / "memory.db")
        self.encryption_key = encryption_key or self._load_or_create_key()
        self.cipher = Fernet(self.encryption_key)
        self._init_db()

    def _load_or_create_key(self) -> bytes:
        """Load encryption key or create a new one"""
        key_file = Path.home() / ".zypheron" / "memory.key"
        key_file.parent.mkdir(parents=True, exist_ok=True)
        
        if key_file.exists():
            return key_file.read_bytes()
        
        key = Fernet.generate_key()
        try:
            key_file.write_bytes(key)
            key_file.chmod(0o600)
            return key
        except Exception as e:
            logger.error(f"Failed to save specific memory key: {e}")
            raise

    def _init_db(self):
        """Initialize SQLite database with schema"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS memories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tier TEXT NOT NULL,
                    context_id TEXT NOT NULL,
                    key TEXT NOT NULL,
                    value TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    metadata TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tier_context ON memories(tier, context_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_key ON memories(key)")

    def _encrypt(self, data: str) -> str:
        """Encrypt string data"""
        return self.cipher.encrypt(data.encode()).decode()

    def _decrypt(self, data: str) -> str:
        """Decrypt string data"""
        return self.cipher.decrypt(data.encode()).decode()

    def store(self, tier: MemoryTier, context_id: str, key: str, value: Any, metadata: Dict[str, Any] = None):
        """Store a memory item"""
        json_value = json.dumps(value)
        encrypted_value = self._encrypt(json_value)
        timestamp = time.time()
        json_metadata = json.dumps(metadata or {})

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO memories (tier, context_id, key, value, timestamp, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (tier.value, context_id, key, encrypted_value, timestamp, json_metadata))
            
    def retrieve(self, tier: MemoryTier, context_id: str, key: str) -> Optional[Any]:
        """Retrieve a specific memory item"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT value FROM memories 
                WHERE tier = ? AND context_id = ? AND key = ?
            """, (tier.value, context_id, key))
            row = cursor.fetchone()
            
            if row:
                try:
                    decrypted = self._decrypt(row[0])
                    return json.loads(decrypted)
                except Exception as e:
                    logger.error(f"Failed to decrypt memory {key}: {e}")
                    return None
            return None

    def retrieve_context(self, tier: MemoryTier, context_id: str) -> Dict[str, Any]:
        """Retrieve all memories for a specific context"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT key, value FROM memories 
                WHERE tier = ? AND context_id = ?
            """, (tier.value, context_id))
            
            results = {}
            for key, encrypted_value in cursor.fetchall():
                try:
                    results[key] = json.loads(self._decrypt(encrypted_value))
                except Exception as e:
                    logger.error(f"Failed to decrypt memory {key}: {e}")
            return results

    def search(self, query: str, tier: Optional[MemoryTier] = None, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Simple text search across memories (decryption required, expensive)
        For production, use FTS5 or vector DB.
        """
        # Optimized for small-scale local DB
        matches = []
        with sqlite3.connect(self.db_path) as conn:
            sql = "SELECT tier, context_id, key, value, metadata FROM memories"
            params = []
            if tier:
                sql += " WHERE tier = ?"
                params.append(tier.value)
            
            cursor = conn.execute(sql, params)
            for row in cursor:
                try:
                    decrypted_val = self._decrypt(row[3])
                    # Naive case-insensitive search
                    if query.lower() in decrypted_val.lower() or query.lower() in row[2].lower():
                        matches.append({
                            "tier": row[0],
                            "context_id": row[1],
                            "key": row[2],
                            "value": json.loads(decrypted_val),
                            "metadata": json.loads(row[4]) if row[4] else {}
                        })
                        if len(matches) >= limit:
                            break
                except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                    continue
        return matches

# Global instance
memory_manager = MemoryManager()
