"""
SQLite FTS5 Full-Text Search Database

Provides fast full-text search across:
- CVE database
- Exploit-DB entries
- MITRE ATT&CK techniques
- Nuclei templates
- Scan results
- Session history

Database location: ~/.zypheron/search.db
"""

import sqlite3
import threading
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class SearchResult:
    """A single search result"""
    table: str
    id: str
    title: str
    snippet: str
    score: float
    metadata: Dict[str, Any]


class SearchDB:
    """
    SQLite FTS5 search database for security data

    Thread-safe singleton pattern ensures one connection per process.
    """

    _instance: Optional['SearchDB'] = None
    _lock = threading.Lock()

    DB_PATH = Path.home() / ".zypheron" / "search.db"

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        self._local = threading.local()
        self._ensure_db_dir()
        self._init_schema()
        logger.info(f"Search database initialized at {self.DB_PATH}")

    def _ensure_db_dir(self):
        """Ensure database directory exists"""
        self.DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Security: Whitelist of allowed FTS5 table names (prevents SQL injection in get_stats)
    ALLOWED_TABLES = frozenset([
        'cve_search', 'exploit_search', 'attack_search',
        'nuclei_search', 'scan_search', 'session_search'
    ])

    @property
    def conn(self) -> sqlite3.Connection:
        """Get thread-local database connection"""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(self.DB_PATH),
                check_same_thread=True  # Security: enforce thread safety
            )
            self._local.conn.row_factory = sqlite3.Row
            # Enable WAL mode for better concurrent read performance
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    def _sanitize_fts5_query(self, query: str) -> str:
        """
        Sanitize FTS5 query to prevent syntax errors and injection.

        Security: Escapes special FTS5 operators that could cause crashes
        or unexpected behavior if user input is malformed.
        """
        if not query or not query.strip():
            return '""'  # Empty query returns no results safely

        query = query.strip()

        # Escape double quotes (FTS5 uses them for phrase search)
        query = query.replace('"', '""')

        # If query contains spaces or special chars, wrap in quotes for literal search
        # This prevents FTS5 syntax errors from unbalanced operators
        special_chars = ['(', ')', ':', '*', '^', 'OR', 'AND', 'NOT', 'NEAR']
        needs_quoting = ' ' in query or any(char in query.upper() for char in special_chars)

        if needs_quoting:
            return f'"{query}"'

        return query

    def _init_schema(self):
        """Initialize FTS5 tables"""
        cursor = self.conn.cursor()

        # CVE Database
        cursor.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS cve_search USING fts5(
                cve_id,
                description,
                affected_products,
                cvss_score UNINDEXED,
                published_date UNINDEXED,
                content='',
                tokenize='porter unicode61'
            )
        """)

        # Exploit-DB
        cursor.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS exploit_search USING fts5(
                exploit_id,
                title,
                description,
                platform,
                cve_references,
                content='',
                tokenize='porter unicode61'
            )
        """)

        # MITRE ATT&CK
        cursor.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS attack_search USING fts5(
                technique_id,
                name,
                description,
                tactics,
                platforms,
                content='',
                tokenize='porter unicode61'
            )
        """)

        # Nuclei Templates
        cursor.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS nuclei_search USING fts5(
                template_id,
                name,
                description,
                severity UNINDEXED,
                tags,
                content='',
                tokenize='porter unicode61'
            )
        """)

        # Scan Results
        cursor.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS scan_search USING fts5(
                scan_id UNINDEXED,
                target,
                findings,
                tools_used,
                timestamp UNINDEXED,
                content='',
                tokenize='porter unicode61'
            )
        """)

        # Session History
        cursor.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS session_search USING fts5(
                session_id UNINDEXED,
                command,
                output_summary,
                timestamp UNINDEXED,
                content='',
                tokenize='porter unicode61'
            )
        """)

        # Metadata table for sync tracking
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sync_metadata (
                table_name TEXT PRIMARY KEY,
                last_sync TEXT,
                record_count INTEGER,
                source_version TEXT
            )
        """)

        self.conn.commit()
        logger.debug("FTS5 schema initialized")

    # =========================================================================
    # CVE Operations
    # =========================================================================

    def add_cve(
        self,
        cve_id: str,
        description: str,
        affected_products: str,
        cvss_score: str,
        published_date: str
    ):
        """Add or update a CVE entry"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO cve_search
            (cve_id, description, affected_products, cvss_score, published_date)
            VALUES (?, ?, ?, ?, ?)
        """, (cve_id, description, affected_products, cvss_score, published_date))
        self.conn.commit()

    def add_cves_batch(self, cves: List[Dict[str, str]]):
        """Batch add CVEs for performance"""
        cursor = self.conn.cursor()
        cursor.executemany("""
            INSERT OR REPLACE INTO cve_search
            (cve_id, description, affected_products, cvss_score, published_date)
            VALUES (:cve_id, :description, :affected_products, :cvss_score, :published_date)
        """, cves)
        self.conn.commit()
        logger.info(f"Added {len(cves)} CVEs to search index")

    def search_cves(self, query: str, limit: int = 20) -> List[SearchResult]:
        """Search CVE database"""
        safe_query = self._sanitize_fts5_query(query)
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT
                cve_id, description, affected_products, cvss_score, published_date,
                bm25(cve_search) as score,
                snippet(cve_search, 1, '<b>', '</b>', '...', 50) as snippet
            FROM cve_search
            WHERE cve_search MATCH ?
            ORDER BY bm25(cve_search)
            LIMIT ?
        """, (safe_query, limit))

        results = []
        for row in cursor.fetchall():
            results.append(SearchResult(
                table="cve",
                id=row['cve_id'],
                title=row['cve_id'],
                snippet=row['snippet'],
                score=row['score'],
                metadata={
                    'description': row['description'],
                    'affected_products': row['affected_products'],
                    'cvss_score': row['cvss_score'],
                    'published_date': row['published_date'],
                }
            ))
        return results

    # =========================================================================
    # Exploit-DB Operations
    # =========================================================================

    def add_exploit(
        self,
        exploit_id: str,
        title: str,
        description: str,
        platform: str,
        cve_references: str
    ):
        """Add or update an Exploit-DB entry"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO exploit_search
            (exploit_id, title, description, platform, cve_references)
            VALUES (?, ?, ?, ?, ?)
        """, (exploit_id, title, description, platform, cve_references))
        self.conn.commit()

    def add_exploits_batch(self, exploits: List[Dict[str, str]]):
        """Batch add exploits"""
        cursor = self.conn.cursor()
        cursor.executemany("""
            INSERT OR REPLACE INTO exploit_search
            (exploit_id, title, description, platform, cve_references)
            VALUES (:exploit_id, :title, :description, :platform, :cve_references)
        """, exploits)
        self.conn.commit()
        logger.info(f"Added {len(exploits)} exploits to search index")

    def search_exploits(self, query: str, limit: int = 20) -> List[SearchResult]:
        """Search Exploit-DB"""
        safe_query = self._sanitize_fts5_query(query)
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT
                exploit_id, title, description, platform, cve_references,
                bm25(exploit_search) as score,
                snippet(exploit_search, 2, '<b>', '</b>', '...', 50) as snippet
            FROM exploit_search
            WHERE exploit_search MATCH ?
            ORDER BY bm25(exploit_search)
            LIMIT ?
        """, (safe_query, limit))

        results = []
        for row in cursor.fetchall():
            results.append(SearchResult(
                table="exploit",
                id=row['exploit_id'],
                title=row['title'],
                snippet=row['snippet'],
                score=row['score'],
                metadata={
                    'description': row['description'],
                    'platform': row['platform'],
                    'cve_references': row['cve_references'],
                }
            ))
        return results

    # =========================================================================
    # MITRE ATT&CK Operations
    # =========================================================================

    def add_attack_technique(
        self,
        technique_id: str,
        name: str,
        description: str,
        tactics: str,
        platforms: str
    ):
        """Add or update a MITRE ATT&CK technique"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO attack_search
            (technique_id, name, description, tactics, platforms)
            VALUES (?, ?, ?, ?, ?)
        """, (technique_id, name, description, tactics, platforms))
        self.conn.commit()

    def add_attack_techniques_batch(self, techniques: List[Dict[str, str]]):
        """Batch add MITRE techniques"""
        cursor = self.conn.cursor()
        cursor.executemany("""
            INSERT OR REPLACE INTO attack_search
            (technique_id, name, description, tactics, platforms)
            VALUES (:technique_id, :name, :description, :tactics, :platforms)
        """, techniques)
        self.conn.commit()
        logger.info(f"Added {len(techniques)} MITRE techniques to search index")

    def search_attack_techniques(self, query: str, limit: int = 20) -> List[SearchResult]:
        """Search MITRE ATT&CK techniques"""
        safe_query = self._sanitize_fts5_query(query)
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT
                technique_id, name, description, tactics, platforms,
                bm25(attack_search) as score,
                snippet(attack_search, 2, '<b>', '</b>', '...', 50) as snippet
            FROM attack_search
            WHERE attack_search MATCH ?
            ORDER BY bm25(attack_search)
            LIMIT ?
        """, (safe_query, limit))

        results = []
        for row in cursor.fetchall():
            results.append(SearchResult(
                table="attack",
                id=row['technique_id'],
                title=f"{row['technique_id']}: {row['name']}",
                snippet=row['snippet'],
                score=row['score'],
                metadata={
                    'description': row['description'],
                    'tactics': row['tactics'],
                    'platforms': row['platforms'],
                }
            ))
        return results

    # =========================================================================
    # Nuclei Template Operations
    # =========================================================================

    def add_nuclei_template(
        self,
        template_id: str,
        name: str,
        description: str,
        severity: str,
        tags: str
    ):
        """Add or update a Nuclei template"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO nuclei_search
            (template_id, name, description, severity, tags)
            VALUES (?, ?, ?, ?, ?)
        """, (template_id, name, description, severity, tags))
        self.conn.commit()

    def add_nuclei_templates_batch(self, templates: List[Dict[str, str]]):
        """Batch add Nuclei templates"""
        cursor = self.conn.cursor()
        cursor.executemany("""
            INSERT OR REPLACE INTO nuclei_search
            (template_id, name, description, severity, tags)
            VALUES (:template_id, :name, :description, :severity, :tags)
        """, templates)
        self.conn.commit()
        logger.info(f"Added {len(templates)} Nuclei templates to search index")

    def search_nuclei_templates(self, query: str, limit: int = 20) -> List[SearchResult]:
        """Search Nuclei templates"""
        safe_query = self._sanitize_fts5_query(query)
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT
                template_id, name, description, severity, tags,
                bm25(nuclei_search) as score,
                snippet(nuclei_search, 2, '<b>', '</b>', '...', 50) as snippet
            FROM nuclei_search
            WHERE nuclei_search MATCH ?
            ORDER BY bm25(nuclei_search)
            LIMIT ?
        """, (safe_query, limit))

        results = []
        for row in cursor.fetchall():
            results.append(SearchResult(
                table="nuclei",
                id=row['template_id'],
                title=row['name'],
                snippet=row['snippet'],
                score=row['score'],
                metadata={
                    'description': row['description'],
                    'severity': row['severity'],
                    'tags': row['tags'],
                }
            ))
        return results

    # =========================================================================
    # Scan Results Operations
    # =========================================================================

    def add_scan_result(
        self,
        scan_id: str,
        target: str,
        findings: str,
        tools_used: str,
        timestamp: Optional[str] = None
    ):
        """Add a scan result"""
        if timestamp is None:
            timestamp = datetime.now().isoformat()

        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO scan_search
            (scan_id, target, findings, tools_used, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (scan_id, target, findings, tools_used, timestamp))
        self.conn.commit()

    def search_scans(self, query: str, limit: int = 20) -> List[SearchResult]:
        """Search scan results"""
        safe_query = self._sanitize_fts5_query(query)
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT
                scan_id, target, findings, tools_used, timestamp,
                bm25(scan_search) as score,
                snippet(scan_search, 2, '<b>', '</b>', '...', 50) as snippet
            FROM scan_search
            WHERE scan_search MATCH ?
            ORDER BY bm25(scan_search)
            LIMIT ?
        """, (safe_query, limit))

        results = []
        for row in cursor.fetchall():
            results.append(SearchResult(
                table="scan",
                id=row['scan_id'],
                title=f"Scan: {row['target']}",
                snippet=row['snippet'],
                score=row['score'],
                metadata={
                    'target': row['target'],
                    'findings': row['findings'],
                    'tools_used': row['tools_used'],
                    'timestamp': row['timestamp'],
                }
            ))
        return results

    # =========================================================================
    # Session History Operations
    # =========================================================================

    def add_session_entry(
        self,
        session_id: str,
        command: str,
        output_summary: str,
        timestamp: Optional[str] = None
    ):
        """Add a session history entry"""
        if timestamp is None:
            timestamp = datetime.now().isoformat()

        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO session_search
            (session_id, command, output_summary, timestamp)
            VALUES (?, ?, ?, ?)
        """, (session_id, command, output_summary, timestamp))
        self.conn.commit()

    def search_sessions(self, query: str, limit: int = 20) -> List[SearchResult]:
        """Search session history"""
        safe_query = self._sanitize_fts5_query(query)
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT
                session_id, command, output_summary, timestamp,
                bm25(session_search) as score,
                snippet(session_search, 1, '<b>', '</b>', '...', 50) as snippet
            FROM session_search
            WHERE session_search MATCH ?
            ORDER BY bm25(session_search)
            LIMIT ?
        """, (safe_query, limit))

        results = []
        for row in cursor.fetchall():
            results.append(SearchResult(
                table="session",
                id=row['session_id'],
                title=row['command'][:100],
                snippet=row['snippet'],
                score=row['score'],
                metadata={
                    'command': row['command'],
                    'output_summary': row['output_summary'],
                    'timestamp': row['timestamp'],
                }
            ))
        return results

    # =========================================================================
    # Universal Search
    # =========================================================================

    def search_all(self, query: str, limit: int = 20) -> List[SearchResult]:
        """Search across all tables"""
        results = []

        # Search each table and combine
        results.extend(self.search_cves(query, limit=limit // 4))
        results.extend(self.search_exploits(query, limit=limit // 4))
        results.extend(self.search_attack_techniques(query, limit=limit // 4))
        results.extend(self.search_nuclei_templates(query, limit=limit // 4))
        results.extend(self.search_scans(query, limit=limit // 4))
        results.extend(self.search_sessions(query, limit=limit // 4))

        # Sort by score and limit
        results.sort(key=lambda r: r.score)
        return results[:limit]

    # =========================================================================
    # Metadata & Stats
    # =========================================================================

    def update_sync_metadata(self, table_name: str, record_count: int, source_version: str = ""):
        """Update sync metadata for a table"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO sync_metadata
            (table_name, last_sync, record_count, source_version)
            VALUES (?, ?, ?, ?)
        """, (table_name, datetime.now().isoformat(), record_count, source_version))
        self.conn.commit()

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        cursor = self.conn.cursor()

        stats = {}

        # Security: Only query tables from whitelist (prevents SQL injection)
        for table in self.ALLOWED_TABLES:
            # Table name is from whitelist, safe to interpolate
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            stats[table] = cursor.fetchone()[0]

        # Get sync metadata
        cursor.execute("SELECT * FROM sync_metadata")
        stats['sync_info'] = {row['table_name']: dict(row) for row in cursor.fetchall()}

        # Database size
        stats['db_size_mb'] = self.DB_PATH.stat().st_size / (1024 * 1024) if self.DB_PATH.exists() else 0

        return stats

    def close(self):
        """Close database connection"""
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
