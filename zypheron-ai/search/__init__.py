"""
Zypheron Search Module

Provides full-text search capabilities using SQLite FTS5:
- CVE database search
- Exploit-DB search
- MITRE ATT&CK technique search
- Nuclei template search
- Scan results search
- Session history search
- PDF document search

Database location: ~/.zypheron/search.db
"""

from .fts_search import SearchDB, SearchResult
from .rag import RAGEngine
from .pdf_loader import PDFLoader
from .data_loaders import (
    DataLoaderManager,
    CVELoader,
    MITRELoader,
    NucleiLoader,
    ExploitDBLoader,
    SyncProgress,
    sync_cves,
    sync_mitre,
    sync_nuclei,
    sync_exploitdb,
)

__all__ = [
    # Core search
    "SearchDB",
    "SearchResult",
    # RAG
    "RAGEngine",
    # PDF
    "PDFLoader",
    # Data loaders
    "DataLoaderManager",
    "CVELoader",
    "MITRELoader",
    "NucleiLoader",
    "ExploitDBLoader",
    "SyncProgress",
    # Convenience functions
    "sync_cves",
    "sync_mitre",
    "sync_nuclei",
    "sync_exploitdb",
]
