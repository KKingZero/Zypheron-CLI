"""
PDF Document Loader for Zypheron

Extracts text from PDF documents and indexes them for full-text search.
Supports:
- Penetration testing reports
- Compliance documentation
- Security advisories
- Technical whitepapers
- Vulnerability research papers

Uses pypdf for PDF parsing and chunks documents for optimal search performance.
"""

import hashlib
import json
import logging
import re
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime

try:
    from pypdf import PdfReader
except ImportError:
    try:
        from PyPDF2 import PdfReader
    except ImportError:
        raise ImportError(
            "PDF parsing library not found. Install with: pip install pypdf"
        )

from .fts_search import SearchDB

logger = logging.getLogger(__name__)


@dataclass
class PDFDocument:
    """Represents a parsed PDF document"""
    file_path: str
    file_hash: str
    title: str
    author: str
    page_count: int
    created_date: Optional[str]
    doc_type: str  # 'pentest_report', 'compliance', 'advisory', 'research', 'other'
    file_size: int
    metadata: Dict[str, Any]


@dataclass
class PDFChunk:
    """A chunk of text from a PDF document"""
    doc_id: str
    chunk_id: int
    page_number: int
    text: str
    char_count: int


class PDFLoader:
    """
    PDF document loader with chunking and FTS5 indexing

    Features:
    - Extracts text from PDF files
    - Chunks large documents for better search results
    - Deduplicates by file hash
    - Stores metadata for filtering
    - Integrates with SearchDB for full-text search

    Security considerations:
    - File paths are validated to prevent path traversal
    - File size limits prevent DoS
    - Hash-based deduplication prevents redundant indexing
    - Input sanitization on all text fields
    """

    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB (conservative for memory)
    CHUNK_SIZE = 2500  # ~500 words
    CHUNK_OVERLAP = 250

    # Allowed directories for PDF loading (security: path traversal protection)
    ALLOWED_DIRS = [
        Path.home(),  # User's home directory
        Path(tempfile.gettempdir()),  # System temp directory
    ]

    DOC_TYPE_KEYWORDS = {
        'pentest_report': [
            'penetration test', 'pentest', 'security assessment',
            'vulnerability assessment', 'red team', 'exploit',
            'findings', 'remediation', 'risk rating'
        ],
        'compliance': [
            'compliance', 'audit', 'pci-dss', 'hipaa', 'gdpr',
            'iso 27001', 'sox', 'nist', 'cis benchmark'
        ],
        'advisory': [
            'security advisory', 'bulletin', 'patch', 'update',
            'cve-', 'vulnerability disclosure', 'security notice'
        ],
        'research': [
            'whitepaper', 'research paper', 'analysis', 'study',
            'methodology', 'technique', 'proof of concept'
        ]
    }

    def __init__(self, search_db: Optional[SearchDB] = None):
        """Initialize PDF loader with database connection"""
        self.db = search_db or SearchDB()
        self._ensure_pdf_tables()
        logger.info("PDFLoader initialized")

    def _ensure_pdf_tables(self):
        """Create PDF-specific tables in the search database"""
        cursor = self.db.conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pdf_documents (
                doc_id TEXT PRIMARY KEY,
                file_path TEXT NOT NULL,
                file_hash TEXT UNIQUE NOT NULL,
                title TEXT,
                author TEXT,
                page_count INTEGER,
                created_date TEXT,
                indexed_date TEXT NOT NULL,
                doc_type TEXT,
                file_size INTEGER,
                metadata TEXT
            )
        """)

        cursor.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS pdf_search USING fts5(
                doc_id UNINDEXED,
                chunk_id UNINDEXED,
                page_number UNINDEXED,
                title,
                doc_type,
                content,
                tokenize='porter unicode61'
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_pdf_hash
            ON pdf_documents(file_hash)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_pdf_type
            ON pdf_documents(doc_type)
        """)

        self.db.conn.commit()
        logger.debug("PDF tables initialized")

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file for deduplication"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(8192), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _validate_file_path(self, file_path: Path) -> None:
        """Validate file path for security"""
        resolved_path = file_path.resolve()

        # Security: Path traversal protection - must be within allowed directories
        is_allowed = any(
            resolved_path == allowed_dir or allowed_dir in resolved_path.parents
            for allowed_dir in self.ALLOWED_DIRS
        )
        if not is_allowed:
            logger.warning(f"SECURITY: Blocked path traversal attempt: {file_path}")
            raise PermissionError(
                f"File path not in allowed directories. "
                f"Allowed: {[str(d) for d in self.ALLOWED_DIRS]}"
            )

        if not resolved_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if not resolved_path.is_file():
            raise ValueError(f"Not a regular file: {file_path}")

        file_size = resolved_path.stat().st_size
        if file_size > self.MAX_FILE_SIZE:
            raise ValueError(
                f"File too large: {file_size} bytes (max: {self.MAX_FILE_SIZE} bytes)"
            )

        if file_size == 0:
            raise ValueError(f"Empty file: {file_path}")

    def _sanitize_text(self, text: str) -> str:
        """Sanitize extracted text"""
        if not text:
            return ""
        text = re.sub(r'[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]', '', text)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()

    def _extract_pdf_metadata(self, reader: PdfReader, file_path: Path) -> Dict[str, Any]:
        """Extract metadata from PDF"""
        metadata = {}
        try:
            if reader.metadata:
                metadata['title'] = reader.metadata.get('/Title', '')
                metadata['author'] = reader.metadata.get('/Author', '')
                metadata['subject'] = reader.metadata.get('/Subject', '')
                metadata['creator'] = reader.metadata.get('/Creator', '')
                metadata['producer'] = reader.metadata.get('/Producer', '')

                created = reader.metadata.get('/CreationDate', '')
                if created:
                    metadata['created_date'] = str(created)

                metadata = {
                    k: self._sanitize_text(str(v)) if v else ''
                    for k, v in metadata.items()
                }
        except Exception as e:
            logger.warning(f"Failed to extract metadata from {file_path}: {e}")
        return metadata

    def _classify_document(self, text: str, metadata: Dict[str, Any]) -> str:
        """Automatically classify document type based on content"""
        combined_text = text.lower()

        if metadata.get('title'):
            combined_text += ' ' + metadata['title'].lower()
        if metadata.get('subject'):
            combined_text += ' ' + metadata['subject'].lower()

        type_scores = {}
        for doc_type, keywords in self.DOC_TYPE_KEYWORDS.items():
            score = sum(1 for keyword in keywords if keyword in combined_text)
            if score > 0:
                type_scores[doc_type] = score

        if type_scores:
            return max(type_scores, key=type_scores.get)
        return 'other'

    def _chunk_text(self, text: str, page_number: int) -> List[Tuple[str, int]]:
        """Split text into overlapping chunks for better search results"""
        if not text or len(text) <= self.CHUNK_SIZE:
            return [(text, page_number)]

        chunks = []
        start = 0

        while start < len(text):
            end = start + self.CHUNK_SIZE

            if end < len(text):
                for marker in ['. ', '.\n', '? ', '! ']:
                    last_sentence = text.rfind(marker, start, end)
                    if last_sentence != -1:
                        end = last_sentence + 1
                        break

            chunk = text[start:end].strip()
            if chunk:
                chunks.append((chunk, page_number))

            start = end - self.CHUNK_OVERLAP if end < len(text) else end

        return chunks

    def extract_text_from_pdf(self, file_path: Path) -> Tuple[str, List[PDFChunk]]:
        """Extract all text from PDF and create chunks"""
        reader = PdfReader(str(file_path))

        full_text_parts = []
        all_chunks = []
        chunk_counter = 0

        for page_num, page in enumerate(reader.pages, start=1):
            try:
                page_text = page.extract_text()
                if not page_text:
                    continue

                page_text = self._sanitize_text(page_text)
                full_text_parts.append(page_text)

                page_chunks = self._chunk_text(page_text, page_num)
                for chunk_text, chunk_page in page_chunks:
                    all_chunks.append(PDFChunk(
                        doc_id='',
                        chunk_id=chunk_counter,
                        page_number=chunk_page,
                        text=chunk_text,
                        char_count=len(chunk_text)
                    ))
                    chunk_counter += 1

            except Exception as e:
                logger.error(f"Failed to extract text from page {page_num}: {e}")

        full_text = '\n'.join(full_text_parts)
        logger.info(
            f"Extracted {len(full_text)} characters from "
            f"{len(reader.pages)} pages, created {len(all_chunks)} chunks"
        )
        return full_text, all_chunks

    def load_pdf(
        self,
        file_path: str,
        doc_type: Optional[str] = None,
        force_reload: bool = False
    ) -> PDFDocument:
        """Load and index a PDF document"""
        path = Path(file_path)
        self._validate_file_path(path)

        file_hash = self._calculate_file_hash(path)

        if not force_reload:
            cursor = self.db.conn.cursor()
            cursor.execute(
                "SELECT doc_id FROM pdf_documents WHERE file_hash = ?",
                (file_hash,)
            )
            existing = cursor.fetchone()
            if existing:
                logger.info(f"PDF already indexed: {file_path}")
                return self.get_document(existing[0])

        logger.info(f"Loading PDF: {file_path}")
        reader = PdfReader(str(path))

        metadata = self._extract_pdf_metadata(reader, path)
        full_text, chunks = self.extract_text_from_pdf(path)

        if not full_text:
            raise ValueError(f"No text could be extracted from PDF: {file_path}")

        if doc_type is None:
            doc_type = self._classify_document(full_text, metadata)

        doc_id = hashlib.md5(file_hash.encode()).hexdigest()

        for chunk in chunks:
            chunk.doc_id = doc_id

        doc = PDFDocument(
            file_path=str(path.resolve()),
            file_hash=file_hash,
            title=metadata.get('title', '') or path.stem,
            author=metadata.get('author', ''),
            page_count=len(reader.pages),
            created_date=metadata.get('created_date'),
            doc_type=doc_type,
            file_size=path.stat().st_size,
            metadata=metadata
        )

        self._index_document(doc, chunks)

        logger.info(
            f"Successfully indexed PDF: {doc.title} "
            f"({doc.page_count} pages, {len(chunks)} chunks, type: {doc.doc_type})"
        )
        return doc

    def _index_document(self, doc: PDFDocument, chunks: List[PDFChunk]):
        """Index document and chunks in FTS5 database"""
        cursor = self.db.conn.cursor()

        try:
            cursor.execute("BEGIN TRANSACTION")

            doc_id = hashlib.md5(doc.file_hash.encode()).hexdigest()

            cursor.execute("""
                INSERT OR REPLACE INTO pdf_documents
                (doc_id, file_path, file_hash, title, author, page_count,
                 created_date, indexed_date, doc_type, file_size, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                doc_id,
                doc.file_path,
                doc.file_hash,
                doc.title,
                doc.author,
                doc.page_count,
                doc.created_date,
                datetime.now().isoformat(),
                doc.doc_type,
                doc.file_size,
                json.dumps(doc.metadata)  # Safe serialization (no eval needed on load)
            ))

            cursor.execute("DELETE FROM pdf_search WHERE doc_id = ?", (doc_id,))

            chunk_data = [
                (chunk.doc_id, chunk.chunk_id, chunk.page_number,
                 doc.title, doc.doc_type, chunk.text)
                for chunk in chunks
            ]

            cursor.executemany("""
                INSERT INTO pdf_search
                (doc_id, chunk_id, page_number, title, doc_type, content)
                VALUES (?, ?, ?, ?, ?, ?)
            """, chunk_data)

            cursor.execute("COMMIT")
            logger.debug(f"Indexed {len(chunks)} chunks for document {doc.title}")

        except Exception as e:
            cursor.execute("ROLLBACK")
            logger.error(f"Failed to index document: {e}")
            raise

    def search_pdfs(
        self,
        query: str,
        doc_type: Optional[str] = None,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Search indexed PDF documents"""
        cursor = self.db.conn.cursor()

        fts_query = f"{query} AND doc_type:{doc_type}" if doc_type else query

        cursor.execute("""
            SELECT
                p.doc_id,
                p.chunk_id,
                p.page_number,
                p.title,
                p.doc_type,
                d.file_path,
                d.author,
                d.page_count,
                bm25(pdf_search) as score,
                snippet(pdf_search, 5, '<b>', '</b>', '...', 64) as snippet
            FROM pdf_search p
            JOIN pdf_documents d ON p.doc_id = d.doc_id
            WHERE pdf_search MATCH ?
            ORDER BY bm25(pdf_search)
            LIMIT ?
        """, (fts_query, limit))

        results = []
        for row in cursor.fetchall():
            results.append({
                'doc_id': row[0],
                'chunk_id': row[1],
                'page_number': row[2],
                'title': row[3],
                'doc_type': row[4],
                'file_path': row[5],
                'author': row[6],
                'total_pages': row[7],
                'score': row[8],
                'snippet': row[9]
            })

        logger.debug(f"PDF search for '{query}' returned {len(results)} results")
        return results

    def get_document(self, doc_id: str) -> Optional[PDFDocument]:
        """Retrieve document metadata by ID"""
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT * FROM pdf_documents WHERE doc_id = ?", (doc_id,))
        row = cursor.fetchone()

        if not row:
            return None

        return PDFDocument(
            file_path=row[1],
            file_hash=row[2],
            title=row[3],
            author=row[4],
            page_count=row[5],
            created_date=row[6],
            doc_type=row[8],
            file_size=row[9],
            metadata=json.loads(row[10]) if row[10] else {}  # Safe deserialization
        )

    def delete_document(self, doc_id: str) -> bool:
        """Delete a document and its chunks"""
        cursor = self.db.conn.cursor()

        try:
            cursor.execute("BEGIN TRANSACTION")
            cursor.execute("DELETE FROM pdf_search WHERE doc_id = ?", (doc_id,))
            cursor.execute("DELETE FROM pdf_documents WHERE doc_id = ?", (doc_id,))
            deleted = cursor.rowcount > 0
            cursor.execute("COMMIT")

            if deleted:
                logger.info(f"Deleted document: {doc_id}")
            return deleted

        except Exception as e:
            cursor.execute("ROLLBACK")
            logger.error(f"Failed to delete document: {e}")
            raise

    def list_documents(
        self,
        doc_type: Optional[str] = None,
        limit: int = 100
    ) -> List[PDFDocument]:
        """List all indexed documents"""
        cursor = self.db.conn.cursor()

        if doc_type:
            cursor.execute("""
                SELECT * FROM pdf_documents
                WHERE doc_type = ?
                ORDER BY indexed_date DESC
                LIMIT ?
            """, (doc_type, limit))
        else:
            cursor.execute("""
                SELECT * FROM pdf_documents
                ORDER BY indexed_date DESC
                LIMIT ?
            """, (limit,))

        documents = []
        for row in cursor.fetchall():
            documents.append(PDFDocument(
                file_path=row[1],
                file_hash=row[2],
                title=row[3],
                author=row[4],
                page_count=row[5],
                created_date=row[6],
                doc_type=row[8],
                file_size=row[9],
                metadata=json.loads(row[10]) if row[10] else {}  # Safe deserialization
            ))
        return documents

    def get_stats(self) -> Dict[str, Any]:
        """Get PDF indexing statistics"""
        cursor = self.db.conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM pdf_documents")
        total_docs = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM pdf_search")
        total_chunks = cursor.fetchone()[0]

        cursor.execute("""
            SELECT doc_type, COUNT(*) FROM pdf_documents GROUP BY doc_type
        """)
        docs_by_type = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute("SELECT SUM(file_size) FROM pdf_documents")
        total_size = cursor.fetchone()[0] or 0

        return {
            'total_documents': total_docs,
            'total_chunks': total_chunks,
            'documents_by_type': docs_by_type,
            'total_size_bytes': total_size,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'avg_chunks_per_doc': round(total_chunks / total_docs, 2) if total_docs > 0 else 0
        }

    def batch_load_directory(
        self,
        directory_path: str,
        recursive: bool = True,
        doc_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Load all PDFs from a directory"""
        dir_path = Path(directory_path)

        if not dir_path.exists() or not dir_path.is_dir():
            raise ValueError(f"Invalid directory: {directory_path}")

        pattern = "**/*.pdf" if recursive else "*.pdf"
        pdf_files = list(dir_path.glob(pattern))

        logger.info(f"Found {len(pdf_files)} PDF files in {directory_path}")

        stats = {
            'total_files': len(pdf_files),
            'successful': 0,
            'failed': 0,
            'skipped': 0,
            'errors': []
        }

        for pdf_file in pdf_files:
            try:
                self.load_pdf(str(pdf_file), doc_type=doc_type)
                stats['successful'] += 1
            except Exception as e:
                stats['failed'] += 1
                stats['errors'].append({'file': str(pdf_file), 'error': str(e)})
                logger.error(f"Failed to load {pdf_file}: {e}")

        logger.info(
            f"Batch load complete: {stats['successful']} successful, "
            f"{stats['failed']} failed"
        )
        return stats
