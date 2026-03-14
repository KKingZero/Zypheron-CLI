"""
Hand-coded RAG (Retrieval-Augmented Generation) Engine

Simple, lean implementation:
1. Search FTS5 database for relevant context
2. Build prompt with retrieved context
3. Generate answer using existing provider manager

~50 lines of core logic, no framework bloat.
"""

from typing import List, Optional, Dict, Any
import logging

from .fts_search import SearchDB, SearchResult
from providers.manager import ai_manager
from providers.base import AIMessage
from autopent.models import RAGResponse

logger = logging.getLogger(__name__)


class RAGEngine:
    """
    Retrieval-Augmented Generation for security queries

    Uses FTS5 for retrieval, existing AI providers for generation.
    """

    def __init__(self, search_db: Optional[SearchDB] = None):
        self.db = search_db or SearchDB()

    async def query(
        self,
        question: str,
        tables: Optional[List[str]] = None,
        limit: int = 10,
        provider: Optional[str] = None
    ) -> RAGResponse:
        """
        Answer a question using RAG

        Args:
            question: User's question
            tables: Which tables to search (None = all)
            limit: Max results to retrieve
            provider: AI provider to use (None = default)

        Returns:
            RAGResponse with answer and sources
        """
        # Step 1: Retrieve relevant context
        results = self._retrieve(question, tables, limit)

        if not results:
            return RAGResponse(
                answer="No relevant information found in the knowledge base.",
                sources=[],
                confidence=0.3,
                related_queries=self._suggest_queries(question),
            )

        # Step 2: Build context string
        context = self._build_context(results)

        # Step 3: Generate answer
        answer = await self._generate(question, context, provider)

        return RAGResponse(
            answer=answer,
            sources=[f"{r.table}:{r.id}" for r in results],
            confidence=min(0.9, 0.5 + len(results) * 0.05),
            related_queries=self._suggest_queries(question),
        )

    def _retrieve(
        self,
        query: str,
        tables: Optional[List[str]],
        limit: int
    ) -> List[SearchResult]:
        """Retrieve relevant documents from FTS5"""
        if tables is None:
            return self.db.search_all(query, limit=limit)

        results = []
        per_table = max(1, limit // len(tables))

        table_methods = {
            'cve': self.db.search_cves,
            'exploit': self.db.search_exploits,
            'attack': self.db.search_attack_techniques,
            'nuclei': self.db.search_nuclei_templates,
            'scan': self.db.search_scans,
            'session': self.db.search_sessions,
        }

        for table in tables:
            if table in table_methods:
                results.extend(table_methods[table](query, limit=per_table))

        # Sort by relevance score
        results.sort(key=lambda r: r.score)
        return results[:limit]

    def _build_context(self, results: List[SearchResult]) -> str:
        """Build context string from search results"""
        context_parts = []

        for i, result in enumerate(results, 1):
            part = f"[{i}] {result.table.upper()}: {result.title}\n"
            part += f"    {result.snippet}\n"

            # Add key metadata
            for key, value in list(result.metadata.items())[:3]:
                if value and len(str(value)) < 200:
                    part += f"    {key}: {value}\n"

            context_parts.append(part)

        return "\n".join(context_parts)

    async def _generate(
        self,
        question: str,
        context: str,
        provider: Optional[str]
    ) -> str:
        """Generate answer using AI provider"""
        messages = [
            AIMessage(
                role="system",
                content="""You are a security expert assistant with access to a knowledge base.
Answer questions using ONLY the provided context. If the context doesn't contain
enough information, say so. Be concise and technical."""
            ),
            AIMessage(
                role="user",
                content=f"""Context from knowledge base:
{context}

Question: {question}

Provide a concise, accurate answer based on the context above."""
            )
        ]

        response = await ai_manager.chat(
            messages=messages,
            provider=provider,
            temperature=0.3,  # Low temp for factual answers
            max_tokens=500,
        )

        return response.content

    def _suggest_queries(self, question: str) -> List[str]:
        """Suggest related queries"""
        # Simple keyword-based suggestions
        keywords = question.lower().split()
        suggestions = []

        if 'cve' in keywords or 'vulnerability' in keywords:
            suggestions.append("Search for recent critical CVEs")
        if 'exploit' in keywords:
            suggestions.append("Find exploits for specific platform")
        if 'mitre' in keywords or 'attack' in keywords:
            suggestions.append("List techniques for lateral movement")
        if 'nuclei' in keywords or 'template' in keywords:
            suggestions.append("Find nuclei templates by severity")

        return suggestions[:3]

    # =========================================================================
    # Convenience Methods
    # =========================================================================

    async def ask_about_cve(self, cve_id: str) -> RAGResponse:
        """Quick query about a specific CVE"""
        return await self.query(
            f"Tell me about {cve_id}",
            tables=['cve', 'exploit'],
            limit=5
        )

    async def find_exploits_for(self, product: str) -> RAGResponse:
        """Find exploits for a product"""
        return await self.query(
            f"Exploits for {product}",
            tables=['exploit', 'cve'],
            limit=10
        )

    async def suggest_attack_techniques(self, scenario: str) -> RAGResponse:
        """Suggest MITRE ATT&CK techniques for a scenario"""
        return await self.query(
            f"Attack techniques for {scenario}",
            tables=['attack'],
            limit=10
        )

    async def find_nuclei_templates(self, vulnerability_type: str) -> RAGResponse:
        """Find relevant Nuclei templates"""
        return await self.query(
            f"Nuclei templates for {vulnerability_type}",
            tables=['nuclei'],
            limit=15
        )
