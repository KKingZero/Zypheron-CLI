"""
Intent Parser for Natural Language Queries
Uses AI to parse complex natural language queries and extract structured intent
"""

from typing import Dict, Any, List, Optional
from providers.manager import ai_manager
from providers.base import AIMessage
from loguru import logger


class IntentParser:
    """Parses natural language queries to extract structured intent"""
    
    def __init__(self):
        self.tool_keywords = {
            "osint": ["osint", "open source intelligence", "information gathering"],
            "recon": ["recon", "reconnaissance", "reconnaissance"],
            "scan": ["scan", "scanning", "security scan", "port scan"],
            "forensics": ["forensics", "forensic", "digital forensics"],
            "api-pentest": ["api", "api test", "api testing", "rest api"],
            "reverse-eng": ["reverse", "reverse engineering", "reverse-eng"],
            "fuzz": ["fuzz", "fuzzing", "directory fuzzing"],
            "secrets": ["secrets", "secret", "secret scanning"],
            "deps": ["deps", "dependencies", "dependency"],
            "authenticated-scan": ["authenticated", "authenticated scan"],
            "pwn": ["pwn", "exploit", "exploitation"],
        }
        
        self.analysis_keywords = {
            "architecture": ["architecture", "arch", "structure", "how", "how does"],
            "maintainer": ["maintainer", "maintainers", "owner", "owners", "who", "who maintains"],
            "vulnerabilities": ["vulnerability", "vulnerabilities", "vuln", "vulns", "security", "exploit"],
        }
    
    async def parse_intent(self, query: str, provider: Optional[str] = None) -> Dict[str, Any]:
        """
        Parse natural language query to extract structured intent
        
        Args:
            query: Natural language query from user
            provider: AI provider to use for parsing (optional)
            
        Returns:
            Dictionary with parsed intent:
            {
                "target": str,
                "tools": List[str],
                "analysis_type": str,
                "context": str,
                "confidence": float
            }
        """
        # First try simple keyword matching
        simple_intent = self._parse_simple(query)
        
        # If simple parsing found target and tools, use it
        if simple_intent["target"] and simple_intent["tools"]:
            logger.debug("Using simple parsing for intent")
            return simple_intent
        
        # Otherwise, use AI for complex parsing
        logger.debug("Using AI parsing for complex intent")
        return await self._parse_with_ai(query, provider)
    
    def _parse_simple(self, query: str) -> Dict[str, Any]:
        """Simple keyword-based parsing"""
        query_lower = query.lower()
        
        intent = {
            "target": self._extract_target_simple(query),
            "tools": self._extract_tools_simple(query_lower),
            "analysis_type": self._extract_analysis_type_simple(query_lower),
            "context": query,
            "confidence": 0.7,  # Medium confidence for simple parsing
        }
        
        return intent
    
    def _extract_target_simple(self, query: str) -> str:
        """Extract target using simple patterns"""
        import re
        
        # URL pattern
        url_pattern = r'https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        match = re.search(url_pattern, query)
        if match:
            return match.group(1)
        
        # Domain pattern
        domain_pattern = r'\b([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})\b'
        match = re.search(domain_pattern, query)
        if match:
            domain = match.group(1)
            # Filter out common false positives
            if domain not in ["example.com", "localhost"]:
                return domain
        
        # IP pattern
        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        match = re.search(ip_pattern, query)
        if match:
            return match.group(1)
        
        # File path pattern
        path_pattern = r'(/[^\s]+|([A-Za-z]:)?[\\/][^\s]+)'
        match = re.search(path_pattern, query)
        if match:
            return match.group(1)
        
        return ""
    
    def _extract_tools_simple(self, query_lower: str) -> List[str]:
        """Extract tools using keyword matching"""
        tools = []
        seen = set()
        
        for tool, keywords in self.tool_keywords.items():
            for keyword in keywords:
                if keyword in query_lower:
                    if tool not in seen:
                        tools.append(tool)
                        seen.add(tool)
                    break
        
        return tools
    
    def _extract_analysis_type_simple(self, query_lower: str) -> str:
        """Extract analysis type using keyword matching"""
        for analysis_type, keywords in self.analysis_keywords.items():
            for keyword in keywords:
                if keyword in query_lower:
                    return analysis_type
        
        return "general"
    
    async def _parse_with_ai(self, query: str, provider: Optional[str] = None) -> Dict[str, Any]:
        """Use AI to parse complex queries"""
        system_prompt = """You are an expert at parsing security testing queries. 
Extract the following information from the user's query:
1. Target: domain, IP address, URL, or file path
2. Tools: list of security tools to execute (osint, recon, scan, forensics, api-pentest, reverse-eng, fuzz, secrets, deps, authenticated-scan, pwn)
3. Analysis type: architecture, maintainer, vulnerabilities, or general
4. Context: any additional context or requirements

Respond in JSON format:
{
    "target": "example.com",
    "tools": ["osint", "recon"],
    "analysis_type": "architecture",
    "context": "user wants to understand the architecture"
}"""

        messages = [
            AIMessage(role="system", content=system_prompt),
            AIMessage(role="user", content=f"Parse this query: {query}"),
        ]
        
        try:
            response = await ai_manager.chat(
                messages=messages,
                provider=provider,
                temperature=0.3,  # Lower temperature for more consistent parsing
                max_tokens=500,
            )
            
            # Try to extract JSON from response
            import json
            import re
            
            # Look for JSON in the response
            json_match = re.search(r'\{[^}]+\}', response.content, re.DOTALL)
            if json_match:
                intent_data = json.loads(json_match.group())
                intent_data["confidence"] = 0.9  # High confidence for AI parsing
                intent_data["context"] = query
                return intent_data
            
            # Fallback: return simple parsing result
            logger.warning("Failed to parse AI response as JSON, falling back to simple parsing")
            return self._parse_simple(query)
            
        except Exception as e:
            logger.error(f"Error in AI parsing: {e}")
            # Fallback to simple parsing
            return self._parse_simple(query)


# Global instance
intent_parser = IntentParser()

