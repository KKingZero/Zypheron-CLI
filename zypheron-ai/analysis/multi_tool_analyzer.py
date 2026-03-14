"""
Multi-Tool Analyzer
Analyzes aggregated results from multiple security tools and generates comprehensive summaries
"""

from typing import Dict, Any, List, Optional
from providers.manager import ai_manager
from providers.base import AIMessage
from loguru import logger


class MultiToolAnalyzer:
    """Analyzes results from multiple security tools and generates comprehensive summaries"""
    
    async def analyze(
        self,
        aggregated_data: Dict[str, Any],
        analysis_type: str,
        user_query: str,
        provider: Optional[str] = None
    ) -> str:
        """
        Analyze aggregated results from multiple tools
        
        Args:
            aggregated_data: Dictionary containing aggregated tool results
            analysis_type: Type of analysis requested (architecture, maintainer, vulnerabilities, general)
            user_query: Original user query
            provider: AI provider to use
            
        Returns:
            Comprehensive analysis summary as string
        """
        # Format the data for AI analysis
        formatted_data = self._format_data_for_ai(aggregated_data)
        
        # Build analysis prompt based on analysis type
        system_prompt = self._build_analysis_prompt(analysis_type, user_query)
        
        messages = [
            AIMessage(role="system", content=system_prompt),
            AIMessage(role="user", content=f"Analyze these results:\n\n{formatted_data}"),
        ]
        
        try:
            response = await ai_manager.chat(
                messages=messages,
                provider=provider,
                temperature=0.7,
                max_tokens=4096,
            )
            
            return response.content
            
        except Exception as e:
            logger.error(f"Error in multi-tool analysis: {e}")
            return self._generate_fallback_summary(aggregated_data, analysis_type)
    
    def _format_data_for_ai(self, aggregated_data: Dict[str, Any]) -> str:
        """Format aggregated data for AI analysis"""
        lines = []
        
        # Target information
        target = aggregated_data.get("target", "Unknown")
        lines.append(f"Target: {target}")
        lines.append("")
        
        # Tool results
        results = aggregated_data.get("results", [])
        lines.append(f"Tools Executed: {len(results)}")
        lines.append("")
        
        for i, result in enumerate(results, 1):
            tool = result.get("tool", "Unknown")
            success = result.get("success", False)
            output = result.get("output", "")
            error = result.get("error", "")
            duration = result.get("duration", "")
            
            lines.append(f"[{i}] Tool: {tool}")
            lines.append(f"Status: {'Success' if success else 'Failed'}")
            if duration:
                lines.append(f"Duration: {duration}")
            
            if success and output:
                # Include output (truncate if too long)
                output_preview = output[:2000] if len(output) > 2000 else output
                lines.append(f"Output:\n{output_preview}")
                if len(output) > 2000:
                    lines.append("... (output truncated)")
            elif error:
                lines.append(f"Error: {error}")
            
            lines.append("")
        
        # Combined output
        total_output = aggregated_data.get("total_output", "")
        if total_output:
            lines.append("Full Combined Output:")
            lines.append(total_output[:5000])  # Limit to 5000 chars
            if len(total_output) > 5000:
                lines.append("... (output truncated)")
        
        return "\n".join(lines)
    
    def _build_analysis_prompt(self, analysis_type: str, user_query: str) -> str:
        """Build analysis prompt based on analysis type"""
        base_prompt = """You are an expert cybersecurity analyst. Analyze the security tool results provided and generate a comprehensive summary.

Guidelines:
- Be thorough and detailed
- Highlight important findings
- Explain technical details in accessible language
- Provide actionable insights
- Focus on security implications

"""
        
        if analysis_type == "architecture":
            return base_prompt + """Focus on:
- System architecture and infrastructure
- Technology stack identification
- Network topology
- Service dependencies
- How the system works overall

User query: """ + user_query
        
        elif analysis_type == "maintainer":
            return base_prompt + """Focus on:
- Who maintains or owns the system
- Organization information
- Contact details if found
- Domain ownership
- Hosting information

User query: """ + user_query
        
        elif analysis_type == "vulnerabilities":
            return base_prompt + """Focus on:
- Security vulnerabilities found
- Risk assessment
- Exploitability
- Remediation recommendations
- Severity prioritization

User query: """ + user_query
        
        else:  # general
            return base_prompt + """Provide a comprehensive analysis covering:
- Key findings
- Security posture
- Notable observations
- Recommendations

User query: """ + user_query
    
    def _generate_fallback_summary(self, aggregated_data: Dict[str, Any], analysis_type: str) -> str:
        """Generate a basic summary if AI analysis fails"""
        lines = []
        lines.append(f"Analysis Summary for {aggregated_data.get('target', 'Unknown')}")
        lines.append("=" * 60)
        lines.append("")
        
        results = aggregated_data.get("results", [])
        success_count = sum(1 for r in results if r.get("success", False))
        failure_count = len(results) - success_count
        
        lines.append(f"Tools Executed: {len(results)}")
        lines.append(f"Successful: {success_count}")
        lines.append(f"Failed: {failure_count}")
        lines.append("")
        
        lines.append("Tool Results:")
        for result in results:
            tool = result.get("tool", "Unknown")
            success = result.get("success", False)
            status = "✓" if success else "✗"
            lines.append(f"  {status} {tool}")
        
        lines.append("")
        lines.append("Note: Detailed AI analysis unavailable. Review tool outputs above.")
        
        return "\n".join(lines)


# Global instance
multi_tool_analyzer = MultiToolAnalyzer()

