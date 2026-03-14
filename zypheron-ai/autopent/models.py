"""
Structured Output Models for AI Decision Engine

Uses Pydantic models with instructor for guaranteed structured responses
from any AI provider. Eliminates manual string parsing and ensures type safety.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum


class DecisionType(str, Enum):
    """Types of decisions the AI can make"""
    NEXT_STEP = "next_step"
    PATH_SELECTION = "path_selection"
    PIVOT_STRATEGY = "pivot_strategy"
    EXPLOIT_SELECTION = "exploit_selection"
    ERROR_RECOVERY = "error_recovery"


class RiskLevel(str, Enum):
    """Risk level for actions"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# =============================================================================
# Core Decision Models
# =============================================================================

class AIDecision(BaseModel):
    """Structured AI decision response - replaces manual string parsing"""
    recommendation: str = Field(
        description="Recommended action, step number, or approach"
    )
    reasoning: str = Field(
        description="Detailed reasoning explaining why this is the best choice"
    )
    alternatives: List[str] = Field(
        default_factory=list,
        description="Alternative approaches if the recommendation fails"
    )
    confidence: float = Field(
        ge=0.0, le=1.0,
        description="Confidence level from 0.0 to 1.0"
    )
    risk_level: Optional[RiskLevel] = Field(
        default=None,
        description="Risk level of the recommended action"
    )


class StepRecommendation(BaseModel):
    """Recommendation for the next attack step"""
    step_number: int = Field(
        ge=1,
        description="Which step to take (1-indexed)"
    )
    reasoning: str = Field(
        description="Why this step is optimal given current context"
    )
    expected_outcome: str = Field(
        description="What we expect to learn or achieve"
    )
    fallback_step: Optional[int] = Field(
        default=None,
        description="Alternative step if this one fails"
    )
    confidence: float = Field(
        ge=0.0, le=1.0,
        description="Confidence in this recommendation"
    )


class ErrorRecovery(BaseModel):
    """Structured error recovery recommendation"""
    action: str = Field(
        description="Recommended recovery action: retry, skip, alternative, abort"
    )
    reasoning: str = Field(
        description="Why this recovery approach is best"
    )
    retry_with_changes: Optional[str] = Field(
        default=None,
        description="If retrying, what parameters to change"
    )
    alternative_approach: Optional[str] = Field(
        default=None,
        description="Alternative attack vector to try"
    )
    should_abort: bool = Field(
        default=False,
        description="Whether to abort the entire attack path"
    )


# =============================================================================
# Chain-of-Thought Models
# =============================================================================

class ThoughtStep(BaseModel):
    """Single step in chain-of-thought reasoning"""
    thought: str = Field(
        description="Current analysis or thinking about the situation"
    )
    action: str = Field(
        description="Action to take based on this thought"
    )
    observation: str = Field(
        description="Expected or actual observation from the action"
    )


class ReasoningChain(BaseModel):
    """Full chain-of-thought reasoning for complex decisions"""
    steps: List[ThoughtStep] = Field(
        description="Step-by-step reasoning process"
    )
    final_answer: str = Field(
        description="Final conclusion after reasoning through all steps"
    )
    confidence: float = Field(
        ge=0.0, le=1.0,
        description="Confidence in the final answer"
    )
    key_insights: List[str] = Field(
        default_factory=list,
        description="Key insights discovered during reasoning"
    )


# =============================================================================
# Attack Path Models
# =============================================================================

class VulnerabilityAssessment(BaseModel):
    """AI assessment of a discovered vulnerability"""
    severity: str = Field(
        description="Severity: critical, high, medium, low, info"
    )
    exploitability: float = Field(
        ge=0.0, le=1.0,
        description="How likely exploitation will succeed"
    )
    impact: str = Field(
        description="What access/damage successful exploitation provides"
    )
    recommended_action: str = Field(
        description="What to do with this finding"
    )
    cve_references: List[str] = Field(
        default_factory=list,
        description="Related CVE IDs if known"
    )


class AttackPathAnalysis(BaseModel):
    """Analysis of an attack path to objective"""
    path_id: str = Field(
        description="Identifier for this path"
    )
    steps_count: int = Field(
        description="Number of steps in this path"
    )
    overall_success_probability: float = Field(
        ge=0.0, le=1.0,
        description="Estimated probability of reaching objective"
    )
    detection_risk: RiskLevel = Field(
        description="Risk of detection by defenders"
    )
    key_dependencies: List[str] = Field(
        default_factory=list,
        description="Critical requirements for this path"
    )
    recommendation: str = Field(
        description="Whether to pursue this path and why"
    )


# =============================================================================
# Tool Selection Models
# =============================================================================

class ToolRecommendation(BaseModel):
    """AI recommendation for which tool to use"""
    tool_name: str = Field(
        description="Name of the recommended tool"
    )
    command_template: str = Field(
        description="Suggested command or parameters"
    )
    reasoning: str = Field(
        description="Why this tool is best for the task"
    )
    alternatives: List[str] = Field(
        default_factory=list,
        description="Other tools that could work"
    )
    expected_output: str = Field(
        description="What output to expect"
    )


# =============================================================================
# RAG/Search Models
# =============================================================================

class SearchQuery(BaseModel):
    """Structured search query for RAG"""
    query: str = Field(
        description="The search query"
    )
    filters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional filters (severity, date range, etc.)"
    )
    limit: int = Field(
        default=10,
        ge=1, le=100,
        description="Maximum results to return"
    )


class RAGResponse(BaseModel):
    """Response from RAG query"""
    answer: str = Field(
        description="Generated answer based on retrieved context"
    )
    sources: List[str] = Field(
        default_factory=list,
        description="Sources used to generate the answer"
    )
    confidence: float = Field(
        ge=0.0, le=1.0,
        description="Confidence in the answer"
    )
    related_queries: List[str] = Field(
        default_factory=list,
        description="Related queries the user might want to explore"
    )
