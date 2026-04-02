"""
AI Decision Engine - Intelligent attack path decision making

Uses instructor for structured output - no more manual string parsing.
Provider fallback priority: Claude > DeepSeek > OpenAI > others
"""

import logging
from typing import List, Dict, Any, Optional, TypeVar, Type
from enum import Enum

try:
    import instructor
except ImportError:  # pragma: no cover - exercised in dynamic runtime smoke tests
    instructor = None
from anthropic import AsyncAnthropic
from openai import AsyncOpenAI
from pydantic import BaseModel

from providers.manager import ai_manager
from providers.base import AIMessage, AIProvider
from core.config import config
from .attack_path_graph import AttackPathGraph, GraphEdge
from .models import (
    AIDecision,
    StepRecommendation,
    ErrorRecovery,
    ReasoningChain,
    ThoughtStep,
    DecisionType,
    RiskLevel,
)

logger = logging.getLogger(__name__)

T = TypeVar('T', bound=BaseModel)


class AIDecisionEngine:
    """
    AI-powered decision engine for autonomous pentesting

    Features:
    - Structured output via instructor (no manual parsing)
    - Provider fallback (Claude > DeepSeek > OpenAI)
    - Context-aware decision making
    - Chain-of-thought reasoning
    - Explains reasoning to user
    - Provides alternatives
    """

    # Provider priority as specified by user
    PROVIDER_PRIORITY = [
        AIProvider.CLAUDE.value,
        AIProvider.DEEPSEEK.value,
        AIProvider.OPENAI.value,
        AIProvider.GEMINI.value,
        AIProvider.KIMI.value,
        AIProvider.GROK.value,
        AIProvider.OLLAMA.value,
    ]

    def __init__(self):
        self.current_provider: Optional[str] = None
        self.available_providers = ai_manager.list_available_providers()
        self._instructor_clients: Dict[str, Any] = {}
        self._select_best_provider()
        self._init_instructor_clients()

    def _select_best_provider(self):
        """Select best available provider based on priority"""
        for provider in self.PROVIDER_PRIORITY:
            if provider in self.available_providers:
                self.current_provider = provider
                logger.info(f"AI Decision Engine using: {provider}")
                return

        logger.warning("No AI providers available for decision engine; using heuristic fallback mode")
        self.current_provider = None

    def _init_instructor_clients(self):
        """Initialize instructor-wrapped clients for all available providers"""
        if instructor is None:
            logger.warning("Instructor is not installed; structured AI decisions will use fallback mode")
            return

        # Claude (Anthropic)
        if AIProvider.CLAUDE.value in self.available_providers:
            try:
                anthropic_key = config.ANTHROPIC_API_KEY
                if anthropic_key:
                    client = AsyncAnthropic(api_key=anthropic_key)
                    self._instructor_clients[AIProvider.CLAUDE.value] = instructor.from_anthropic(client)
                    logger.debug("Instructor client initialized for Claude")
            except Exception as e:
                logger.warning(f"Failed to init instructor for Claude: {e}")

        # OpenAI
        if AIProvider.OPENAI.value in self.available_providers:
            try:
                openai_key = config.OPENAI_API_KEY
                if openai_key:
                    client = AsyncOpenAI(api_key=openai_key)
                    self._instructor_clients[AIProvider.OPENAI.value] = instructor.from_openai(client)
                    logger.debug("Instructor client initialized for OpenAI")
            except Exception as e:
                logger.warning(f"Failed to init instructor for OpenAI: {e}")

        # DeepSeek (OpenAI-compatible)
        if AIProvider.DEEPSEEK.value in self.available_providers:
            try:
                deepseek_key = config.DEEPSEEK_API_KEY
                if deepseek_key:
                    client = AsyncOpenAI(
                        api_key=deepseek_key,
                        base_url="https://api.deepseek.com/v1"
                    )
                    self._instructor_clients[AIProvider.DEEPSEEK.value] = instructor.from_openai(client)
                    logger.debug("Instructor client initialized for DeepSeek")
            except Exception as e:
                logger.warning(f"Failed to init instructor for DeepSeek: {e}")

        # Gemini (OpenAI-compatible mode)
        if AIProvider.GEMINI.value in self.available_providers:
            try:
                gemini_key = config.GOOGLE_API_KEY or config.GEMINI_API_KEY
                if gemini_key:
                    client = AsyncOpenAI(
                        api_key=gemini_key,
                        base_url="https://generativelanguage.googleapis.com/v1beta/openai/"
                    )
                    self._instructor_clients[AIProvider.GEMINI.value] = instructor.from_openai(client)
                    logger.debug("Instructor client initialized for Gemini")
            except Exception as e:
                logger.warning(f"Failed to init instructor for Gemini: {e}")

        # Grok (OpenAI-compatible)
        if AIProvider.GROK.value in self.available_providers:
            try:
                grok_key = config.GROK_API_KEY
                if grok_key:
                    client = AsyncOpenAI(
                        api_key=grok_key,
                        base_url="https://api.x.ai/v1"
                    )
                    self._instructor_clients[AIProvider.GROK.value] = instructor.from_openai(client)
                    logger.debug("Instructor client initialized for Grok")
            except Exception as e:
                logger.warning(f"Failed to init instructor for Grok: {e}")

        # Kimi (OpenAI-compatible)
        if AIProvider.KIMI.value in self.available_providers:
            try:
                kimi_key = config.KIMI_API_KEY
                if kimi_key:
                    client = AsyncOpenAI(
                        api_key=kimi_key,
                        base_url="https://api.moonshot.cn/v1"
                    )
                    self._instructor_clients[AIProvider.KIMI.value] = instructor.from_openai(client)
                    logger.debug("Instructor client initialized for Kimi")
            except Exception as e:
                logger.warning(f"Failed to init instructor for Kimi: {e}")

        # Ollama (OpenAI-compatible)
        if AIProvider.OLLAMA.value in self.available_providers:
            try:
                client = AsyncOpenAI(
                    api_key="ollama",  # Ollama doesn't need a real key
                    base_url="http://localhost:11434/v1"
                )
                self._instructor_clients[AIProvider.OLLAMA.value] = instructor.from_openai(client)
                logger.debug("Instructor client initialized for Ollama")
            except Exception as e:
                logger.warning(f"Failed to init instructor for Ollama: {e}")

    def _get_fallback_provider(self) -> Optional[str]:
        """Get next available provider in priority list"""
        if not self.current_provider:
            return None

        try:
            current_index = self.PROVIDER_PRIORITY.index(self.current_provider)
            for provider in self.PROVIDER_PRIORITY[current_index + 1:]:
                if provider in self.available_providers and provider in self._instructor_clients:
                    logger.info(f"Falling back to provider: {provider}")
                    return provider
        except ValueError:
            pass

        return None

    def _get_model_for_provider(self, provider: str) -> str:
        """Get the appropriate model name for a provider"""
        model_map = {
            AIProvider.CLAUDE.value: config.CLAUDE_MODEL or "claude-3-sonnet-20240229",
            AIProvider.OPENAI.value: config.OPENAI_MODEL or "gpt-4-turbo-preview",
            AIProvider.DEEPSEEK.value: "deepseek-chat",
            AIProvider.GEMINI.value: "gemini-1.5-pro",
            AIProvider.GROK.value: "grok-beta",
            AIProvider.KIMI.value: "moonshot-v1-8k",
            AIProvider.OLLAMA.value: config.OLLAMA_MODEL or "llama3:latest",
        }
        return model_map.get(provider, "gpt-4-turbo-preview")

    async def _query_structured(
        self,
        response_model: Type[T],
        system_prompt: str,
        user_prompt: str,
        max_retries: int = 2
    ) -> T:
        """
        Query AI provider with structured output via instructor

        Args:
            response_model: Pydantic model for response
            system_prompt: System message
            user_prompt: User message
            max_retries: Number of fallback attempts

        Returns:
            Parsed response as Pydantic model instance
        """
        provider = self.current_provider
        retries = 0

        while retries <= max_retries:
            if provider is None:
                return self._default_response(response_model, user_prompt)
            if provider not in self._instructor_clients:
                # Fallback to raw parsing if no instructor client
                logger.warning(f"No instructor client for {provider}, using fallback")
                return await self._fallback_query(response_model, system_prompt, user_prompt)

            client = self._instructor_clients[provider]
            model = self._get_model_for_provider(provider)

            try:
                logger.debug(f"Querying {provider} with instructor for {response_model.__name__}")

                # Handle Anthropic vs OpenAI API differences
                if provider == AIProvider.CLAUDE.value:
                    response = await client.messages.create(
                        model=model,
                        max_tokens=1000,
                        messages=[{"role": "user", "content": user_prompt}],
                        system=system_prompt,
                        response_model=response_model,
                    )
                else:
                    response = await client.chat.completions.create(
                        model=model,
                        max_tokens=1000,
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        response_model=response_model,
                    )

                return response

            except Exception as e:
                logger.warning(f"AI provider {provider} failed: {e}")

                # Try fallback
                fallback = self._get_fallback_provider()
                if fallback and retries < max_retries:
                    provider = fallback
                    self.current_provider = provider
                    retries += 1
                    continue
                else:
                    raise RuntimeError(f"All AI providers failed. Last error: {e}")

        raise RuntimeError("AI decision failed after all retries")

    async def _fallback_query(
        self,
        response_model: Type[T],
        system_prompt: str,
        user_prompt: str
    ) -> T:
        """Fallback to raw query + manual parsing when instructor isn't available"""
        logger.warning(
            "Structured provider unavailable; using deterministic fallback for %s",
            response_model.__name__,
        )
        return self._default_response(response_model, user_prompt)

    def _default_response(self, response_model: Type[T], source_text: str) -> T:
        """Return a deterministic fallback response when AI structuring is unavailable."""
        if response_model is AIDecision:
            return response_model(
                recommendation="follow_optimal_path",
                reasoning=(source_text or "Falling back to deterministic attack-path heuristics.")[:500],
                alternatives=["gather_more_intel", "try_alternative_path"],
                confidence=0.5,
                risk_level=RiskLevel.MEDIUM,
            )
        if response_model is ReasoningChain:
            return response_model(
                steps=[
                    ThoughtStep(
                        thought="Structured reasoning provider was unavailable.",
                        action="Use deterministic fallback analysis.",
                        observation="Proceed with the highest-probability known path.",
                    )
                ],
                final_answer=(source_text or "Fallback reasoning applied.")[:500],
                confidence=0.4,
                key_insights=["AI decision engine is operating in fallback mode."],
            )
        if response_model is ErrorRecovery:
            return response_model(
                action="alternative",
                reasoning=(source_text or "Use an alternative approach after a failed step.")[:500],
                retry_with_changes=None,
                alternative_approach="try_alternative_path",
                should_abort=False,
            )
        return response_model.model_validate({})

    # =========================================================================
    # Decision Methods
    # =========================================================================

    async def decide_next_step(
        self,
        attack_graph: AttackPathGraph,
        current_position: str,
        objective: str,
        context: Dict[str, Any]
    ) -> AIDecision:
        """
        Decide the next attack step to take

        Args:
            attack_graph: Current attack path graph
            current_position: Current node ID in graph
            objective: User-defined objective
            context: Additional context (discovered vulns, credentials, etc.)

        Returns:
            AIDecision with recommended next step
        """
        possible_steps = attack_graph.get_next_steps(current_position)

        if not possible_steps:
            return AIDecision(
                recommendation="explore_new_paths",
                reasoning="No immediate next steps available. Need to discover new attack vectors.",
                alternatives=["run_reconnaissance", "try_credential_spray", "scan_for_vulns"],
                confidence=0.8,
            )

        # Build prompt
        steps_description = "\n".join([
            f"{i+1}. {edge.description}\n"
            f"   - Tool: {edge.tool}\n"
            f"   - Success Probability: {edge.success_probability:.0%}\n"
            f"   - Complexity: {edge.complexity}\n"
            f"   - Detection Risk: {edge.detection_likelihood}\n"
            f"   - Requires Credentials: {'Yes' if edge.requires_credentials else 'No'}"
            for i, edge in enumerate(possible_steps[:5])
        ])

        context_info = (
            f"Compromised Hosts: {len(context.get('compromised_hosts', []))}\n"
            f"Discovered Credentials: {len(context.get('discovered_credentials', []))}\n"
            f"Known Vulnerabilities: {len(context.get('vulnerabilities', []))}"
        )

        system_prompt = """You are an expert penetration tester analyzing attack paths.
Your goal is to help select the optimal next step in an attack chain.

Consider:
1. Success probability and complexity
2. Detection risk (stealth vs. speed trade-off)
3. Alignment with the objective
4. Available resources (credentials, access levels)"""

        user_prompt = f"""Current Attack Path Analysis:

Objective: {objective}
Current Position: {current_position}

Context:
{context_info}

Possible Next Steps:
{steps_description}

Which step should we take next to best achieve the objective?"""

        decision = await self._query_structured(
            response_model=AIDecision,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

        return decision

    async def decide_path_to_objective(
        self,
        attack_graph: AttackPathGraph,
        objective: str
    ) -> AIDecision:
        """
        Decide which path to pursue toward the objective

        Returns:
            AIDecision with recommended attack path
        """
        paths = attack_graph.find_paths_to_objective()

        if not paths:
            return AIDecision(
                recommendation="no_path_found",
                reasoning="No paths to objective found in current graph. Need more reconnaissance.",
                alternatives=["expand_network_scan", "try_different_vulnerabilities"],
                confidence=0.9,
            )

        optimal_edges = attack_graph.get_optimal_path_to_objective()

        if not optimal_edges:
            return AIDecision(
                recommendation="continue_exploration",
                reasoning="Multiple paths exist but none are currently optimal.",
                alternatives=["gather_more_intel", "test_credentials"],
                confidence=0.7,
            )

        return AIDecision(
            recommendation="follow_optimal_path",
            reasoning=f"Found optimal path with {len(optimal_edges)} steps. "
                     f"Estimated success: {sum(e.success_probability for e in optimal_edges) / len(optimal_edges):.0%}",
            alternatives=["try_alternative_path", "gather_more_credentials"],
            confidence=0.85,
        )

    async def decide_on_error(
        self,
        error: str,
        failed_edge: GraphEdge,
        attack_graph: AttackPathGraph
    ) -> AIDecision:
        """
        Decide how to proceed after an error

        Returns:
            AIDecision with recommended error recovery
        """
        system_prompt = "You are a penetration tester analyzing why an attack step failed and suggesting recovery options."

        user_prompt = f"""Attack Step Failed:

Step: {failed_edge.description}
Tool: {failed_edge.tool}
Error: {error}

Technique: {failed_edge.technique}
Target: {failed_edge.target_id}

Available alternatives: {len(attack_graph.get_next_steps(failed_edge.source_id))} other attack paths from this position

What should we do next?

Options to consider:
1. Try alternative attack path
2. Adjust parameters and retry
3. Gather more intelligence about the target
4. Abort this path and try different approach"""

        return await self._query_structured(
            response_model=AIDecision,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )

    async def reason_step_by_step(
        self,
        problem: str,
        context: Dict[str, Any]
    ) -> ReasoningChain:
        """
        Use chain-of-thought reasoning for complex decisions

        Args:
            problem: The problem to reason through
            context: Additional context

        Returns:
            ReasoningChain with step-by-step thinking
        """
        system_prompt = """You are an expert penetration tester using systematic reasoning.
Think through the problem step by step:
1. Analyze the current situation
2. Consider possible approaches
3. Evaluate risks and benefits
4. Make a decision with clear reasoning"""

        context_str = "\n".join(f"{k}: {v}" for k, v in context.items())

        user_prompt = f"""Problem: {problem}

Context:
{context_str}

Think through this step by step to reach the best decision."""

        return await self._query_structured(
            response_model=ReasoningChain,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )
