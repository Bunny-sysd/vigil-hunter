"""
Orchestrator for AI providers.

Supports runtime fallback and dynamic loading of providers based on config.
"""

from __future__ import annotations

import logging
from typing import Any

from vigil.ai.providers.base import LLMProvider
from vigil.ai.providers.gemini import GeminiProvider
from vigil.ai.providers.openai import OpenAIProvider
from vigil.ai.providers.ollama import OllamaProvider
from vigil.config import VigilConfig

logger = logging.getLogger("vigil.ai.brain")


class AIBrain:
    """
    The orchestrator that loads the correct LLM provider, handles structured schemas,
    and supports runtime fallback strategies.
    """

    def __init__(self, config: VigilConfig):
        self.config = config
        self.provider: LLMProvider | None = None
        self._load_provider()

    def _load_provider(self) -> None:
        """Instantiate the active provider based on configuration."""
        if not self.config.has_ai and self.config.provider != "ollama":
            logger.info("No AI credentials found. Running in rule-only mode.")
            return

        try:
            if self.config.provider == "gemini":
                self.provider = GeminiProvider(
                    api_key=self.config.gemini_key,
                    model_name=self.config.gemini_model,
                )
            elif self.config.provider == "openai":
                self.provider = OpenAIProvider(
                    api_key=self.config.openai_key,
                    model_name=self.config.openai_model,
                )
            elif self.config.provider == "ollama":
                self.provider = OllamaProvider(
                    endpoint=self.config.ollama_endpoint,
                    model_name=self.config.ollama_model,
                )
        except Exception as e:
            logger.error(f"Failed to load AI provider '{self.config.provider}': {e}")
            self.provider = None

    def analyze(self, system_prompt: str, user_content: str) -> str:
        """Send content to the active provider, falling back to other providers if one fails."""
        if not self.provider:
            return ""

        try:
            return self.provider.analyze(system_prompt, user_content)
        except Exception as e:
            logger.warning(f"Active provider '{self.config.provider}' failed: {e}. Attempting fallback...")
            return self._attempt_fallback_analyze(system_prompt, user_content)

    def structured_output(self, system_prompt: str, user_content: str, response_schema: dict[str, Any]) -> dict[str, Any]:
        """Request structured output, with automated fallback execution."""
        if not self.provider:
            return {}

        try:
            return self.provider.structured_output(system_prompt, user_content, response_schema)
        except Exception as e:
            logger.warning(f"Active provider '{self.config.provider}' failed structured output: {e}. Attempting fallback...")
            return self._attempt_fallback_structured(system_prompt, user_content, response_schema)

    def _attempt_fallback_analyze(self, system_prompt: str, user_content: str) -> str:
        """Attempt alternative providers in priority sequence."""
        # Order: Gemini -> OpenAI -> Ollama
        providers_to_try = []
        if self.config.provider != "gemini" and self.config.gemini_key:
            providers_to_try.append(("gemini", lambda: GeminiProvider(self.config.gemini_key, self.config.gemini_model)))
        if self.config.provider != "openai" and self.config.openai_key:
            providers_to_try.append(("openai", lambda: OpenAIProvider(self.config.openai_key, self.config.openai_model)))
        if self.config.provider != "ollama":
            providers_to_try.append(("ollama", lambda: OllamaProvider(self.config.ollama_endpoint, self.config.ollama_model)))

        for name, factory in providers_to_try:
            try:
                logger.info(f"Fallback: trying provider '{name}'...")
                p = factory()
                res = p.analyze(system_prompt, user_content)
                logger.info(f"Fallback to '{name}' successful.")
                return res
            except Exception as fe:
                logger.warning(f"Fallback provider '{name}' failed: {fe}")
        
        return ""

    def _attempt_fallback_structured(self, system_prompt: str, user_content: str, response_schema: dict[str, Any]) -> dict[str, Any]:
        """Attempt structured fallback execution."""
        providers_to_try = []
        if self.config.provider != "gemini" and self.config.gemini_key:
            providers_to_try.append(("gemini", lambda: GeminiProvider(self.config.gemini_key, self.config.gemini_model)))
        if self.config.provider != "openai" and self.config.openai_key:
            providers_to_try.append(("openai", lambda: OpenAIProvider(self.config.openai_key, self.config.openai_model)))
        if self.config.provider != "ollama":
            providers_to_try.append(("ollama", lambda: OllamaProvider(self.config.ollama_endpoint, self.config.ollama_model)))

        for name, factory in providers_to_try:
            try:
                logger.info(f"Fallback structured: trying provider '{name}'...")
                p = factory()
                res = p.structured_output(system_prompt, user_content, response_schema)
                logger.info(f"Fallback structured to '{name}' successful.")
                return res
            except Exception as fe:
                logger.warning(f"Fallback structured provider '{name}' failed: {fe}")

        return {}
