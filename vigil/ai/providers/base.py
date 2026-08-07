"""
Base interface for all LLM providers in Vigil.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class LLMProvider(ABC):
    """
    Abstract base class for all AI/LLM model providers.

    All integrations (Gemini, OpenAI, Ollama) must inherit from this
    and implement these methods to ensure plug-and-play capability.
    """

    @abstractmethod
    def analyze(self, system_prompt: str, user_content: str) -> str:
        """
        Send a text-based prompt to the model and return the response.

        Args:
            system_prompt: Guidelines and behavior instructions for the AI.
            user_content: The log data or code snippet to analyze.

        Returns:
            The raw text response from the model.
        """
        pass

    @abstractmethod
    def structured_output(self, system_prompt: str, user_content: str, response_schema: dict[str, Any]) -> dict[str, Any]:
        """
        Send a prompt to the model and guarantee the response is valid JSON matching the schema.

        Args:
            system_prompt: Guidelines and behavior instructions.
            user_content: The content to analyze.
            response_schema: A JSON-schema-like dictionary describing the expected output structure.

        Returns:
            A parsed dictionary matching the schema.
        """
        pass
