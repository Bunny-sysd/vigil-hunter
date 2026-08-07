"""
Google Gemini API provider implementation.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from vigil.ai.providers.base import LLMProvider

logger = logging.getLogger("vigil.ai.gemini")


class GeminiProvider(LLMProvider):
    """
    Google Gemini implementation of LLMProvider.
    Uses the modern google-genai SDK.
    """

    def __init__(self, api_key: str, model_name: str = "gemini-2.5-flash"):
        self.api_key = api_key
        self.model_name = model_name
        self.client = None
        self._init_client()

    def _init_client(self) -> None:
        """Initialize the Google GenAI client asynchronously or on-demand."""
        try:
            from google import genai
            from google.genai import types
            self.genai = genai
            self.types = types
            # Initialize with the modern client constructor
            self.client = genai.Client(api_key=self.api_key)
        except ImportError:
            logger.error("google-genai package not installed. Run pip install google-genai")
            raise RuntimeError("Missing dependency: google-genai")

    def analyze(self, system_prompt: str, user_content: str) -> str:
        if not self.client:
            raise RuntimeError("Gemini client is not initialized.")

        try:
            config = self.types.GenerateContentConfig(
                system_instruction=system_prompt,
                temperature=0.2,
            )
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=user_content,
                config=config,
            )
            return response.text or ""
        except Exception as e:
            logger.error(f"Gemini generation error: {e}")
            raise RuntimeError(f"Gemini API failure: {e}")

    def structured_output(self, system_prompt: str, user_content: str, response_schema: dict[str, Any]) -> dict[str, Any]:
        if not self.client:
            raise RuntimeError("Gemini client is not initialized.")

        try:
            # Construct a structured output schema config using the modern API.
            # Using JSON response mime_type + supplying schema forces Gemini to comply.
            config = self.types.GenerateContentConfig(
                system_instruction=system_prompt,
                response_mime_type="application/json",
                response_schema=response_schema,
                temperature=0.1,
            )
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=user_content,
                config=config,
            )
            text = response.text or "{}"
            return json.loads(text)
        except Exception as e:
            logger.error(f"Gemini structured output error: {e}")
            # Try to recover or fall back
            raise RuntimeError(f"Gemini structured output API failure: {e}")
