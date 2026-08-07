"""
OpenAI API provider implementation.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from vigil.ai.providers.base import LLMProvider

logger = logging.getLogger("vigil.ai.openai")


class OpenAIProvider(LLMProvider):
    """
    OpenAI implementation of LLMProvider.
    Supports any OpenAI-compatible API (like LocalAI, DeepSeek, custom gateways).
    """

    def __init__(self, api_key: str, model_name: str = "gpt-4o-mini", base_url: str | None = None):
        self.api_key = api_key
        self.model_name = model_name
        self.base_url = base_url
        self.client = None
        self._init_client()

    def _init_client(self) -> None:
        try:
            from openai import OpenAI
            self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)
        except ImportError:
            logger.error("openai package not installed. Run pip install openai")
            raise RuntimeError("Missing dependency: openai")

    def analyze(self, system_prompt: str, user_content: str) -> str:
        if not self.client:
            raise RuntimeError("OpenAI client is not initialized.")

        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                temperature=0.2,
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            logger.error(f"OpenAI generation error: {e}")
            raise RuntimeError(f"OpenAI API failure: {e}")

    def structured_output(self, system_prompt: str, user_content: str, response_schema: dict[str, Any]) -> dict[str, Any]:
        if not self.client:
            raise RuntimeError("OpenAI client is not initialized.")

        try:
            # We can use json_object response format
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
            )
            text = response.choices[0].message.content or "{}"
            return json.loads(text)
        except Exception as e:
            logger.error(f"OpenAI structured output error: {e}")
            raise RuntimeError(f"OpenAI structured output failure: {e}")
