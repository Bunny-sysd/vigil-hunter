"""
Ollama Local LLM provider implementation.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import requests

from vigil.ai.providers.base import LLMProvider

logger = logging.getLogger("vigil.ai.ollama")


class OllamaProvider(LLMProvider):
    """
    Ollama implementation of LLMProvider.
    Connects to a local Ollama instance without requiring API keys.
    """

    def __init__(self, endpoint: str = "http://localhost:11434", model_name: str = "llama3.1"):
        self.endpoint = endpoint.rstrip("/")
        self.model_name = model_name

    def analyze(self, system_prompt: str, user_content: str) -> str:
        url = f"{self.endpoint}/api/generate"
        payload = {
            "model": self.model_name,
            "prompt": f"{system_prompt}\n\nUser Input:\n{user_content}",
            "stream": False,
            "options": {
                "temperature": 0.2,
            }
        }

        try:
            response = requests.post(url, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            return data.get("response", "")
        except Exception as e:
            logger.error(f"Ollama connection error: {e}")
            raise RuntimeError(f"Ollama local service failure: {e}")

    def structured_output(self, system_prompt: str, user_content: str, response_schema: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.endpoint}/api/generate"
        
        # We supply format="json" to force Ollama models to respond in valid JSON.
        # We append schema requirements to prompt as most local models need prompting context as well.
        json_prompt = (
            f"{system_prompt}\n\n"
            f"You MUST format your output as a valid JSON object matching this schema:\n"
            f"{json.dumps(response_schema, indent=2)}\n\n"
            f"User Input:\n{user_content}"
        )
        
        payload = {
            "model": self.model_name,
            "prompt": json_prompt,
            "format": "json",
            "stream": False,
            "options": {
                "temperature": 0.1,
            }
        }

        try:
            response = requests.post(url, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            text = data.get("response", "{}")
            return json.loads(text)
        except Exception as e:
            logger.error(f"Ollama structured generation error: {e}")
            raise RuntimeError(f"Ollama structured generation failure: {e}")
