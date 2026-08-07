"""
Configuration management for Vigil.

Handles API keys, provider selection, dynamic search parameters, and user preferences.
Keys are stored in environment variables or a local .env file —
never committed to git, never logged, never transmitted.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Default config file location: ~/.vigil/config.json
DEFAULT_CONFIG_DIR = Path.home() / ".vigil"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"


@dataclass
class VigilConfig:
    """
    Vigil runtime configuration.

    Priority for API keys:
        1. Environment variables (VIGIL_GEMINI_KEY, GEMINI_API_KEY, etc.)
        2. Config file (~/.vigil/config.json)
        3. .env file in current directory
    """

    # AI Provider settings
    provider: str = "gemini"
    """Active AI provider: 'gemini', 'openai', 'ollama', 'none'."""

    gemini_key: str = ""
    openai_key: str = ""
    nvd_api_key: str = ""
    github_token: str = ""

    ollama_endpoint: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"

    gemini_model: str = "gemini-2.5-flash"
    openai_model: str = "gpt-4o-mini"

    # Vulnerability & Exploit Search Settings
    offline_mode: bool = False
    """Disable external API queries (use local offline DBs only)."""

    cvss_threshold: float = 4.0
    """Minimum CVSS score threshold for reporting vulnerabilities."""

    exploit_search_enabled: bool = True
    """Enable automatic GitHub / ExploitDB PoC repository discovery."""

    # Analysis settings
    default_mode: str = "default"
    """Default analysis mode: 'default', 'htb', 'incident'."""

    severity_threshold: str = "LOW"
    """Minimum severity to report: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'."""

    brute_force_threshold: int = 5
    """Number of failed logins to trigger brute force detection."""

    brute_force_window: int = 60
    """Time window (seconds) for brute force detection."""

    max_log_lines: int = 100_000
    """Maximum log lines to process per file (safety limit)."""

    # Output settings
    default_format: str = "cli"
    """Default output format: 'cli', 'json', 'html', 'markdown'."""

    color_output: bool = True
    """Whether to use colors in CLI output."""

    verbose: bool = False
    """Whether to show debug/verbose output."""

    @classmethod
    def load(cls, config_path: Path | None = None) -> VigilConfig:
        """
        Load configuration from multiple sources.

        Priority: env vars > config file > defaults.
        """
        config = cls()

        # Layer 1: Load from config file if it exists
        path = config_path or DEFAULT_CONFIG_FILE
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                config._apply_dict(data)
            except (json.JSONDecodeError, OSError):
                pass

        # Layer 2: Load from .env file in current directory
        env_file = Path.cwd() / ".env"
        if env_file.exists():
            config._load_dotenv(env_file)

        # Layer 3: Environment variables override everything
        config._apply_env_vars()

        return config

    def save(self, config_path: Path | None = None) -> None:
        """Save current config to disk (excluding sensitive keys)."""
        path = config_path or DEFAULT_CONFIG_FILE
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "provider": self.provider,
            "ollama_endpoint": self.ollama_endpoint,
            "ollama_model": self.ollama_model,
            "gemini_model": self.gemini_model,
            "openai_model": self.openai_model,
            "cvss_threshold": self.cvss_threshold,
            "exploit_search_enabled": self.exploit_search_enabled,
            "default_mode": self.default_mode,
            "severity_threshold": self.severity_threshold,
            "brute_force_threshold": self.brute_force_threshold,
            "brute_force_window": self.brute_force_window,
            "max_log_lines": self.max_log_lines,
            "default_format": self.default_format,
            "color_output": self.color_output,
        }

        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def save_key(self, provider_name: str, key: str) -> None:
        """Securely store an API key in ~/.vigil/keys.json."""
        DEFAULT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        keystore = DEFAULT_CONFIG_DIR / "keys.json"

        keys = {}
        if keystore.exists():
            try:
                keys = json.loads(keystore.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass

        keys[provider_name.lower()] = key
        keystore.write_text(json.dumps(keys, indent=2), encoding="utf-8")

        # Set runtime attribute immediately
        if provider_name.lower() == "gemini":
            self.gemini_key = key
        elif provider_name.lower() == "openai":
            self.openai_key = key
        elif provider_name.lower() == "nvd":
            self.nvd_api_key = key
        elif provider_name.lower() == "github":
            self.github_token = key

    @property
    def has_ai(self) -> bool:
        if self.provider == "ollama":
            return True
        if self.provider == "gemini" and self.gemini_key:
            return True
        if self.provider == "openai" and self.openai_key:
            return True
        return False

    @property
    def active_key(self) -> str:
        if self.provider == "gemini":
            return self.gemini_key
        if self.provider == "openai":
            return self.openai_key
        return ""

    @property
    def active_model(self) -> str:
        if self.provider == "gemini":
            return self.gemini_model
        if self.provider == "openai":
            return self.openai_model
        if self.provider == "ollama":
            return self.ollama_model
        return ""

    def _apply_dict(self, data: dict[str, Any]) -> None:
        for key, value in data.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def _apply_env_vars(self) -> None:
        env_map = {
            "VIGIL_PROVIDER": "provider",
            "VIGIL_GEMINI_KEY": "gemini_key",
            "GEMINI_API_KEY": "gemini_key",
            "VIGIL_OPENAI_KEY": "openai_key",
            "OPENAI_API_KEY": "openai_key",
            "VIGIL_NVD_KEY": "nvd_api_key",
            "VIGIL_GITHUB_TOKEN": "github_token",
            "VIGIL_OLLAMA_ENDPOINT": "ollama_endpoint",
            "VIGIL_OLLAMA_MODEL": "ollama_model",
            "VIGIL_GEMINI_MODEL": "gemini_model",
            "VIGIL_OPENAI_MODEL": "openai_model",
            "VIGIL_OFFLINE": "offline_mode",
            "VIGIL_MODE": "default_mode",
            "VIGIL_FORMAT": "default_format",
            "VIGIL_VERBOSE": "verbose",
        }
        for env_var, attr in env_map.items():
            value = os.environ.get(env_var)
            if value is not None:
                if attr in ("verbose", "offline_mode"):
                    setattr(self, attr, value.lower() in ("1", "true", "yes"))
                else:
                    setattr(self, attr, value)

        keystore = DEFAULT_CONFIG_DIR / "keys.json"
        if keystore.exists():
            try:
                keys = json.loads(keystore.read_text(encoding="utf-8"))
                if not self.gemini_key and "gemini" in keys:
                    self.gemini_key = keys["gemini"]
                if not self.openai_key and "openai" in keys:
                    self.openai_key = keys["openai"]
                if not self.nvd_api_key and "nvd" in keys:
                    self.nvd_api_key = keys["nvd"]
                if not self.github_token and "github" in keys:
                    self.github_token = keys["github"]
            except (json.JSONDecodeError, OSError):
                pass

    def _load_dotenv(self, path: Path) -> None:
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip().strip("'\"")
                    if value:
                        os.environ.setdefault(key, value)
        except OSError:
            pass
