"""Configuration management for PocketPC Agent using pydantic-settings."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, List, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Telegram Security Settings
    OWNER_TELEGRAM_ID: int = 0
    TELEGRAM_BOT_TOKEN: str = ""

    # Tier 3 Safety PIN
    SAFETY_PIN: str = "1234"

    # Directory Jail (Safe Sandboxing)
    ALLOWED_DIRS: List[Path] = Field(
        default_factory=lambda: [Path("./sandbox_files").resolve()]
    )

    # Undo Engine Storage
    UNDO_DIR: Path = Field(
        default_factory=lambda: Path("./.undo_storage").resolve()
    )

    # LLM Configuration
    LLM_PROVIDER: Literal["ollama", "openai"] = "ollama"
    LLM_MODEL: str = "llama3"
    LLM_BASE_URL: str = "http://localhost:11434/v1"
    LLM_API_KEY: str = "ollama"

    # Database
    DATABASE_PATH: Path = Field(
        default_factory=lambda: Path("./pocket_pc.db").resolve()
    )

    @field_validator("ALLOWED_DIRS", mode="before")
    @classmethod
    def parse_allowed_dirs(cls, v: Any) -> List[Path]:
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("[") and v.endswith("]"):
                try:
                    parsed = json.loads(v)
                    return [Path(p).resolve() for p in parsed]
                except Exception:
                    pass
            # Split comma or semicolon separated paths
            parts = [p.strip() for p in v.replace(";", ",").split(",") if p.strip()]
            if parts:
                return [Path(p).resolve() for p in parts]
            return [Path("./sandbox_files").resolve()]
        elif isinstance(v, (list, tuple, set)):
            return [Path(p).resolve() for p in v]
        return [Path("./sandbox_files").resolve()]

    @field_validator("UNDO_DIR", "DATABASE_PATH", mode="before")
    @classmethod
    def parse_path(cls, v: Any) -> Path:
        if isinstance(v, (str, Path)):
            return Path(v).resolve()
        return v


@lru_cache()
def get_settings() -> Settings:
    """Return cached Settings instance."""
    return Settings()


def reload_settings() -> Settings:
    """Clear cached settings and return fresh instance."""
    get_settings.cache_clear()
    return get_settings()
