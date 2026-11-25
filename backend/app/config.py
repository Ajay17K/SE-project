from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = Path(os.getenv("FINREQ_DB_PATH", str(DATA_DIR / "finreq.db")))
KB_DIR = BASE_DIR / "knowledge_base"


class LLMConfig(BaseModel):
    provider: Literal["fallback", "gemini", "openai", "ollama"] = os.getenv("FINREQ_LLM_PROVIDER", "fallback")  # type: ignore[assignment]
    model: str = os.getenv("FINREQ_LLM_MODEL", "deterministic-grounded-v1")
    gemini_api_key: str | None = os.getenv("GEMINI_API_KEY")
    openai_api_key: str | None = os.getenv("OPENAI_API_KEY")
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    temperature: float = 0.1
    timeout_seconds: float = 30.0
    confidence_escalation_threshold: float = 0.72
    advisory_mode: bool = True


DEFAULT_CONFIG = LLMConfig()
