from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional, Tuple

import httpx

from backend.app.config import DEFAULT_CONFIG, LLMConfig
from backend.app.security import filter_llm_output


class PluggableLLMClient:
    """
    Unified pluggable LLM adapter supporting:
      - fallback (deterministic grounded mode, zero external dependency)
      - gemini (Google Gemini REST API)
      - openai (OpenAI Chat Completions REST API)
      - ollama (Local Ollama server)
    """

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or DEFAULT_CONFIG

    def update_config(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        gemini_api_key: Optional[str] = None,
        openai_api_key: Optional[str] = None,
        ollama_base_url: Optional[str] = None,
        advisory_mode: Optional[bool] = None,
    ) -> LLMConfig:
        data = self.config.model_dump()
        if provider:
            data["provider"] = provider
        if model:
            data["model"] = model
        if gemini_api_key is not None:
            data["gemini_api_key"] = gemini_api_key or None
        if openai_api_key is not None:
            data["openai_api_key"] = openai_api_key or None
        if ollama_base_url:
            data["ollama_base_url"] = ollama_base_url
        if advisory_mode is not None:
            data["advisory_mode"] = advisory_mode
        self.config = LLMConfig(**data)
        return self.config

    def generate_text(
        self,
        system_prompt: str,
        user_prompt: str,
        fallback_fn,
    ) -> Tuple[str, Dict[str, Any]]:
        provider = self.config.provider
        if provider == "fallback":
            out = fallback_fn()
            return filter_llm_output(out), {
                "provider": "fallback",
                "model": self.config.model,
                "fallback_used": False,
            }

        try:
            if provider == "gemini":
                out = self._call_gemini(system_prompt, user_prompt)
            elif provider == "openai":
                out = self._call_openai(system_prompt, user_prompt)
            elif provider == "ollama":
                out = self._call_ollama(system_prompt, user_prompt)
            else:
                raise ValueError(f"Unsupported provider: {provider}")
            return filter_llm_output(out), {
                "provider": provider,
                "model": self.config.model,
                "fallback_used": False,
            }
        except Exception as exc:
            out = fallback_fn()
            return filter_llm_output(out), {
                "provider": provider,
                "model": self.config.model,
                "fallback_used": True,
                "fallback_reason": str(exc),
            }

    def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        fallback_fn,
    ) -> Tuple[Any, Dict[str, Any]]:
        provider = self.config.provider
        if provider == "fallback":
            return fallback_fn(), {
                "provider": "fallback",
                "model": self.config.model,
                "fallback_used": False,
            }
        raw, meta = self.generate_text(
            system_prompt + "\nRespond with valid JSON only.",
            user_prompt,
            fallback_fn=lambda: json.dumps(fallback_fn()),
        )
        parsed = self._extract_json(raw)
        if parsed is not None:
            return parsed, meta
        return fallback_fn(), {**meta, "fallback_used": True, "fallback_reason": "JSON parse fallback"}

    def _call_gemini(self, system_prompt: str, user_prompt: str) -> str:
        api_key = self.config.gemini_api_key
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY not configured")
        model = self.config.model if self.config.model != "deterministic-grounded-v1" else "gemini-2.5-flash"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {"temperature": self.config.temperature},
        }
        with httpx.Client(timeout=self.config.timeout_seconds) as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]

    def _call_openai(self, system_prompt: str, user_prompt: str) -> str:
        api_key = self.config.openai_api_key
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY not configured")
        model = self.config.model if self.config.model != "deterministic-grounded-v1" else "gpt-4o-mini"
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        payload = {
            "model": model,
            "temperature": self.config.temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        with httpx.Client(timeout=self.config.timeout_seconds) as client:
            resp = client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
        return data["choices"][0]["message"]["content"]

    def _call_ollama(self, system_prompt: str, user_prompt: str) -> str:
        model = self.config.model if self.config.model != "deterministic-grounded-v1" else "llama3.1"
        url = f"{self.config.ollama_base_url.rstrip('/')}/api/chat"
        payload = {
            "model": model,
            "stream": False,
            "options": {"temperature": self.config.temperature},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        with httpx.Client(timeout=self.config.timeout_seconds) as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
        return data["message"]["content"]

    @staticmethod
    def _extract_json(text: str) -> Any:
        text = text.strip()
        fenced = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if fenced:
            text = fenced.group(1).strip()
        try:
            return json.loads(text)
        except Exception:
            return None
