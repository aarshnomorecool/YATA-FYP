from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import requests

try:
    from openai import APIStatusError, OpenAI
except ImportError:  # pragma: no cover - handled via runtime fallback
    APIStatusError = None
    OpenAI = None


@dataclass(slots=True)
class LLMResponse:
    success: bool
    content: str
    model: str
    provider: str
    used_fallback: bool
    error: str | None = None


class LLMClient:
    DEFAULT_MODEL = "qwen/qwen3-next-80b-a3b-instruct"
    MODEL_FALLBACKS = {
        "qwen/qwen2.5-coder-32b-instruct": DEFAULT_MODEL,
        "qwen/qwen3-coder-480b-a35b-instruct": DEFAULT_MODEL,
    }
    execution_mode = "nvidia_assisted"
    fallback_message_printed = False

    def __init__(
        self,
        *,
        env_path: Path | None = None,
        model: str | None = None,
        base_url: str | None = None,
        timeout: int = 90,
    ) -> None:
        env_values = self._load_env_file(env_path or Path(__file__).resolve().parent / ".env")

        self.model = (
            os.getenv("YATA_LLM_MODEL")
            or env_values.get("YATA_LLM_MODEL")
            or model
            or self.DEFAULT_MODEL
        )
        raw_base_url = (
            os.getenv("NVIDIA_API_BASE_URL")
            or env_values.get("NVIDIA_API_BASE_URL")
            or base_url
            or "https://integrate.api.nvidia.com/v1"
        )
        self.base_url = self._normalize_base_url(raw_base_url)
        self.api_key = (
            os.getenv("NVIDIA_API_KEY")
            or env_values.get("NVIDIA_API_KEY")
            or os.getenv("NGC_API_KEY")
            or env_values.get("NGC_API_KEY")
        )
        if not self.api_key and LLMClient.execution_mode != "demo":
            LLMClient.execution_mode = "autonomous_fallback"
        self.timeout = timeout
        self.llm_requests = 0
        self.llm_time = 0.0

    def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        fallback_text: str,
        temperature: float = 0.2,
        top_p: float = 0.7,
        max_tokens: int = 700,
    ) -> LLMResponse:
        import time
        start_time = time.time()
        self.llm_requests += 1

        try:
            if not self.api_key:
                return self._fallback(
                    "Missing NVIDIA_API_KEY or NGC_API_KEY in .env; using local fallback behavior.",
                    fallback_text,
                )

            try:
                return self._invoke_model(
                    model_name=self.model,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    temperature=temperature,
                    top_p=top_p,
                    max_tokens=max_tokens,
                )
            except Exception as exc:
                replacement_model = self.MODEL_FALLBACKS.get(self.model)
                error_message = self._format_exception(exc)
                if replacement_model and self._looks_end_of_life_error(error_message):
                    try:
                        return self._invoke_model(
                            model_name=replacement_model,
                            system_prompt=system_prompt,
                            user_prompt=user_prompt,
                            temperature=temperature,
                            top_p=top_p,
                            max_tokens=max_tokens,
                        )
                    except Exception as replacement_exc:
                        replacement_error = self._format_exception(replacement_exc)
                        combined_error = (
                            f"{error_message} | Replacement model {replacement_model} also failed: {replacement_error}"
                        )
                        return self._fallback(combined_error, fallback_text)
                return self._fallback(error_message, fallback_text)
        finally:
            self.llm_time += time.time() - start_time

    def _fallback(self, error: str, fallback_text: str) -> LLMResponse:
        if LLMClient.execution_mode == "nvidia_assisted":
            LLMClient.execution_mode = "autonomous_fallback"
            if not LLMClient.fallback_message_printed:
                LLMClient.fallback_message_printed = True
                print("\n[YATA]\nAutonomous Fallback Mode Activated\n\nNVIDIA API unavailable or timed out.\nSwitching to offline deterministic models.")
        return LLMResponse(
            success=False,
            content=fallback_text,
            model=self.model,
            provider="nvidia",
            used_fallback=True,
            error=error,
        )

    def _load_env_file(self, env_path: Path) -> dict[str, str]:
        if not env_path.exists():
            return {}

        values: dict[str, str] = {}
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
        return values

    def _normalize_base_url(self, raw_base_url: str) -> str:
        normalized = raw_base_url.strip().rstrip("/")
        if normalized.endswith("/chat/completions"):
            normalized = normalized[: -len("/chat/completions")]
        return normalized

    def _invoke_model(
        self,
        *,
        model_name: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        top_p: float,
        max_tokens: int,
    ) -> LLMResponse:
        if OpenAI is not None:
            client = OpenAI(base_url=self.base_url, api_key=self.api_key, timeout=self.timeout)
            messages = []
            if system_prompt.strip():
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": user_prompt})
            completion = client.chat.completions.create(
                model=model_name,
                messages=messages,
                temperature=temperature,
                top_p=top_p,
                max_tokens=max_tokens,
                stream=False,
            )
            content = (completion.choices[0].message.content or "").strip()
            if not content:
                raise RuntimeError("NVIDIA API returned an empty response.")
            return LLMResponse(
                success=True,
                content=content,
                model=model_name,
                provider="nvidia",
                used_fallback=False,
            )

        payload = {
            "model": model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "top_p": top_p,
            "max_tokens": max_tokens,
            "stream": False,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        response = requests.post(
            f"{self.base_url}/chat/completions",
            headers=headers,
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
        if not content:
            raise RuntimeError("NVIDIA API returned an empty response.")
        return LLMResponse(
            success=True,
            content=content,
            model=model_name,
            provider="nvidia",
            used_fallback=False,
        )

    def _looks_end_of_life_error(self, error_message: str) -> bool:
        lowered = error_message.lower()
        return "end of life" in lowered or "no longer available" in lowered

    def _format_exception(self, exc: Exception) -> str:
        if APIStatusError is not None and isinstance(exc, APIStatusError):
            body = exc.body
            if isinstance(body, dict):
                detail = body.get("detail") or body.get("message") or str(body)
            else:
                detail = str(body) if body else str(exc)
            return f"HTTP {exc.status_code}: {detail}"
        return str(exc)
