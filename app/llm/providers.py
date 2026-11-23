"""Optional real LLM providers + the provider factory.

Neither SDK is a required dependency. A provider is only used when:

* ``PROMPTGUARD_LLM_PROVIDER`` is set to ``openai`` or ``anthropic``,
* the matching API key is present in the environment, and
* the SDK package is installed (``pip install openai`` / ``pip install anthropic``).

Otherwise PromptGuard falls back to the offline MockLLM. API keys are only ever
read from the environment - never hardcoded, never logged.

Real providers here are text-only (no tool calling) to keep the integration
small; tool-call demos use the MockLLM.
"""

from __future__ import annotations

import logging

from app.config import Settings
from app.llm.base import BaseLLM, LLMRequest, LLMResponse, SYSTEM_PROMPT
from app.llm.mock import MockLLM

logger = logging.getLogger("promptguard.llm")


class OpenAILLM(BaseLLM):
    name = "openai"

    def __init__(self, api_key: str, model: str) -> None:
        from openai import OpenAI  # lazy import: optional dependency

        self.client = OpenAI(api_key=api_key)
        self.model = model

    def generate(self, request: LLMRequest) -> LLMResponse:
        completion = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.rendered_prompt},
            ],
        )
        return LLMResponse(text=completion.choices[0].message.content or "", provider=self.name)


class AnthropicLLM(BaseLLM):
    name = "anthropic"

    def __init__(self, api_key: str, model: str) -> None:
        import anthropic  # lazy import: optional dependency

        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def generate(self, request: LLMRequest) -> LLMResponse:
        # Server-side refusal fallback: if the model declines on policy grounds,
        # the API re-runs the request on a fallback model chosen per category.
        response = self.client.beta.messages.create(
            model=self.model,
            max_tokens=16000,
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            system=request.system_prompt,
            messages=[{"role": "user", "content": request.rendered_prompt}],
        )
        if response.stop_reason == "refusal":
            return LLMResponse(text="[The model declined this request.]", provider=self.name, notes=["refusal"])
        text = "".join(block.text for block in response.content if block.type == "text")
        return LLMResponse(text=text, provider=self.name)


def build_llm(settings: Settings) -> BaseLLM:
    """Return the configured provider, falling back to MockLLM when unavailable."""
    provider = settings.llm_provider
    try:
        if provider == "openai" and settings.openai_api_key:
            return OpenAILLM(settings.openai_api_key, settings.openai_model)
        if provider == "anthropic" and settings.anthropic_api_key:
            return AnthropicLLM(settings.anthropic_api_key, settings.anthropic_model)
    except ImportError:
        logger.warning("SDK for provider %r is not installed; falling back to MockLLM.", provider)
    if provider not in {"mock", ""}:
        logger.warning("Provider %r not usable (missing key or SDK); using MockLLM.", provider)
    return MockLLM(SYSTEM_PROMPT)
