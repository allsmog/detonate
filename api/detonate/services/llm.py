from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

from detonate.config import settings


@dataclass
class LLMMessage:
    role: str  # "system", "user", "assistant", "tool"
    content: str
    tool_call_id: str | None = None
    tool_calls: list[dict[str, Any]] | None = None


@dataclass
class LLMResponse:
    content: str
    tool_calls: list[dict[str, Any]] | None = None
    model: str = ""
    usage: dict[str, int] = field(default_factory=dict)


@dataclass
class LLMStreamChunk:
    delta: str
    done: bool = False


class BaseLLMProvider(ABC):
    @classmethod
    @abstractmethod
    def is_configured(cls) -> bool:
        """Return True if this provider has all required config (keys, URLs, etc.)."""
        ...

    @abstractmethod
    async def complete(
        self,
        messages: list[LLMMessage],
        system: str | None = None,
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse: ...

    @abstractmethod
    async def stream(
        self,
        messages: list[LLMMessage],
        system: str | None = None,
    ) -> AsyncIterator[LLMStreamChunk]: ...


class OllamaProvider(BaseLLMProvider):
    @classmethod
    def is_configured(cls) -> bool:
        return True  # No API key needed

    def __init__(self) -> None:
        import ollama

        self.client = ollama.AsyncClient(host=settings.ollama_base_url)
        self.model = settings.ollama_model

    def _to_ollama_messages(
        self, messages: list[LLMMessage], system: str | None = None
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if system:
            out.append({"role": "system", "content": system})
        for m in messages:
            msg: dict[str, Any] = {"role": m.role, "content": m.content}
            if m.tool_calls:
                # Convert flat {id, name, arguments} to Ollama's {function: {name, arguments}}
                msg["tool_calls"] = [
                    {
                        "function": {
                            "name": tc["name"],
                            "arguments": tc.get("arguments", {}),
                        }
                    }
                    for tc in m.tool_calls
                ]
            out.append(msg)
        return out

    def _to_ollama_tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        ollama_tools = []
        for t in tools:
            ollama_tools.append({
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t.get("input_schema", {}),
                },
            })
        return ollama_tools

    async def complete(
        self,
        messages: list[LLMMessage],
        system: str | None = None,
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        import asyncio

        ollama_msgs = self._to_ollama_messages(messages, system)
        kwargs: dict[str, Any] = {"model": self.model, "messages": ollama_msgs}
        if tools:
            kwargs["tools"] = self._to_ollama_tools(tools)

        # Timeout per call: 120s for tool calls (can be slow), 300s for plain
        timeout = 120 if tools else 300
        resp = await asyncio.wait_for(self.client.chat(**kwargs), timeout=timeout)
        msg = resp.get("message", {})
        content = msg.get("content", "")

        tool_calls = None
        if msg.get("tool_calls"):
            tool_calls = []
            for tc in msg["tool_calls"]:
                fn = tc.get("function", {})
                tool_calls.append({
                    "id": fn.get("name", ""),
                    "name": fn.get("name", ""),
                    "arguments": fn.get("arguments", {}),
                })

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            model=self.model,
            usage={
                "prompt_tokens": resp.get("prompt_eval_count", 0),
                "completion_tokens": resp.get("eval_count", 0),
            },
        )

    async def stream(
        self,
        messages: list[LLMMessage],
        system: str | None = None,
    ) -> AsyncIterator[LLMStreamChunk]:
        ollama_msgs = self._to_ollama_messages(messages, system)
        response = await self.client.chat(
            model=self.model, messages=ollama_msgs, stream=True
        )
        async for chunk in response:
            msg = chunk.get("message", {})
            delta = msg.get("content", "")
            done = chunk.get("done", False)
            yield LLMStreamChunk(delta=delta, done=done)


class AnthropicProvider(BaseLLMProvider):
    @classmethod
    def is_configured(cls) -> bool:
        return bool(settings.anthropic_api_key.get_secret_value())

    def __init__(self) -> None:
        import anthropic

        key = settings.anthropic_api_key.get_secret_value()
        if not key:
            raise ValueError("ANTHROPIC_API_KEY is required when LLM_PROVIDER=anthropic")
        self.client = anthropic.AsyncAnthropic(api_key=key)
        self.model = settings.anthropic_model

    async def complete(
        self,
        messages: list[LLMMessage],
        system: str | None = None,
        tools: list[dict[str, Any]] | None = None,
    ) -> LLMResponse:
        anthropic_msgs = [{"role": m.role, "content": m.content} for m in messages]
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": settings.llm_max_tokens,
            "messages": anthropic_msgs,
        }
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = [
                {
                    "name": t["name"],
                    "description": t["description"],
                    "input_schema": t.get("input_schema", {}),
                }
                for t in tools
            ]

        resp = await self.client.messages.create(**kwargs)

        content = ""
        tool_calls = None
        for block in resp.content:
            if block.type == "text":
                content += block.text
            elif block.type == "tool_use":
                if tool_calls is None:
                    tool_calls = []
                tool_calls.append({
                    "id": block.id,
                    "name": block.name,
                    "arguments": block.input,
                })

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            model=self.model,
            usage={
                "prompt_tokens": resp.usage.input_tokens,
                "completion_tokens": resp.usage.output_tokens,
            },
        )

    async def stream(
        self,
        messages: list[LLMMessage],
        system: str | None = None,
    ) -> AsyncIterator[LLMStreamChunk]:
        anthropic_msgs = [{"role": m.role, "content": m.content} for m in messages]
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": settings.llm_max_tokens,
            "messages": anthropic_msgs,
        }
        if system:
            kwargs["system"] = system

        async with self.client.messages.stream(**kwargs) as stream:
            async for text in stream.text_stream:
                yield LLMStreamChunk(delta=text, done=False)
        yield LLMStreamChunk(delta="", done=True)


PROVIDER_REGISTRY: dict[str, type[BaseLLMProvider]] = {
    "ollama": OllamaProvider,
    "anthropic": AnthropicProvider,
}


def is_provider_configured() -> bool:
    provider_cls = PROVIDER_REGISTRY.get(settings.llm_provider)
    if provider_cls is None:
        return False
    return provider_cls.is_configured()


_llm: BaseLLMProvider | None = None


def get_llm_provider() -> BaseLLMProvider:
    global _llm
    if _llm is None:
        provider_cls = PROVIDER_REGISTRY.get(settings.llm_provider)
        if provider_cls is None:
            raise ValueError(f"Unknown LLM provider: {settings.llm_provider}")
        _llm = provider_cls()
    return _llm
