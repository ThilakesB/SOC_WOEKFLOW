"""LLM provider abstraction with tool-calling and streaming.

Three providers behind one normalised interface:
  gemini    — Google Generative Language REST API (primary)
  openrouter — OpenAI-compatible gateway
  ollama    — local models, no key required

Design note: the analyst pipeline is fully functional with *no* LLM at all.
The model is a judgment layer that adds narrative and can call tools; it is
never on the critical path for producing a verdict.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import inspect
import json
import time
from typing import Any, AsyncIterator, Callable

import httpx

from .config import settings


class LLMError(RuntimeError):
    pass


class CreditError(LLMError):
    """Provider rejected the request for billing/credit reasons."""


# ── tool contract ────────────────────────────────────────────────

class Tool:
    def __init__(
        self,
        name: str,
        description: str,
        parameters: dict[str, Any],
        handler: Callable[[dict[str, Any]], Any],
    ):
        self.name = name
        self.description = description
        self.parameters = parameters
        self._handler = handler

    async def handler(self, args: dict[str, Any]) -> Any:
        """Accept sync or async callables so handlers stay declarative."""
        out = self._handler(args)
        if inspect.isawaitable(out):
            out = await out
        return out

    def spec(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
        }


# ── normalised response ──────────────────────────────────────────

class Turn:
    def __init__(self, text: str = "", tool_calls: list[dict[str, Any]] | None = None,
                 usage: dict[str, Any] | None = None):
        self.text = text
        self.tool_calls = tool_calls or []
        self.usage = usage or {}


# ── providers ────────────────────────────────────────────────────

class Gemini:
    name = "gemini"
    base = "https://generativelanguage.googleapis.com/v1beta/models"

    def available(self) -> bool:
        return bool(settings.gemini_key)

    def _body(self, messages: list[dict], tools: list[dict] | None,
              max_tokens: int, temperature: float) -> dict[str, Any]:
        system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        contents: list[dict[str, Any]] = []
        for m in messages:
            if m["role"] == "system":
                continue
            role = "model" if m["role"] == "assistant" else "user"
            if m["role"] == "tool":
                contents.append(
                    {"role": "user", "parts": [
                        {"functionResponse": {
                            "name": m["name"],
                            "response": m.get("content") if isinstance(m.get("content"), dict)
                            else {"result": m.get("content")},
                        }}
                    ]}
                )
                continue
            if m["role"] == "assistant" and m.get("tool_calls"):
                parts = []
                if m.get("content"):
                    parts.append({"text": m["content"]})
                for tc in m["tool_calls"]:
                    parts.append({"functionCall": {
                        "name": tc["name"],
                        "args": tc.get("arguments", {}),
                    }})
                contents.append({"role": "model", "parts": parts})
                continue
            contents.append({"role": role, "parts": [{"text": m.get("content") or ""}]})

        body: dict[str, Any] = {"contents": contents}
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        if tools:
            body["tools"] = [{"functionDeclarations": [
                {"name": t["name"], "description": t["description"], "parameters": t["parameters"]}
                for t in tools
            ]}]
        body["generationConfig"] = {
            "maxOutputTokens": max_tokens,
            "temperature": temperature,
            "responseMimeType": "application/json",
        }
        return body

    async def stream(
        self, messages: list[dict], tools: list[dict] | None, max_tokens: int, temperature: float
    ) -> AsyncIterator[dict[str, Any]]:
        url = f"{self.base}/{settings.gemini_model}:streamGenerateContent?alt=sse"
        body = self._body(messages, tools, max_tokens, temperature)
        timeout = httpx.Timeout(settings.agent_timeout)
        async with httpx.AsyncClient(timeout=timeout) as client:
            async with client.stream(
                "POST", url, json=body,
                headers={"x-goog-api-key": settings.gemini_key},
            ) as r:
                if r.status_code == 429:
                    raise CreditError("Gemini rate limit or quota exhausted")
                if r.status_code >= 400:
                    detail = (await r.aread()).decode("utf-8", "replace")[:300]
                    if any(w in detail.lower() for w in ("quota", "billing", "payment")):
                        raise CreditError(f"Gemini quota: {detail}")
                    raise LLMError(f"Gemini HTTP {r.status_code}: {detail}")
                async for line in r.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    chunk = line[5:].strip()
                    if not chunk or chunk == "[DONE]":
                        continue
                    try:
                        yield json.loads(chunk)
                    except json.JSONDecodeError:
                        continue

    async def turn(self, messages: list[dict], tools: list[dict] | None,
                   max_tokens: int, temperature: float = 0.2) -> Turn:
        url = f"{self.base}/{settings.gemini_model}:generateContent"
        body = self._body(messages, tools, max_tokens, temperature)
        timeout = httpx.Timeout(settings.agent_timeout)
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(url, json=body,
                                   headers={"x-goog-api-key": settings.gemini_key})
        if r.status_code == 429:
            raise CreditError("Gemini rate limit or quota exhausted")
        if r.status_code >= 400:
            detail = r.text[:300]
            if any(w in detail.lower() for w in ("quota", "billing", "payment")):
                raise CreditError(f"Gemini quota: {detail}")
            raise LLMError(f"Gemini HTTP {r.status_code}: {detail}")

        data = r.json()
        text_parts: list[str] = []
        calls: list[dict[str, Any]] = []
        for cand in data.get("candidates", []):
            for part in (cand.get("content", {}) or {}).get("parts", []) or []:
                if "text" in part:
                    text_parts.append(part["text"])
                fc = part.get("functionCall")
                if fc:
                    calls.append({"id": f"call_{len(calls)}",
                                  "name": fc.get("name", ""),
                                  "arguments": fc.get("args", {}) or {}})
        usage = (data.get("usageMetadata") or {})
        return Turn(
            text="".join(text_parts).strip(),
            tool_calls=calls,
            usage={"input": usage.get("promptTokenCount", 0),
                   "output": usage.get("candidatesTokenCount", 0)},
        )

    async def healthy(self) -> bool:
        if not settings.gemini_key:
            return False
        try:
            async with httpx.AsyncClient(timeout=6) as c:
                r = await c.get(
                    "https://generativelanguage.googleapis.com/v1beta/models",
                    params={"key": settings.gemini_key, "pageSize": 1},
                )
                return r.status_code == 200
        except Exception:
            return False


class OpenRouter:
    name = "openrouter"
    base = "https://openrouter.ai/api/v1"

    def available(self) -> bool:
        return bool(settings.openrouter_key)

    def _client(self):
        from openai import AsyncOpenAI

        return AsyncOpenAI(base_url=self.base, api_key=settings.openrouter_key, timeout=settings.agent_timeout)

    @staticmethod
    def _tools(tools: list[dict] | None) -> list[dict] | None:
        if not tools:
            return None
        return [{"type": "function", "function": {
            "name": t["name"], "description": t["description"], "parameters": t["parameters"],
        }} for t in tools]

    @staticmethod
    def _messages(messages: list[dict]) -> list[dict[str, Any]]:
        """OpenAI-compatible: tool results need a string body and a tool_call_id."""
        out: list[dict[str, Any]] = []
        for m in messages:
            if m["role"] == "tool":
                content = m.get("content")
                out.append({
                    "role": "tool",
                    "tool_call_id": m.get("id", "call_0"),
                    "content": content if isinstance(content, str) else json.dumps(content, default=str),
                })
                continue
            if m["role"] == "assistant":
                msg: dict[str, Any] = {"role": "assistant", "content": m.get("content") or ""}
                if m.get("tool_calls"):
                    msg["tool_calls"] = [
                        {"id": c.get("id", "call_0"), "type": "function",
                         "function": {"name": c["name"],
                                      "arguments": json.dumps(c.get("arguments", {}), default=str)}}
                        for c in m["tool_calls"]
                    ]
                    msg["content"] = m.get("content") or ""
                out.append(msg)
                continue
            out.append({"role": m["role"], "content": m.get("content") or ""})
        return out

    async def turn(self, messages: list[dict], tools: list[dict] | None,
                   max_tokens: int, temperature: float = 0.2) -> Turn:
        client = self._client()
        try:
            r = await client.chat.completions.create(
                model=settings.openrouter_model,
                messages=self._messages(messages),
                tools=self._tools(tools),
                max_tokens=max_tokens,
                temperature=temperature,
                response_format={"type": "json_object"},
            )
        except Exception as e:
            msg = str(e)
            if "credit" in msg.lower() or "402" in msg:
                raise CreditError(f"OpenRouter: {msg[:200]}") from e
            raise LLMError(f"OpenRouter: {msg[:200]}") from e

        m = r.choices[0].message
        calls = []
        for i, tc in enumerate(m.tool_calls or []):
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            calls.append({"id": tc.id or f"call_{i}",
                          "name": tc.function.name, "arguments": args})
        return Turn(
            text=(m.content or "").strip(),
            tool_calls=calls,
            usage={"input": r.usage.prompt_tokens if r.usage else 0,
                   "output": r.usage.completion_tokens if r.usage else 0},
        )

    async def healthy(self) -> bool:
        if not settings.openrouter_key:
            return False
        try:
            async with httpx.AsyncClient(timeout=6) as c:
                r = await c.get(f"{self.base}/credits",
                                headers={"Authorization": f"Bearer {settings.openrouter_key}"})
                return r.status_code == 200
        except Exception:
            return False


class Ollama:
    name = "ollama"
    base = settings.ollama_host

    def available(self) -> bool:
        return bool(settings.ollama_host)

    def _tools(self, tools: list[dict] | None) -> list[dict] | None:
        if not tools:
            return None
        return [{"type": "function", "function": {
            "name": t["name"], "description": t["description"], "parameters": t["parameters"],
        }} for t in tools]

    async def turn(self, messages: list[dict], tools: list[dict] | None,
                   max_tokens: int, temperature: float = 0.2) -> Turn:
        payload: dict[str, Any] = {
            "model": settings.ollama_model,
            "messages": OpenRouter._messages(messages),
            "stream": False,
            "format": "json",
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        if tools:
            payload["tools"] = self._tools(tools)
        try:
            async with httpx.AsyncClient(timeout=settings.agent_timeout) as c:
                r = await c.post(f"{self.base}/api/chat", json=payload)
            if r.status_code >= 400:
                raise LLMError(f"Ollama HTTP {r.status_code}: {r.text[:200]}")
        except httpx.ConnectError as e:
            raise LLMError("Ollama not reachable") from e

        m = r.json().get("message", {})
        calls = []
        for i, tc in enumerate(m.get("tool_calls") or []):
            fn = tc.get("function", {})
            calls.append({"id": f"call_{i}", "name": fn.get("name", ""),
                          "arguments": fn.get("arguments", {}) or {}})
        return Turn(text=(m.get("content") or "").strip(), tool_calls=calls,
                    usage={})

    async def healthy(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=4) as c:
                r = await c.get(f"{self.base}/api/tags")
                return r.status_code == 200
        except Exception:
            return False


PROVIDERS: dict[str, Any] = {p.name: p for p in (Gemini(), OpenRouter(), Ollama())}


# ── router ───────────────────────────────────────────────────────

class Router:
    """Tries providers in order; records which one actually served the request."""

    def __init__(self, order: list[str] | None = None):
        self.order = order if order is not None else settings.chain
        self.last_used: str | None = None
        self.last_error: str | None = None

    async def turn(self, messages: list[dict], tools: list[dict] | None,
                   max_tokens: int, temperature: float = 0.2,
                   on_failover: Callable[[str, str], None] | None = None) -> Turn:
        errors: list[str] = []
        for name in self.order:
            p = PROVIDERS.get(name)
            if not p or not p.available():
                continue
            try:
                turn = await p.turn(messages, tools, max_tokens, temperature)
                if turn.text or turn.tool_calls:
                    self.last_used = name
                    self.last_error = None
                    return turn
                errors.append(f"{name}: empty response")
            except CreditError as e:
                errors.append(f"{name}: {e}")
                if on_failover:
                    on_failover(name, str(e))
            except LLMError as e:
                errors.append(f"{name}: {e}")
            except Exception as e:  # provider bugs must not kill the pipeline
                errors.append(f"{name}: {type(e).__name__}: {e}")
        self.last_error = "; ".join(errors) or "no provider configured"
        raise LLMError(self.last_error)

    async def health(self) -> list[dict[str, Any]]:
        out = []
        for name in self.order:
            p = PROVIDERS.get(name)
            if not p:
                continue
            ok = False
            try:
                ok = await p.healthy()
            except Exception:
                ok = False
            out.append({"provider": name, "configured": p.available(), "reachable": ok})
        return out


# ── JSON repair ──────────────────────────────────────────────────

def parse_json_loose(text: str) -> dict[str, Any]:
    """Parse model JSON that may be wrapped in prose or code fences."""
    if not text:
        return {}
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else t
        t = t.rsplit("```", 1)[0]
    t = t.strip()
    try:
        v = json.loads(t)
        return v if isinstance(v, dict) else {"result": v}
    except json.JSONDecodeError:
        pass
    for opener, closer in (("{", "}"), ("[", "]")):
        i, j = t.find(opener), t.rfind(closer)
        if i != -1 and j > i:
            try:
                v = json.loads(t[i:j + 1])
                return v if isinstance(v, dict) else {"result": v}
            except json.JSONDecodeError:
                continue
    return {}


def decode_payload(value: str) -> str:
    """Best-effort decode of base64 blobs found in command lines."""
    out: list[str] = []
    for cand in re_split_b64(value):
        try:
            raw = base64.b64decode(cand, validate=True)
        except (binascii.Error, ValueError):
            continue
        for enc in ("utf-16-le", "utf-8"):
            try:
                text = raw.decode(enc).strip("\x00").strip()
            except UnicodeDecodeError:
                continue
            if text and sum(c.isprintable() or c in "\r\n\t" for c in text) / len(text) > 0.85:
                out.append(f"[{enc}] {text[:400]}")
                break
    return "\n".join(out) if out else "No decodable base64 payload found."


def re_split_b64(value: str) -> list[str]:
    import re

    return [m for m in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", value or "")]


async def run_with_timeout(coro, seconds: float):
    try:
        return await asyncio.wait_for(coro, timeout=seconds)
    except asyncio.TimeoutError:
        return None


class Timer:
    def __enter__(self):
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, *a):
        self.ms = int((time.perf_counter() - self.t0) * 1000)
