from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .logging_config import logger
from .providers import ProviderConfig


LOG = logger("llm")


class LLMClient:
    provider_id: Optional[str] = None
    provider_name: Optional[str] = None
    model: Optional[str] = None

    def complete(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        raise NotImplementedError


@dataclass
class OpenAICompatibleLLM(LLMClient):
    api_key: str
    model: str
    endpoint: str = "https://api.openai.com/v1/chat/completions"
    timeout_seconds: int = 120
    extra_json: Dict[str, Any] = field(default_factory=dict)
    provider_id: Optional[str] = None
    provider_name: Optional[str] = None

    def complete(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        result = self.request(system_prompt, user_prompt)
        if not result["ok"]:
            return None
        return result.get("content")

    def request(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        payload = self._payload(system_prompt, user_prompt)
        started = time.monotonic()
        LOG.info(
            "LLM 请求开始 provider=%s model=%s endpoint=%s",
            self.provider_id or self.provider_name or "unknown",
            self.model,
            self.endpoint,
        )
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "authorization": f"Bearer {self.api_key}",
                "content-type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                status = response.status
                body_text = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            LOG.warning(
                "LLM HTTP 错误 provider=%s status=%s latency_ms=%s body=%s",
                self.provider_id or self.provider_name or "unknown",
                exc.code,
                _latency_ms(started),
                body[:500],
            )
            return _failure(exc.code, started, f"HTTP {exc.code}: {body[:500]}")
        except urllib.error.URLError as exc:
            LOG.warning(
                "LLM 网络错误 provider=%s latency_ms=%s error=%s",
                self.provider_id or self.provider_name or "unknown",
                _latency_ms(started),
                exc,
            )
            return _failure(None, started, str(exc))
        except (socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
            LOG.warning(
                "LLM 连接错误 provider=%s latency_ms=%s error=%s",
                self.provider_id or self.provider_name or "unknown",
                _latency_ms(started),
                exc,
            )
            return _failure(None, started, str(exc))
        try:
            body = json.loads(body_text)
        except json.JSONDecodeError as exc:
            LOG.warning(
                "LLM 响应 JSON 解析失败 provider=%s status=%s latency_ms=%s body=%s",
                self.provider_id or self.provider_name or "unknown",
                status,
                _latency_ms(started),
                body_text[:500],
            )
            return _failure(status, started, f"响应不是合法 JSON：{exc}")
        choices = body.get("choices") or []
        if not choices:
            LOG.warning(
                "LLM 响应缺少 choices provider=%s status=%s latency_ms=%s body=%s",
                self.provider_id or self.provider_name or "unknown",
                status,
                _latency_ms(started),
                body_text[:500],
            )
            return _failure(status, started, "响应中没有 choices")
        message = choices[0].get("message") or {}
        content = message.get("content")
        if not content:
            LOG.warning(
                "LLM 响应缺少 message.content provider=%s status=%s latency_ms=%s body=%s",
                self.provider_id or self.provider_name or "unknown",
                status,
                _latency_ms(started),
                body_text[:500],
            )
            return _failure(status, started, "响应中没有 message.content")
        LOG.info(
            "LLM 请求完成 provider=%s status=%s latency_ms=%s content_chars=%s",
            self.provider_id or self.provider_name or "unknown",
            status,
            _latency_ms(started),
            len(str(content)),
        )
        return {
            "ok": True,
            "status": status,
            "latency_ms": _latency_ms(started),
            "content": str(content).strip(),
            "response_excerpt": str(content).strip()[:500],
        }

    def test_connection(self) -> Dict[str, Any]:
        result = self.request("你正在进行 connectivity API 连通性测试。", "只回复：OK")
        result.update(
            {
                "provider_id": self.provider_id,
                "provider_name": self.provider_name,
                "model": self.model,
                "endpoint": self.endpoint,
            }
        )
        return result

    def _payload(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        if "temperature" not in self.extra_json:
            payload["temperature"] = 0.1
        for key, value in self.extra_json.items():
            if key in {"model", "messages"}:
                continue
            payload[key] = value
        return payload


def build_llm_clients(
    enabled: bool,
    affirmative_provider: Optional[ProviderConfig] = None,
    negative_provider: Optional[ProviderConfig] = None,
    legacy_model: Optional[str] = None,
    legacy_endpoint: Optional[str] = None,
) -> tuple[Optional[LLMClient], Optional[LLMClient]]:
    if not enabled:
        return None, None
    if affirmative_provider or negative_provider:
        affirmative = build_client_from_provider(affirmative_provider) if affirmative_provider else None
        negative = build_client_from_provider(negative_provider) if negative_provider else None
        return affirmative, negative
    legacy = build_legacy_llm_client(legacy_model, legacy_endpoint)
    return legacy, legacy


def build_client_from_provider(provider: Optional[ProviderConfig], api_key_override: Optional[str] = None) -> Optional[LLMClient]:
    if provider is None:
        return None
    api_key = provider.resolved_api_key(api_key_override)
    if not api_key:
        return None
    return OpenAICompatibleLLM(
        api_key=api_key,
        model=provider.model,
        endpoint=provider.endpoint,
        extra_json=dict(provider.extra_json),
        provider_id=provider.id,
        provider_name=provider.name,
    )


def build_legacy_llm_client(model: Optional[str], endpoint: Optional[str]) -> Optional[LLMClient]:
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("VULN_JUDGER_LLM_API_KEY")
    chosen_model = model or os.environ.get("VULN_JUDGER_LLM_MODEL")
    if not api_key or not chosen_model:
        return None
    return OpenAICompatibleLLM(
        api_key=api_key,
        model=chosen_model,
        endpoint=endpoint or os.environ.get("VULN_JUDGER_LLM_ENDPOINT") or OpenAICompatibleLLM.endpoint,
        provider_id="legacy",
        provider_name="旧版环境变量提供商",
    )


def test_provider_connection(provider: ProviderConfig, api_key_override: Optional[str] = None) -> Dict[str, Any]:
    client = build_client_from_provider(provider, api_key_override=api_key_override)
    if client is None:
        return {
            "ok": False,
            "provider_id": provider.id,
            "provider_name": provider.name,
            "model": provider.model,
            "endpoint": provider.endpoint,
            "latency_ms": 0,
            "error": "API key 未配置，或环境变量未设置",
        }
    if isinstance(client, OpenAICompatibleLLM):
        return client.test_connection()
    return {"ok": False, "provider_id": provider.id, "error": "不支持的客户端类型"}


def _failure(status: Optional[int], started: float, error: str) -> Dict[str, Any]:
    return {
        "ok": False,
        "status": status,
        "latency_ms": _latency_ms(started),
        "error": error,
    }


def _latency_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
