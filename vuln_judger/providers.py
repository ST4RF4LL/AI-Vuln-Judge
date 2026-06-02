from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


PROVIDER_TYPE = "openai-compatible"
DEFAULT_PROVIDERS_FILE = Path(".vuln-judger") / "providers.json"


@dataclass
class ProviderConfig:
    id: str
    name: str
    type: str
    endpoint: str
    model: str
    api_key_env: Optional[str] = None
    api_key: Optional[str] = None
    extra_json: Dict[str, Any] = field(default_factory=dict)

    def resolved_api_key(self, override: Optional[str] = None) -> Optional[str]:
        if override:
            return override
        if self.api_key_env:
            value = os.environ.get(self.api_key_env)
            if value:
                return value
        return self.api_key

    def public_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "endpoint": self.endpoint,
            "model": self.model,
            "api_key_env": self.api_key_env,
            "api_key_saved": bool(self.api_key),
            "api_key": "********" if self.api_key else "",
            "extra_json": self.extra_json,
        }

    def private_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "endpoint": self.endpoint,
            "model": self.model,
            "api_key_env": self.api_key_env,
            "api_key": self.api_key,
            "extra_json": self.extra_json,
        }


class ProviderStore:
    def __init__(self, path: Path):
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def list(self) -> List[Dict[str, Any]]:
        return [provider.public_dict() for provider in self._providers().values()]

    def get(self, provider_id: str) -> Optional[ProviderConfig]:
        return self._providers().get(provider_id)

    def upsert(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        data = self._load()
        providers = data.setdefault("providers", [])
        provider = provider_from_payload(payload, existing=self.get(str(payload.get("id") or "")))
        replaced = False
        for index, item in enumerate(providers):
            if item.get("id") == provider.id:
                providers[index] = provider.private_dict()
                replaced = True
                break
        if not replaced:
            providers.append(provider.private_dict())
        self._save(data)
        return provider.public_dict()

    def delete(self, provider_id: str) -> bool:
        data = self._load()
        providers = data.setdefault("providers", [])
        kept = [item for item in providers if item.get("id") != provider_id]
        removed = len(kept) != len(providers)
        data["providers"] = kept
        defaults = data.setdefault("defaults", {})
        if defaults.get("affirmative") == provider_id:
            defaults["affirmative"] = None
        if defaults.get("negative") == provider_id:
            defaults["negative"] = None
        if removed:
            self._save(data)
        return removed

    def defaults(self) -> Dict[str, Optional[str]]:
        defaults = self._load().get("defaults") or {}
        return {
            "affirmative": defaults.get("affirmative"),
            "negative": defaults.get("negative"),
        }

    def set_defaults(self, affirmative: Optional[str], negative: Optional[str]) -> Dict[str, Optional[str]]:
        providers = self._providers()
        if affirmative and affirmative not in providers:
            raise ValueError(f"unknown affirmative provider: {affirmative}")
        if negative and negative not in providers:
            raise ValueError(f"unknown negative provider: {negative}")
        data = self._load()
        data["defaults"] = {"affirmative": affirmative, "negative": negative}
        self._save(data)
        return self.defaults()

    def resolve_pair(
        self,
        affirmative_provider_id: Optional[str],
        negative_provider_id: Optional[str],
    ) -> tuple[Optional[ProviderConfig], Optional[ProviderConfig]]:
        defaults = self.defaults()
        affirmative_id = affirmative_provider_id or defaults.get("affirmative") or defaults.get("negative")
        negative_id = negative_provider_id or defaults.get("negative") or defaults.get("affirmative")
        providers = self._providers()
        affirmative = providers.get(affirmative_id) if affirmative_id else None
        negative = providers.get(negative_id) if negative_id else None
        return affirmative, negative

    def _providers(self) -> Dict[str, ProviderConfig]:
        result = {}
        for item in self._load().get("providers", []):
            provider = provider_from_payload(item)
            result[provider.id] = provider
        return result

    def _load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "defaults": {"affirmative": None, "negative": None}, "providers": []}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        data.setdefault("version", 1)
        data.setdefault("defaults", {"affirmative": None, "negative": None})
        data.setdefault("providers", [])
        return data

    def _save(self, data: Dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            self.path.chmod(0o600)
        except OSError:
            pass


def provider_from_payload(payload: Dict[str, Any], existing: Optional[ProviderConfig] = None) -> ProviderConfig:
    provider_id = str(payload.get("id") or "").strip()
    if not provider_id:
        raise ValueError("provider id is required")
    if not re.match(r"^[A-Za-z0-9_.-]+$", provider_id):
        raise ValueError("provider id may only contain letters, numbers, dot, underscore, and hyphen")
    provider_type = str(payload.get("type") or PROVIDER_TYPE)
    if provider_type != PROVIDER_TYPE:
        raise ValueError("only openai-compatible providers are supported")
    endpoint = str(payload.get("endpoint") or "").strip()
    model = str(payload.get("model") or "").strip()
    if not endpoint:
        raise ValueError("provider endpoint is required")
    if not model:
        raise ValueError("provider model is required")
    api_key_env = str(payload.get("api_key_env") or "").strip() or None
    if "api_key" in payload:
        raw_key = payload.get("api_key")
        api_key = str(raw_key).strip() if raw_key is not None else None
        if api_key == "********" and existing is not None:
            api_key = existing.api_key
        elif api_key == "":
            api_key = None
    else:
        api_key = existing.api_key if existing is not None else None
    return ProviderConfig(
        id=provider_id,
        name=str(payload.get("name") or provider_id).strip(),
        type=provider_type,
        endpoint=endpoint,
        model=model,
        api_key_env=api_key_env,
        api_key=api_key,
        extra_json=parse_extra_json(payload.get("extra_json")),
    )


def parse_extra_json(value: Any) -> Dict[str, Any]:
    if value is None or value == "":
        return {}
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"extra_json is not valid JSON: {exc}") from exc
    elif isinstance(value, dict):
        parsed = value
    else:
        raise ValueError("extra_json must be a JSON object")
    if not isinstance(parsed, dict):
        raise ValueError("extra_json must be a JSON object")
    blocked = {"model", "messages"}
    conflicts = sorted(key for key in parsed if key in blocked)
    if conflicts:
        raise ValueError(f"extra_json cannot override: {', '.join(conflicts)}")
    return parsed
