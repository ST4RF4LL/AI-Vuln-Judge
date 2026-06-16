from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .mcp import MCPStdioClient


DEFAULT_MCP_SERVERS_FILE = Path(".vuln-judger") / "mcp.json"
MCP_TRANSPORT_STDIO = "stdio"


@dataclass
class MCPServerConfig:
    id: str
    name: str
    transport: str = MCP_TRANSPORT_STDIO
    command: str = "atlas"
    args: List[str] = field(default_factory=lambda: ["mcp", "--log-format", "json"])
    cwd: Optional[str] = "{project}"
    env: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    kind: str = "atlas"
    description: str = ""

    def public_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "transport": self.transport,
            "command": self.command,
            "args": list(self.args),
            "cwd": self.cwd,
            "env": _masked_env(self.env),
            "enabled": self.enabled,
            "kind": self.kind,
            "description": self.description,
        }

    def private_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "transport": self.transport,
            "command": self.command,
            "args": list(self.args),
            "cwd": self.cwd,
            "env": dict(self.env),
            "enabled": self.enabled,
            "kind": self.kind,
            "description": self.description,
        }

    def command_for_project(self, project: Path) -> tuple[List[str], Path, Dict[str, str]]:
        variables = {"project": str(project), "source_root": str(project)}
        command = _render(self.command, variables)
        args = [_render(arg, variables) for arg in self.args]
        cwd_text = _render(self.cwd or "{project}", variables)
        env = {_render(key, variables): _render(value, variables) for key, value in self.env.items()}
        return [command, *args], Path(cwd_text).expanduser().resolve(), env


class MCPServerStore:
    def __init__(self, path: Path):
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def list(self) -> List[Dict[str, Any]]:
        return [server.public_dict() for server in self._servers().values()]

    def get(self, server_id: str) -> Optional[MCPServerConfig]:
        return self._servers().get(server_id)

    def upsert(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        data = self._load()
        servers = data.setdefault("servers", [])
        server = server_from_payload(payload, existing=self.get(str(payload.get("id") or "")))
        replaced = False
        for index, item in enumerate(servers):
            if item.get("id") == server.id:
                servers[index] = server.private_dict()
                replaced = True
                break
        if not replaced:
            servers.append(server.private_dict())
        data.setdefault("defaults", {})
        if not data["defaults"].get(server.kind):
            data["defaults"][server.kind] = server.id
        self._save(data)
        return server.public_dict()

    def delete(self, server_id: str) -> bool:
        data = self._load()
        servers = data.setdefault("servers", [])
        kept = [item for item in servers if item.get("id") != server_id]
        removed = len(kept) != len(servers)
        data["servers"] = kept
        defaults = data.setdefault("defaults", {})
        for key, value in list(defaults.items()):
            if value == server_id:
                defaults[key] = None
        if removed:
            self._save(data)
        return removed

    def defaults(self) -> Dict[str, Optional[str]]:
        defaults = self._load().get("defaults") or {}
        return {"atlas": defaults.get("atlas")}

    def set_defaults(self, atlas: Optional[str]) -> Dict[str, Optional[str]]:
        servers = self._servers()
        if atlas and atlas not in servers:
            raise ValueError(f"未知 Atlas MCP Server：{atlas}")
        data = self._load()
        defaults = data.setdefault("defaults", {})
        defaults["atlas"] = atlas
        self._save(data)
        return self.defaults()

    def default_for_kind(self, kind: str) -> Optional[MCPServerConfig]:
        server_id = (self._load().get("defaults") or {}).get(kind)
        servers = self._servers()
        if server_id and server_id in servers:
            server = servers[server_id]
            return server if server.enabled else None
        for server in servers.values():
            if server.kind == kind and server.enabled:
                return server
        return None

    def test(self, server_id: str, project_path: Optional[Path] = None) -> Dict[str, Any]:
        server = self.get(server_id)
        if server is None:
            raise ValueError("MCP Server 未找到")
        project = (project_path or Path.cwd()).expanduser().resolve()
        command, cwd, env = server.command_for_project(project)
        started_at = project
        try:
            with MCPStdioClient(command, cwd, timeout=10, env=env) as client:
                tools = [tool.get("name") for tool in client.list_tools()]
            return {
                "ok": True,
                "server_id": server.id,
                "project_path": str(started_at),
                "command": command,
                "cwd": str(cwd),
                "tools": tools,
            }
        except Exception as exc:
            return {
                "ok": False,
                "server_id": server.id,
                "project_path": str(started_at),
                "command": command,
                "cwd": str(cwd),
                "error": str(exc),
            }

    def ensure_default_atlas(self) -> None:
        data = self._load()
        servers = data.setdefault("servers", [])
        for item in servers:
            if item.get("id") != "atlas-default":
                continue
            changed = False
            if item.get("args") == ["mcp", "--project", "{project}", "--log-format", "json"]:
                item["args"] = ["mcp", "--log-format", "json"]
                changed = True
            if str(item.get("description") or "").strip() in {
                "",
                "使用 atlas mcp --project {project} 启动本地 Atlas MCP Server。",
                "使用本地 atlas mcp 启动项目代码图 MCP Server。",
            }:
                item["description"] = "使用 Atlas v1.5+ MCP Focus 模式启动本地代码图 MCP Server；项目通过 cwd 或 project/open 激活。"
                changed = True
            defaults = data.setdefault("defaults", {})
            if defaults.get("atlas") is None:
                defaults["atlas"] = "atlas-default"
                changed = True
            if changed:
                self._save(data)
            return
        servers.append(
            MCPServerConfig(
                id="atlas-default",
                name="Atlas 默认 MCP",
                description="使用 Atlas v1.5+ MCP Focus 模式启动本地代码图 MCP Server；项目通过 cwd 或 project/open 激活。",
            ).private_dict()
        )
        data.setdefault("defaults", {})["atlas"] = "atlas-default"
        self._save(data)

    def _servers(self) -> Dict[str, MCPServerConfig]:
        result = {}
        for item in self._load().get("servers", []):
            server = server_from_payload(item)
            result[server.id] = server
        return result

    def _load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "defaults": {"atlas": None}, "servers": []}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        data.setdefault("version", 1)
        data.setdefault("defaults", {"atlas": None})
        data.setdefault("servers", [])
        return data

    def _save(self, data: Dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            self.path.chmod(0o600)
        except OSError:
            pass


def server_from_payload(payload: Dict[str, Any], existing: Optional[MCPServerConfig] = None) -> MCPServerConfig:
    server_id = str(payload.get("id") or "").strip()
    if not server_id:
        raise ValueError("MCP Server ID 不能为空")
    if not re.match(r"^[A-Za-z0-9_.-]+$", server_id):
        raise ValueError("MCP Server ID 只能包含字母、数字、点、下划线和连字符")
    transport = str(payload.get("transport") or MCP_TRANSPORT_STDIO).strip()
    if transport != MCP_TRANSPORT_STDIO:
        raise ValueError("当前仅支持 stdio MCP Server")
    command = str(payload.get("command") or "").strip()
    if not command:
        raise ValueError("MCP Server command 不能为空")
    return MCPServerConfig(
        id=server_id,
        name=str(payload.get("name") or server_id).strip(),
        transport=transport,
        command=command,
        args=_parse_args(payload.get("args"), existing.args if existing else []),
        cwd=str(payload.get("cwd") or (existing.cwd if existing else "{project}")).strip() or None,
        env=_parse_env(payload.get("env"), existing.env if existing else {}),
        enabled=bool(payload.get("enabled", existing.enabled if existing else True)),
        kind=str(payload.get("kind") or (existing.kind if existing else "atlas")).strip() or "generic",
        description=str(payload.get("description") or "").strip(),
    )


def _parse_args(value: Any, fallback: List[str]) -> List[str]:
    if value is None:
        return list(fallback)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            parsed = [item for item in value.split() if item]
    else:
        parsed = value
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        raise ValueError("MCP Server args 必须是字符串数组")
    return parsed


def _parse_env(value: Any, fallback: Dict[str, str]) -> Dict[str, str]:
    if value is None:
        return dict(fallback)
    if isinstance(value, str):
        if not value.strip():
            return {}
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"MCP Server env 不是合法 JSON：{exc}") from exc
    else:
        parsed = value
    if not isinstance(parsed, dict):
        raise ValueError("MCP Server env 必须是 JSON 对象")
    result = {}
    for key, val in parsed.items():
        text_key = str(key)
        text_val = str(val)
        if text_val == "********" and text_key in fallback:
            result[text_key] = fallback[text_key]
        else:
            result[text_key] = text_val
    return result


def _render(value: str, variables: Dict[str, str]) -> str:
    rendered = str(value)
    for key, replacement in variables.items():
        rendered = rendered.replace("{" + key + "}", replacement)
    return rendered


def _masked_env(env: Dict[str, str]) -> Dict[str, str]:
    result = {}
    for key, value in env.items():
        lowered = key.lower()
        if any(marker in lowered for marker in ("key", "token", "secret", "password")):
            result[key] = "********"
        else:
            result[key] = value
    return result


def merged_env(extra: Dict[str, str]) -> Dict[str, str]:
    env = dict(os.environ)
    env.update(extra)
    return env
