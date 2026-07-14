from __future__ import annotations

import json
from typing import Any, Dict, List


def format_codex_ndjson(value: str) -> str:
    """Render `codex exec --json` events as a readable execution transcript."""

    rendered: List[str] = []
    for raw_line in str(value or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            rendered.append(raw_line)
            continue
        if not isinstance(event, dict):
            rendered.append(_json_text(event))
            continue
        text = _format_event(event)
        if text:
            rendered.append(text)
    return "\n\n".join(rendered) + ("\n" if rendered else "")


def _format_event(event: Dict[str, Any]) -> str:
    event_type = str(event.get("type") or "").strip()
    if event_type == "thread.started":
        thread_id = _first_text(event, "thread_id", "threadID", "id")
        return _section("会话", thread_id or "已启动")
    if event_type == "turn.started":
        return _section("任务", "开始")
    if event_type == "turn.completed":
        usage = _format_usage(event.get("usage"))
        return _section("任务", f"完成{f' · {usage}' if usage else ''}")
    if event_type in {"turn.failed", "error"}:
        detail = _error_text(event.get("error")) or _first_text(event, "message") or _json_text(event)
        return _section("错误", detail)
    if event_type.startswith("item."):
        item = event.get("item")
        if isinstance(item, dict):
            phase = event_type.split(".", 1)[1]
            return _format_item(item, phase)
    return _json_text(event)


def _format_item(item: Dict[str, Any], phase: str) -> str:
    item_type = str(item.get("type") or "").strip()
    phase_label = {"started": "开始", "completed": "完成", "updated": "更新"}.get(phase, phase)

    if item_type == "agent_message":
        return _section("Codex", _content_text(item) or _json_text(item))
    if item_type == "reasoning":
        return _section("分析", _content_text(item) or _json_text(item))
    if item_type == "command_execution":
        command = _command_text(item.get("command")) or "命令"
        details = [f"$ {command}"]
        output = _first_text(item, "aggregated_output", "output")
        if output:
            details.append(output.rstrip())
        status = _first_text(item, "status")
        exit_code = item.get("exit_code")
        if exit_code is None:
            exit_code = item.get("exitCode")
        outcome = []
        if status:
            outcome.append(status)
        if exit_code is not None:
            outcome.append(f"exit {exit_code}")
        if outcome:
            details.append(f"[{', '.join(outcome)}]")
        return _section(f"命令{phase_label}", "\n".join(details))
    if item_type == "file_change":
        changes = _format_file_changes(item.get("changes"))
        return _section(f"文件修改{phase_label}", changes or _json_text(item))
    if item_type == "mcp_tool_call":
        server = _first_text(item, "server", "server_name")
        tool = _first_text(item, "tool", "tool_name")
        title = "/".join(part for part in (server, tool) if part) or "MCP"
        details = []
        if "arguments" in item:
            details.append(f"参数\n{_value_text(item['arguments'])}")
        if "result" in item:
            details.append(f"结果\n{_value_text(item['result'])}")
        error = _error_text(item.get("error"))
        if error:
            details.append(f"错误\n{error}")
        return _section(f"工具{phase_label} · {title}", "\n\n".join(details) or _json_text(item))
    if item_type == "web_search":
        query = _first_text(item, "query") or _content_text(item) or _json_text(item)
        return _section(f"搜索{phase_label}", query)
    if item_type == "todo_list":
        return _section("任务清单", _format_todos(item.get("items")) or _json_text(item))
    if item_type == "error":
        detail = _error_text(item.get("error")) or _first_text(item, "message") or _json_text(item)
        return _section("错误", detail)
    return _section(f"事件 · {item_type or 'unknown'} · {phase_label}", _json_text(item))


def _content_text(item: Dict[str, Any]) -> str:
    text = _first_text(item, "text", "message")
    if text:
        return text
    content = item.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for entry in content:
            if isinstance(entry, str):
                parts.append(entry)
            elif isinstance(entry, dict):
                entry_text = _first_text(entry, "text", "content")
                if entry_text:
                    parts.append(entry_text)
        return "\n".join(parts)
    return ""


def _format_usage(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    labels = (
        ("input_tokens", "输入"),
        ("cached_input_tokens", "缓存"),
        ("output_tokens", "输出"),
    )
    parts = [f"{label} {value[key]} tokens" for key, label in labels if value.get(key) is not None]
    return " · ".join(parts)


def _format_file_changes(value: Any) -> str:
    if not isinstance(value, list):
        return ""
    rows = []
    for change in value:
        if not isinstance(change, dict):
            rows.append(_value_text(change))
            continue
        path = _first_text(change, "path", "file_path", "filePath")
        kind = _first_text(change, "kind", "type", "status")
        rows.append(" · ".join(part for part in (kind, path) if part) or _json_text(change))
    return "\n".join(rows)


def _format_todos(value: Any) -> str:
    if not isinstance(value, list):
        return ""
    rows = []
    for todo in value:
        if not isinstance(todo, dict):
            rows.append(f"- {_value_text(todo)}")
            continue
        completed = bool(todo.get("completed")) or str(todo.get("status") or "") == "completed"
        text = _first_text(todo, "text", "title", "description") or _json_text(todo)
        rows.append(f"[{'x' if completed else ' '}] {text}")
    return "\n".join(rows)


def _command_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(str(part) for part in value)
    return ""


def _error_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return _first_text(value, "message", "detail") or _json_text(value)
    return ""


def _first_text(values: Dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = values.get(key)
        if value is not None and not isinstance(value, (dict, list)):
            text = str(value).strip()
            if text:
                return text
    return ""


def _value_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return _json_text(value)


def _section(label: str, body: str) -> str:
    return f"[{label}]\n{body}" if body else f"[{label}]"


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
