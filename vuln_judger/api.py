from __future__ import annotations

import gzip
import json
import subprocess
from datetime import datetime, timezone
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Lock, Thread
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse
from uuid import uuid4

from .agents import DEFAULT_AGENTS_DIR, AgentDirectoryStore
from .codex_runner import (
    CLI_ENGINES,
    CODEX_ENGINE,
    OPENCODE_ENGINE,
    CodexDrivenRunner,
    CodexRunnerError,
    CodexRunnerStopped,
    _findings_from_persisted,
    _normalized_findings_payload,
    attach_session_websocket,
    capture_session,
    send_session_input,
    session_live,
    stop_sessions,
)
from .codex_event_log import format_codex_ndjson
from .evidence_graph import build_evidence_graph, graph_to_markdown
from .llm import test_provider_connection
from .logging_config import DEFAULT_LOG_FILE, DEFAULT_LOG_RETENTION_DAYS, configure_logging, logger
from .mcp_config import DEFAULT_MCP_SERVERS_FILE, MCPServerStore
from .models import DEFAULT_SILENCE_REMINDER_MINUTES, AgentConfig, RunConfig, run_config_snapshot, to_jsonable
from .opencode_runner import (
    OpenCodeDrivenRunner,
    ensure_opencode_tui,
    send_opencode_session_message,
)
from .pipeline import RunStopped, run_judgement
from .providers import DEFAULT_PROVIDERS_FILE, ProviderStore
from .records import RunControlStore, RunRecordStore, normalize_run_origin
from .run_state import (
    FINDING_COMPLETED,
    completed_finding_count,
    finding_report_status,
    first_incomplete_finding_index,
    mark_incomplete_findings_pending,
)
from .skills import DEFAULT_SKILLS_FILE, SkillSourceStore


DEFAULT_RECORDS_DIR = Path(".vuln-judger") / "runs"
STATIC_DIR = Path(__file__).resolve().parent / "static"
RUN_ORIGIN_WEB = "web"
RESUMABLE_RUN_STATUSES = {"paused", "failed"}
MANUAL_REVIEW_DECISIONS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "INCONCLUSIVE"}
MANUAL_REVIEW_EVIDENCE_MAX_LENGTH = 50_000
LOG = logger("api")
PROMPT_ECHO_MARKERS = (
    "AGENT.md",
    "Agent 配置",
    "角色配置",
    "角色名称",
    "正方 Agent",
    "反方 Agent",
    "提示词",
    "用户要求",
    "用户请求",
    "分析用户请求",
    "理解目标",
    "分析输入",
    "用户希望我担任",
    "反方质疑摘要",
    "任务要求",
    "格式要求",
    "方向：",
    "约束：",
    "结论标签固定",
    "标签约束",
    "强约束",
    "分析请求",
    "必须遵守",
    "禁止编造",
    "每个具体论断",
    "输出必须",
    "只输出",
    "只返回",
    "证据解释约束",
)


def serve(
    host: str = "127.0.0.1",
    port: int = 8765,
    records_dir: Path = DEFAULT_RECORDS_DIR,
    providers_file: Path = DEFAULT_PROVIDERS_FILE,
    agents_dir: Path = DEFAULT_AGENTS_DIR,
    log_file: Path = DEFAULT_LOG_FILE,
    mcp_servers_file: Path = DEFAULT_MCP_SERVERS_FILE,
    skills_file: Path = DEFAULT_SKILLS_FILE,
    log_retention_days: int = DEFAULT_LOG_RETENTION_DAYS,
) -> None:
    configured_log = configure_logging(log_file, retention_days=log_retention_days)
    store = RunRecordStore(records_dir)
    provider_store = ProviderStore(providers_file)
    agent_store = AgentDirectoryStore(agents_dir)
    mcp_store = MCPServerStore(mcp_servers_file)
    mcp_store.ensure_default_atlas()
    skill_store = SkillSourceStore(skills_file)
    server = ThreadingHTTPServer((host, port), make_handler(store, provider_store, agent_store, mcp_store, skill_store))
    print(f"vuln-judger Web 界面监听：http://{host}:{port}")
    print(f"运行记录目录：{store.root}")
    print(f"提供商配置文件：{provider_store.path}")
    print(f"Agent 配置目录：{agent_store.root}")
    print(f"MCP Server 配置文件：{mcp_store.path}")
    print(f"Skill Source 配置文件：{skill_store.path}")
    print(f"日志文件：{configured_log}")
    LOG.info(
        "API 服务启动",
        extra={
            "event": "api.start",
            "host": host,
            "port": port,
            "records_dir": str(store.root),
            "providers_file": str(provider_store.path),
            "agents_dir": str(agent_store.root),
            "mcp_file": str(mcp_store.path),
            "skills_file": str(skill_store.path),
            "log_file": str(configured_log),
            "log_retention_days": log_retention_days,
        },
    )
    server.serve_forever()


def make_handler(
    store: RunRecordStore,
    provider_store: Optional[ProviderStore] = None,
    agent_store: Optional[AgentDirectoryStore] = None,
    mcp_store: Optional[MCPServerStore] = None,
    skill_store: Optional[SkillSourceStore] = None,
):
    provider_store = provider_store or ProviderStore(store.root.parent / "providers.json")
    agent_store = agent_store or AgentDirectoryStore(DEFAULT_AGENTS_DIR)
    mcp_store = mcp_store or MCPServerStore(store.root.parent / "mcp.json")
    mcp_store.ensure_default_atlas()
    skill_store = skill_store or SkillSourceStore(store.root.parent / "skills.json")
    control_store = RunControlStore(store.root)
    recovered = store.recover_unfinished()
    if recovered:
        LOG.info("恢复未完成运行记录 count=%s ids=%s", len(recovered), ",".join(str(item.get("run_id")) for item in recovered))
    tasks = {}
    stop_events = {}
    pause_events = {}
    tasks_lock = Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "vuln-judger/0.1"

        def do_PUT(self) -> None:  # noqa: N802
            parts = _parts(self.path)
            try:
                if len(parts) == 5 and parts[0] == "runs" and parts[2] == "findings" and parts[4] == "manual-review":
                    run_id = parts[1]
                    finding_id = parts[3]
                    persisted = store.get(run_id)
                    task = _get_task(tasks, tasks_lock, run_id)
                    effective = _merge_manual_reviews(task, persisted) if task is not None else persisted
                    if effective is None:
                        self._json({"error": "运行记录未找到"}, HTTPStatus.NOT_FOUND)
                        return
                    if not _finding_exists(effective, finding_id):
                        self._json({"error": "发现未找到"}, HTTPStatus.NOT_FOUND)
                        return
                    decision, evidence = _validated_manual_review_payload(self._read_json())
                    saved = store.update_manual_review(
                        run_id,
                        finding_id,
                        decision=decision,
                        evidence=evidence,
                    )
                    if saved is None:
                        self._json({"error": "运行记录未找到"}, HTTPStatus.NOT_FOUND)
                        return
                    review, created = saved
                    LOG.info(
                        "保存人工复核 run_id=%s finding_id=%s decision=%s created=%s",
                        run_id,
                        finding_id,
                        decision,
                        created,
                    )
                    self._json(
                        {"run_id": run_id, "finding_id": finding_id, "created": created, "manual_review": review},
                        HTTPStatus.CREATED if created else HTTPStatus.OK,
                    )
                    return
                self._json({"error": "未找到"}, HTTPStatus.NOT_FOUND)
            except Exception as exc:
                LOG.exception("PUT 处理失败 path=%s", self.path)
                self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

        def do_POST(self) -> None:  # noqa: N802
            parts = _parts(self.path)
            try:
                if parts == ["runs"]:
                    payload = self._read_json()
                    run_id = _new_run_id()
                    LOG.info(
                        "收到创建任务请求",
                        extra={
                            "event": "run.create",
                            "run_id": run_id,
                            "engine": str(payload.get("engine") or "builtin"),
                            "payload": _safe_payload(payload),
                        },
                    )
                    config = _config_from_payload(payload, provider_store.path, run_id, agent_store, mcp_store.path, skill_store)
                    _apply_reused_findings(config, store, tasks, tasks_lock)
                    task = _task_from_config(config, run_id, "running")
                    stop_event = Event()
                    pause_event = Event()
                    control_owner_id = control_store.claim(run_id, origin=RUN_ORIGIN_WEB)
                    if control_owner_id is None:
                        raise RuntimeError(f"任务 {run_id} 已被其他 worker 占用")
                    worker = Thread(
                        target=_run_task,
                        args=(
                            config,
                            store,
                            tasks,
                            stop_events,
                            pause_events,
                            tasks_lock,
                            stop_event,
                            pause_event,
                            control_store,
                            control_owner_id,
                            RUN_ORIGIN_WEB,
                        ),
                        daemon=True,
                    )
                    try:
                        store.save_payload(task)
                        with tasks_lock:
                            tasks[run_id] = task
                            stop_events[run_id] = stop_event
                            pause_events[run_id] = pause_event
                        worker.start()
                    except Exception:
                        with tasks_lock:
                            tasks.pop(run_id, None)
                            stop_events.pop(run_id, None)
                            pause_events.pop(run_id, None)
                        control_store.release(run_id, control_owner_id)
                        store.delete(run_id)
                        raise
                    self._json(
                        {
                            "run_id": run_id,
                            "status": "running",
                            "finding_count": 0,
                            "created_at": task["created_at"],
                        },
                        HTTPStatus.CREATED,
                    )
                    return
                if len(parts) == 3 and parts[0] == "runs" and parts[2] == "stop":
                    result = _request_stop(
                        tasks,
                        stop_events,
                        tasks_lock,
                        parts[1],
                        store=store,
                        control_store=control_store,
                    )
                    if result is None:
                        self._json({"error": "运行任务未找到或已结束"}, HTTPStatus.NOT_FOUND)
                    else:
                        LOG.info(
                            "收到停止任务请求",
                            extra={"event": "run.stop", "run_id": parts[1], "status": result.get("status")},
                        )
                        self._json(result)
                    return
                if len(parts) == 3 and parts[0] == "runs" and parts[2] == "pause":
                    result = _request_pause(
                        tasks,
                        pause_events,
                        tasks_lock,
                        parts[1],
                        store=store,
                        control_store=control_store,
                    )
                    if result is None:
                        self._json({"error": "运行任务未找到或已结束"}, HTTPStatus.NOT_FOUND)
                    else:
                        LOG.info(
                            "收到暂停任务请求",
                            extra={"event": "run.pause", "run_id": parts[1], "status": result.get("status")},
                        )
                        self._json(result)
                    return
                if len(parts) == 3 and parts[0] == "runs" and parts[2] == "resume":
                    result = _request_resume(
                        store,
                        tasks,
                        stop_events,
                        pause_events,
                        tasks_lock,
                        parts[1],
                        provider_store.path,
                        agent_store,
                        mcp_store.path,
                        skill_store,
                        control_store,
                    )
                    if result is None:
                        self._json({"error": "暂停或失败任务未找到，或当前状态不允许恢复"}, HTTPStatus.NOT_FOUND)
                    else:
                        LOG.info(
                            "收到恢复任务请求",
                            extra={"event": "run.resume", "run_id": parts[1], "status": result.get("status")},
                        )
                        self._json(result)
                    return
                if len(parts) == 4 and parts[0] == "runs" and parts[2] in {"cli-sessions", "codex-sessions"} and parts[3] == "stop":
                    result = _stop_cli_sessions(store, tasks, tasks_lock, parts[1])
                    if result is None:
                        self._json({"error": "运行记录未找到"}, HTTPStatus.NOT_FOUND)
                    else:
                        LOG.info(
                            "收到关闭 CLI sessions 请求",
                            extra={
                                "event": "cli.sessions.stop",
                                "run_id": parts[1],
                                "stopped": result.get("stopped"),
                            },
                        )
                        self._json(result)
                    return
                if len(parts) == 5 and parts[0] == "runs" and parts[2] in {"cli-sessions", "codex-sessions"} and parts[4] == "input":
                    payload = self._read_json()
                    result = _send_codex_session_input(store, tasks, tasks_lock, parts[1], parts[3], str(payload.get("message") or ""))
                    if result is None:
                        self._json({"error": "CLI session 未找到"}, HTTPStatus.NOT_FOUND)
                    else:
                        self._json(result)
                    return
                if parts == ["providers"]:
                    self._json(provider_store.upsert(self._read_json()), HTTPStatus.CREATED)
                    return
                if parts == ["providers", "defaults"]:
                    payload = self._read_json()
                    self._json(
                        provider_store.set_defaults(
                            payload.get("affirmative"),
                            payload.get("negative"),
                            payload.get("moderator"),
                        )
                    )
                    return
                if parts == ["agent-prompts", "agents-md"]:
                    self._json(agent_store.upsert_agents_config(self._read_json()), HTTPStatus.CREATED)
                    return
                if parts == ["agent-prompts", "agents-md", "default"]:
                    payload = self._read_json()
                    self._json(agent_store.set_default_agents_config(payload.get("id")))
                    return
                if parts == ["agent-prompts"]:
                    payload = self._read_json()
                    if payload.get("reset"):
                        agent_store.ensure_defaults()
                        self._json(agent_store.summary())
                    elif payload.get("action") == "star":
                        self._json(
                            to_jsonable(
                                agent_store.set_starred(
                                    payload.get("role"),
                                    payload.get("profile_id"),
                                    bool(payload.get("starred")),
                                )
                            )
                        )
                    else:
                        role = payload.get("role")
                        profile_id = payload.get("profile_id")
                        instructions = payload.get("instructions")
                        self._json(to_jsonable(agent_store.save_profile(role, profile_id, instructions)), HTTPStatus.CREATED)
                    return
                if parts == ["mcp-servers"]:
                    self._json(mcp_store.upsert(self._read_json()), HTTPStatus.CREATED)
                    return
                if parts == ["mcp-servers", "defaults"]:
                    payload = self._read_json()
                    self._json(mcp_store.set_defaults(payload.get("atlas")))
                    return
                if len(parts) == 3 and parts[0] == "mcp-servers" and parts[2] == "test":
                    payload = self._read_json()
                    project_path = Path(payload["project_path"]) if payload.get("project_path") else None
                    result = mcp_store.test(parts[1], project_path)
                    self._json(result, HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST)
                    return
                if parts == ["skill-sources"]:
                    self._json(skill_store.upsert(self._read_json()), HTTPStatus.CREATED)
                    return
                if parts == ["skill-sources", "defaults"]:
                    payload = self._read_json()
                    self._json(skill_store.set_defaults(payload.get("project")))
                    return
                if len(parts) == 3 and parts[0] == "skill-sources" and parts[2] == "test":
                    result = skill_store.test(parts[1])
                    self._json(result, HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST)
                    return
                if len(parts) == 3 and parts[0] == "providers" and parts[2] == "test":
                    provider = provider_store.get(parts[1])
                    if provider is None:
                        self._json({"error": "提供商未找到"}, HTTPStatus.NOT_FOUND)
                        return
                    payload = self._read_json()
                    LOG.info("Provider 连通性测试 provider=%s override_key=%s", parts[1], bool(payload.get("api_key")))
                    result = test_provider_connection(provider, api_key_override=payload.get("api_key"))
                    result.pop("content", None)
                    self._json(result, HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST)
                    return
                self._json({"error": "未找到"}, HTTPStatus.NOT_FOUND)
            except Exception as exc:
                LOG.exception("POST 处理失败 path=%s", self.path)
                self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

        def do_DELETE(self) -> None:  # noqa: N802
            parts = _parts(self.path)
            if len(parts) == 3 and parts[:2] == ["agent-prompts", "agents-md"]:
                try:
                    self._json(agent_store.delete_agents_config(parts[2]))
                except Exception as exc:
                    LOG.exception("删除 AGENTS.md 配置失败 id=%s", parts[2])
                    self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return
            if len(parts) == 5 and parts[0] == "runs" and parts[2] == "findings" and parts[4] == "manual-review":
                run_id = parts[1]
                finding_id = parts[3]
                persisted = store.get(run_id)
                task = _get_task(tasks, tasks_lock, run_id)
                effective = _merge_manual_reviews(task, persisted) if task is not None else persisted
                if effective is None:
                    self._json({"error": "运行记录未找到"}, HTTPStatus.NOT_FOUND)
                    return
                if not _finding_exists(effective, finding_id):
                    self._json({"error": "发现未找到"}, HTTPStatus.NOT_FOUND)
                    return
                deleted = bool(store.delete_manual_review(run_id, finding_id))
                self._json({"deleted": deleted, "run_id": run_id, "finding_id": finding_id})
                return
            if len(parts) == 2 and parts[0] == "runs":
                deleted_record = store.delete(parts[1])
                deleted_task = _delete_task(tasks, tasks_lock, parts[1])
                if deleted_record or deleted_task:
                    LOG.info("删除运行记录 run_id=%s record=%s task=%s", parts[1], deleted_record, deleted_task)
                    self._json({"deleted": True, "run_id": parts[1]})
                else:
                    self._json({"error": "运行记录未找到"}, HTTPStatus.NOT_FOUND)
                return
            if len(parts) == 3 and parts[0] == "agent-prompts":
                try:
                    self._json(agent_store.delete_profile(parts[1], parts[2]))
                except Exception as exc:
                    LOG.exception("删除 Agent 配置失败 role=%s profile=%s", parts[1], parts[2])
                    self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return
            if len(parts) == 2 and parts[0] == "providers":
                if provider_store.delete(parts[1]):
                    self._json({"deleted": True})
                else:
                    self._json({"error": "提供商未找到"}, HTTPStatus.NOT_FOUND)
                return
            if len(parts) == 2 and parts[0] == "mcp-servers":
                if mcp_store.delete(parts[1]):
                    self._json({"deleted": True})
                else:
                    self._json({"error": "MCP Server 未找到"}, HTTPStatus.NOT_FOUND)
                return
            if len(parts) == 2 and parts[0] == "skill-sources":
                if skill_store.delete(parts[1]):
                    self._json({"deleted": True})
                else:
                    self._json({"error": "Skill Source 未找到"}, HTTPStatus.NOT_FOUND)
                return
            self._json({"error": "未找到"}, HTTPStatus.NOT_FOUND)

        def do_GET(self) -> None:  # noqa: N802
            parts = _parts(self.path)
            if not parts or parts == ["ui"]:
                self._html(app_html())
                return
            if parts and parts[0] == "static":
                self._static(parts[1:])
                return
            if parts == ["healthz"]:
                self._json({"ok": True})
                return
            if parts == ["providers"]:
                self._json(provider_store.list())
                return
            if parts == ["providers", "defaults"]:
                self._json(provider_store.defaults())
                return
            if parts == ["agent-prompts"]:
                self._json(agent_store.summary())
                return
            if parts == ["agent-prompts", "agents-md"]:
                self._json(agent_store.agents_configs_summary())
                return
            if parts == ["agent-prompts", "defaults"]:
                self._json(agent_store.defaults())
                return
            if parts == ["mcp-servers"]:
                self._json(mcp_store.list())
                return
            if parts == ["mcp-servers", "defaults"]:
                self._json(mcp_store.defaults())
                return
            if len(parts) == 2 and parts[0] == "mcp-servers":
                server = mcp_store.get(parts[1])
                if server is None:
                    self._json({"error": "MCP Server 未找到"}, HTTPStatus.NOT_FOUND)
                    return
                self._json(server.public_dict())
                return
            if parts == ["skill-sources"]:
                self._json(skill_store.list())
                return
            if parts == ["skill-sources", "defaults"]:
                self._json(skill_store.defaults())
                return
            if len(parts) == 2 and parts[0] == "skill-sources":
                source = skill_store.get(parts[1])
                if source is None:
                    self._json({"error": "Skill Source 未找到"}, HTTPStatus.NOT_FOUND)
                    return
                self._json(source.public_dict())
                return
            if len(parts) == 2 and parts[0] == "providers":
                provider = provider_store.get(parts[1])
                if provider is None:
                    self._json({"error": "提供商未找到"}, HTTPStatus.NOT_FOUND)
                    return
                self._json(provider.public_dict())
                return
            if parts == ["runs"]:
                self._json(_list_runs(store, tasks, tasks_lock))
                return
            if len(parts) >= 2 and parts[0] == "runs":
                if len(parts) == 3 and parts[2] == "status":
                    task = _get_task(tasks, tasks_lock, parts[1])
                    payload = task if task is not None else store.get(parts[1])
                    if payload is None:
                        self._json({"error": "运行记录未找到"}, HTTPStatus.NOT_FOUND)
                        return
                    self._json(
                        {
                            "run_id": parts[1],
                            "status": payload.get("status", "completed"),
                            "revision": store.revision(parts[1]),
                        }
                    )
                    return
                run = store.get(parts[1])
                task = _get_task(tasks, tasks_lock, parts[1])
                if task is not None:
                    task = _merge_manual_reviews(task, run)
                active_task = task if task is not None and task.get("status") != "completed" else None
                terminal_payload = active_task if active_task is not None else run if run is not None else task
                if len(parts) == 5 and parts[2] in {"cli-sessions", "codex-sessions"} and parts[4] in {"terminal-ui", "ws"}:
                    if terminal_payload is None:
                        self._json({"error": "运行记录未找到"}, HTTPStatus.NOT_FOUND)
                        return
                    session = _codex_session_for_role(terminal_payload, parts[3])
                    if session is None:
                        self._json({"error": "CLI session 未找到"}, HTTPStatus.NOT_FOUND)
                        return
                    session = dict(session)
                    backend = str(session.get("backend") or terminal_payload.get("engine") or "")
                    if backend == OPENCODE_ENGINE:
                        try:
                            session["target"] = ensure_opencode_tui(session)
                        except CodexRunnerError as exc:
                            self._json({"error": str(exc)}, HTTPStatus.CONFLICT)
                            return
                        session["window_name"] = "tui"
                    target = str(session.get("target") or session.get("session_name") or "")
                    if parts[4] == "terminal-ui":
                        self._html(_codex_terminal_page(parts[1], parts[3], session))
                        return
                    accepts_input = _cli_session_accepts_input(terminal_payload, session)
                    if backend == CODEX_ENGINE and not accepts_input:
                        self._json(
                            {"error": "Codex 使用持久化执行日志，不提供 tmux WebSocket"},
                            HTTPStatus.CONFLICT,
                        )
                        return
                    attach_session_websocket(
                        self,
                        target,
                        read_only=backend == OPENCODE_ENGINE,
                    )
                    return
                if len(parts) == 3 and parts[2] == "export":
                    payload = active_task if active_task is not None else run if run is not None else task
                    if payload is None:
                        self._json({"error": "运行记录未找到"}, HTTPStatus.NOT_FOUND)
                        return
                    fmt = _query_value(self.path, "format", "markdown").lower()
                    if fmt in {"json", "JSON"}:
                        raw = json.dumps(to_jsonable(payload), ensure_ascii=False, indent=2).encode("utf-8")
                        self._download(raw, "application/json; charset=utf-8", f"{parts[1]}.json")
                    else:
                        raw = _export_run_markdown(payload).encode("utf-8")
                        self._download(raw, "text/markdown; charset=utf-8", f"{parts[1]}.md")
                    return
                if active_task is not None:
                    if len(parts) == 2:
                        self._json(_run_detail(active_task, revision=store.revision(parts[1])))
                        return
                    if len(parts) == 3 and parts[2] == "findings":
                        self._json([_finding_summary(report, _manual_review_for(active_task, report.get("finding_id"))) for report in active_task.get("reports", [])])
                        return
                    if len(parts) == 4 and parts[2] == "findings":
                        for report in active_task.get("reports", []):
                            if report.get("finding_id") == parts[3]:
                                self._json(_finding_detail(report, active_task, revision=store.revision(parts[1])))
                                return
                        self._json({"error": "发现尚未生成或未找到"}, HTTPStatus.NOT_FOUND)
                        return
                    if len(parts) == 3 and parts[2] in {"cli-sessions", "codex-sessions"}:
                        self._json(_cli_sessions(active_task))
                        return
                    if len(parts) == 5 and parts[2] in {"cli-sessions", "codex-sessions"} and parts[4] == "terminal":
                        self._json(_cli_session_terminal(active_task, parts[3]))
                        return
                if run is None:
                    if task is None:
                        self._json({"error": "运行记录未找到"}, HTTPStatus.NOT_FOUND)
                        return
                    if len(parts) == 2:
                        self._json(_run_detail(task, revision=store.revision(parts[1])))
                        return
                    if len(parts) == 3 and parts[2] == "findings":
                        self._json([_finding_summary(report, _manual_review_for(task, report.get("finding_id"))) for report in task.get("reports", [])])
                        return
                    if len(parts) == 4 and parts[2] == "findings":
                        for report in task.get("reports", []):
                            if report.get("finding_id") == parts[3]:
                                self._json(_finding_detail(report, task, revision=store.revision(parts[1])))
                                return
                        self._json({"error": "发现尚未生成或未找到"}, HTTPStatus.NOT_FOUND)
                        return
                    self._json({"error": "运行尚未完成"}, HTTPStatus.BAD_REQUEST)
                    return
                if len(parts) == 2:
                    self._json(_run_detail(run, revision=store.revision(parts[1])))
                    return
                if len(parts) == 3 and parts[2] in {"cli-sessions", "codex-sessions"}:
                    self._json(_cli_sessions(run))
                    return
                if len(parts) == 5 and parts[2] in {"cli-sessions", "codex-sessions"} and parts[4] == "terminal":
                    self._json(_cli_session_terminal(run, parts[3]))
                    return
                if len(parts) == 3 and parts[2] == "findings":
                    self._json([_finding_summary(report, _manual_review_for(run, report.get("finding_id"))) for report in run.get("reports", [])])
                    return
                if len(parts) == 4 and parts[2] == "findings":
                    for report in run.get("reports", []):
                        if report.get("finding_id") == parts[3]:
                            self._json(_finding_detail(report, run, revision=store.revision(parts[1])))
                            return
                    self._json({"error": "发现未找到"}, HTTPStatus.NOT_FOUND)
                    return
            self._json({"error": "未找到"}, HTTPStatus.NOT_FOUND)

        def log_message(self, format: str, *args) -> None:  # noqa: A002
            return

        def _read_json(self):
            length = int(self.headers.get("content-length") or 0)
            body = self.rfile.read(length).decode("utf-8")
            return json.loads(body or "{}")

        def _json(self, payload, status: HTTPStatus = HTTPStatus.OK) -> None:
            raw = json.dumps(to_jsonable(payload), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            use_gzip = "gzip" in str(self.headers.get("accept-encoding") or "").lower() and len(raw) >= 1024
            if use_gzip:
                raw = gzip.compress(raw, compresslevel=5)
            self.send_response(status)
            self.send_header("content-type", "application/json; charset=utf-8")
            self.send_header("cache-control", "no-store")
            if use_gzip:
                self.send_header("content-encoding", "gzip")
                self.send_header("vary", "Accept-Encoding")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _html(self, html: str, status: HTTPStatus = HTTPStatus.OK) -> None:
            raw = html.encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("cache-control", "no-store")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _download(self, raw: bytes, content_type: str, filename: str, status: HTTPStatus = HTTPStatus.OK) -> None:
            self.send_response(status)
            self.send_header("content-type", content_type)
            self.send_header("cache-control", "no-store")
            self.send_header("content-disposition", f'attachment; filename="{filename}"')
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _static(self, parts: list[str]) -> None:
            if not parts:
                self._json({"error": "静态资源未找到"}, HTTPStatus.NOT_FOUND)
                return
            root = STATIC_DIR.resolve()
            candidate = (root / Path(*parts)).resolve()
            if root not in candidate.parents or not candidate.is_file():
                self._json({"error": "静态资源未找到"}, HTTPStatus.NOT_FOUND)
                return
            suffix = candidate.suffix.lower()
            content_type = {
                ".css": "text/css; charset=utf-8",
                ".js": "application/javascript; charset=utf-8",
                ".txt": "text/plain; charset=utf-8",
            }.get(suffix, "application/octet-stream")
            raw = candidate.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("content-type", content_type)
            self.send_header("cache-control", "public, max-age=3600")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    return Handler


def _parts(path: str) -> list[str]:
    return [unquote(part) for part in urlparse(path).path.strip("/").split("/") if part]


def _query_value(path: str, key: str, default: str = "") -> str:
    values = parse_qs(urlparse(path).query).get(key)
    return values[0] if values else default


def _config_from_payload(
    payload,
    providers_file: Path,
    run_id: Optional[str] = None,
    agent_store: Optional[AgentDirectoryStore] = None,
    mcp_servers_file: Optional[Path] = None,
    skill_store: Optional[SkillSourceStore] = None,
) -> RunConfig:
    skills_path: Optional[Path] = Path(payload["skills_path"]) if payload.get("skills_path") else None
    skill_source_id = payload.get("skill_source_id")
    if skills_path is None and skill_source_id and skill_store is not None:
        skill_source = skill_store.get(skill_source_id)
        if skill_source is None:
            raise ValueError(f"未知 Skill Source：{skill_source_id}")
        skills_path = Path(skill_source.path)
    report_path = payload.get("sarif_path") or payload.get("report_path")
    if not report_path:
        raise ValueError("report_path 或 sarif_path 不能为空")
    engine = str(payload.get("engine") or "builtin").strip().lower() or "builtin"
    if engine not in {*CLI_ENGINES, "builtin"}:
        raise ValueError(f"不支持的执行引擎：{engine}")
    cli_engine = engine in CLI_ENGINES
    agents_config_id = str(payload.get("agents_config_id") or "").strip() or None
    agents_config_path = str(payload.get("agents_config_path") or "").strip() or None
    if "agents_instructions" in payload:
        agents_instructions = str(payload.get("agents_instructions") or "").strip()
    elif agent_store is not None:
        agents_config = agent_store.default_agents_config()
        agents_config_id = str(agents_config.get("id") or "").strip() or None
        agents_config_path = str(agents_config.get("resolved_path") or "").strip() or None
        agents_instructions = str(agents_config.get("instructions") or "")
    else:
        agents_instructions = ""
    affirmative_agent = None
    negative_agent = None
    moderator_agent = None
    if cli_engine:
        if agent_store is not None:
            affirmative_agent = agent_store.agent("affirmative", payload.get("affirmative_agent_profile"))
            negative_agent = agent_store.agent("negative", payload.get("negative_agent_profile"))
            moderator_agent = agent_store.agent("moderator", payload.get("moderator_agent_profile"))
    else:
        affirmative_agent = _agent_config_from_payload(payload, "affirmative")
        negative_agent = _agent_config_from_payload(payload, "negative")
        moderator_agent = _agent_config_from_payload(payload, "moderator")
        if agent_store is not None:
            if affirmative_agent is None:
                affirmative_agent = agent_store.agent("affirmative", payload.get("affirmative_agent_profile"))
            if negative_agent is None:
                negative_agent = agent_store.agent("negative", payload.get("negative_agent_profile"))
            if moderator_agent is None:
                moderator_agent = agent_store.agent("moderator", payload.get("moderator_agent_profile"))
    return RunConfig(
        sarif_path=Path(report_path),
        source_path=Path(payload["source_path"]),
        engine=engine,
        skills_path=skills_path,
        providers_file=providers_file,
        mcp_servers_file=None if cli_engine else mcp_servers_file,
        run_id=run_id,
        max_rounds=int(payload.get("max_rounds") or 4),
        silence_reminder_minutes=_bounded_int(
            payload.get("silence_reminder_minutes"),
            default=DEFAULT_SILENCE_REMINDER_MINUTES,
            minimum=1,
            maximum=1440,
        ),
        auto_index_tools=False if cli_engine else bool(payload.get("auto_index_tools") or False),
        enable_external_tools=True if cli_engine else bool(payload.get("enable_external_tools", True)),
        enable_llm=False if cli_engine else bool(payload.get("enable_llm", False)),
        llm_model=payload.get("llm_model") if engine == OPENCODE_ENGINE else (None if cli_engine else payload.get("llm_model")),
        llm_endpoint=None if cli_engine else payload.get("llm_endpoint"),
        affirmative_provider_id=None if cli_engine else payload.get("affirmative_provider_id"),
        negative_provider_id=None if cli_engine else payload.get("negative_provider_id"),
        moderator_provider_id=None if cli_engine else payload.get("moderator_provider_id"),
        affirmative_agent=affirmative_agent,
        negative_agent=negative_agent,
        moderator_agent=moderator_agent,
        agents_config_id=agents_config_id,
        agents_config_path=agents_config_path,
        agents_instructions=agents_instructions,
        reuse_findings_from_run_id=(str(payload.get("reuse_findings_from_run_id") or "").strip() or None),
    )


def _apply_reused_findings(
    config: RunConfig,
    store: RunRecordStore,
    tasks: dict,
    tasks_lock: Lock,
) -> None:
    source_run_id = config.reuse_findings_from_run_id
    if not source_run_id:
        return
    if not source_run_id.startswith("run-") or any(
        not (character.isalnum() or character in {"-", "_"}) for character in source_run_id
    ):
        raise ValueError("复用报告拆分结果的来源任务 ID 非法")
    source_run = store.get(source_run_id) or _get_task(tasks, tasks_lock, source_run_id)
    if source_run is None:
        raise ValueError(f"复用报告拆分结果失败：来源任务 {source_run_id} 不存在")
    source_report_path = str(
        source_run.get("sarif_path")
        or (source_run.get("config") or {}).get("report_path")
        or (source_run.get("config") or {}).get("sarif_path")
        or ""
    ).strip()
    if source_report_path and Path(source_report_path).expanduser().resolve() != config.sarif_path.expanduser().resolve():
        raise ValueError("复用报告拆分结果失败：新任务报告路径与来源任务不一致，请取消勾选后重新拆分")
    findings_payload = _report_findings_payload(source_run)
    if findings_payload is None:
        raise ValueError(f"复用报告拆分结果失败：来源任务 {source_run_id} 尚无可复用的 findings")
    findings = _findings_from_persisted(findings_payload, config.sarif_path)
    finding_ids = [finding.finding_id for finding in findings]
    if len(finding_ids) != len(set(finding_ids)):
        raise ValueError(f"复用报告拆分结果失败：来源任务 {source_run_id} 包含重复 finding_id")
    config.reused_findings = findings
    config.reused_findings_payload = _normalized_findings_payload(
        findings,
        origin=str(findings_payload.get("origin") or "unknown"),
        reused_from_run_id=source_run_id,
    )


def _report_findings_payload(run: dict) -> Optional[dict]:
    snapshot = run.get("report_findings") if isinstance(run, dict) else None
    if isinstance(snapshot, dict) and isinstance(snapshot.get("findings"), list) and snapshot["findings"]:
        return json.loads(json.dumps(snapshot, ensure_ascii=False))
    if not isinstance(run, dict):
        return None
    workflow = run.get("cli_workflow") if isinstance(run.get("cli_workflow"), dict) else {}
    if not workflow and isinstance(run.get("codex_workflow"), dict):
        workflow = run["codex_workflow"]
    run_dir_text = str(workflow.get("run_dir") or "").strip()
    findings_path_text = str(workflow.get("findings_path") or "").strip()
    if not run_dir_text:
        return None
    run_dir = Path(run_dir_text).expanduser().resolve()
    run_id = str(run.get("run_id") or "")
    if run_dir.name != run_id:
        return None
    expected_path = run_dir / "findings.json"
    findings_path = Path(findings_path_text).expanduser().resolve() if findings_path_text else expected_path
    if findings_path != expected_path or not findings_path.is_file():
        return None
    try:
        data = json.loads(findings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _reusable_findings_metadata(run: dict) -> dict:
    payload = _report_findings_payload(run)
    findings = payload.get("findings") if isinstance(payload, dict) else None
    available = isinstance(findings, list) and bool(findings)
    return {
        "available": available,
        "finding_count": len(findings) if available else 0,
        "origin": str(payload.get("origin") or "unknown") if available else None,
    }


def _run_detail(run, *, revision: Optional[str] = None):
    cli_sessions = _cli_sessions(run)
    cli_workflow = run.get("cli_workflow") or run.get("codex_workflow") or {}
    return {
        "run_id": run.get("run_id"),
        "revision": revision,
        "status": run.get("status", "completed"),
        "engine": run.get("engine") or (run.get("config") or {}).get("engine") or "builtin",
        "run_origin": normalize_run_origin(run),
        "created_at": run.get("created_at"),
        "source_path": run.get("source_path"),
        "sarif_path": run.get("sarif_path"),
        "languages": run.get("languages", []),
        "finding_count": run.get("finding_count", 0),
        "project_context_facts": run.get("project_context_facts", 0),
        "diagnostics": run.get("diagnostics", []),
        "llm_providers": run.get("llm_providers", {}),
        "agent_configs": run.get("agent_configs", {}),
        "verdict_counts": _verdict_counts(run),
        "completed_finding_count": run.get(
            "completed_finding_count",
            completed_finding_count(run.get("reports", [])),
        ),
        "current_finding_id": run.get("current_finding_id"),
        "current_finding_index": run.get("current_finding_index"),
        "current_finding_ids": run.get("current_finding_ids") or {},
        "resume_from_finding_id": run.get("resume_from_finding_id"),
        "resume_from_finding_index": run.get("resume_from_finding_index"),
        "config": run.get("config", {}),
        "manual_reviews": _manual_reviews(run),
        "manual_review_count": len(_manual_reviews(run)),
        "reusable_findings": _reusable_findings_metadata(run),
        "error": run.get("error"),
        "cli_sessions": cli_sessions,
        "cli_workflow": cli_workflow,
        "codex_sessions": _codex_sessions(run),
        "codex_workflow": run.get("codex_workflow", {}),
    }


def _list_runs(store: RunRecordStore, tasks: dict, tasks_lock: Lock):
    records = store.list()
    with tasks_lock:
        visible_tasks = [
            {**dict(task), "revision": store.revision(str(task.get("run_id") or ""))}
            for task in tasks.values()
            if task.get("status") != "completed"
        ]
    active_ids = {item.get("run_id") for item in visible_tasks}
    records = [item for item in records if item.get("run_id") not in active_ids]
    combined = visible_tasks + records
    combined.sort(key=lambda item: item.get("created_at") or "", reverse=True)
    return combined


def _get_task(tasks: dict, tasks_lock: Lock, run_id: str):
    with tasks_lock:
        task = tasks.get(run_id)
        return dict(task) if task else None


def _delete_task(tasks: dict, tasks_lock: Lock, run_id: str) -> bool:
    with tasks_lock:
        return tasks.pop(run_id, None) is not None


def _new_run_id() -> str:
    return f"run-{uuid4().hex[:12]}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _task_from_config(config: RunConfig, run_id: str, status: str, error: Optional[str] = None):
    return {
        "run_id": run_id,
        "status": status,
        "engine": config.engine,
        "run_origin": RUN_ORIGIN_WEB,
        "created_at": _now(),
        "source_path": str(config.source_path),
        "sarif_path": str(config.sarif_path),
        "languages": list(config.languages),
        "finding_count": 0,
        "project_context_facts": 0,
        "diagnostic_count": 0,
        "diagnostics": [],
        "llm_providers": {},
        "agent_configs": _agent_task_metadata(config),
        "verdict_counts": {},
        "reports": [],
        "report_findings": dict(config.reused_findings_payload),
        "reusable_findings": {
            "available": bool(config.reused_findings),
            "finding_count": len(config.reused_findings),
            "origin": str(config.reused_findings_payload.get("origin") or "unknown") if config.reused_findings else None,
        },
        "error": error,
        "config": _config_task_snapshot(config),
        "completed_finding_count": 0,
        "current_finding_id": None,
        "current_finding_index": None,
        "current_finding_ids": {},
        "resume_from_finding_id": None,
        "resume_from_finding_index": 0,
    }


def _run_task(
    config: RunConfig,
    store: RunRecordStore,
    tasks: dict,
    stop_events: dict,
    pause_events: dict,
    tasks_lock: Lock,
    stop_event: Event,
    pause_event: Event,
    control_store: Optional[RunControlStore] = None,
    control_owner_id: Optional[str] = None,
    run_origin: str = RUN_ORIGIN_WEB,
) -> None:
    if config.engine in CLI_ENGINES:
        _run_codex_task(
            config,
            store,
            tasks,
            stop_events,
            pause_events,
            tasks_lock,
            stop_event,
            pause_event,
            control_store,
            control_owner_id,
            run_origin,
        )
        return
    last_payload = None
    try:
        LOG.info("后台任务开始 run_id=%s report=%s source=%s", config.run_id, config.sarif_path, config.source_path)
        def on_progress(progress_report):
            nonlocal last_payload
            payload = to_jsonable(progress_report)
            payload["run_origin"] = run_origin
            payload["config"] = _config_task_snapshot(config)
            last_payload = payload
            action = _requested_run_action(
                config.run_id,
                stop_event,
                pause_event,
                control_store,
                control_owner_id,
            )
            status = "stopping" if action == "stop" else "pausing" if action == "pause" else "running"
            payload["status"] = status
            with tasks_lock:
                tasks[payload["run_id"]] = _task_from_report_payload(payload, status)
            store.save_payload(payload)
            LOG.info(
                "后台任务进度 run_id=%s reports=%s debate_turns=%s",
                payload["run_id"],
                len(payload.get("reports", [])),
                sum(len(item.get("debate", [])) for item in payload.get("reports", [])),
            )

        report = run_judgement(
            config,
            progress_callback=on_progress,
            should_stop=lambda: _requested_run_action(
                config.run_id,
                stop_event,
                pause_event,
                control_store,
                control_owner_id,
            )
            is not None,
        )
        payload = to_jsonable(report)
        last_payload = payload
        if _requested_run_action(
            config.run_id,
            stop_event,
            pause_event,
            control_store,
            control_owner_id,
        ) is not None:
            raise RunStopped("任务完成返回时收到暂停或停止请求")
        payload["run_origin"] = run_origin
        payload["config"] = _config_task_snapshot(config)
        store.save_payload(payload)
        with tasks_lock:
            tasks[report.run_id] = _task_from_report_payload(payload, "completed")
        LOG.info("后台任务完成 run_id=%s findings=%s", report.run_id, report.finding_count)
    except RunStopped as exc:
        action = _requested_run_action(
            config.run_id,
            stop_event,
            pause_event,
            control_store,
            control_owner_id,
        )
        if action == "pause":
            LOG.info("后台任务已暂停 run_id=%s", config.run_id)
            stopped_payload = _pause_payload(config, last_payload, str(exc), run_origin=run_origin)
            status = "paused"
        else:
            LOG.info("后台任务已停止 run_id=%s", config.run_id)
            stopped_payload = dict(last_payload or _task_from_config(config, config.run_id or _new_run_id(), "stopped"))
            stopped_payload["status"] = "stopped"
            stopped_payload["error"] = None
            diagnostics = list(stopped_payload.get("diagnostics", []))
            diagnostics.append(str(exc))
            stopped_payload["diagnostics"] = diagnostics
            if "reports" not in stopped_payload:
                stopped_payload["reports"] = []
            stopped_payload["config"] = _config_task_snapshot(config)
            stopped_payload["run_origin"] = run_origin
            status = "stopped"
        store.save_payload(stopped_payload)
        with tasks_lock:
            tasks[stopped_payload["run_id"]] = _task_from_report_payload(stopped_payload, status)
    except Exception as exc:
        LOG.exception("后台任务失败 run_id=%s", config.run_id)
        with tasks_lock:
            existing = tasks.get(config.run_id or "")
            failed = dict(existing or _task_from_config(config, config.run_id or _new_run_id(), "failed"))
            failed["status"] = "failed"
            failed["error"] = str(exc)
            failed["diagnostics"] = [str(exc)]
            failed["run_origin"] = run_origin
            tasks[failed["run_id"]] = failed
            store.save_payload(failed)
    finally:
        with tasks_lock:
            stop_events.pop(config.run_id, None)
            pause_events.pop(config.run_id, None)
        if control_store is not None and control_owner_id is not None:
            control_store.release(str(config.run_id), control_owner_id)


def _run_codex_task(
    config: RunConfig,
    store: RunRecordStore,
    tasks: dict,
    stop_events: dict,
    pause_events: dict,
    tasks_lock: Lock,
    stop_event: Event,
    pause_event: Event,
    control_store: Optional[RunControlStore] = None,
    control_owner_id: Optional[str] = None,
    run_origin: str = RUN_ORIGIN_WEB,
) -> None:
    cli_name = "OpenCode" if config.engine == OPENCODE_ENGINE else "Codex"
    last_payload = None
    try:
        LOG.info("%s-driven 后台任务开始 run_id=%s report=%s source=%s", cli_name, config.run_id, config.sarif_path, config.source_path)

        def on_progress(progress_payload):
            nonlocal last_payload
            payload = dict(progress_payload)
            payload["run_origin"] = run_origin
            payload["engine"] = config.engine
            payload["config"] = payload.get("config") or _config_task_snapshot(config)
            status = payload.get("status") or "running"
            if status == "running":
                action = _requested_run_action(
                    config.run_id,
                    stop_event,
                    pause_event,
                    control_store,
                    control_owner_id,
                )
                status = "stopping" if action == "stop" else "pausing" if action == "pause" else "running"
                payload["status"] = status
            last_payload = payload
            with tasks_lock:
                tasks[payload["run_id"]] = _task_from_report_payload(payload, status)
            store.save_payload(payload)
            LOG.info(
                "%s-driven 任务进度 run_id=%s status=%s reports=%s",
                cli_name,
                payload["run_id"],
                status,
                len(payload.get("reports", [])),
            )

        runner = (
            OpenCodeDrivenRunner(records_dir=store.root)
            if config.engine == OPENCODE_ENGINE
            else CodexDrivenRunner(records_dir=store.root)
        )
        payload = runner.run(
            config,
            store=store,
            progress_callback=on_progress,
            run_origin=run_origin,
            should_stop=lambda: _requested_run_action(
                config.run_id,
                stop_event,
                pause_event,
                control_store,
                control_owner_id,
            )
            is not None,
        )
        last_payload = payload
        if _requested_run_action(
            config.run_id,
            stop_event,
            pause_event,
            control_store,
            control_owner_id,
        ) is not None:
            raise CodexRunnerStopped(f"{cli_name} 任务完成返回时收到暂停或停止请求")
        payload["run_origin"] = run_origin
        payload["engine"] = config.engine
        payload["config"] = payload.get("config") or _config_task_snapshot(config)
        store.save_payload(payload)
        with tasks_lock:
            tasks[payload["run_id"]] = _task_from_report_payload(payload, "completed")
        LOG.info("%s-driven 后台任务完成 run_id=%s findings=%s", cli_name, payload.get("run_id"), payload.get("finding_count"))
    except CodexRunnerStopped as exc:
        stop_sessions(last_payload or {})
        action = _requested_run_action(
            config.run_id,
            stop_event,
            pause_event,
            control_store,
            control_owner_id,
        )
        if action == "pause":
            LOG.info("%s-driven 后台任务已暂停 run_id=%s", cli_name, config.run_id)
            stopped_payload = _pause_payload(config, last_payload, str(exc), run_origin=run_origin)
            status = "paused"
        else:
            LOG.info("%s-driven 后台任务已停止 run_id=%s", cli_name, config.run_id)
            stopped_payload = dict(last_payload or _task_from_config(config, config.run_id or _new_run_id(), "stopped"))
            stopped_payload["status"] = "stopped"
            stopped_payload["engine"] = config.engine
            stopped_payload["error"] = None
            diagnostics = list(stopped_payload.get("diagnostics", []))
            diagnostics.append(str(exc))
            stopped_payload["diagnostics"] = diagnostics
            stopped_payload["config"] = stopped_payload.get("config") or _config_task_snapshot(config)
            stopped_payload["run_origin"] = run_origin
            status = "stopped"
        store.save_payload(stopped_payload)
        with tasks_lock:
            tasks[stopped_payload["run_id"]] = _task_from_report_payload(stopped_payload, status)
    except Exception as exc:
        LOG.exception("%s-driven 后台任务失败 run_id=%s", cli_name, config.run_id)
        stop_sessions(last_payload or {})
        with tasks_lock:
            existing = tasks.get(config.run_id or "")
            failed = dict(existing or last_payload or _task_from_config(config, config.run_id or _new_run_id(), "failed"))
            failed["status"] = "failed"
            failed["engine"] = config.engine
            failed["error"] = str(exc)
            diagnostics = list(failed.get("diagnostics") or [])
            diagnostics.append(str(exc))
            failed["diagnostics"] = diagnostics
            failed["config"] = failed.get("config") or _config_task_snapshot(config)
            failed["run_origin"] = run_origin
            tasks[failed["run_id"]] = failed
            store.save_payload(failed)
    finally:
        with tasks_lock:
            stop_events.pop(config.run_id, None)
            pause_events.pop(config.run_id, None)
        if control_store is not None and control_owner_id is not None:
            control_store.release(str(config.run_id), control_owner_id)


def _task_from_report_payload(payload: dict, status: str) -> dict:
    return {
        "run_id": payload.get("run_id"),
        "status": status,
        "engine": payload.get("engine") or (payload.get("config") or {}).get("engine") or "builtin",
        "run_origin": normalize_run_origin(payload),
        "created_at": payload.get("created_at"),
        "source_path": payload.get("source_path"),
        "sarif_path": payload.get("sarif_path"),
        "languages": payload.get("languages", []),
        "finding_count": payload.get("finding_count", 0),
        "project_context_facts": payload.get("project_context_facts", 0),
        "diagnostic_count": len(payload.get("diagnostics", [])),
        "diagnostics": payload.get("diagnostics", []),
        "llm_providers": payload.get("llm_providers", {}),
        "agent_configs": payload.get("agent_configs", {}),
        "verdict_counts": _verdict_counts(payload),
        "reports": payload.get("reports", []),
        "report_findings": payload.get("report_findings", {}),
        "reusable_findings": _reusable_findings_metadata(payload),
        "error": payload.get("error"),
        "config": payload.get("config", {}),
        "completed_finding_count": payload.get(
            "completed_finding_count",
            completed_finding_count(payload.get("reports", [])),
        ),
        "current_finding_id": payload.get("current_finding_id"),
        "current_finding_index": payload.get("current_finding_index"),
        "current_finding_ids": payload.get("current_finding_ids") or {},
        "resume_from_finding_id": payload.get("resume_from_finding_id"),
        "resume_from_finding_index": payload.get("resume_from_finding_index"),
        "cli_sessions": _cli_sessions(payload),
        "cli_workflow": payload.get("cli_workflow") or payload.get("codex_workflow") or {},
        "codex_sessions": _codex_sessions(payload),
        "codex_workflow": payload.get("codex_workflow", {}),
    }


def _cli_sessions(payload: dict) -> list[dict]:
    if not isinstance(payload, dict):
        return []
    raw = payload.get("cli_sessions")
    if raw is None:
        raw = payload.get("codex_sessions")
    if raw is None and isinstance(payload.get("cli_workflow"), dict):
        raw = payload["cli_workflow"].get("sessions")
    if raw is None and isinstance(payload.get("codex_workflow"), dict):
        raw = payload["codex_workflow"].get("sessions")
    result = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        session = dict(item)
        target = str(session.get("target") or session.get("session_name") or "")
        backend = str(session.get("backend") or payload.get("engine") or "")
        if backend == OPENCODE_ENGINE:
            target = f"{session.get('session_name')}:tui"
            server_target = str(session.get("server_target") or f"{session.get('session_name')}:server")
            session["target"] = target
            session["window_name"] = "tui"
            session["server_target"] = server_target
            session["live"] = session_live(server_target)
            session["terminal_live"] = session_live(target)
        else:
            terminal_live = session_live(target) if target else False
            session["live"] = terminal_live
            session["terminal_live"] = terminal_live
        result.append(session)
    return result


def _codex_sessions(payload: dict) -> list[dict]:
    if str((payload or {}).get("engine") or "") not in {"", CODEX_ENGINE}:
        return []
    return _cli_sessions(payload)


def _codex_session_for_role(payload: dict, role: str) -> Optional[dict]:
    role = str(role or "").strip().lower()
    for session in _cli_sessions(payload):
        if str(session.get("role") or "").lower() == role:
            return session
    return None


def _cli_session_accepts_input(payload: dict, session: dict) -> bool:
    backend = str(session.get("backend") or payload.get("engine") or "")
    if backend == OPENCODE_ENGINE:
        return True
    return str(session.get("transport") or "tmux-tui") == "tmux-tui"


def _codex_uses_event_log(session: dict) -> bool:
    return str(session.get("transport") or "tmux-tui") == "exec-ephemeral-json"


def _codex_session_terminal(payload: dict, role: str) -> dict:
    session = _codex_session_for_role(payload, role)
    if session is None:
        return {"error": "Codex session 未找到", "role": role, "live": False, "output": ""}
    target = str(session.get("target") or session.get("session_name") or "")
    event_log = _codex_uses_event_log(session)
    output = _codex_event_log(session) if event_log else capture_session(target)
    result = {
        "role": session.get("role"),
        "session_name": session.get("session_name"),
        "window_name": session.get("window_name"),
        "target": target,
        "live": session_live(target),
        "output": output,
    }
    if event_log:
        result["formatted_output"] = format_codex_ndjson(output)
    return result


def _cli_session_terminal(payload: dict, role: str) -> dict:
    session = _codex_session_for_role(payload, role)
    if session is None:
        return {"error": "CLI session 未找到", "role": role, "live": False, "output": ""}
    target = str(session.get("target") or session.get("session_name") or "")
    backend = str(session.get("backend") or payload.get("engine") or "")
    event_log = backend == CODEX_ENGINE and _codex_uses_event_log(session)
    output = _codex_event_log(session) if event_log else capture_session(target)
    result = {
        "role": session.get("role"),
        "backend": backend,
        "session_name": session.get("session_name"),
        "window_name": session.get("window_name"),
        "target": target,
        "live": session_live(target),
        "output": output,
    }
    if event_log:
        result["formatted_output"] = format_codex_ndjson(output)
    return result


def _codex_event_log(session: dict, lines: int = 4000) -> str:
    cwd_text = str(session.get("cwd") or "").strip()
    if not cwd_text:
        return ""
    cwd = Path(cwd_text).expanduser().resolve()
    candidates = []
    event_log = str(session.get("event_log") or "").strip()
    if event_log:
        candidates.append(Path(event_log).expanduser())
    candidates.append(cwd / ".vuln-judger-codex" / "current.ndjson")
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            resolved.relative_to(cwd)
        except (OSError, ValueError):
            continue
        if not resolved.is_file():
            continue
        try:
            rows = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        return "\n".join(rows[-max(1, min(int(lines), 10000)) :]) + ("\n" if rows else "")
    return ""


def _stop_codex_sessions(
    store: RunRecordStore,
    tasks: dict,
    tasks_lock: Lock,
    run_id: str,
) -> Optional[dict]:
    with tasks_lock:
        payload = dict(tasks.get(run_id) or {})
    if not payload:
        record = store.get(run_id)
        payload = dict(record or {})
    if not payload:
        return None
    before = _codex_sessions(payload)
    stopped = sum(1 for session in before if session.get("live"))
    stop_sessions(payload)
    return {
        "ok": True,
        "run_id": run_id,
        "stopped": stopped,
        "sessions": _codex_sessions(payload),
    }


def _stop_cli_sessions(
    store: RunRecordStore,
    tasks: dict,
    tasks_lock: Lock,
    run_id: str,
) -> Optional[dict]:
    with tasks_lock:
        payload = dict(tasks.get(run_id) or {})
    if not payload:
        payload = dict(store.get(run_id) or {})
    if not payload:
        return None
    before = _cli_sessions(payload)
    stopped = sum(1 for session in before if session.get("live"))
    stop_sessions(payload)
    return {"ok": True, "run_id": run_id, "stopped": stopped, "sessions": _cli_sessions(payload)}


def _codex_terminal_page(run_id: str, role: str, session: dict) -> str:
    target = str(session.get("target") or session.get("session_name") or "")
    label = {"moderator": "Moderator", "affirmative": "正方", "negative": "反方"}.get(role, role)
    backend = str(session.get("backend") or CODEX_ENGINE)
    if backend == OPENCODE_ENGINE:
        return _opencode_terminal_page(run_id, role, label, target)
    if not _codex_uses_event_log(session):
        return _codex_native_terminal_page(run_id, role, label, target)
    return _codex_log_page(run_id, role, label, target)


def _codex_native_terminal_page(run_id: str, role: str, label: str, target: str) -> str:
    websocket_path = f"/runs/{run_id}/cli-sessions/{role}/ws"
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(label)} · Codex TUI</title>
  <link rel="stylesheet" href="/static/vendor/xterm/xterm.css">
  <style>
    html, body {{ height: 100%; margin: 0; background: #0d1117; color: #c9d1d9; }}
    body {{ display: grid; grid-template-rows: auto minmax(0, 1fr); font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    header {{ display: flex; justify-content: space-between; gap: 16px; align-items: center; padding: 10px 12px; border-bottom: 1px solid #30363d; background: #161b22; }}
    h1 {{ margin: 0; font-size: 14px; font-weight: 650; }}
    .meta {{ color: #8b949e; font-size: 12px; overflow-wrap: anywhere; }}
    #terminal {{ min-height: 0; height: 100%; padding: 8px; box-sizing: border-box; }}
    .xterm {{ height: 100%; }}
    .error {{ color: #ff7b72; padding: 12px; white-space: pre-wrap; }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1>{escape(label)} Codex TUI</h1>
      <div class="meta">{escape(run_id)} · {escape(target)}</div>
    </div>
    <div class="meta">原生 tmux TUI · stage 切换时重置上下文</div>
  </header>
  <div id="terminal"></div>
  <script src="/static/vendor/xterm/xterm.js"></script>
  <script src="/static/vendor/xterm/addon-fit.js"></script>
  <script>
    const websocketPath = {json.dumps(websocket_path)};
    const terminalNode = document.getElementById('terminal');
    const TerminalCtor = window.Terminal;
    const FitAddonCtor = window.FitAddon?.FitAddon || window.FitAddon;
    function websocketURL(path) {{
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      return `${{protocol}}//${{window.location.host}}${{path}}`;
    }}
    if (!TerminalCtor || !FitAddonCtor) {{
      terminalNode.innerHTML = '<div class="error">xterm.js 未加载，无法打开 Codex TUI。</div>';
    }} else {{
      const term = new TerminalCtor({{
        cursorBlink: true,
        fontSize: 14,
        fontFamily: 'JetBrains Mono, Menlo, Monaco, Consolas, monospace',
        scrollback: 10000,
        theme: {{
          background: '#0d1117',
          foreground: '#c9d1d9',
          cursor: '#58a6ff',
          selectionBackground: '#264f78'
        }}
      }});
      const fitAddon = new FitAddonCtor();
      term.loadAddon(fitAddon);
      term.open(terminalNode);
      const ws = new WebSocket(websocketURL(websocketPath));
      ws.binaryType = 'arraybuffer';
      function sendResize() {{
        if (ws.readyState !== WebSocket.OPEN) return;
        fitAddon.fit();
        ws.send(JSON.stringify({{ type: 'resize', rows: term.rows, cols: term.cols }}));
      }}
      ws.onopen = () => {{
        sendResize();
        term.focus();
      }};
      ws.onmessage = event => {{
        if (event.data instanceof ArrayBuffer) term.write(new Uint8Array(event.data));
        else if (event.data instanceof Blob) {{
          event.data.arrayBuffer().then(buffer => term.write(new Uint8Array(buffer)));
        }}
      }};
      ws.onclose = () => term.write('\\r\\n\\x1b[33m[tmux connection closed]\\x1b[0m\\r\\n');
      ws.onerror = () => term.write('\\r\\n\\x1b[31m[websocket error]\\x1b[0m\\r\\n');
      term.onData(data => {{
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({{ type: 'input', data }}));
      }});
      const resizeObserver = new ResizeObserver(() => setTimeout(sendResize, 50));
      resizeObserver.observe(terminalNode);
      window.addEventListener('beforeunload', () => ws.close());
      requestAnimationFrame(sendResize);
    }}
  </script>
</body>
</html>"""


def _opencode_terminal_page(run_id: str, role: str, label: str, target: str) -> str:
    websocket_path = f"/runs/{run_id}/cli-sessions/{role}/ws"
    message_path = f"/runs/{run_id}/cli-sessions/{role}/input"
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(label)} · OpenCode 任务会话</title>
  <link rel="stylesheet" href="/static/vendor/xterm/xterm.css">
  <style>
    html, body {{ height: 100%; margin: 0; background: #0d1117; color: #c9d1d9; }}
    body {{ display: grid; grid-template-rows: auto minmax(0, 1fr) auto; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    header {{ display: flex; justify-content: space-between; gap: 16px; align-items: center; padding: 10px 12px; border-bottom: 1px solid #30363d; background: #161b22; }}
    h1 {{ margin: 0; font-size: 14px; font-weight: 650; }}
    .meta {{ color: #8b949e; font-size: 12px; overflow-wrap: anywhere; }}
    #terminal {{ min-height: 0; height: 100%; padding: 8px; box-sizing: border-box; }}
    .xterm {{ height: 100%; }}
    .error {{ color: #ff7b72; padding: 12px; white-space: pre-wrap; }}
    #message-form {{ display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; padding: 8px 12px 12px; border-top: 1px solid #30363d; background: #161b22; }}
    #message-input {{ min-width: 0; border: 1px solid #30363d; background: #0d1117; color: #c9d1d9; padding: 9px 10px; font: inherit; }}
    #message-form button {{ border: 1px solid #388bfd; background: #238636; color: white; padding: 0 16px; font: inherit; cursor: pointer; }}
    #message-form button:disabled {{ opacity: .55; cursor: default; }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1>{escape(label)} OpenCode 任务会话</h1>
      <div class="meta">{escape(run_id)} · {escape(target)}</div>
    </div>
    <div class="meta">只读 TUI · HTTP 消息</div>
  </header>
  <div id="terminal"></div>
  <form id="message-form">
    <input id="message-input" autocomplete="off" placeholder="发送消息到 OpenCode">
    <button type="submit">发送</button>
  </form>
  <script src="/static/vendor/xterm/xterm.js"></script>
  <script src="/static/vendor/xterm/addon-fit.js"></script>
  <script>
    const websocketPath = {json.dumps(websocket_path)};
    const messagePath = {json.dumps(message_path)};
    const terminalNode = document.getElementById('terminal');
    const TerminalCtor = window.Terminal;
    const FitAddonCtor = window.FitAddon?.FitAddon || window.FitAddon;
    function websocketURL(path) {{
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      return `${{protocol}}//${{window.location.host}}${{path}}`;
    }}
    if (!TerminalCtor || !FitAddonCtor) {{
      terminalNode.innerHTML = '<div class="error">xterm.js 未加载，无法打开 CLI session。</div>';
    }} else {{
      const term = new TerminalCtor({{
        cursorBlink: true,
        fontSize: 14,
        fontFamily: 'JetBrains Mono, Menlo, Monaco, Consolas, monospace',
        scrollback: 10000,
        theme: {{
          background: '#0d1117',
          foreground: '#c9d1d9',
          cursor: '#58a6ff',
          selectionBackground: '#264f78'
        }}
      }});
      const fitAddon = new FitAddonCtor();
      term.loadAddon(fitAddon);
      term.open(terminalNode);
      function fitTerminal() {{
        fitAddon.fit();
      }}
      const ws = new WebSocket(websocketURL(websocketPath));
      ws.binaryType = 'arraybuffer';
      ws.onopen = () => {{
        fitTerminal();
        ws.send(JSON.stringify({{ type: 'resize', rows: term.rows, cols: term.cols }}));
      }};
      ws.onmessage = event => {{
        if (event.data instanceof ArrayBuffer) term.write(new Uint8Array(event.data));
        else if (event.data instanceof Blob) {{
          event.data.arrayBuffer().then(buffer => term.write(new Uint8Array(buffer)));
        }}
      }};
      ws.onclose = () => term.write('\\r\\n\\x1b[33m[tmux connection closed]\\x1b[0m\\r\\n');
      ws.onerror = () => term.write('\\r\\n\\x1b[31m[websocket error]\\x1b[0m\\r\\n');

      const messageForm = document.getElementById('message-form');
      const messageInput = document.getElementById('message-input');
      messageForm.addEventListener('submit', async event => {{
        event.preventDefault();
        const message = messageInput.value.trim();
        if (!message) return;
        const button = messageForm.querySelector('button');
        button.disabled = true;
        try {{
          const response = await fetch(messagePath, {{
            method: 'POST',
            headers: {{ 'content-type': 'application/json' }},
            body: JSON.stringify({{ message }})
          }});
          const payload = await response.json();
          if (!response.ok || !payload.ok) throw new Error(payload.error || `HTTP ${{response.status}}`);
          messageInput.value = '';
        }} catch (error) {{
          term.write(`\\r\\n\\x1b[31m[message error] ${{error.message}}\\x1b[0m\\r\\n`);
        }} finally {{
          button.disabled = false;
          messageInput.focus();
        }}
      }});
      const resizeObserver = new ResizeObserver(() => setTimeout(() => {{
        fitTerminal();
        if (ws.readyState === WebSocket.OPEN) {{
          ws.send(JSON.stringify({{ type: 'resize', rows: term.rows, cols: term.cols }}));
        }}
      }}, 50));
      resizeObserver.observe(terminalNode);
      window.addEventListener('beforeunload', () => ws.close());
      requestAnimationFrame(fitTerminal);
    }}
  </script>
</body>
</html>"""


def _codex_log_page(run_id: str, role: str, label: str, target: str) -> str:
    terminal_path = f"/runs/{run_id}/cli-sessions/{role}/terminal"
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(label)} · Codex 执行日志</title>
  <style>
    :root {{ color-scheme: dark; }}
    html, body {{ height: 100%; margin: 0; background: #0d1117; color: #c9d1d9; }}
    body {{ display: grid; grid-template-rows: auto minmax(0, 1fr); font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    header {{ display: flex; flex-wrap: wrap; justify-content: space-between; gap: 10px 18px; align-items: center; padding: 10px 12px; border-bottom: 1px solid #30363d; background: #161b22; }}
    h1 {{ margin: 0; font-size: 14px; font-weight: 650; }}
    .meta {{ color: #8b949e; font-size: 12px; overflow-wrap: anywhere; }}
    .controls {{ display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }}
    .segmented {{ display: inline-grid; grid-template-columns: 1fr 1fr; border: 1px solid #30363d; border-radius: 4px; overflow: hidden; }}
    .segmented button {{ min-width: 64px; border: 0; border-right: 1px solid #30363d; background: #0d1117; color: #8b949e; padding: 6px 10px; font: inherit; cursor: pointer; }}
    .segmented button:last-child {{ border-right: 0; }}
    .segmented button[aria-pressed="true"] {{ background: #238636; color: #ffffff; }}
    .follow {{ display: inline-flex; align-items: center; gap: 6px; color: #c9d1d9; font-size: 12px; }}
    .status {{ min-width: 64px; color: #8b949e; font-size: 12px; text-align: right; }}
    .status.live {{ color: #3fb950; }}
    .status.error {{ color: #ff7b72; }}
    #log {{ min-width: 0; min-height: 0; margin: 0; padding: 14px 16px 28px; overflow: auto; box-sizing: border-box; white-space: pre-wrap; overflow-wrap: anywhere; tab-size: 2; font: 13px/1.55 "JetBrains Mono", Menlo, Monaco, Consolas, monospace; }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1>{escape(label)} Codex 执行日志</h1>
      <div class="meta">{escape(run_id)} · {escape(target)}</div>
    </div>
    <div class="controls">
      <div class="segmented" role="group" aria-label="日志显示模式">
        <button type="button" data-log-mode="readable" aria-pressed="true">可读</button>
        <button type="button" data-log-mode="raw" aria-pressed="false">原始</button>
      </div>
      <label class="follow"><input id="follow-log" type="checkbox" checked>自动跟随</label>
      <span id="log-status" class="status">连接中</span>
    </div>
  </header>
  <pre id="log"></pre>
  <script>
    const terminalPath = {json.dumps(terminal_path)};
    const logNode = document.getElementById('log');
    const statusNode = document.getElementById('log-status');
    const followNode = document.getElementById('follow-log');
    const modeButtons = Array.from(document.querySelectorAll('[data-log-mode]'));
    let mode = 'readable';
    let rawOutput = '';
    let formattedOutput = '';
    let renderedOutput = null;

    function nearBottom() {{
      return logNode.scrollHeight - logNode.scrollTop - logNode.clientHeight < 48;
    }}

    function renderLog() {{
      const output = mode === 'raw' ? rawOutput : formattedOutput;
      if (output === renderedOutput) return;
      const follow = followNode.checked && (renderedOutput === null || nearBottom());
      renderedOutput = output;
      logNode.textContent = output || '[暂无执行日志]';
      if (follow) requestAnimationFrame(() => {{ logNode.scrollTop = logNode.scrollHeight; }});
    }}

    modeButtons.forEach(button => button.addEventListener('click', () => {{
      mode = button.dataset.logMode;
      modeButtons.forEach(item => item.setAttribute('aria-pressed', String(item === button)));
      renderedOutput = null;
      renderLog();
    }}));

    async function pollLog() {{
      try {{
        const response = await fetch(terminalPath, {{ cache: 'no-store' }});
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || `HTTP ${{response.status}}`);
        rawOutput = String(payload.output || '');
        formattedOutput = String(payload.formatted_output || rawOutput);
        statusNode.textContent = payload.live ? '日志在线' : '日志已停止';
        statusNode.className = `status${{payload.live ? ' live' : ''}}`;
        renderLog();
      }} catch (error) {{
        statusNode.textContent = error.message;
        statusNode.className = 'status error';
      }} finally {{
        window.setTimeout(pollLog, 1000);
      }}
    }}

    pollLog();
  </script>
</body>
</html>"""


def _send_codex_session_input(
    store: RunRecordStore,
    tasks: dict,
    tasks_lock: Lock,
    run_id: str,
    role: str,
    message: str,
) -> Optional[dict]:
    with tasks_lock:
        payload = dict(tasks.get(run_id) or {})
    if not payload:
        record = store.get(run_id)
        payload = dict(record or {})
    if not payload:
        return None
    session = _codex_session_for_role(payload, role)
    if session is None:
        return None
    if not _cli_session_accepts_input(payload, session):
        return {
            "ok": False,
            "role": role,
            "error": "当前 CLI 自动控制使用隔离的非交互任务 transport，不接受 prompt 注入",
        }
    backend = str(session.get("backend") or payload.get("engine") or "")
    if backend == OPENCODE_ENGINE:
        try:
            submitted = send_opencode_session_message(session, message)
        except CodexRunnerError as exc:
            return {"ok": False, "role": role, "error": str(exc)}
        return {"ok": True, "role": role, **submitted}
    target = str(session.get("target") or session.get("session_name") or "")
    if not target:
        return None
    try:
        send_session_input(target, message)
    except (CodexRunnerError, subprocess.CalledProcessError) as exc:
        return {"ok": False, "role": role, "error": str(exc)}
    return {"ok": True, "role": role, "target": target}


def _config_task_snapshot(config: RunConfig) -> dict:
    return run_config_snapshot(config)


def _pause_payload(
    config: RunConfig,
    last_payload: Optional[dict],
    reason: str,
    *,
    run_origin: str = RUN_ORIGIN_WEB,
) -> dict:
    payload = dict(last_payload or _task_from_config(config, config.run_id or _new_run_id(), "paused"))
    payload["run_origin"] = run_origin
    reports = mark_incomplete_findings_pending(
        payload.get("reports") or [],
        payload.get("completed_finding_count"),
    )
    finding_count = max(int(payload.get("finding_count") or 0), len(reports))
    completed_count = completed_finding_count(reports)
    if config.engine not in CLI_ENGINES:
        reports = reports[:completed_count]
    resume_index = first_incomplete_finding_index(reports, finding_count)
    resume_report = reports[resume_index] if resume_index < len(reports) else {}
    resume_id = (
        resume_report.get("finding_id")
        or payload.get("current_finding_id")
        or payload.get("resume_from_finding_id")
    )
    payload["status"] = "paused"
    payload["error"] = None
    payload["reports"] = reports
    payload["completed_finding_count"] = completed_count
    payload["current_finding_id"] = None
    payload["current_finding_index"] = None
    payload["current_finding_ids"] = {}
    payload["resume_from_finding_id"] = resume_id
    payload["resume_from_finding_index"] = resume_index
    payload["config"] = payload.get("config") or _config_task_snapshot(config)
    diagnostics = list(payload.get("diagnostics") or [])
    resume_text = f"finding index {resume_index}"
    if resume_id:
        resume_text += f" ({resume_id})"
    diagnostics.append(f"{reason}；任务已暂停，恢复时将从 {resume_text} 的首个未完成 stage 继续。")
    payload["diagnostics"] = diagnostics
    return payload


def _requested_run_action(
    run_id: Optional[str],
    stop_event: Event,
    pause_event: Event,
    control_store: Optional[RunControlStore],
    control_owner_id: Optional[str],
) -> Optional[str]:
    if stop_event.is_set():
        return "stop"
    if pause_event.is_set():
        return "pause"
    if control_store is None or control_owner_id is None or not run_id:
        return None
    return control_store.requested_action(str(run_id), control_owner_id)


def _bounded_int(value, *, default: int, minimum: int, maximum: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        result = default
    return min(max(result, minimum), maximum)


def _request_stop(
    tasks: dict,
    stop_events: dict,
    tasks_lock: Lock,
    run_id: str,
    *,
    store: Optional[RunRecordStore] = None,
    control_store: Optional[RunControlStore] = None,
) -> Optional[dict]:
    updated = None
    stop_event = None
    with tasks_lock:
        task = tasks.get(run_id)
        stop_event = stop_events.get(run_id)
        if task is not None and task.get("status") in {"completed", "failed", "stopped"}:
            return dict(task)
        if task is not None and stop_event is not None:
            updated = dict(task)
            updated["status"] = "stopping"
            updated["stop_requested"] = True
            tasks[run_id] = updated
    control = control_store or (RunControlStore(store.root) if store is not None else None)
    if updated is not None:
        signaled = False
        if control is not None:
            signaled = control.request(
                run_id,
                "stop",
                requested_by=RUN_ORIGIN_WEB,
                before_signal=(lambda: store.save_payload(updated)) if store is not None else None,
            )
        if store is not None and not signaled:
            store.save_payload(updated)
        if stop_event is not None:
            stop_event.set()
        return dict(updated)
    if store is None or control is None:
        return None
    stored = store.get(run_id)
    if not stored or stored.get("status") not in {"queued", "running", "pausing", "stopping"}:
        return None
    updated = dict(stored)
    updated["status"] = "stopping"
    updated["stop_requested"] = True
    if not control.request(
        run_id,
        "stop",
        requested_by=RUN_ORIGIN_WEB,
        before_signal=lambda: store.save_payload(updated),
    ):
        return None
    return updated


def _request_pause(
    tasks: dict,
    pause_events: dict,
    tasks_lock: Lock,
    run_id: str,
    *,
    store: Optional[RunRecordStore] = None,
    control_store: Optional[RunControlStore] = None,
) -> Optional[dict]:
    updated = None
    pause_event = None
    with tasks_lock:
        task = tasks.get(run_id)
        pause_event = pause_events.get(run_id)
        if task is not None and task.get("status") == "paused":
            return dict(task)
        if task is not None and pause_event is not None and task.get("status") not in {"completed", "failed", "stopped"}:
            updated = dict(task)
            updated["status"] = "pausing"
            updated["pause_requested"] = True
            tasks[run_id] = updated
    control = control_store or (RunControlStore(store.root) if store is not None else None)
    if updated is not None:
        signaled = False
        if control is not None:
            signaled = control.request(
                run_id,
                "pause",
                requested_by=RUN_ORIGIN_WEB,
                before_signal=(lambda: store.save_payload(updated)) if store is not None else None,
            )
        if store is not None and not signaled:
            store.save_payload(updated)
        if pause_event is not None:
            pause_event.set()
        return dict(updated)
    if store is None or control is None:
        return None
    stored = store.get(run_id)
    if not stored:
        return None
    if stored.get("status") == "paused":
        return dict(stored)
    if stored.get("status") not in {"queued", "running", "pausing"}:
        return None
    updated = dict(stored)
    updated["status"] = "pausing"
    updated["pause_requested"] = True
    if not control.request(
        run_id,
        "pause",
        requested_by=RUN_ORIGIN_WEB,
        before_signal=lambda: store.save_payload(updated),
    ):
        return None
    return updated


def _request_resume(
    store: RunRecordStore,
    tasks: dict,
    stop_events: dict,
    pause_events: dict,
    tasks_lock: Lock,
    run_id: str,
    providers_file: Path,
    agent_store: AgentDirectoryStore,
    mcp_servers_file: Path,
    skill_store: SkillSourceStore,
    control_store: Optional[RunControlStore] = None,
) -> Optional[dict]:
    control = control_store or RunControlStore(store.root)
    control_owner_id = None
    run_origin = RUN_ORIGIN_WEB
    with tasks_lock:
        active_task = tasks.get(run_id)
        if active_task and active_task.get("status") in {"running", "pausing", "stopping"}:
            return dict(active_task)
        stored_payload = store.get(run_id)
        resumable_payload = (
            active_task
            if active_task and active_task.get("status") in RESUMABLE_RUN_STATUSES
            else stored_payload
        )
        if not resumable_payload or resumable_payload.get("status") not in RESUMABLE_RUN_STATUSES:
            return None
        checkpoint = _resume_checkpoint_payload(resumable_payload)
        config = _config_from_paused_payload(checkpoint, providers_file, agent_store, mcp_servers_file, skill_store)
        run_origin = normalize_run_origin(resumable_payload)
        control_owner_id = control.claim(
            run_id,
            origin=run_origin,
            allow_paused_takeover=True,
        )
        if control_owner_id is None:
            return None
        stop_event = Event()
        pause_event = Event()
        task = _task_from_report_payload(checkpoint, "running")
        task["status"] = "running"
        task["error"] = None
        try:
            store.save_payload(task)
        except Exception:
            control.release(run_id, control_owner_id)
            raise
        tasks[run_id] = task
        stop_events[run_id] = stop_event
        pause_events[run_id] = pause_event
    if config.engine in CLI_ENGINES:
        stop_sessions(resumable_payload)
    worker = Thread(
        target=_run_task,
        args=(
            config,
            store,
            tasks,
            stop_events,
            pause_events,
            tasks_lock,
            stop_event,
            pause_event,
            control,
            control_owner_id,
            run_origin,
        ),
        daemon=True,
    )
    try:
        worker.start()
    except Exception:
        with tasks_lock:
            tasks[run_id] = _task_from_report_payload(resumable_payload, str(resumable_payload.get("status") or "paused"))
            stop_events.pop(run_id, None)
            pause_events.pop(run_id, None)
        store.save_payload(resumable_payload)
        control.release(run_id, control_owner_id)
        raise
    return dict(task)


def _resume_checkpoint_payload(payload: dict) -> dict:
    checkpoint = dict(payload)
    source_status = str(checkpoint.get("status") or "").strip().lower()
    reports = mark_incomplete_findings_pending(
        checkpoint.get("reports") or [],
        checkpoint.get("completed_finding_count"),
    )
    engine = str(checkpoint.get("engine") or (checkpoint.get("config") or {}).get("engine") or "builtin")
    completed_count = completed_finding_count(reports)
    if engine not in CLI_ENGINES:
        reports = reports[:completed_count]
    finding_count = max(
        _bounded_int(
            checkpoint.get("finding_count"),
            default=len(reports),
            minimum=0,
            maximum=1_000_000,
        ),
        len(reports),
    )
    resume_index = first_incomplete_finding_index(reports, finding_count)
    resume_report = reports[resume_index] if resume_index < len(reports) else {}
    resume_id = resume_report.get("finding_id") or checkpoint.get("resume_from_finding_id")
    checkpoint["reports"] = reports
    checkpoint["completed_finding_count"] = completed_count
    checkpoint["current_finding_id"] = None
    checkpoint["current_finding_index"] = None
    checkpoint["current_finding_ids"] = {}
    checkpoint["resume_from_finding_id"] = resume_id
    checkpoint["resume_from_finding_index"] = resume_index
    checkpoint["error"] = None
    diagnostics = list(checkpoint.get("diagnostics") or [])
    checkpoint_text = f"finding index {resume_index}"
    if resume_id:
        checkpoint_text += f" ({resume_id})"
    diagnostics.append(f"任务从 {source_status or '未知'} 状态恢复，将从 {checkpoint_text} 的首个未完成 stage 继续。")
    checkpoint["diagnostics"] = diagnostics
    return checkpoint


def _config_from_paused_payload(
    payload: dict,
    providers_file: Path,
    agent_store: AgentDirectoryStore,
    mcp_servers_file: Path,
    skill_store: SkillSourceStore,
) -> RunConfig:
    config_payload = dict(payload.get("config") or {})
    if not config_payload:
        config_payload = {
            "report_path": payload.get("sarif_path"),
            "source_path": payload.get("source_path"),
            "enable_external_tools": True,
        }
    providers = payload.get("llm_providers") if isinstance(payload.get("llm_providers"), dict) else {}
    for role in ("affirmative", "negative", "moderator"):
        key = f"{role}_provider_id"
        if config_payload.get(key):
            continue
        provider = providers.get(role) if isinstance(providers.get(role), dict) else {}
        provider_id = provider.get("provider_id")
        if provider_id:
            config_payload[key] = provider_id
    run_id = str(payload.get("run_id") or _new_run_id())
    config = _config_from_payload(config_payload, providers_file, run_id, agent_store, mcp_servers_file, skill_store)
    reports = list(payload.get("reports") or [])
    config.created_at = payload.get("created_at")
    config.resume_reports = reports
    config.resume_diagnostics = list(payload.get("diagnostics") or [])
    config.resume_from_finding_index = first_incomplete_finding_index(
        reports,
        int(payload.get("finding_count") or len(reports)),
    )
    if config.reuse_findings_from_run_id:
        findings_payload = _report_findings_payload(payload)
        if findings_payload is not None:
            config.reused_findings = _findings_from_persisted(findings_payload, config.sarif_path)
            config.reused_findings_payload = _normalized_findings_payload(
                config.reused_findings,
                origin=str(findings_payload.get("origin") or "unknown"),
                reused_from_run_id=config.reuse_findings_from_run_id,
            )
    return config


def _safe_payload(payload) -> dict:
    if not isinstance(payload, dict):
        return {}
    masked = dict(payload)
    for key in list(masked):
        lowered = str(key).lower()
        if "api_key" in lowered or "key" in lowered or "token" in lowered or "secret" in lowered:
            masked[key] = "***"
    return masked


def _manual_reviews(run: Optional[dict]) -> dict:
    value = run.get("manual_reviews") if isinstance(run, dict) else None
    if not isinstance(value, dict):
        return {}
    return {
        str(finding_id): dict(review)
        for finding_id, review in value.items()
        if finding_id and isinstance(review, dict)
    }


def _manual_review_for(run: Optional[dict], finding_id) -> Optional[dict]:
    review = _manual_reviews(run).get(str(finding_id or ""))
    return dict(review) if isinstance(review, dict) else None


def _merge_manual_reviews(payload: Optional[dict], persisted: Optional[dict]) -> Optional[dict]:
    if payload is None:
        return dict(persisted) if isinstance(persisted, dict) else None
    merged = dict(payload)
    merged["manual_reviews"] = _manual_reviews(persisted)
    return merged


def _finding_exists(run: dict, finding_id: str) -> bool:
    return any(str(report.get("finding_id") or "") == finding_id for report in run.get("reports") or [])


def _validated_manual_review_payload(payload) -> tuple[str, str]:
    if not isinstance(payload, dict):
        raise ValueError("人工复核请求必须是 JSON 对象")
    decision = str(payload.get("decision") or "").strip().upper()
    if decision not in MANUAL_REVIEW_DECISIONS:
        raise ValueError("人工复核结论必须是 TRUE_POSITIVE、FALSE_POSITIVE 或 INCONCLUSIVE")
    evidence_value = payload.get("evidence", "")
    if evidence_value is None:
        evidence_value = ""
    if not isinstance(evidence_value, str):
        raise ValueError("人工复核证据必须是文本")
    evidence = evidence_value.strip()
    if len(evidence) > MANUAL_REVIEW_EVIDENCE_MAX_LENGTH:
        raise ValueError(f"人工复核证据不能超过 {MANUAL_REVIEW_EVIDENCE_MAX_LENGTH} 个字符")
    return decision, evidence


def _finding_detail(report: dict, run: Optional[dict], *, revision: Optional[str] = None) -> dict:
    detail = dict(report)
    detail["revision"] = revision
    detail["manual_review"] = _manual_review_for(run, report.get("finding_id"))
    return detail


def _finding_summary(report, manual_review: Optional[dict] = None):
    delivery = _codex_delivery_summary(report)
    return {
        "finding_id": report.get("finding_id"),
        "rule_id": report.get("rule_id"),
        "finding_status": finding_report_status(report),
        "verdict": report.get("verdict"),
        "confidence": report.get("confidence"),
        "summary": _finding_report_summary(report),
        "final_conclusion": report.get("final_conclusion"),
        "source_locations": report.get("source_locations", []),
        "evidence_count": len(report.get("evidence_chain", [])),
        "debate_turn_count": len(report.get("debate", [])),
        "cli_delivery": delivery,
        "codex_delivery": delivery,
        "manual_review": dict(manual_review) if isinstance(manual_review, dict) else None,
    }


def _codex_delivery_summary(report: dict) -> dict:
    workflow = report.get("cli_workflow") if isinstance(report.get("cli_workflow"), dict) else {}
    if not workflow and isinstance(report.get("codex_workflow"), dict):
        workflow = report["codex_workflow"]
    return {
        "affirmative": bool(workflow.get("affirmative")),
        "negative": bool(workflow.get("negative")),
        "moderator": bool(workflow.get("moderator")),
    }


def _finding_report_summary(report: dict) -> str:
    report_evidence = _report_evidence(report)
    if report_evidence:
        data = report_evidence.get("data") if isinstance(report_evidence.get("data"), dict) else {}
        rule_id = str(data.get("rule_id") or report.get("rule_id") or "").strip()
        level = str(data.get("level") or "").strip()
        message = str(data.get("message") or "").strip()
        locations = data.get("locations") if isinstance(data.get("locations"), list) else []
        parts = []
        if rule_id:
            parts.append(f"{rule_id}（{level}）" if level else rule_id)
        if message:
            parts.append(message)
        if locations:
            parts.append("位置：" + "; ".join(str(item) for item in locations[:3]))
        return "；".join(parts) or str(report_evidence.get("summary") or "")
    fallback = str(report.get("final_conclusion") or report.get("reasoning_summary") or "")
    return _strip_prompt_echo_text(fallback)


def _report_evidence(report: dict) -> Optional[dict]:
    for item in report.get("evidence_chain") or []:
        if not isinstance(item, dict):
            continue
        if item.get("kind") == "REPORT" or item.get("source") == "input-report":
            return item
    return None


def _strip_prompt_echo_text(value: str) -> str:
    lines = []
    for line in str(value or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        stripped = line.strip()
        if stripped and any(marker.lower() in stripped.lower() for marker in PROMPT_ECHO_MARKERS):
            continue
        lines.append(line)
    cleaned = "\n".join(lines).strip()
    return cleaned or "摘要疑似为提示词回显，已隐藏。"


def _agent_config_from_payload(payload, role: str) -> Optional[AgentConfig]:
    raw = payload.get(f"{role}_agent") or {}
    name = ""
    instructions = ""
    if isinstance(raw, dict):
        name = str(raw.get("name") or "")
        instructions = str(raw.get("instructions") or "")
    elif raw:
        instructions = str(raw)
    name = str(payload.get(f"{role}_agent_name") or name).strip()
    instructions = str(payload.get(f"{role}_agent_instructions") or instructions).strip()
    if not name and not instructions:
        return None
    return AgentConfig(name=name, instructions=instructions)


def _agent_task_metadata(config: RunConfig) -> dict:
    return {
        "affirmative": to_jsonable(config.affirmative_agent) if config.affirmative_agent else None,
        "negative": to_jsonable(config.negative_agent) if config.negative_agent else None,
        "moderator": to_jsonable(config.moderator_agent) if config.moderator_agent else None,
    }


def _verdict_counts(run):
    counts = {}
    for report in run.get("reports", []):
        if finding_report_status(report) != FINDING_COMPLETED:
            continue
        verdict = report.get("verdict", "UNKNOWN")
        counts[verdict] = counts.get(verdict, 0) + 1
    return counts


def _export_run_markdown(run: dict) -> str:
    lines = [
        "# 漏洞研判报告",
        "",
        f"- 任务 ID：{run.get('run_id') or ''}",
        f"- 状态：{run.get('status', 'completed')}",
        f"- 任务来源：{_run_origin_label(normalize_run_origin(run))}",
        f"- 创建时间：{run.get('created_at') or ''}",
        f"- 输入报告：{run.get('sarif_path') or ''}",
        f"- 源码目录：{run.get('source_path') or ''}",
        f"- 语言：{', '.join(run.get('languages') or [])}",
        f"- 发现数：{run.get('finding_count', 0)}",
        f"- 项目知识库事实数：{run.get('project_context_facts', 0)}",
        "",
    ]
    diagnostics = run.get("diagnostics") or []
    if diagnostics:
        lines.extend(["## 运行诊断", ""])
        lines.extend(f"- {item}" for item in diagnostics)
        lines.append("")
    reports = run.get("reports") or []
    if not reports:
        lines.extend(["## 漏洞发现", "", "暂无漏洞发现记录。", ""])
        return "\n".join(lines).rstrip() + "\n"
    for index, report in enumerate(reports, start=1):
        lines.extend(
            [
                f"## 发现 {index}: {report.get('rule_id') or report.get('finding_id') or ''}",
                "",
                f"- 发现 ID：{report.get('finding_id') or ''}",
                f"- 研判状态：{finding_report_status(report)}",
                f"- 结论：{report.get('verdict') or ''}",
                f"- 置信度：{report.get('confidence')}",
                "",
                "### 人工复核",
                "",
                _manual_review_markdown(_manual_review_for(run, report.get("finding_id"))),
                "",
                "### 最终结论",
                "",
                _conclusion_without_graph(str(report.get("final_conclusion") or "无")),
                "",
                graph_to_markdown(_report_evidence_graph(report)).rstrip(),
                "",
                "### 摘要",
                "",
                str(report.get("reasoning_summary") or "无"),
                "",
                "### 研判用例",
                "",
                _verification_case_markdown(report),
                "",
                "### 证据评分卡",
                "",
                _scorecard_markdown(report),
                "",
                "### 证据台账",
                "",
                _evidence_ledger_markdown(report),
                "",
                "### 源码位置",
                "",
            ]
        )
        source_locations = report.get("source_locations") or []
        if source_locations:
            for location in source_locations:
                lines.append(f"- {_location_text(location)}")
        else:
            lines.append("- 无")
        lines.extend(
            [
                "",
                "### 防护研判",
                "",
                str(report.get("protection_assessment") or "无"),
                "",
                "### 影响研判",
                "",
                str(report.get("impact_assessment") or "无"),
                "",
            ]
        )
        disputed = report.get("disputed_points") or []
        if disputed:
            lines.extend(["### 争议点", ""])
            lines.extend(f"- {item}" for item in disputed)
            lines.append("")
        lines.extend(["### 博弈过程", ""])
        debate = report.get("debate") or []
        if debate:
            for turn in debate:
                lines.extend(
                    [
                        f"#### {_role_text(turn.get('role'))} 第 {turn.get('round_index')} 回合",
                        "",
                        str(turn.get("claim") or "").strip() or "无",
                        "",
                    ]
                )
                evidence_ids = turn.get("evidence_ids") or []
                if evidence_ids:
                    lines.extend(["引用证据：" + ", ".join(evidence_ids), ""])
                raw_claim = str(turn.get("raw_claim") or "").strip()
                claim = str(turn.get("claim") or "").strip()
                if raw_claim and raw_claim != claim:
                    lines.extend(
                        [
                            "<details><summary>原始输出</summary>",
                            "",
                            "```text",
                            raw_claim.rstrip(),
                            "```",
                            "",
                            "</details>",
                            "",
                        ]
                    )
        else:
            lines.extend(["无博弈过程记录。", ""])
        lines.extend(["### 证据链", ""])
        evidence_chain = report.get("evidence_chain") or []
        if evidence_chain:
            for item in evidence_chain:
                lines.append(
                    f"- `{item.get('evidence_id')}` {item.get('kind')} / {item.get('strength')} / {item.get('source')}：{item.get('summary')}"
                )
                locations = item.get("locations") or []
                if locations:
                    lines.append("  - 位置：" + " -> ".join(_location_text(location) for location in locations))
                snippet = item.get("snippet")
                if snippet:
                    lines.extend(["", "```text", str(snippet).rstrip(), "```", ""])
        else:
            lines.append("- 无")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _manual_review_markdown(review: Optional[dict]) -> str:
    if not isinstance(review, dict):
        return "未复核。"
    label = {
        "TRUE_POSITIVE": "真实漏洞",
        "FALSE_POSITIVE": "误报",
        "INCONCLUSIVE": "证据不足",
    }.get(str(review.get("decision") or ""), str(review.get("decision") or "未知"))
    evidence = str(review.get("evidence") or "").strip() or "未填写"
    return "\n".join(
        [
            f"- 人工结论：{label}",
            f"- 创建时间：{review.get('created_at') or ''}",
            f"- 更新时间：{review.get('updated_at') or ''}",
            "",
            "#### 人工证据",
            "",
            evidence,
        ]
    )


def _verification_case_markdown(report: dict) -> str:
    case = report.get("verification_case") if isinstance(report.get("verification_case"), dict) else {}
    if not case:
        return "无"
    lines = [
        f"- 漏洞类型/规则：{case.get('vulnerability_type') or '未知'}",
        f"- 报告消息：{case.get('reported_message') or '未知'}",
        f"- 报告位置：{case.get('reported_location') or '未知'}",
        f"- 报告源点：{case.get('reported_source') or '未提取'}",
        f"- 报告汇点/危险函数：{case.get('reported_sink') or case.get('dangerous_function') or '未提取'}",
        f"- 报告期望路径：{case.get('expected_attack_path') or '未提供 codeFlow'}",
    ]
    proof = case.get("required_proof") if isinstance(case.get("required_proof"), list) else []
    if proof:
        lines.append("- 必须闭环的证明要件：")
        lines.extend(f"  - {item}" for item in proof)
    return "\n".join(lines)


def _scorecard_markdown(report: dict) -> str:
    scorecard = report.get("scorecard") if isinstance(report.get("scorecard"), dict) else {}
    if not scorecard:
        return "无"
    rows = [
        ("源码定位", scorecard.get("source_location")),
        ("入口可达", scorecard.get("entry_reachability")),
        ("调用链", scorecard.get("call_chain")),
        ("数据流", scorecard.get("data_flow")),
        ("输入可控性", scorecard.get("controllability")),
        ("防护消减", scorecard.get("protection")),
        ("影响归因", scorecard.get("impact")),
    ]
    lines = [f"- {name}：{_status_text(status)}" for name, status in rows]
    if scorecard.get("verdict_label"):
        lines.append(f"- 结论标签：{scorecard.get('verdict_label')}")
    if scorecard.get("confidence") not in (None, ""):
        lines.append(f"- 置信度：{scorecard.get('confidence')}")
    rationale = scorecard.get("rationale") if isinstance(scorecard.get("rationale"), list) else []
    if rationale:
        lines.append("- 理由：")
        lines.extend(f"  - {item}" for item in rationale)
    return "\n".join(lines)


def _evidence_ledger_markdown(report: dict) -> str:
    ledger = report.get("evidence_ledger") if isinstance(report.get("evidence_ledger"), list) else []
    if not ledger:
        return "无"
    lines = []
    for item in ledger:
        if not isinstance(item, dict):
            continue
        evidence_ids = item.get("evidence_ids") if isinstance(item.get("evidence_ids"), list) else []
        evidence_text = "；证据：" + ", ".join(str(value) for value in evidence_ids[:8]) if evidence_ids else ""
        location = f"；位置：{item.get('location')}" if item.get("location") else ""
        lines.append(
            f"- {item.get('claim') or item.get('type') or item.get('id')}：{_status_text(item.get('status'))}"
            f"；来源：{item.get('source') or 'not-collected'}{location}{evidence_text}"
        )
    return "\n".join(lines) if lines else "无"


def _status_text(status) -> str:
    labels = {
        "confirmed": "已确认",
        "candidate": "候选/部分",
        "missing": "缺失",
        "invalid": "无效",
        "none": "未发现",
        "blocks": "已阻断",
    }
    return labels.get(str(status or ""), str(status or "未知"))


def _run_origin_label(origin: str) -> str:
    labels = {
        "web": "Web 端",
        "mcp": "MCP",
        "unknown": "未知来源",
    }
    return labels.get(str(origin or "unknown"), str(origin or "未知来源"))


def _report_evidence_graph(report: dict) -> dict:
    graph = report.get("evidence_graph")
    if isinstance(graph, dict) and graph.get("nodes"):
        return graph
    return build_evidence_graph(report.get("evidence_chain") or [], report.get("disputed_points") or [])


def _conclusion_without_graph(text: str) -> str:
    for marker in ("\n### 证据串联图", "\n### 调用链 / 数据流概览"):
        if marker in text:
            return text.split(marker, 1)[0].rstrip()
    if text.startswith("### 证据串联图") or text.startswith("### 调用链 / 数据流概览"):
        return ""
    return text.rstrip()


def _location_text(location) -> str:
    if not isinstance(location, dict):
        return str(location)
    file = str(location.get("file") or "")
    line = location.get("line")
    column = location.get("column")
    if line is None:
        return file
    if column is None:
        return f"{file}:{line}"
    return f"{file}:{line}:{column}"


def _role_text(role) -> str:
    return {
        "AFFIRMATIVE": "正方",
        "NEGATIVE": "反方",
        "MODERATOR": "主持人",
    }.get(str(role), str(role or "未知角色"))


def app_html() -> str:
    title = "漏洞研判记录"
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #17202a;
      --muted: #5f6b7a;
      --line: #d9dee7;
      --accent: #146c94;
      --tp: #1b7f49;
      --fp: #9a4d0a;
      --inc: #7161a5;
      --bad: #b42318;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--bg); color: var(--text); }}
    header {{
      min-height: 72px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 24px;
      padding: 18px 28px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
    }}
    h1 {{ margin: 0; font-size: 22px; line-height: 1.2; font-weight: 700; letter-spacing: 0; }}
    main {{
      display: grid;
      grid-template-columns: minmax(320px, 390px) minmax(0, 1fr);
      gap: 18px;
      padding: 18px;
      height: calc(100vh - 73px);
      min-height: 660px;
    }}
    button, input, select, textarea {{ font: inherit; }}
    button {{
      border: 1px solid var(--line);
      background: #ffffff;
      color: var(--text);
      border-radius: 6px;
      padding: 8px 11px;
      cursor: pointer;
    }}
    button:hover {{ border-color: var(--accent); color: #0d4f6f; }}
    button:disabled {{ cursor: not-allowed; opacity: 0.52; border-color: var(--line); color: var(--muted); }}
    button.danger-button {{
      border-color: #e19090;
      background: #fff1f1;
      color: #9a2f2f;
      font-weight: 700;
    }}
    button.danger-button:hover:not(:disabled) {{
      border-color: #b42318;
      background: #ffe4e1;
      color: #7f1d1d;
    }}
    button.toggle-active {{ border-color: var(--accent); background: #edf7fb; color: #0d4f6f; }}
    input, select, textarea {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px 10px;
      background: #ffffff;
      color: var(--text);
    }}
    textarea {{ min-height: 88px; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    [hidden] {{ display: none !important; }}
    label {{ display: grid; gap: 5px; font-size: 12px; color: var(--muted); }}
    .checkbox-row {{
      display: flex;
      align-items: center;
      gap: 8px;
      min-height: 34px;
      color: var(--text);
    }}
    .checkbox-row input[type="checkbox"] {{
      width: auto;
      min-height: 0;
      padding: 0;
    }}
    .toolbar {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
    .muted {{ color: var(--muted); }}
    .pane {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      min-width: 0;
      min-height: 0;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }}
    .pane-title {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 14px 16px;
      border-bottom: 1px solid var(--line);
      min-height: 54px;
    }}
    .pane-title h2 {{ margin: 0; font-size: 15px; line-height: 1.2; }}
    .scroll {{ overflow: auto; min-height: 0; }}
    .run-list {{ display: grid; gap: 0; }}
    .run-item {{
      display: grid;
      position: relative;
      content-visibility: auto;
      contain-intrinsic-size: auto 150px;
      gap: 8px;
      width: 100%;
      text-align: left;
      border: 0;
      border-bottom: 1px solid var(--line);
      border-radius: 0;
      padding: 15px;
      background: #ffffff;
    }}
    .run-item.active {{ box-shadow: inset 4px 0 0 var(--accent); background: #edf7fb; }}
    .run-item-headline {{
      display: grid;
      gap: 8px;
      padding-right: 92px;
    }}
    .run-item-actions {{
      position: absolute;
      top: 10px;
      right: 12px;
      display: flex;
      gap: 6px;
      align-items: center;
      justify-content: flex-end;
      z-index: 1;
    }}
    .run-id {{ font-weight: 700; overflow-wrap: anywhere; }}
    .path {{ color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }}
    .chips {{ display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }}
    .run-verdict-chips {{ flex-wrap: nowrap; overflow-x: auto; padding-bottom: 1px; }}
    .run-verdict-chips .chip {{ flex: 0 0 auto; }}
    .chip {{
      display: inline-flex;
      align-items: center;
      min-height: 22px;
      padding: 3px 7px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: #f8fafc;
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
    }}
    .chip.tp {{ color: var(--tp); border-color: #8fd4aa; background: #effaf3; }}
    .chip.fp {{ color: var(--fp); border-color: #edc391; background: #fff7ed; }}
    .chip.inc {{ color: var(--inc); border-color: #c9c1ef; background: #f6f3ff; }}
    .chip.origin {{ color: #31565d; border-color: #a8c8cd; background: #f0f8f9; }}
    .chip.status-chip {{
      font-weight: 700;
      border-width: 1.5px;
      box-shadow: inset 0 0 0 1px rgba(15, 23, 42, 0.03);
    }}
    .chip.status-completed {{ color: #17663a; border-color: #75c894; background: #eaf8ef; }}
    .chip.status-running {{ color: #0d4f6f; border-color: #74bdd8; background: #e8f6fb; }}
    .chip.status-stopped {{ color: #8a332c; border-color: #e0a29a; background: #fff1f0; }}
    .chip.status-stopping, .chip.status-pausing {{ color: #8a4b11; border-color: #e2b36f; background: #fff8e7; }}
    .chip.status-paused {{ color: #6c4a9f; border-color: #bfa9e8; background: #f6f0ff; }}
    .chip.status-failed {{ color: #9a2f2f; border-color: #e19090; background: #fff1f1; }}
    .chip.status-queued {{ color: #35516e; border-color: #9fb8d2; background: #eef6ff; }}
    .chip.status-pending {{ color: #6b4f16; border-color: #d8bd76; background: #fff9e8; }}
    .chip.status-in_progress {{ color: #0d4f6f; border-color: #74bdd8; background: #e8f6fb; }}
    .chip.run-delete {{ cursor: pointer; color: var(--bad); }}
    .chip.run-delete:hover {{ border-color: var(--bad); background: #fff1f0; }}
    .chip.run-delete.confirming {{ color: #fff; border-color: var(--bad); background: var(--bad); }}
    .chip.run-stop, .chip.run-pause, .chip.run-resume {{ cursor: pointer; color: var(--accent); }}
    .chip.run-stop:hover, .chip.run-pause:hover, .chip.run-resume:hover {{ border-color: var(--accent); background: #edf7fb; }}
    .content {{ padding: 16px; display: grid; gap: 16px; }}
    .detail-pane {{
      min-height: 0;
    }}
    .run-overview {{
      flex: 0 0 auto;
      border-bottom: 1px solid var(--line);
      background: #f8fafc;
      max-height: min(34vh, 330px);
      overflow: auto;
    }}
    .run-overview:empty {{ display: none; }}
    .run-overview-grid {{
      display: grid;
      gap: 0;
      padding: 12px;
    }}
    .overview-card {{
      min-width: 0;
      min-height: 0;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #ffffff;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }}
    .overview-head {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      min-height: 42px;
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
      background: #fbfcfe;
    }}
    .overview-head h3 {{ margin: 0; font-size: 14px; line-height: 1.25; }}
    .overview-body {{
      min-height: 0;
      padding: 12px;
      overflow: auto;
      display: grid;
      gap: 10px;
      align-content: start;
    }}
    .overview-summary {{
      display: grid;
      grid-template-columns: repeat(4, minmax(86px, 1fr));
      gap: 8px;
      margin-bottom: 2px;
    }}
    .overview-metric {{
      min-width: 0;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px;
      background: #fbfcfe;
    }}
    .overview-metric .label {{ color: var(--muted); font-size: 11px; }}
    .overview-metric .value {{ margin-top: 4px; font-size: 16px; font-weight: 700; overflow-wrap: anywhere; }}
    .findings-table-wrap {{
      min-height: 0;
      overflow-x: auto;
      overflow-y: visible;
    }}
    .findings-table-wrap table {{ min-width: 620px; }}
    .findings-table-wrap tbody tr {{
      content-visibility: auto;
      contain-intrinsic-size: auto 56px;
    }}
    .findings-table-wrap tr.active {{ background: #edf7fb; box-shadow: inset 4px 0 0 var(--accent); }}
    .manual-review-cell {{ width: 118px; white-space: nowrap; }}
    .manual-review-toggle {{ padding: 5px 8px; background: #fbfcfe; }}
    .manual-review-row > td {{ padding: 0; border-top: 0; background: #f8fafc; }}
    .manual-review-card {{
      display: grid;
      gap: 12px;
      padding: 14px;
      border: 1px solid #b9d8e5;
      border-left: 4px solid var(--accent);
      border-radius: 6px;
      background: #ffffff;
      margin: 8px;
    }}
    .manual-review-card h4 {{ margin: 0; font-size: 14px; }}
    .manual-review-options {{ display: flex; gap: 10px; flex-wrap: wrap; }}
    .manual-review-option {{
      display: inline-flex;
      grid-template-columns: none;
      align-items: center;
      gap: 6px;
      padding: 7px 10px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: #fbfcfe;
      color: var(--text);
      cursor: pointer;
      font-size: 13px;
    }}
    .manual-review-option input {{ width: auto; margin: 0; padding: 0; }}
    .manual-review-card textarea {{ min-height: 118px; }}
    .manual-review-meta {{ font-size: 12px; color: var(--muted); }}
    .manual-review-status {{ min-height: 20px; font-size: 12px; }}
    .findings-section {{
      overflow: visible;
    }}
    .selected-finding-sticky {{
      position: sticky;
      top: 0;
      z-index: 5;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #ffffff;
      box-shadow: 0 8px 18px rgba(15, 23, 42, 0.12);
      padding: 10px 12px;
      display: grid;
      grid-template-columns: auto minmax(0, 1fr) auto;
      gap: 10px;
      align-items: center;
    }}
    .selected-finding-sticky.hidden {{ display: none; }}
    .selected-finding-actions {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }}
    .finding-review-button {{
      height: 38px;
      min-width: 58px;
      padding: 0 13px;
      border-color: #b9d7e5;
      background: #ffffff;
      color: #0d4f6f;
      font-weight: 700;
      white-space: nowrap;
    }}
    .finding-review-button:hover {{
      border-color: var(--accent);
      background: #edf7fb;
      color: #08384f;
    }}
    .floating-manual-review {{
      position: absolute;
      top: calc(100% + 8px);
      right: 0;
      z-index: 8;
      width: min(520px, calc(100% - 24px));
      max-height: min(70vh, 640px);
      overflow: auto;
      border-radius: 8px;
      background: #ffffff;
      box-shadow: 0 18px 40px rgba(15, 23, 42, 0.2);
    }}
    .floating-manual-review .manual-review-card {{
      margin: 0;
      border-radius: 8px;
    }}
    .finding-nav-button {{
      width: 38px;
      height: 38px;
      min-width: 38px;
      padding: 0;
      border-radius: 999px;
      border-color: #b9d7e5;
      background: #edf7fb;
      color: #0d4f6f;
      font-size: 20px;
      font-weight: 700;
      line-height: 1;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      box-shadow: inset 0 0 0 1px rgba(20, 108, 148, 0.08);
    }}
    .finding-nav-button:hover {{
      border-color: var(--accent);
      background: #dff0f7;
      color: #08384f;
    }}
    .finding-nav-button:disabled {{
      background: #f8fafc;
      color: #a5afbd;
      border-color: var(--line);
      box-shadow: none;
    }}
    .selected-finding-main {{
      min-width: 0;
      display: grid;
      gap: 6px;
    }}
    .detail-scroll {{ flex: 1 1 auto; }}
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(120px, 1fr));
      gap: 10px;
    }}
    .metric {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fbfcfe;
      min-height: 76px;
    }}
    .metric .label {{ color: var(--muted); font-size: 12px; }}
    .metric .value {{ margin-top: 6px; font-size: 20px; font-weight: 700; overflow-wrap: anywhere; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 10px 9px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }}
    th {{ font-size: 12px; color: var(--muted); background: #fbfcfe; position: sticky; top: 0; }}
    tr.clickable {{ cursor: pointer; }}
    tr.clickable:hover {{ background: #f5fbff; }}
    .detail {{
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
      background: #ffffff;
    }}
    .detail h3 {{
      margin: 0;
      padding: 12px 14px;
      font-size: 14px;
      border-bottom: 1px solid var(--line);
      background: #fbfcfe;
    }}
    .detail-summary {{
      margin: 0;
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
      background: #fbfcfe;
      cursor: pointer;
      font-size: 14px;
      font-weight: 700;
    }}
    .detail-summary .chips {{
      display: inline-flex;
      margin-left: 10px;
      vertical-align: middle;
      font-weight: 400;
    }}
    details.detail:not([open]) .detail-summary {{
      border-bottom: 0;
    }}
    .detail-body {{ padding: 14px; display: grid; gap: 12px; }}
    #agent-affirmative-profile-panel,
    #agent-negative-profile-panel {{
      min-height: 560px;
      height: auto;
      overflow: visible;
    }}
    #integrations-modal .settings-body {{
      display: flex;
      flex-direction: column;
      gap: 16px;
      align-content: stretch;
    }}
    #integrations-modal .detail {{
      flex: 0 0 auto;
      min-width: 0;
      overflow: hidden;
      position: relative;
    }}
    #agent-affirmative-profile-panel .detail-body,
    #agent-negative-profile-panel .detail-body {{
      min-height: 500px;
      align-content: start;
      grid-auto-rows: max-content;
    }}
    #mcp-server-panel {{
      min-height: 0;
      height: auto;
    }}
    #skill-source-panel {{
      min-height: 0;
      height: auto;
    }}
    #mcp-server-panel .detail-body,
    #skill-source-panel .detail-body {{
      min-height: 0;
      align-content: start;
      grid-auto-rows: max-content;
    }}
    #mcp-server-panel textarea {{
      min-height: 68px;
    }}
    #mcp-description {{
      min-height: 54px;
    }}
    .form-grid {{ display: grid; grid-template-columns: repeat(2, minmax(160px, 1fr)); gap: 12px; }}
    .form-grid .wide {{ grid-column: 1 / -1; }}
    .run-agent-grid {{
      grid-column: 1 / -1;
      display: grid;
      grid-template-columns: repeat(2, minmax(160px, 1fr));
      gap: 12px;
    }}
    pre {{
      margin: 0;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      background: #111827;
      color: #f8fafc;
      border-radius: 6px;
      padding: 12px;
      font-size: 12px;
      line-height: 1.5;
      max-height: 280px;
      overflow: auto;
    }}
    .markdown-body {{
      display: grid;
      gap: 8px;
      line-height: 1.65;
      overflow-wrap: anywhere;
    }}
    .markdown-body p {{ margin: 0; }}
    .markdown-body ul,
    .markdown-body ol {{ margin: 0; padding-left: 22px; }}
    .markdown-body li {{ margin: 3px 0; }}
    .markdown-body li.task-item {{ list-style: none; margin-left: -18px; }}
    .markdown-body h1,
    .markdown-body h2,
    .markdown-body h3,
    .markdown-body h4 {{
      margin: 2px 0 0;
      font-size: 14px;
      line-height: 1.4;
    }}
    .markdown-body h5,
    .markdown-body h6 {{
      margin: 2px 0 0;
      font-size: 13px;
      line-height: 1.4;
    }}
    .markdown-body blockquote {{
      margin: 0;
      padding: 8px 10px;
      border-left: 3px solid var(--line);
      background: #f8fafc;
      color: var(--muted);
    }}
    .markdown-body table {{
      width: 100%;
      border-collapse: collapse;
      display: block;
      overflow-x: auto;
      white-space: normal;
      font-size: 12px;
    }}
    .markdown-body th,
    .markdown-body td {{
      border: 1px solid var(--line);
      padding: 6px 8px;
      text-align: left;
      vertical-align: top;
      position: static;
    }}
    .markdown-body th {{ background: #f8fafc; color: var(--text); }}
    .markdown-body hr {{ width: 100%; border: 0; border-top: 1px solid var(--line); margin: 4px 0; }}
    .markdown-body a {{ color: var(--accent); text-decoration: none; }}
    .markdown-body a:hover {{ text-decoration: underline; }}
    .markdown-body code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      background: #eef2f7;
      border-radius: 4px;
      padding: 1px 4px;
    }}
    .markdown-body pre {{
      max-height: none;
      white-space: pre-wrap;
    }}
    .markdown-body pre code {{ background: transparent; padding: 0; color: inherit; }}
    .markdown-field {{
      display: grid;
      gap: 5px;
    }}
    .markdown-field > strong {{
      color: var(--text);
    }}
    .codex-evidence-list {{
      display: grid;
      gap: 8px;
      margin: 0;
      padding-left: 20px;
    }}
    .codex-evidence-list > li {{
      padding-left: 2px;
    }}
    .debate-turn .markdown-body {{
      gap: 6px;
    }}
    .plain-text {{
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      line-height: 1.65;
    }}
    .plain-inline {{
      white-space: normal;
      overflow-wrap: anywhere;
    }}
    .debate-turn {{
      display: grid;
      gap: 8px;
    }}
    .debate-structured {{
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fbfcfe;
      overflow: hidden;
    }}
    .debate-structured summary {{
      cursor: pointer;
      padding: 8px 10px;
      color: var(--muted);
      font-weight: 700;
    }}
    .debate-structured .detail-body {{
      padding: 10px;
      border-top: 1px solid var(--line);
      background: #ffffff;
    }}
    .path-overview {{
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      line-height: 1.7;
      margin: 0;
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fbfcfe;
      color: var(--text);
    }}
    .empty {{ padding: 42px 18px; color: var(--muted); text-align: center; }}
    .error {{ color: var(--bad); }}
    .success {{ color: var(--tp); }}
    .modal-backdrop {{
      position: fixed;
      inset: 0;
      z-index: 20;
      display: none;
      align-items: stretch;
      justify-content: flex-end;
      background: rgba(15, 23, 42, 0.42);
    }}
    .modal-backdrop.open {{ display: flex; }}
    .settings-panel {{
      width: min(760px, 100%);
      height: 100%;
      background: var(--panel);
      border-left: 1px solid var(--line);
      display: flex;
      flex-direction: column;
      box-shadow: -18px 0 40px rgba(15, 23, 42, 0.18);
    }}
    .settings-head {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 18px 20px;
      border-bottom: 1px solid var(--line);
    }}
    .settings-head h2 {{ margin: 0; font-size: 18px; }}
    .settings-body {{ flex: 1 1 auto; min-height: 0; padding: 16px; overflow: auto; display: grid; gap: 16px; align-content: start; }}
    .profile-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
      gap: 10px;
      align-items: stretch;
      grid-auto-rows: minmax(220px, auto);
    }}
    .profile-card {{
      min-width: 0;
      min-height: 220px;
      height: 100%;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      background: #fbfcfe;
      display: flex;
      flex-direction: column;
      gap: 8px;
      overflow: hidden;
    }}
    .profile-card.starred {{ border-color: #f0c55a; background: #fffbeb; }}
    .profile-card.default {{ box-shadow: inset 3px 0 0 var(--accent); }}
    .profile-head {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; min-width: 0; }}
    .profile-title {{ font-weight: 700; overflow-wrap: anywhere; min-width: 0; }}
    .profile-path {{ color: var(--muted); font-size: 12px; line-height: 1.35; overflow-wrap: anywhere; }}
    .profile-preview {{
      color: var(--muted);
      font-size: 12px;
      line-height: 1.45;
      flex: 1 1 auto;
      overflow: hidden;
      display: -webkit-box;
      -webkit-line-clamp: 6;
      -webkit-box-orient: vertical;
    }}
    .profile-actions {{ display: flex; gap: 7px; flex-wrap: wrap; align-items: center; }}
    .profile-actions button {{ padding: 6px 9px; min-height: 30px; }}
    .profile-actions button:disabled {{ cursor: not-allowed; opacity: 0.52; border-color: var(--line); color: var(--muted); }}
    .codex-session-buttons {{ display: flex; gap: 8px; flex-wrap: wrap; }}
    .codex-terminal-frame-panel {{ width: min(1280px, 100%); height: min(860px, 94vh); }}
    .codex-terminal-frame-body {{ flex: 1 1 auto; padding: 0; display: block; min-height: 0; height: 100%; }}
    .codex-terminal-frame {{
      display: block;
      width: 100%;
      height: 100%;
      min-height: 560px;
      border: 0;
      background: #0d1117;
    }}
    @media (max-width: 900px) {{
      header {{ align-items: flex-start; flex-direction: column; }}
      main {{ grid-template-columns: 1fr; height: auto; min-height: 0; }}
      .pane {{ min-height: 360px; }}
      .overview-summary {{ grid-template-columns: repeat(2, minmax(86px, 1fr)); }}
      .summary-grid {{ grid-template-columns: repeat(2, minmax(120px, 1fr)); }}
      .form-grid {{ grid-template-columns: 1fr; }}
      .run-agent-grid {{ grid-template-columns: 1fr; }}
      .profile-grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1>漏洞研判记录</h1>
      <div class="muted" id="subtitle">静态报告漏洞研判历史</div>
    </div>
    <div class="toolbar">
      <button id="open-run-config" type="button" title="启动新的研判任务">启动任务</button>
      <button id="open-providers" type="button" title="配置 LLM 提供商">LLM 提供商</button>
      <button id="open-agent-prompts" type="button" title="配置 Agent 提示词">Agent 配置</button>
      <button id="open-integrations" type="button" title="配置 MCP Server 和项目 Skills">MCP / Skills</button>
      <button id="refresh" type="button" title="刷新记录">刷新</button>
      <button id="auto-refresh" type="button" title="没有运行中任务" aria-pressed="false" disabled>自动刷新：关</button>
      <button id="clear-selection" type="button" title="清空当前详情">清空</button>
    </div>
  </header>
  <main>
    <section class="pane" aria-label="运行记录">
      <div class="pane-title">
        <h2>任务</h2>
        <span class="muted" id="run-count">0 条记录</span>
      </div>
      <div class="scroll">
        <div class="run-list" id="run-list"></div>
      </div>
    </section>
    <section class="pane detail-pane" aria-label="运行详情和提供商设置">
      <div class="pane-title">
        <h2 id="detail-title">运行详情</h2>
        <span class="muted" id="detail-status">未选择任务</span>
      </div>
      <div class="run-overview" id="run-overview"></div>
      <div class="scroll detail-scroll" id="detail-scroll">
        <div class="content" id="detail"></div>
      </div>
    </section>
  </main>
  <div class="modal-backdrop" id="providers-modal" role="dialog" aria-modal="true" aria-labelledby="providers-title">
    <section class="settings-panel" aria-label="LLM 提供商设置">
      <div class="settings-head">
        <div>
          <h2 id="providers-title">LLM 提供商</h2>
          <div class="muted">为正方、反方和主持人 Agent 配置 OpenAI 兼容 API。</div>
        </div>
        <button id="close-providers" type="button" title="关闭提供商设置">关闭</button>
      </div>
      <div class="settings-body">
        <div class="detail" id="provider-panel">
          <h3>提供商配置</h3>
          <div class="detail-body">
            <div class="muted">保存的 API key 仅存储在本地；优先使用环境变量方式配置密钥。</div>
            <div class="form-grid">
              <label>ID<input id="provider-id" placeholder="openai-main"></label>
              <label>名称<input id="provider-name" placeholder="OpenAI 主模型"></label>
              <label class="wide">Endpoint 地址<input id="provider-endpoint" placeholder="https://api.openai.com/v1/chat/completions"></label>
              <label>模型<input id="provider-model" placeholder="gpt-4.1"></label>
              <label>API key 环境变量<input id="provider-key-env" placeholder="OPENAI_API_KEY"></label>
              <label class="wide">API key（可选明文）<input id="provider-key" type="password" placeholder="留空则保留当前已保存密钥"></label>
              <label class="wide">额外 JSON<textarea id="provider-extra" placeholder='{{"temperature":0.1,"max_tokens":1200}}'></textarea></label>
              <label>正方默认提供商<select id="default-affirmative"></select></label>
              <label>反方默认提供商<select id="default-negative"></select></label>
              <label>主持人默认提供商<select id="default-moderator"></select></label>
            </div>
            <div class="toolbar">
              <button id="save-provider" type="button">保存提供商</button>
              <button id="test-provider" type="button">测试当前提供商</button>
              <button id="delete-provider" type="button">删除当前提供商</button>
              <button id="save-defaults" type="button">保存默认值</button>
            </div>
            <div class="chips" id="provider-list"></div>
            <pre id="provider-result">尚未执行提供商连通性测试。</pre>
          </div>
        </div>
      </div>
    </section>
  </div>
  <div class="modal-backdrop" id="agent-prompts-modal" role="dialog" aria-modal="true" aria-labelledby="agent-prompts-title">
    <section class="settings-panel" aria-label="Agent 提示词设置">
      <div class="settings-head">
        <div>
          <h2 id="agent-prompts-title">Agent 配置</h2>
          <div class="muted">配置默认 AGENTS.md 文件，以及正方、反方和主持人的 AGENT.md 角色提示词。</div>
        </div>
        <button id="close-agent-prompts" type="button" title="关闭 Agent 提示词设置">关闭</button>
      </div>
      <div class="settings-body">
        <div class="detail" id="agents-md-config-panel">
          <h3>AGENTS.md 默认配置</h3>
          <div class="detail-body">
            <div class="muted">登记已有 AGENTS.md 文件并选择默认项；Web 不修改文件内容。相对路径以 Agent 配置目录为基准。</div>
            <div class="profile-grid" id="agents-md-config-list"></div>
            <div class="form-grid">
              <label>AGENTS.md 配置<select id="agents-md-config"></select></label>
              <label>配置 ID<input id="agents-md-config-id" placeholder="Agents_custom"></label>
              <label>配置名称<input id="agents-md-config-name" placeholder="安全审计默认配置"></label>
              <label class="wide">文件路径<input id="agents-md-config-path" placeholder="/path/to/AGENTS.md"></label>
              <label>默认配置<select id="default-agents-md-config"></select></label>
            </div>
            <div class="toolbar">
              <button id="new-agents-md-config" type="button">新增配置</button>
              <button id="save-agents-md-config" type="button">保存配置</button>
              <button id="delete-agents-md-config" type="button">删除配置</button>
              <button id="save-default-agents-md-config" type="button">保存默认配置</button>
            </div>
          </div>
        </div>
        <div class="detail" id="agent-affirmative-profile-panel">
          <h3>正方配置档案</h3>
          <div class="detail-body">
            <div class="profile-grid" id="agent-affirmative-profile-list"></div>
            <div class="form-grid">
              <label>正方配置档案<select id="agent-affirmative-profile"></select></label>
              <label>正方配置档案 ID<input id="agent-affirmative-profile-id" placeholder="Affirmative_default"></label>
              <label class="wide">正方 AGENT.md<textarea id="agent-affirmative-instructions"></textarea></label>
            </div>
            <div class="toolbar">
              <button id="new-affirmative-agent" type="button">新增正方 Agent</button>
              <button id="save-affirmative-agent" type="button">保存正方 Agent</button>
            </div>
          </div>
        </div>
        <div class="detail" id="agent-negative-profile-panel">
          <h3>反方配置档案</h3>
          <div class="detail-body">
            <div class="profile-grid" id="agent-negative-profile-list"></div>
            <div class="form-grid">
              <label>反方配置档案<select id="agent-negative-profile"></select></label>
              <label>反方配置档案 ID<input id="agent-negative-profile-id" placeholder="Negative_default"></label>
              <label class="wide">反方 AGENT.md<textarea id="agent-negative-instructions"></textarea></label>
            </div>
            <div class="toolbar">
              <button id="new-negative-agent" type="button">新增反方 Agent</button>
              <button id="save-negative-agent" type="button">保存反方 Agent</button>
            </div>
          </div>
        </div>
        <div class="detail" id="agent-moderator-profile-panel">
          <h3>主持人配置档案</h3>
          <div class="detail-body">
            <div class="profile-grid" id="agent-moderator-profile-list"></div>
            <div class="form-grid">
              <label>主持人配置档案<select id="agent-moderator-profile"></select></label>
              <label>主持人配置档案 ID<input id="agent-moderator-profile-id" placeholder="Moderator_default"></label>
              <label class="wide">主持人 AGENT.md<textarea id="agent-moderator-instructions"></textarea></label>
            </div>
            <div class="toolbar">
              <button id="new-moderator-agent" type="button">新增主持人 Agent</button>
              <button id="save-moderator-agent" type="button">保存主持人 Agent</button>
            </div>
          </div>
        </div>
        <div class="detail" id="agent-profile-actions">
          <h3>配置档案操作</h3>
          <div class="detail-body">
            <div class="toolbar">
              <button id="reset-agent-prompts" type="button">确保默认 Agent 存在</button>
            </div>
            <pre id="agent-prompts-result">尚未修改 Agent 提示词。</pre>
          </div>
        </div>
      </div>
    </section>
  </div>
  <div class="modal-backdrop" id="integrations-modal" role="dialog" aria-modal="true" aria-labelledby="integrations-title">
    <section class="settings-panel" aria-label="MCP 和 Skill 设置">
      <div class="settings-head">
        <div>
          <h2 id="integrations-title">MCP / Skills</h2>
          <div class="muted">配置本地 MCP Server 启动参数和项目知识库 Skill Source。</div>
        </div>
        <button id="close-integrations" type="button" title="关闭 MCP 和 Skill 设置">关闭</button>
      </div>
      <div class="settings-body">
        <div class="detail" id="mcp-server-panel">
          <h3>MCP Server</h3>
          <div class="detail-body">
            <div class="form-grid">
              <label>ID<input id="mcp-id" placeholder="atlas-default"></label>
              <label>名称<input id="mcp-name" placeholder="Atlas 默认 MCP"></label>
              <label>类型<input id="mcp-kind" value="atlas"></label>
              <label>命令<input id="mcp-command" placeholder="atlas"></label>
              <label class="wide checkbox-row"><input id="mcp-enabled" type="checkbox" checked> 启用 MCP Server</label>
              <label class="wide">参数 JSON<textarea id="mcp-args" placeholder='["mcp","--log-format","json"]'></textarea></label>
              <label class="wide">工作目录<input id="mcp-cwd" placeholder="{{project}}"></label>
              <label class="wide">环境变量 JSON<textarea id="mcp-env" placeholder='{{"HTTP_PROXY":"http://127.0.0.1:7890"}}'></textarea></label>
              <label class="wide">说明<textarea id="mcp-description" placeholder="本地 Atlas MCP Server"></textarea></label>
              <label>默认 Atlas MCP<select id="default-atlas-mcp"></select></label>
              <label>测试项目路径<input id="mcp-test-project" placeholder="/path/to/project"></label>
            </div>
            <div class="toolbar">
              <button id="save-mcp" type="button">保存 MCP</button>
              <button id="test-mcp" type="button">测试 MCP</button>
              <button id="delete-mcp" type="button">删除 MCP</button>
              <button id="save-mcp-defaults" type="button">保存默认 MCP</button>
            </div>
            <div class="chips" id="mcp-list"></div>
            <pre id="mcp-result">尚未测试 MCP Server。</pre>
          </div>
        </div>
        <div class="detail" id="skill-source-panel">
          <h3>Skill Source</h3>
          <div class="detail-body">
            <div class="form-grid">
              <label>ID<input id="skill-id" placeholder="faiss-kb"></label>
              <label>名称<input id="skill-name" placeholder="Faiss 项目知识库"></label>
              <label class="wide">路径<input id="skill-path" placeholder="/path/to/project/skills"></label>
              <label class="wide">说明<textarea id="skill-description" placeholder="项目架构、威胁建模、接口、资产等知识库。"></textarea></label>
              <label>默认 Skill Source<select id="default-skill-source"></select></label>
            </div>
            <div class="chips">
              <label><input id="skill-enabled" type="checkbox" checked> 启用</label>
              <label><input id="skill-starred" type="checkbox"> 星标</label>
            </div>
            <div class="toolbar">
              <button id="save-skill" type="button">保存 Skill Source</button>
              <button id="test-skill" type="button">测试加载</button>
              <button id="delete-skill" type="button">删除 Skill Source</button>
              <button id="save-skill-defaults" type="button">保存默认 Skill</button>
            </div>
            <div class="chips" id="skill-list"></div>
            <pre id="skill-result">尚未测试 Skill Source。</pre>
          </div>
        </div>
      </div>
    </section>
  </div>
  <div class="modal-backdrop" id="run-config-modal" role="dialog" aria-modal="true" aria-labelledby="run-config-title">
    <section class="settings-panel" aria-label="任务启动配置">
      <div class="settings-head">
        <div>
          <h2 id="run-config-title">启动任务</h2>
          <div class="muted">基于本地路径创建静态报告漏洞研判任务。</div>
        </div>
        <button id="close-run-config" type="button" title="关闭任务配置">关闭</button>
      </div>
      <div class="settings-body">
        <div class="detail" id="run-config-panel">
          <h3>任务配置</h3>
          <div class="detail-body">
            <div class="form-grid">
              <label class="wide">报告路径<input id="run-sarif" placeholder="fixtures/demo_sarif/report.sarif 或 report.md"></label>
              <label class="wide">源码路径<input id="run-source" placeholder="fixtures/demo_sarif/source"></label>
              <label class="wide checkbox-row" id="run-reuse-findings-option" hidden><input id="run-reuse-findings" type="checkbox" checked> 复用报告拆分结果 <span class="muted" id="run-reuse-findings-note"></span></label>
              <label>Skill Source<select id="run-skill-source"></select></label>
              <label class="wide">Skills 路径<input id="run-skills" placeholder="fixtures/demo_sarif/skills"></label>
              <label>执行引擎<select id="run-engine"><option value="codex" selected>Codex 三方复核</option><option value="opencode">OpenCode 三方复核</option><option value="builtin">内置旧流程</option></select></label>
              <label class="run-builtin-control" hidden>最大回合数<input id="run-max-rounds" type="number" min="1" value="4"></label>
              <label class="run-codex-control">静默提醒时间（分钟）<input id="run-silence-reminder-minutes" type="number" min="1" max="1440" value="{DEFAULT_SILENCE_REMINDER_MINUTES}"></label>
              <label class="run-opencode-control" hidden>OpenCode 模型<input id="run-opencode-model" placeholder="provider/model（留空使用 OpenCode 默认配置）"></label>
              <div class="run-agent-grid" id="run-provider-agent-grid">
                <label class="run-provider-control" hidden>正方提供商<select id="run-affirmative-provider"></select></label>
                <label class="run-agent-control">正方 Agent 配置档案<select id="run-affirmative-agent-profile"></select></label>
                <label class="run-provider-control" hidden>反方提供商<select id="run-negative-provider"></select></label>
                <label class="run-agent-control">反方 Agent 配置档案<select id="run-negative-agent-profile"></select></label>
                <label class="run-provider-control" hidden>主持人提供商<select id="run-moderator-provider"></select></label>
                <label class="run-agent-control">主持人 Agent 配置档案<select id="run-moderator-agent-profile"></select></label>
              </div>
            </div>
            <div class="chips" id="run-tool-provider-options">
              <label><input id="run-external-tools" type="checkbox" checked> 启用外部工具</label>
              <label><input id="run-auto-index" type="checkbox"> 预热 Atlas 持久缓存</label>
              <label><input id="run-llm" type="checkbox"> 使用 LLM 博弈</label>
            </div>
            <div class="muted" id="run-codex-config-note" hidden></div>
            <div class="toolbar">
              <button id="start-run" type="button">启动任务</button>
            </div>
            <pre id="run-result">尚未启动任务。</pre>
          </div>
        </div>
      </div>
    </section>
  </div>
  <div class="modal-backdrop" id="codex-terminal-frame-modal" role="dialog" aria-modal="true" aria-labelledby="codex-terminal-frame-title">
    <section class="settings-panel codex-terminal-frame-panel" aria-label="Codex TUI">
      <div class="settings-head">
        <div>
          <h2 id="codex-terminal-frame-title">Codex TUI</h2>
          <div class="muted" id="codex-terminal-frame-meta">未连接</div>
        </div>
        <button id="close-codex-terminal-frame" type="button" title="关闭 Codex TUI">关闭</button>
      </div>
      <div class="settings-body codex-terminal-frame-body">
        <iframe id="codex-terminal-frame" class="codex-terminal-frame" title="Codex TUI"></iframe>
      </div>
    </section>
  </div>
  <script>
    const state = {{ runs: [], selectedRun: null, selectedFinding: null, currentRun: null, currentFindings: [], providers: [], defaults: {{}}, agentPrompts: {{}}, mcpServers: [], mcpDefaults: {{}}, skillSources: [], skillDefaults: {{}}, pollTimer: null, pollInFlight: false, autoRefreshEnabled: false, runListSignature: '', findingDetailCache: {{}}, reuseFindingsFromRunId: null, deleteConfirmRunId: null, expandedManualReviewKey: null, floatingManualReviewKey: null, manualReviewDrafts: {{}} }};
    const MANUAL_REVIEW_EVIDENCE_MAX_LENGTH = {MANUAL_REVIEW_EVIDENCE_MAX_LENGTH};
    const el = {{
      list: document.getElementById('run-list'),
      count: document.getElementById('run-count'),
      overview: document.getElementById('run-overview'),
      detail: document.getElementById('detail'),
      detailScroll: document.getElementById('detail-scroll'),
      title: document.getElementById('detail-title'),
      status: document.getElementById('detail-status'),
      subtitle: document.getElementById('subtitle'),
      providerList: document.getElementById('provider-list'),
      providersModal: document.getElementById('providers-modal'),
      agentPromptsModal: document.getElementById('agent-prompts-modal'),
      integrationsModal: document.getElementById('integrations-modal'),
      runConfigModal: document.getElementById('run-config-modal'),
      codexTerminalFrameModal: document.getElementById('codex-terminal-frame-modal'),
      codexTerminalFrameTitle: document.getElementById('codex-terminal-frame-title'),
      codexTerminalFrameMeta: document.getElementById('codex-terminal-frame-meta'),
      codexTerminalFrame: document.getElementById('codex-terminal-frame'),
      autoRefresh: document.getElementById('auto-refresh'),
      providerResult: document.getElementById('provider-result'),
      agentPromptsResult: document.getElementById('agent-prompts-result'),
      mcpResult: document.getElementById('mcp-result'),
      skillResult: document.getElementById('skill-result'),
      providerId: document.getElementById('provider-id'),
      providerName: document.getElementById('provider-name'),
      providerEndpoint: document.getElementById('provider-endpoint'),
      providerModel: document.getElementById('provider-model'),
      providerKeyEnv: document.getElementById('provider-key-env'),
      providerKey: document.getElementById('provider-key'),
      providerExtra: document.getElementById('provider-extra'),
      defaultAffirmative: document.getElementById('default-affirmative'),
      defaultNegative: document.getElementById('default-negative'),
      defaultModerator: document.getElementById('default-moderator'),
      mcpList: document.getElementById('mcp-list'),
      mcpId: document.getElementById('mcp-id'),
      mcpName: document.getElementById('mcp-name'),
      mcpKind: document.getElementById('mcp-kind'),
      mcpCommand: document.getElementById('mcp-command'),
      mcpArgs: document.getElementById('mcp-args'),
      mcpCwd: document.getElementById('mcp-cwd'),
      mcpEnv: document.getElementById('mcp-env'),
      mcpDescription: document.getElementById('mcp-description'),
      mcpEnabled: document.getElementById('mcp-enabled'),
      defaultAtlasMcp: document.getElementById('default-atlas-mcp'),
      mcpTestProject: document.getElementById('mcp-test-project'),
      skillList: document.getElementById('skill-list'),
      skillId: document.getElementById('skill-id'),
      skillName: document.getElementById('skill-name'),
      skillPath: document.getElementById('skill-path'),
      skillDescription: document.getElementById('skill-description'),
      skillEnabled: document.getElementById('skill-enabled'),
      skillStarred: document.getElementById('skill-starred'),
      defaultSkillSource: document.getElementById('default-skill-source'),
      agentAffirmativeProfileList: document.getElementById('agent-affirmative-profile-list'),
      agentNegativeProfileList: document.getElementById('agent-negative-profile-list'),
      agentModeratorProfileList: document.getElementById('agent-moderator-profile-list'),
      agentAffirmativeProfile: document.getElementById('agent-affirmative-profile'),
      agentNegativeProfile: document.getElementById('agent-negative-profile'),
      agentModeratorProfile: document.getElementById('agent-moderator-profile'),
      agentAffirmativeProfileId: document.getElementById('agent-affirmative-profile-id'),
      agentNegativeProfileId: document.getElementById('agent-negative-profile-id'),
      agentModeratorProfileId: document.getElementById('agent-moderator-profile-id'),
      agentAffirmativeInstructions: document.getElementById('agent-affirmative-instructions'),
      agentNegativeInstructions: document.getElementById('agent-negative-instructions'),
      agentModeratorInstructions: document.getElementById('agent-moderator-instructions'),
      agentsMdConfigList: document.getElementById('agents-md-config-list'),
      agentsMdConfig: document.getElementById('agents-md-config'),
      agentsMdConfigId: document.getElementById('agents-md-config-id'),
      agentsMdConfigName: document.getElementById('agents-md-config-name'),
      agentsMdConfigPath: document.getElementById('agents-md-config-path'),
      defaultAgentsMdConfig: document.getElementById('default-agents-md-config'),
      runSarif: document.getElementById('run-sarif'),
      runSource: document.getElementById('run-source'),
      runReuseFindingsOption: document.getElementById('run-reuse-findings-option'),
      runReuseFindings: document.getElementById('run-reuse-findings'),
      runReuseFindingsNote: document.getElementById('run-reuse-findings-note'),
      runSkillSource: document.getElementById('run-skill-source'),
      runSkills: document.getElementById('run-skills'),
      runEngine: document.getElementById('run-engine'),
      runMaxRounds: document.getElementById('run-max-rounds'),
      runSilenceReminderMinutes: document.getElementById('run-silence-reminder-minutes'),
      runOpenCodeModel: document.getElementById('run-opencode-model'),
      runProviderAgentGrid: document.getElementById('run-provider-agent-grid'),
      runToolProviderOptions: document.getElementById('run-tool-provider-options'),
      runCodexConfigNote: document.getElementById('run-codex-config-note'),
      runAffirmativeProvider: document.getElementById('run-affirmative-provider'),
      runNegativeProvider: document.getElementById('run-negative-provider'),
      runModeratorProvider: document.getElementById('run-moderator-provider'),
      runAffirmativeAgentProfile: document.getElementById('run-affirmative-agent-profile'),
      runNegativeAgentProfile: document.getElementById('run-negative-agent-profile'),
      runModeratorAgentProfile: document.getElementById('run-moderator-agent-profile'),
      runExternalTools: document.getElementById('run-external-tools'),
      runAutoIndex: document.getElementById('run-auto-index'),
      runLlm: document.getElementById('run-llm'),
      runResult: document.getElementById('run-result'),
    }};

    document.getElementById('open-run-config').addEventListener('click', async () => {{
      configureRunFindingsReuse(null);
      el.runConfigModal.classList.add('open');
      await Promise.all([loadProviders(), loadAgentPrompts(), loadIntegrations()]);
      updateRunEngineVisibility();
    }});
    document.getElementById('close-run-config').addEventListener('click', () => {{
      el.runConfigModal.classList.remove('open');
    }});
    el.runConfigModal.addEventListener('click', (event) => {{
      if (event.target === el.runConfigModal) el.runConfigModal.classList.remove('open');
    }});
    document.getElementById('close-codex-terminal-frame').addEventListener('click', closeCodexTerminal);
    el.codexTerminalFrameModal.addEventListener('click', (event) => {{
      if (event.target === el.codexTerminalFrameModal) closeCodexTerminal();
    }});
    document.getElementById('open-providers').addEventListener('click', async () => {{
      el.providersModal.classList.add('open');
      await loadProviders();
    }});
    document.getElementById('close-providers').addEventListener('click', () => {{
      el.providersModal.classList.remove('open');
    }});
    el.providersModal.addEventListener('click', (event) => {{
      if (event.target === el.providersModal) el.providersModal.classList.remove('open');
    }});
    document.getElementById('open-agent-prompts').addEventListener('click', async () => {{
      el.agentPromptsModal.classList.add('open');
      await loadAgentPrompts();
    }});
    document.getElementById('close-agent-prompts').addEventListener('click', () => {{
      el.agentPromptsModal.classList.remove('open');
    }});
    el.agentPromptsModal.addEventListener('click', (event) => {{
      if (event.target === el.agentPromptsModal) el.agentPromptsModal.classList.remove('open');
    }});
    document.getElementById('open-integrations').addEventListener('click', async () => {{
      el.integrationsModal.classList.add('open');
      await loadIntegrations();
    }});
    document.getElementById('close-integrations').addEventListener('click', () => {{
      el.integrationsModal.classList.remove('open');
    }});
    el.integrationsModal.addEventListener('click', (event) => {{
      if (event.target === el.integrationsModal) el.integrationsModal.classList.remove('open');
    }});
    document.getElementById('refresh').addEventListener('click', refreshAll);
    el.autoRefresh.addEventListener('click', toggleAutoRefresh);
    el.list.addEventListener('click', handleRunListClick);
    el.list.addEventListener('keydown', handleRunListKeydown);
    el.detailScroll.addEventListener('scroll', updateStickyFindingVisibility);
    document.getElementById('clear-selection').addEventListener('click', () => {{
      const previousRunId = state.selectedRun;
      state.selectedRun = null;
      state.selectedFinding = null;
      state.currentFindings = [];
      updateSelectedRunCard(previousRunId, null);
      renderEmpty('选择一个任务查看发现、证据和博弈回合。');
    }});
    document.getElementById('save-provider').addEventListener('click', saveProvider);
    document.getElementById('test-provider').addEventListener('click', testProvider);
    document.getElementById('delete-provider').addEventListener('click', deleteProvider);
    document.getElementById('save-defaults').addEventListener('click', saveDefaults);
    document.getElementById('new-affirmative-agent').addEventListener('click', () => newAgentProfile('affirmative'));
    document.getElementById('new-negative-agent').addEventListener('click', () => newAgentProfile('negative'));
    document.getElementById('new-moderator-agent').addEventListener('click', () => newAgentProfile('moderator'));
    document.getElementById('save-affirmative-agent').addEventListener('click', () => saveAgentProfile('affirmative'));
    document.getElementById('save-negative-agent').addEventListener('click', () => saveAgentProfile('negative'));
    document.getElementById('save-moderator-agent').addEventListener('click', () => saveAgentProfile('moderator'));
    document.getElementById('new-agents-md-config').addEventListener('click', newAgentsMdConfig);
    document.getElementById('save-agents-md-config').addEventListener('click', saveAgentsMdConfig);
    document.getElementById('delete-agents-md-config').addEventListener('click', deleteAgentsMdConfig);
    document.getElementById('save-default-agents-md-config').addEventListener('click', saveDefaultAgentsMdConfig);
    el.agentsMdConfig.addEventListener('change', fillAgentsMdConfigEditor);
    document.getElementById('reset-agent-prompts').addEventListener('click', resetAgentPrompts);
    document.getElementById('save-mcp').addEventListener('click', saveMcpServer);
    document.getElementById('test-mcp').addEventListener('click', testMcpServer);
    document.getElementById('delete-mcp').addEventListener('click', deleteMcpServer);
    document.getElementById('save-mcp-defaults').addEventListener('click', saveMcpDefaults);
    document.getElementById('save-skill').addEventListener('click', saveSkillSource);
    document.getElementById('test-skill').addEventListener('click', testSkillSource);
    document.getElementById('delete-skill').addEventListener('click', deleteSkillSource);
    document.getElementById('save-skill-defaults').addEventListener('click', saveSkillDefaults);
    document.getElementById('start-run').addEventListener('click', startRun);
    el.runEngine.addEventListener('change', updateRunEngineVisibility);
    el.runAffirmativeProvider.addEventListener('change', enableRunLlmForSelectedProviders);
    el.runNegativeProvider.addEventListener('change', enableRunLlmForSelectedProviders);
    el.runModeratorProvider.addEventListener('change', enableRunLlmForSelectedProviders);
    el.runSkillSource.addEventListener('change', fillRunSkillSource);
    el.agentAffirmativeProfile.addEventListener('change', () => fillAgentProfileEditor('affirmative'));
    el.agentNegativeProfile.addEventListener('change', () => fillAgentProfileEditor('negative'));
    el.agentModeratorProfile.addEventListener('change', () => fillAgentProfileEditor('moderator'));

    function esc(value) {{
      return String(value ?? '').replace(/[&<>"']/g, ch => ({{
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
      }}[ch]));
    }}
    const promptEchoPatterns = [
      /AGENT\\.md/i,
      /Agent\\s*配置/i,
      /角色配置/,
      /角色名称/,
      /提示词/,
      /用户要求/,
      /任务要求/,
      /格式要求/,
      /格式说明/,
      /结论标签固定/,
      /标签约束/,
      /强约束/,
      /分析请求/,
      /必须遵守/,
      /之前的分析/,
      /禁止编造/,
      /每个具体论断/,
      /输出必须/,
      /只输出/,
      /只返回/,
      /证据解释约束/,
      /SOURCE_ROOT\\s*只能证明/i,
      /rg\\/grep\\s*证据必须/i
    ];
    function displayText(value) {{
      const raw = String(value ?? '').replace(/\\r\\n?/g, '\\n');
      if (!raw.trim()) return '';
      const kept = raw.split('\\n').filter(line => {{
        const trimmed = line.trim();
        if (!trimmed) return true;
        return !promptEchoPatterns.some(pattern => pattern.test(trimmed));
      }}).join('\\n').trim();
      return kept || '内容疑似为提示词回显，已隐藏。';
    }}
    function plainText(value) {{
      return esc(displayText(value));
    }}
    function plainInlineText(value) {{
      return esc(displayText(value).replace(/\\s+/g, ' ').trim());
    }}
    function rawText(value) {{
      return esc(String(value ?? '').replace(/\\r\\n?/g, '\\n'));
    }}
    function renderMarkdown(value) {{
      const text = String(value ?? '').replace(/\\r\\n?/g, '\\n');
      if (!text.trim()) return '';
      const lines = text.split('\\n');
      const html = [];
      const listStack = [];
      let inCode = false;
      let codeLang = '';
      let codeLines = [];
      let paragraph = [];

      function closeLists(targetIndent = -1) {{
        while (listStack.length && listStack[listStack.length - 1].indent >= targetIndent) {{
          const item = listStack.pop();
          html.push(`</${{item.type}}>`);
        }}
      }}
      function ensureList(type, indent) {{
        while (listStack.length && listStack[listStack.length - 1].indent > indent) {{
          const item = listStack.pop();
          html.push(`</${{item.type}}>`);
        }}
        let current = listStack[listStack.length - 1];
        if (current && current.indent === indent && current.type !== type) {{
          const item = listStack.pop();
          html.push(`</${{item.type}}>`);
          current = listStack[listStack.length - 1];
        }}
        if (!current || current.indent < indent || current.type !== type) {{
          html.push(`<${{type}}>`);
          listStack.push({{ type, indent }});
        }}
      }}
      function flushParagraph() {{
        if (!paragraph.length) return;
        html.push(`<p>${{paragraph.map(inlineMarkdown).join('<br>')}}</p>`);
        paragraph = [];
      }}
      function flushCode() {{
        const langClass = codeLang ? ` class="language-${{esc(codeLang)}}"` : '';
        html.push(`<pre><code${{langClass}}>${{esc(codeLines.join('\\n'))}}</code></pre>`);
        codeLines = [];
        codeLang = '';
      }}
      function safeUrl(raw) {{
        const url = String(raw || '').trim();
        if (/^(https?:|mailto:|#|\\/)/i.test(url)) return esc(url);
        return '#';
      }}
      function inlineMarkdown(raw) {{
        const codes = [];
        let prepared = String(raw ?? '').replace(/`([^`]+)`/g, (_match, code) => {{
          const token = `@@CODE${{codes.length}}@@`;
          codes.push(`<code>${{esc(code)}}</code>`);
          return token;
        }});
        let output = esc(prepared);
        output = output.replace(/\\[([^\\]]+)\\]\\(([^)\\s]+)(?:\\s+&quot;[^&]*&quot;)?\\)/g, (_match, label, href) => (
          `<a href="${{safeUrl(href)}}" target="_blank" rel="noreferrer noopener">${{label}}</a>`
        ));
        output = output.replace(/\\*\\*([^*]+)\\*\\*/g, '<strong>$1</strong>');
        output = output.replace(/__([^_]+)__/g, '<strong>$1</strong>');
        output = output.replace(/~~([^~]+)~~/g, '<del>$1</del>');
        output = output.replace(/(^|\\s)\\*([^*\\s][^*]*?)\\*/g, '$1<em>$2</em>');
        output = output.replace(/(^|\\s)_([^_\\s][^_]*?)_/g, '$1<em>$2</em>');
        codes.forEach((code, index) => {{
          output = output.replaceAll(`@@CODE${{index}}@@`, code);
        }});
        return output;
      }}
      function isTableSeparator(line) {{
        return /^\\s*\\|?\\s*:?-{{3,}}:?(\\s*\\|\\s*:?-{{3,}}:?)*\\s*\\|?\\s*$/.test(line);
      }}
      function looksLikeTable(index) {{
        return index + 1 < lines.length && lines[index].includes('|') && isTableSeparator(lines[index + 1]);
      }}
      function splitTableRow(row) {{
        let trimmed = row.trim();
        if (trimmed.startsWith('|')) trimmed = trimmed.slice(1);
        if (trimmed.endsWith('|')) trimmed = trimmed.slice(0, -1);
        return trimmed.split('|').map(cell => cell.trim());
      }}
      function renderTable(start) {{
        const headers = splitTableRow(lines[start]);
        let index = start + 2;
        const rows = [];
        while (index < lines.length && lines[index].includes('|') && lines[index].trim()) {{
          rows.push(splitTableRow(lines[index]));
          index += 1;
        }}
        html.push('<table><thead><tr>' + headers.map(cell => `<th>${{inlineMarkdown(cell)}}</th>`).join('') + '</tr></thead><tbody>');
        for (const row of rows) {{
          html.push('<tr>' + headers.map((_header, column) => `<td>${{inlineMarkdown(row[column] || '')}}</td>`).join('') + '</tr>');
        }}
        html.push('</tbody></table>');
        return index;
      }}
      function renderListItem(type, indent, content) {{
        flushParagraph();
        ensureList(type, indent);
        const task = content.match(/^\\[([ xX])\\]\\s+(.+)$/);
        if (task) {{
          const checked = task[1].toLowerCase() === 'x' ? ' checked' : '';
          html.push(`<li class="task-item"><input type="checkbox" disabled${{checked}}> ${{inlineMarkdown(task[2])}}</li>`);
        }} else {{
          html.push(`<li>${{inlineMarkdown(content)}}</li>`);
        }}
      }}

      for (let index = 0; index < lines.length; index += 1) {{
        const line = lines[index];
        const fence = line.match(/^```\\s*([^`]*)\\s*$/);
        if (fence) {{
          if (inCode) {{
            flushCode();
            inCode = false;
          }} else {{
            flushParagraph();
            closeLists();
            inCode = true;
            codeLang = (fence[1] || '').trim().split(/\\s+/)[0] || '';
            codeLines = [];
          }}
          continue;
        }}
        if (inCode) {{
          codeLines.push(line);
          continue;
        }}
        if (!line.trim()) {{
          flushParagraph();
          closeLists();
          continue;
        }}
        if (looksLikeTable(index)) {{
          flushParagraph();
          closeLists();
          index = renderTable(index) - 1;
          continue;
        }}
        const heading = line.match(/^(#{{1,6}})\\s+(.+)$/);
        if (heading) {{
          flushParagraph();
          closeLists();
          const level = heading[1].length;
          html.push(`<h${{level}}>${{inlineMarkdown(heading[2])}}</h${{level}}>`);
          continue;
        }}
        if (/^\\s*(-{{3,}}|_{{3,}}|\\*{{3,}})\\s*$/.test(line)) {{
          flushParagraph();
          closeLists();
          html.push('<hr>');
          continue;
        }}
        const quote = line.match(/^>\\s?(.+)$/);
        if (quote) {{
          flushParagraph();
          closeLists();
          html.push(`<blockquote>${{inlineMarkdown(quote[1])}}</blockquote>`);
          continue;
        }}
        const unordered = line.match(/^(\\s*)[-*+]\\s+(.+)$/);
        if (unordered) {{
          renderListItem('ul', unordered[1].length, unordered[2]);
          continue;
        }}
        const ordered = line.match(/^(\\s*)\\d+[.)]\\s+(.+)$/);
        if (ordered) {{
          renderListItem('ol', ordered[1].length, ordered[2]);
          continue;
        }}
        closeLists();
        paragraph.push(line.trim());
      }}
      if (inCode) flushCode();
      flushParagraph();
      closeLists();
      return html.join('');
    }}
    function markdownBlock(value, fallback = '') {{
      const text = displayText(value);
      if (!text.trim()) return fallback ? `<div class="muted">${{esc(fallback)}}</div>` : '';
      return `<div class="markdown-body">${{renderMarkdown(text)}}</div>`;
    }}
    function markdownField(label, value, fallback = '') {{
      const body = markdownBlock(value, fallback);
      if (!body) return '';
      return `<div class="markdown-field"><strong>${{esc(label)}}：</strong>${{body}}</div>`;
    }}
    function markdownList(label, values) {{
      const items = (Array.isArray(values) ? values : []).map(value => displayText(value)).filter(Boolean);
      if (!items.length) return '';
      return `<div class="markdown-field"><strong>${{esc(label)}}：</strong><div class="markdown-body"><ul>
        ${{items.map(value => `<li>${{renderMarkdown(value)}}</li>`).join('')}}
      </ul></div></div>`;
    }}
    function fmtDate(value) {{
      if (!value) return '未知时间';
      const date = new Date(value);
      return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
    }}
    function statusLabel(status) {{
      const labels = {{
        running: '运行中',
        pausing: '正在暂停',
        paused: '已暂停',
        stopping: '正在停止',
        stopped: '已停止',
        completed: '已完成',
        failed: '失败',
        queued: '排队中'
      }};
      return labels[status] || status || '未知状态';
    }}
    function statusChipClass(status) {{
      const normalized = String(status || 'completed').toLowerCase().replace(/[^a-z0-9_-]+/g, '-');
      return `chip status-chip status-${{normalized || 'unknown'}}`;
    }}
    function runOriginLabel(run) {{
      const origin = String((run && (run.run_origin || run.origin || run.task_origin)) || '').toLowerCase();
      if (origin === 'web') return 'Web 端';
      if (origin === 'mcp') return 'MCP';
      if (run && run.config && typeof run.config === 'object' && Object.keys(run.config).length) return 'Web 端';
      if (run && Object.prototype.hasOwnProperty.call(run, 'source_finding_count')) return 'MCP';
      return '未知来源';
    }}
    function verdictLabel(verdict) {{
      const labels = {{
        TRUE_POSITIVE: '真实漏洞',
        FALSE_POSITIVE: '误报',
        INCONCLUSIVE: '证据不足'
      }};
      return labels[verdict] || verdict || '未知结论';
    }}
    function findingStatusLabel(status) {{
      const labels = {{
        pending: '未完成',
        in_progress: '处理中',
        completed: '已完成'
      }};
      return labels[status] || status || '未完成';
    }}
    function findingStatusChip(finding) {{
      const status = finding && finding.finding_status ? finding.finding_status : 'completed';
      if (status === 'completed') {{
        return `<span class="chip ${{verdictClass(finding.verdict)}}">${{esc(verdictLabel(finding.verdict))}}</span>`;
      }}
      return `<span class="${{statusChipClass(status)}}">${{esc(findingStatusLabel(status))}}</span>`;
    }}
    function roleLabel(role) {{
      const labels = {{
        AFFIRMATIVE: '正方',
        NEGATIVE: '反方',
        MODERATOR: '主持人',
        affirmative: '正方',
        negative: '反方',
        moderator: '主持人',
        Affirmative: '正方',
        Negative: '反方',
        Moderator: '主持人'
      }};
      return labels[role] || role || '未知角色';
    }}
    function evidenceKindLabel(kind) {{
      const labels = {{
        REPORT: '输入报告',
        SOURCE_ROOT: '源码根目录',
        SOURCE_LOCATION: '源码位置',
        SARIF_CODE_FLOW: 'SARIF 代码流',
        CALL_CHAIN: '调用链',
        DATA_FLOW: '数据流',
        PROTECTION: '防护证据',
        IMPACT: '影响证据',
        TOOL_DIAGNOSTIC: '工具诊断',
        PROJECT_CONTEXT: '项目上下文'
      }};
      return labels[kind] || kind || '未知证据';
    }}
    function evidenceStrengthLabel(strength) {{
      const labels = {{
        STRONG: '强',
        MEDIUM: '中',
        WEAK: '弱',
        PARTIAL: '部分'
      }};
      return labels[strength] || strength || '未知强度';
    }}
    function verdictClass(verdict) {{
      if (verdict === 'TRUE_POSITIVE') return 'tp';
      if (verdict === 'FALSE_POSITIVE') return 'fp';
      if (verdict === 'INCONCLUSIVE') return 'inc';
      return '';
    }}
    async function fetchJson(url, options) {{
      const response = await fetch(url, options);
      if (!response.ok) {{
        const body = await response.text();
        throw new Error(`${{response.status}} ${{response.statusText}}: ${{body}}`);
      }}
      return response.json();
    }}
    function jsonPost(body) {{
      return {{ method: 'POST', headers: {{ 'content-type': 'application/json' }}, body: JSON.stringify(body || {{}}) }};
    }}
    function jsonPut(body) {{
      return {{ method: 'PUT', headers: {{ 'content-type': 'application/json' }}, body: JSON.stringify(body || {{}}) }};
    }}

    async function refreshAll() {{
      const selectedRun = state.selectedRun;
      await Promise.all([loadProviders(), loadAgentPrompts(), loadIntegrations(), loadRuns()]);
      if (selectedRun && state.runs.some(run => run.run_id === selectedRun)) {{
        await refreshSelectedRun(false);
      }}
    }}

    async function refreshSelectedRun(resetFinding = false) {{
      if (!state.selectedRun) return;
      await selectRun(state.selectedRun, resetFinding);
    }}

    async function loadProviders() {{
      try {{
        const [providers, defaults] = await Promise.all([fetchJson('/providers'), fetchJson('/providers/defaults')]);
        state.providers = providers;
        state.defaults = defaults;
        renderProviders();
      }} catch (error) {{
        el.providerResult.textContent = error.message;
      }}
    }}

    async function loadAgentPrompts() {{
      try {{
        state.agentPrompts = await fetchJson('/agent-prompts');
        renderAgentPrompts();
      }} catch (error) {{
        el.agentPromptsResult.textContent = error.message;
      }}
    }}

    async function loadIntegrations() {{
      try {{
        const [mcpServers, mcpDefaults, skillSources, skillDefaults] = await Promise.all([
          fetchJson('/mcp-servers'),
          fetchJson('/mcp-servers/defaults'),
          fetchJson('/skill-sources'),
          fetchJson('/skill-sources/defaults')
        ]);
        state.mcpServers = mcpServers;
        state.mcpDefaults = mcpDefaults;
        state.skillSources = skillSources;
        state.skillDefaults = skillDefaults;
        renderIntegrations();
      }} catch (error) {{
        el.mcpResult.textContent = error.message;
      }}
    }}

    function renderIntegrations() {{
      renderMcpServers();
      renderSkillSources();
    }}

    function renderMcpServers() {{
      el.mcpList.innerHTML = state.mcpServers.map(server => `
        <button type="button" class="chip" data-mcp-id="${{esc(server.id)}}">${{esc(server.name)}} / ${{esc(server.kind || 'mcp')}}</button>
      `).join('') || '<span class="muted">尚未配置 MCP Server。</span>';
      for (const button of el.mcpList.querySelectorAll('button[data-mcp-id]')) {{
        button.addEventListener('click', () => fillMcpServer(button.dataset.mcpId));
      }}
      const options = '<option value="">无</option>' + state.mcpServers.map(server => (
        `<option value="${{esc(server.id)}}">${{esc(server.name)}} / ${{esc(server.command)}}</option>`
      )).join('');
      el.defaultAtlasMcp.innerHTML = options;
      el.defaultAtlasMcp.value = state.mcpDefaults.atlas || '';
      if (!el.mcpId.value && state.mcpServers.length) fillMcpServer(state.mcpDefaults.atlas || state.mcpServers[0].id);
    }}

    function fillMcpServer(serverId) {{
      const server = state.mcpServers.find(item => item.id === serverId);
      if (!server) return;
      el.mcpId.value = server.id;
      el.mcpName.value = server.name || server.id;
      el.mcpKind.value = server.kind || 'atlas';
      el.mcpCommand.value = server.command || '';
      el.mcpArgs.value = JSON.stringify(server.args || [], null, 2);
      el.mcpCwd.value = server.cwd || '{{project}}';
      el.mcpEnv.value = JSON.stringify(server.env || {{}}, null, 2);
      el.mcpDescription.value = server.description || '';
      el.mcpEnabled.checked = server.enabled !== false;
    }}

    async function saveMcpServer() {{
      try {{
        const payload = {{
          id: el.mcpId.value.trim(),
          name: el.mcpName.value.trim(),
          kind: el.mcpKind.value.trim() || 'atlas',
          command: el.mcpCommand.value.trim(),
          args: el.mcpArgs.value.trim(),
          cwd: el.mcpCwd.value.trim() || '{{project}}',
          env: el.mcpEnv.value.trim() || {{}},
          enabled: el.mcpEnabled.checked,
          description: el.mcpDescription.value.trim()
        }};
        const saved = await fetchJson('/mcp-servers', jsonPost(payload));
        el.mcpResult.textContent = JSON.stringify(saved, null, 2);
        await loadIntegrations();
      }} catch (error) {{
        el.mcpResult.textContent = error.message;
      }}
    }}

    async function testMcpServer() {{
      try {{
        const id = el.mcpId.value.trim();
        if (!id) throw new Error('请先选择或输入 MCP Server ID。');
        const result = await fetchJson(`/mcp-servers/${{encodeURIComponent(id)}}/test`, jsonPost({{
          project_path: el.mcpTestProject.value.trim() || el.runSource.value.trim() || null
        }}));
        el.mcpResult.textContent = JSON.stringify(result, null, 2);
      }} catch (error) {{
        el.mcpResult.textContent = error.message;
      }}
    }}

    async function deleteMcpServer() {{
      try {{
        const id = el.mcpId.value.trim();
        if (!id) throw new Error('请先选择或输入 MCP Server ID。');
        await fetchJson(`/mcp-servers/${{encodeURIComponent(id)}}`, {{ method: 'DELETE' }});
        el.mcpResult.textContent = `已删除 ${{id}}`;
        el.mcpId.value = '';
        await loadIntegrations();
      }} catch (error) {{
        el.mcpResult.textContent = error.message;
      }}
    }}

    async function saveMcpDefaults() {{
      try {{
        const defaults = await fetchJson('/mcp-servers/defaults', jsonPost({{ atlas: el.defaultAtlasMcp.value || null }}));
        state.mcpDefaults = defaults;
        el.mcpResult.textContent = JSON.stringify(defaults, null, 2);
      }} catch (error) {{
        el.mcpResult.textContent = error.message;
      }}
    }}

    function renderSkillSources() {{
      el.skillList.innerHTML = state.skillSources.map(source => `
        <button type="button" class="chip" data-skill-id="${{esc(source.id)}}">${{source.starred ? '* ' : ''}}${{esc(source.name)}} / ${{esc(source.path)}}</button>
      `).join('') || '<span class="muted">尚未配置 Skill Source。</span>';
      for (const button of el.skillList.querySelectorAll('button[data-skill-id]')) {{
        button.addEventListener('click', () => fillSkillSource(button.dataset.skillId));
      }}
      const options = '<option value="">手动输入路径</option>' + state.skillSources.map(source => (
        `<option value="${{esc(source.id)}}">${{esc(source.name)}} / ${{esc(source.path)}}</option>`
      )).join('');
      el.defaultSkillSource.innerHTML = '<option value="">无</option>' + state.skillSources.map(source => (
        `<option value="${{esc(source.id)}}">${{esc(source.name)}} / ${{esc(source.path)}}</option>`
      )).join('');
      el.runSkillSource.innerHTML = options;
      el.defaultSkillSource.value = state.skillDefaults.project || '';
      el.runSkillSource.value = state.skillDefaults.project || '';
      fillRunSkillSource();
      if (!el.skillId.value && state.skillSources.length) fillSkillSource(state.skillDefaults.project || state.skillSources[0].id);
    }}

    function fillSkillSource(sourceId) {{
      const source = state.skillSources.find(item => item.id === sourceId);
      if (!source) return;
      el.skillId.value = source.id;
      el.skillName.value = source.name || source.id;
      el.skillPath.value = source.path || '';
      el.skillDescription.value = source.description || '';
      el.skillEnabled.checked = source.enabled !== false;
      el.skillStarred.checked = Boolean(source.starred);
    }}

    function fillRunSkillSource() {{
      const source = state.skillSources.find(item => item.id === el.runSkillSource.value);
      if (source) el.runSkills.value = source.path || '';
    }}

    function setSelectValue(select, value, label) {{
      const normalized = value || '';
      if (normalized && !Array.from(select.options).some(option => option.value === normalized)) {{
        const option = document.createElement('option');
        option.value = normalized;
        option.textContent = label || `${{normalized}} / 历史配置`;
        select.appendChild(option);
      }}
      select.value = normalized;
    }}

    function isCliRunEngine() {{
      return ['codex', 'opencode'].includes(el.runEngine.value || 'codex');
    }}

    function isOpenCodeRunEngine() {{
      return (el.runEngine.value || 'codex') === 'opencode';
    }}

    function updateRunEngineVisibility() {{
      const cliMode = isCliRunEngine();
      const openCodeMode = isOpenCodeRunEngine();
      el.runProviderAgentGrid.hidden = false;
      document.querySelectorAll('.run-provider-control').forEach(item => item.hidden = cliMode);
      document.querySelectorAll('.run-agent-control').forEach(item => item.hidden = false);
      document.querySelectorAll('.run-builtin-control').forEach(item => item.hidden = cliMode);
      document.querySelectorAll('.run-codex-control').forEach(item => item.hidden = !cliMode);
      document.querySelectorAll('.run-opencode-control').forEach(item => item.hidden = !openCodeMode);
      el.runToolProviderOptions.hidden = cliMode;
      el.runCodexConfigNote.hidden = !cliMode;
      el.runCodexConfigNote.textContent = openCodeMode
        ? 'OpenCode 使用本机 provider、MCP 与认证配置；任务角色目录会注入 permission=allow。'
        : 'Codex 三方复核使用项目 .codex/config.toml 中的模型、MCP 与环境变量默认配置。';
      if (cliMode) {{
        el.runLlm.checked = false;
        el.runAutoIndex.checked = false;
        el.runExternalTools.checked = true;
        for (const select of [
          el.runAffirmativeProvider,
          el.runNegativeProvider,
          el.runModeratorProvider
        ]) {{
          select.value = '';
        }}
      }}
    }}

    async function copyRunToConfig(runId) {{
      if (!runId) return;
      try {{
        el.runResult.textContent = '正在读取历史任务配置...';
        const run = await fetchJson(`/runs/${{encodeURIComponent(runId)}}`);
        await Promise.all([loadProviders(), loadAgentPrompts(), loadIntegrations()]);
        fillRunConfigFromHistory(run);
        el.runConfigModal.classList.add('open');
      }} catch (error) {{
        el.runConfigModal.classList.add('open');
        el.runResult.textContent = error.message;
      }}
    }}

    function fillRunConfigFromHistory(run) {{
      const config = (run && run.config && typeof run.config === 'object') ? run.config : {{}};
      const agents = (run && run.agent_configs && typeof run.agent_configs === 'object') ? run.agent_configs : {{}};
      const agentConfig = role => config[`${{role}}_agent`] || agents[role] || {{}};
      const agentProfile = role => {{
        const value = agentConfig(role);
        return value.profile_id || value.profile || value.id || '';
      }};
      el.runSarif.value = config.report_path || config.sarif_path || run.sarif_path || '';
      el.runSource.value = config.source_path || run.source_path || '';
      configureRunFindingsReuse(run);
      el.runSkills.value = config.skills_path || '';
      el.runEngine.value = config.engine || run.engine || 'codex';
      el.runOpenCodeModel.value = config.llm_model || '';
      setSelectValue(el.runSkillSource, config.skill_source_id || '');
      setSelectValue(el.runAffirmativeProvider, config.affirmative_provider_id || '');
      setSelectValue(el.runNegativeProvider, config.negative_provider_id || '');
      setSelectValue(el.runModeratorProvider, config.moderator_provider_id || '');
      setSelectValue(el.runAffirmativeAgentProfile, agentProfile('affirmative'));
      setSelectValue(el.runNegativeAgentProfile, agentProfile('negative'));
      setSelectValue(el.runModeratorAgentProfile, agentProfile('moderator'));
      el.runMaxRounds.value = String(config.max_rounds || 4);
      el.runSilenceReminderMinutes.value = String(config.silence_reminder_minutes || {DEFAULT_SILENCE_REMINDER_MINUTES});
      el.runExternalTools.checked = config.enable_external_tools !== false;
      el.runAutoIndex.checked = Boolean(config.auto_index_tools);
      el.runLlm.checked = Boolean(
        config.enable_llm ||
        config.affirmative_provider_id ||
        config.negative_provider_id ||
        config.moderator_provider_id
      );
      updateRunEngineVisibility();
      const reuseText = el.runReuseFindings.checked ? '将复用报告拆分结果。' : '该任务没有可复用的报告拆分结果。';
      el.runResult.textContent = `已从 ${{run.run_id || '历史任务'}} 填入配置。${{reuseText}}可调整参数后再启动。`;
    }}

    function configureRunFindingsReuse(run) {{
      const reuse = run && run.reusable_findings && typeof run.reusable_findings === 'object'
        ? run.reusable_findings
        : {{}};
      const available = Boolean(run && run.run_id && reuse.available);
      state.reuseFindingsFromRunId = available ? run.run_id : null;
      el.runReuseFindingsOption.hidden = !run;
      el.runReuseFindings.checked = available;
      el.runReuseFindings.disabled = !available;
      el.runReuseFindingsNote.textContent = available
        ? `（来源 ${{run.run_id}}，${{Number(reuse.finding_count || 0)}} 个 finding）`
        : (run ? '（来源任务尚无可复用的 findings）' : '');
    }}

    async function saveSkillSource() {{
      try {{
        const payload = {{
          id: el.skillId.value.trim(),
          name: el.skillName.value.trim(),
          path: el.skillPath.value.trim(),
          description: el.skillDescription.value.trim(),
          enabled: el.skillEnabled.checked,
          starred: el.skillStarred.checked
        }};
        const saved = await fetchJson('/skill-sources', jsonPost(payload));
        el.skillResult.textContent = JSON.stringify(saved, null, 2);
        await loadIntegrations();
      }} catch (error) {{
        el.skillResult.textContent = error.message;
      }}
    }}

    async function testSkillSource() {{
      try {{
        const id = el.skillId.value.trim();
        if (!id) throw new Error('请先选择或输入 Skill Source ID。');
        const result = await fetchJson(`/skill-sources/${{encodeURIComponent(id)}}/test`, jsonPost({{}}));
        el.skillResult.textContent = JSON.stringify(result, null, 2);
      }} catch (error) {{
        el.skillResult.textContent = error.message;
      }}
    }}

    async function deleteSkillSource() {{
      try {{
        const id = el.skillId.value.trim();
        if (!id) throw new Error('请先选择或输入 Skill Source ID。');
        await fetchJson(`/skill-sources/${{encodeURIComponent(id)}}`, {{ method: 'DELETE' }});
        el.skillResult.textContent = `已删除 ${{id}}`;
        el.skillId.value = '';
        await loadIntegrations();
      }} catch (error) {{
        el.skillResult.textContent = error.message;
      }}
    }}

    async function saveSkillDefaults() {{
      try {{
        const defaults = await fetchJson('/skill-sources/defaults', jsonPost({{ project: el.defaultSkillSource.value || null }}));
        state.skillDefaults = defaults;
        el.skillResult.textContent = JSON.stringify(defaults, null, 2);
      }} catch (error) {{
        el.skillResult.textContent = error.message;
      }}
    }}

    function renderAgentPrompts() {{
      const currentAffirmative = el.agentAffirmativeProfile.value;
      const currentNegative = el.agentNegativeProfile.value;
      const currentModerator = el.agentModeratorProfile.value;
      const currentRunAffirmative = el.runAffirmativeAgentProfile.value;
      const currentRunNegative = el.runNegativeAgentProfile.value;
      const currentRunModerator = el.runModeratorAgentProfile.value;
      const affirmativeOptions = profileOptions('affirmative');
      const negativeOptions = profileOptions('negative');
      const moderatorOptions = profileOptions('moderator');
      renderAgentsMdConfigs();
      el.agentAffirmativeProfile.innerHTML = affirmativeOptions;
      el.agentNegativeProfile.innerHTML = negativeOptions;
      el.agentModeratorProfile.innerHTML = moderatorOptions;
      el.runAffirmativeAgentProfile.innerHTML = affirmativeOptions;
      el.runNegativeAgentProfile.innerHTML = negativeOptions;
      el.runModeratorAgentProfile.innerHTML = moderatorOptions;
      el.agentAffirmativeProfile.value = profileExists('affirmative', currentAffirmative) ? currentAffirmative : defaultProfileId('affirmative');
      el.agentNegativeProfile.value = profileExists('negative', currentNegative) ? currentNegative : defaultProfileId('negative');
      el.agentModeratorProfile.value = profileExists('moderator', currentModerator) ? currentModerator : defaultProfileId('moderator');
      el.runAffirmativeAgentProfile.value = profileExists('affirmative', currentRunAffirmative) ? currentRunAffirmative : defaultProfileId('affirmative');
      el.runNegativeAgentProfile.value = profileExists('negative', currentRunNegative) ? currentRunNegative : defaultProfileId('negative');
      el.runModeratorAgentProfile.value = profileExists('moderator', currentRunModerator) ? currentRunModerator : defaultProfileId('moderator');
      renderAgentProfileCards('affirmative');
      renderAgentProfileCards('negative');
      renderAgentProfileCards('moderator');
      fillAgentProfileEditor('affirmative');
      fillAgentProfileEditor('negative');
      fillAgentProfileEditor('moderator');
    }}

    function profileOptions(role) {{
      return profilesFor(role).map(profile => (
        `<option value="${{esc(profile.profile_id)}}">${{esc(profile.profile_id)}} / ${{esc(profile.path || 'AGENT.md')}}</option>`
      )).join('');
    }}

    function profilesFor(role) {{
      return ((state.agentPrompts.roles || {{}})[role] || []);
    }}

    function profileExists(role, profileId) {{
      return Boolean(profileId && profilesFor(role).some(profile => profile.profile_id === profileId));
    }}

    function defaultProfileId(role) {{
      const defaults = state.agentPrompts.defaults || {{}};
      const profiles = profilesFor(role);
      return defaults[role] || (profiles[0] && profiles[0].profile_id) || '';
    }}

    function findAgentProfile(role, profileId) {{
      return profilesFor(role).find(profile => profile.profile_id === profileId) || profilesFor(role)[0] || null;
    }}

    function agentProfileListEl(role) {{
      return role === 'affirmative' ? el.agentAffirmativeProfileList
        : role === 'negative' ? el.agentNegativeProfileList
        : el.agentModeratorProfileList;
    }}

    function agentProfileSelectEl(role) {{
      return role === 'affirmative' ? el.agentAffirmativeProfile
        : role === 'negative' ? el.agentNegativeProfile
        : el.agentModeratorProfile;
    }}

    function agentProfileIdEl(role) {{
      return role === 'affirmative' ? el.agentAffirmativeProfileId
        : role === 'negative' ? el.agentNegativeProfileId
        : el.agentModeratorProfileId;
    }}

    function agentInstructionsEl(role) {{
      return role === 'affirmative' ? el.agentAffirmativeInstructions
        : role === 'negative' ? el.agentNegativeInstructions
        : el.agentModeratorInstructions;
    }}

    function runAgentProfileSelectEl(role) {{
      return role === 'affirmative' ? el.runAffirmativeAgentProfile
        : role === 'negative' ? el.runNegativeAgentProfile
        : el.runModeratorAgentProfile;
    }}

    function renderAgentProfileCards(role) {{
      const container = agentProfileListEl(role);
      const profiles = profilesFor(role);
      container.innerHTML = profiles.map(profile => profileCard(role, profile)).join('') || '<div class="muted">未找到配置档案。</div>';
      for (const button of container.querySelectorAll('button[data-agent-edit]')) {{
        button.addEventListener('click', () => {{
          const select = agentProfileSelectEl(role);
          select.value = button.dataset.profileId;
          fillAgentProfileEditor(role);
        }});
      }}
      for (const button of container.querySelectorAll('button[data-agent-star]')) {{
        button.addEventListener('click', () => toggleAgentStar(role, button.dataset.profileId, button.dataset.starred !== 'true'));
      }}
      for (const button of container.querySelectorAll('button[data-agent-delete]')) {{
        button.addEventListener('click', () => deleteAgentProfile(role, button.dataset.profileId));
      }}
    }}

    function profileCard(role, profile) {{
      const classes = ['profile-card'];
      if (profile.starred) classes.push('starred');
      if (profile.is_default) classes.push('default');
      const deleteDisabled = profile.deletable ? '' : 'disabled';
      const deleteTitle = profile.deletable ? '删除 Agent 配置档案' : '默认 Agent 不能删除';
      return `<div class="${{classes.join(' ')}}">
        <div class="profile-head">
          <div>
            <div class="profile-title">${{profile.starred ? '*' : ''}} ${{esc(profile.profile_id || profile.name || 'Agent')}}</div>
            <div class="profile-path">${{esc(profile.path || 'AGENT.md')}}</div>
          </div>
          <span class="chip">${{profile.is_default ? '默认' : esc(roleLabel(profile.role || role))}}</span>
        </div>
        <div class="profile-preview">${{esc(profile.instructions || '')}}</div>
        <div class="profile-actions">
          <button type="button" data-agent-edit="true" data-profile-id="${{esc(profile.profile_id)}}">编辑</button>
          <button type="button" data-agent-star="true" data-profile-id="${{esc(profile.profile_id)}}" data-starred="${{profile.starred ? 'true' : 'false'}}">${{profile.starred ? '取消星标' : '星标'}}</button>
          <button type="button" data-agent-delete="true" data-profile-id="${{esc(profile.profile_id)}}" title="${{esc(deleteTitle)}}" ${{deleteDisabled}}>删除</button>
        </div>
      </div>`;
    }}

    function fillAgentProfileEditor(role) {{
      const select = agentProfileSelectEl(role);
      const idInput = agentProfileIdEl(role);
      const promptInput = agentInstructionsEl(role);
      const profile = findAgentProfile(role, select.value);
      idInput.value = profile ? profile.profile_id : '';
      promptInput.value = profile ? profile.instructions : '';
    }}

    function newAgentProfile(role) {{
      const idInput = agentProfileIdEl(role);
      const promptInput = agentInstructionsEl(role);
      const prefix = role === 'affirmative' ? 'Affirmative_custom' : role === 'negative' ? 'Negative_custom' : 'Moderator_custom';
      const profileId = nextAgentProfileId(role, prefix);
      const baseProfile = findAgentProfile(role, defaultProfileId(role)) || findAgentProfile(role, '');
      idInput.value = profileId;
      promptInput.value = baseProfile ? baseProfile.instructions : '';
      el.agentPromptsResult.textContent = `已创建${{roleLabel(role)}} Agent 草稿：${{profileId}}。编辑 AGENT.md 后保存即可创建。`;
    }}

    function nextAgentProfileId(role, prefix) {{
      const existing = new Set(profilesFor(role).map(profile => profile.profile_id));
      const seed = String(Date.now()).slice(-6);
      let candidate = `${{prefix}}_${{seed}}`;
      let index = 2;
      while (existing.has(candidate)) {{
        candidate = `${{prefix}}_${{seed}}_${{index}}`;
        index += 1;
      }}
      return candidate;
    }}

    async function saveAgentProfile(role) {{
      try {{
        const profileId = agentProfileIdEl(role).value.trim();
        const instructions = agentInstructionsEl(role).value.trim();
        const saved = await fetchJson('/agent-prompts', jsonPost({{ role, profile_id: profileId, instructions }}));
        await loadAgentPrompts();
        const select = agentProfileSelectEl(role);
        const runSelect = runAgentProfileSelectEl(role);
        select.value = saved.profile_id;
        runSelect.value = saved.profile_id;
        fillAgentProfileEditor(role);
        el.agentPromptsResult.textContent = JSON.stringify(saved, null, 2);
      }} catch (error) {{
        el.agentPromptsResult.textContent = error.message;
      }}
    }}

    async function toggleAgentStar(role, profileId, starred) {{
      try {{
        const profile = await fetchJson('/agent-prompts', jsonPost({{ action: 'star', role, profile_id: profileId, starred }}));
        await loadAgentPrompts();
        el.agentPromptsResult.textContent = JSON.stringify(profile, null, 2);
      }} catch (error) {{
        el.agentPromptsResult.textContent = error.message;
      }}
    }}

    function agentsMdConfigs() {{
      return ((state.agentPrompts.agents_md || {{}}).configs || []);
    }}

    function findAgentsMdConfig(configId) {{
      return agentsMdConfigs().find(config => config.id === configId) || agentsMdConfigs()[0] || null;
    }}

    function renderAgentsMdConfigs() {{
      const metadata = state.agentPrompts.agents_md || {{}};
      const configs = agentsMdConfigs();
      const current = el.agentsMdConfig.value;
      const options = configs.map(config => (
        `<option value="${{esc(config.id)}}">${{esc(config.name || config.id)}} / ${{esc(config.path || '')}}</option>`
      )).join('');
      el.agentsMdConfig.innerHTML = options;
      el.defaultAgentsMdConfig.innerHTML = options;
      el.agentsMdConfig.value = configs.some(config => config.id === current)
        ? current
        : (metadata.default_id || (configs[0] && configs[0].id) || '');
      el.defaultAgentsMdConfig.value = metadata.default_id || '';
      el.agentsMdConfigList.innerHTML = configs.map(config => `
        <div class="profile-card ${{config.is_default ? 'default' : ''}}">
          <div class="profile-head">
            <div>
              <div class="profile-title">${{esc(config.name || config.id)}}</div>
              <div class="profile-path">${{esc(config.path || '')}}</div>
            </div>
            <span class="chip">${{config.is_default ? '默认' : (config.exists ? '可用' : '文件缺失')}}</span>
          </div>
          <div class="profile-preview">${{esc(config.resolved_path || '')}}</div>
          <div class="profile-actions"><button type="button" data-agents-md-edit="true" data-config-id="${{esc(config.id)}}">配置</button></div>
        </div>`).join('') || '<div class="muted">尚未登记 AGENTS.md 配置。</div>';
      for (const button of el.agentsMdConfigList.querySelectorAll('[data-agents-md-edit]')) {{
        button.addEventListener('click', () => {{
          el.agentsMdConfig.value = button.dataset.configId;
          fillAgentsMdConfigEditor();
        }});
      }}
      fillAgentsMdConfigEditor();
    }}

    function fillAgentsMdConfigEditor() {{
      const config = findAgentsMdConfig(el.agentsMdConfig.value);
      el.agentsMdConfigId.value = config ? config.id : '';
      el.agentsMdConfigName.value = config ? config.name : '';
      el.agentsMdConfigPath.value = config ? config.path : '';
    }}

    function newAgentsMdConfig() {{
      el.agentsMdConfig.value = '';
      el.agentsMdConfigId.value = `Agents_custom_${{String(Date.now()).slice(-6)}}`;
      el.agentsMdConfigName.value = '';
      el.agentsMdConfigPath.value = '';
      el.agentPromptsResult.textContent = '请填写已有 AGENTS.md 文件路径并保存配置。';
    }}

    async function saveAgentsMdConfig() {{
      try {{
        const saved = await fetchJson('/agent-prompts/agents-md', jsonPost({{
          id: el.agentsMdConfigId.value.trim(),
          name: el.agentsMdConfigName.value.trim(),
          path: el.agentsMdConfigPath.value.trim(),
        }}));
        await loadAgentPrompts();
        el.agentsMdConfig.value = saved.id;
        fillAgentsMdConfigEditor();
        el.agentPromptsResult.textContent = JSON.stringify(saved, null, 2);
      }} catch (error) {{
        el.agentPromptsResult.textContent = error.message;
      }}
    }}

    async function deleteAgentsMdConfig() {{
      try {{
        const configId = el.agentsMdConfig.value || el.agentsMdConfigId.value.trim();
        if (!configId) throw new Error('请先选择 AGENTS.md 配置。');
        const result = await fetchJson(`/agent-prompts/agents-md/${{encodeURIComponent(configId)}}`, {{ method: 'DELETE' }});
        state.agentPrompts.agents_md = result;
        renderAgentsMdConfigs();
        el.agentPromptsResult.textContent = `已删除 AGENTS.md 配置 ${{configId}}。`;
      }} catch (error) {{
        el.agentPromptsResult.textContent = error.message;
      }}
    }}

    async function saveDefaultAgentsMdConfig() {{
      try {{
        const result = await fetchJson('/agent-prompts/agents-md/default', jsonPost({{
          id: el.defaultAgentsMdConfig.value || null,
        }}));
        state.agentPrompts.agents_md = result;
        renderAgentsMdConfigs();
        el.agentPromptsResult.textContent = JSON.stringify(result, null, 2);
      }} catch (error) {{
        el.agentPromptsResult.textContent = error.message;
      }}
    }}

    async function deleteAgentProfile(role, profileId) {{
      try {{
        const result = await fetchJson(`/agent-prompts/${{encodeURIComponent(role)}}/${{encodeURIComponent(profileId)}}`, {{ method: 'DELETE' }});
        state.agentPrompts = result;
        renderAgentPrompts();
        el.agentPromptsResult.textContent = `已删除 ${{profileId}}`;
      }} catch (error) {{
        el.agentPromptsResult.textContent = error.message;
      }}
    }}

    async function resetAgentPrompts() {{
      try {{
        state.agentPrompts = await fetchJson('/agent-prompts', jsonPost({{ reset: true }}));
        renderAgentPrompts();
        el.agentPromptsResult.textContent = JSON.stringify(state.agentPrompts, null, 2);
      }} catch (error) {{
        el.agentPromptsResult.textContent = error.message;
      }}
    }}

    function renderProviders() {{
      el.providerList.innerHTML = state.providers.map(provider => `
        <button type="button" class="chip" data-provider-id="${{esc(provider.id)}}">${{esc(provider.name)}} / ${{esc(provider.model)}}</button>
      `).join('') || '<span class="muted">尚未配置提供商。</span>';
      for (const button of el.providerList.querySelectorAll('button[data-provider-id]')) {{
        button.addEventListener('click', () => fillProvider(button.dataset.providerId));
      }}
      const options = '<option value="">无</option>' + state.providers.map(provider => (
        `<option value="${{esc(provider.id)}}">${{esc(provider.name)}} / ${{esc(provider.model)}}</option>`
      )).join('');
      el.defaultAffirmative.innerHTML = options;
      el.defaultNegative.innerHTML = options;
      el.defaultModerator.innerHTML = options;
      el.runAffirmativeProvider.innerHTML = options;
      el.runNegativeProvider.innerHTML = options;
      el.runModeratorProvider.innerHTML = options;
      el.defaultAffirmative.value = state.defaults.affirmative || '';
      el.defaultNegative.value = state.defaults.negative || '';
      el.defaultModerator.value = state.defaults.moderator || '';
      el.runAffirmativeProvider.value = state.defaults.affirmative || '';
      el.runNegativeProvider.value = state.defaults.negative || '';
      el.runModeratorProvider.value = state.defaults.moderator || '';
      enableRunLlmForSelectedProviders();
      updateRunEngineVisibility();
    }}

    function enableRunLlmForSelectedProviders() {{
      if (isCliRunEngine()) return;
      if (el.runAffirmativeProvider.value || el.runNegativeProvider.value || el.runModeratorProvider.value) {{
        el.runLlm.checked = true;
      }}
    }}

    function fillProvider(providerId) {{
      const provider = state.providers.find(item => item.id === providerId);
      if (!provider) return;
      el.providerId.value = provider.id;
      el.providerName.value = provider.name;
      el.providerEndpoint.value = provider.endpoint;
      el.providerModel.value = provider.model;
      el.providerKeyEnv.value = provider.api_key_env || '';
      el.providerKey.value = '';
      el.providerExtra.value = JSON.stringify(provider.extra_json || {{}}, null, 2);
    }}

    async function saveProvider() {{
      try {{
        const payload = {{
          id: el.providerId.value.trim(),
          name: el.providerName.value.trim(),
          type: 'openai-compatible',
          endpoint: el.providerEndpoint.value.trim(),
          model: el.providerModel.value.trim(),
          api_key_env: el.providerKeyEnv.value.trim(),
          extra_json: el.providerExtra.value.trim() || {{}}
        }};
        if (el.providerKey.value.trim()) payload.api_key = el.providerKey.value.trim();
        const provider = await fetchJson('/providers', jsonPost(payload));
        el.providerResult.textContent = JSON.stringify(provider, null, 2);
        await loadProviders();
      }} catch (error) {{
        el.providerResult.textContent = error.message;
      }}
    }}

    async function testProvider() {{
      try {{
        const id = el.providerId.value.trim();
        if (!id) throw new Error('请先选择或输入提供商 ID。');
        const payload = el.providerKey.value.trim() ? {{ api_key: el.providerKey.value.trim() }} : {{}};
        const result = await fetchJson(`/providers/${{encodeURIComponent(id)}}/test`, jsonPost(payload));
        el.providerResult.textContent = JSON.stringify(result, null, 2);
      }} catch (error) {{
        el.providerResult.textContent = error.message;
      }}
    }}

    async function deleteProvider() {{
      try {{
        const id = el.providerId.value.trim();
        if (!id) throw new Error('请先选择或输入提供商 ID。');
        await fetchJson(`/providers/${{encodeURIComponent(id)}}`, {{ method: 'DELETE' }});
        el.providerResult.textContent = `已删除 ${{id}}`;
        await loadProviders();
      }} catch (error) {{
        el.providerResult.textContent = error.message;
      }}
    }}

    async function saveDefaults() {{
      try {{
        const defaults = await fetchJson('/providers/defaults', jsonPost({{
          affirmative: el.defaultAffirmative.value || null,
          negative: el.defaultNegative.value || null,
          moderator: el.defaultModerator.value || null
        }}));
        state.defaults = defaults;
        el.providerResult.textContent = JSON.stringify(defaults, null, 2);
      }} catch (error) {{
        el.providerResult.textContent = error.message;
      }}
    }}

    async function startRun() {{
      try {{
        const cliMode = isCliRunEngine();
        const openCodeMode = isOpenCodeRunEngine();
        const payload = {{
          report_path: el.runSarif.value.trim(),
          source_path: el.runSource.value.trim(),
          engine: el.runEngine.value || 'codex',
          skill_source_id: el.runSkillSource.value || null,
          skills_path: el.runSkills.value.trim() || null,
          max_rounds: Number(el.runMaxRounds.value || 4),
          silence_reminder_minutes: Number(el.runSilenceReminderMinutes.value || {DEFAULT_SILENCE_REMINDER_MINUTES}),
          llm_model: openCodeMode ? (el.runOpenCodeModel.value.trim() || null) : null,
          enable_external_tools: cliMode ? true : el.runExternalTools.checked,
          auto_index_tools: cliMode ? false : el.runAutoIndex.checked,
          enable_llm: cliMode ? false : el.runLlm.checked,
          affirmative_provider_id: cliMode ? null : (el.runAffirmativeProvider.value || null),
          negative_provider_id: cliMode ? null : (el.runNegativeProvider.value || null),
          moderator_provider_id: cliMode ? null : (el.runModeratorProvider.value || null),
          reuse_findings_from_run_id: el.runReuseFindings.checked ? state.reuseFindingsFromRunId : null,
          affirmative_agent_profile: el.runAffirmativeAgentProfile.value || null,
          negative_agent_profile: el.runNegativeAgentProfile.value || null,
          moderator_agent_profile: el.runModeratorAgentProfile.value || null
        }};
        if (!payload.report_path || !payload.source_path) {{
          throw new Error('报告路径和源码路径不能为空。');
        }}
        el.runResult.textContent = '正在启动任务...';
        const created = await fetchJson('/runs', jsonPost(payload));
        el.runResult.textContent = JSON.stringify(created, null, 2);
        el.runConfigModal.classList.remove('open');
        state.autoRefreshEnabled = true;
        if (created.run_id) {{
          ensurePolling(created.run_id);
        }}
        await loadRuns();
        if (created.run_id) {{
          await selectRun(created.run_id);
        }}
      }} catch (error) {{
        el.runResult.textContent = error.message;
      }}
    }}

    async function pollRunningRuns() {{
      if (!state.autoRefreshEnabled || state.pollInFlight) return;
      const active = runningRuns();
      if (!active.length) {{
        updateAutoRefreshControl();
        return;
      }}
      state.pollInFlight = true;
      try {{
        const statuses = await Promise.all(active.map(async run => {{
          try {{
            return await fetchJson(`/runs/${{encodeURIComponent(run.run_id)}}/status`);
          }} catch (_error) {{
            return null;
          }}
        }}));
        const changed = statuses.filter(item => {{
          if (!item) return false;
          const current = state.runs.find(run => run.run_id === item.run_id);
          return !current || current.revision !== item.revision || current.status !== item.status;
        }});
        await Promise.all(changed.map(refreshRunFromPoll));
      }} finally {{
        state.pollInFlight = false;
        updateAutoRefreshControl();
        scheduleGlobalPoll();
      }}
    }}

    async function refreshRunFromPoll(status) {{
      const runId = status.run_id;
      const current = state.runs.find(run => run.run_id === runId) || {{ run_id: runId }};
      try {{
        const run = await fetchJson(`/runs/${{encodeURIComponent(runId)}}`);
        const next = {{ ...current, ...run, revision: run.revision || status.revision }};
        const index = state.runs.findIndex(item => item.run_id === runId);
        if (index >= 0) state.runs[index] = next;
        else state.runs.unshift(next);
        updateRunListItem(next);
        if (state.selectedRun === runId) {{
          const findings = await fetchJson(`/runs/${{encodeURIComponent(runId)}}/findings`);
          if (state.selectedRun !== runId) return;
          renderRunDetail(run, findings);
        }}
      }} catch (_error) {{
        return;
      }}
    }}

    function scheduleGlobalPoll(delay = 1000) {{
      if (state.pollTimer || state.pollInFlight || !state.autoRefreshEnabled || !runningRuns().length) return;
      state.pollTimer = window.setTimeout(() => {{
        state.pollTimer = null;
        pollRunningRuns();
      }}, delay);
    }}

    function stopGlobalPolling() {{
      if (state.pollTimer) window.clearTimeout(state.pollTimer);
      state.pollTimer = null;
    }}

    function ensurePolling(runId = null) {{
      void runId;
      scheduleGlobalPoll();
    }}

    function runningRuns() {{
      return state.runs.filter(run => !isTerminalStatus(run.status));
    }}

    function updateAutoRefreshControl() {{
      const running = runningRuns();
      if (!running.length) {{
        state.autoRefreshEnabled = false;
        stopGlobalPolling();
      }}
      el.autoRefresh.disabled = !running.length;
      el.autoRefresh.textContent = state.autoRefreshEnabled ? '自动刷新：开' : '自动刷新：关';
      el.autoRefresh.title = running.length
        ? (state.autoRefreshEnabled ? '点击关闭自动刷新，便于选择和复制文本' : '点击开启运行中任务自动刷新')
        : '没有运行中任务';
      el.autoRefresh.setAttribute('aria-pressed', state.autoRefreshEnabled ? 'true' : 'false');
      el.autoRefresh.classList.toggle('toggle-active', state.autoRefreshEnabled && Boolean(running.length));
    }}

    function toggleAutoRefresh() {{
      if (el.autoRefresh.disabled) return;
      state.autoRefreshEnabled = !state.autoRefreshEnabled;
      if (!state.autoRefreshEnabled) {{
        stopGlobalPolling();
        updateAutoRefreshControl();
        return;
      }}
      updateAutoRefreshControl();
      ensurePolling();
    }}

    async function loadRuns() {{
      el.subtitle.textContent = '正在加载记录...';
      try {{
        const runs = await fetchJson('/runs');
        const signature = runListSignature(runs);
        const changed = signature !== state.runListSignature;
        state.runs = runs;
        state.runListSignature = signature;
        if (changed) renderRuns();
        else updateSelectedRunCard(null, state.selectedRun);
        updateAutoRefreshControl();
        if (state.autoRefreshEnabled) {{
          ensurePolling();
        }}
        el.subtitle.textContent = '静态报告漏洞研判历史';
        if (!state.selectedRun && state.runs.length > 0) {{
          await selectRun(state.runs[0].run_id);
        }} else if (!state.runs.length) {{
          renderEmpty('暂无记录。可以通过“启动任务”按钮、POST /runs 或 CLI/API 工作流创建任务。');
        }}
      }} catch (error) {{
        renderError(error);
      }}
    }}

    function runListSignature(runs) {{
      return JSON.stringify((runs || []).map(run => [run.run_id, run.revision || '', run.status || 'completed']));
    }}

    function renderRunItem(run) {{
      const counts = run.verdict_counts || {{}};
      const status = run.status || 'completed';
      const resumable = status === 'paused' || status === 'failed';
      const origin = runOriginLabel(run);
      const pauseButton = status === 'running' || status === 'pausing'
        ? `<span class="chip run-pause" data-run-pause="true" data-run-id="${{esc(run.run_id)}}" role="button" tabindex="0" title="暂停该任务">暂停</span>`
        : '';
      const resumeButton = resumable
        ? `<span class="chip run-resume" data-run-resume="true" data-run-id="${{esc(run.run_id)}}" role="button" tabindex="0" title="${{status === 'failed' ? '从失败断点恢复任务' : '从当前 finding 恢复任务'}}">恢复</span>`
        : '';
      const stopButton = status === 'running' || status === 'stopping' || status === 'pausing'
        ? `<span class="chip run-stop" data-run-stop="true" data-run-id="${{esc(run.run_id)}}" role="button" tabindex="0" title="停止该任务">停止</span>`
        : '';
      const deleteConfirming = state.deleteConfirmRunId === run.run_id;
      return `<button class="run-item ${{state.selectedRun === run.run_id ? 'active' : ''}}" type="button" data-run-id="${{esc(run.run_id)}}">
        <div class="run-item-actions">
          ${{pauseButton}}
          ${{resumeButton}}
          ${{stopButton}}
          <span class="chip run-delete ${{deleteConfirming ? 'confirming' : ''}}" data-run-delete="true" data-run-id="${{esc(run.run_id)}}" role="button" tabindex="0" aria-label="${{deleteConfirming ? '再次点击确认删除' : '删除该任务记录'}}" title="${{deleteConfirming ? '再次点击确认删除' : '删除该任务记录'}}">${{deleteConfirming ? '确认删除？' : '删除'}}</span>
        </div>
        <div class="run-item-headline">
          <div class="run-id">${{esc(run.run_id)}}</div>
          <div class="muted">${{esc(fmtDate(run.created_at))}}</div>
          <div class="path">${{esc(run.source_path || '')}}</div>
        </div>
        <div class="chips">
          <span class="chip origin">${{esc(origin)}}</span>
          <span class="${{statusChipClass(status)}}">${{esc(statusLabel(status))}}</span>
          <span class="chip">${{esc(run.finding_count)}} 个发现</span>
        </div>
        <div class="chips run-verdict-chips">
          <span class="chip tp">真实 ${{counts.TRUE_POSITIVE || 0}}</span>
          <span class="chip fp">误报 ${{counts.FALSE_POSITIVE || 0}}</span>
          <span class="chip inc">不足 ${{counts.INCONCLUSIVE || 0}}</span>
        </div>
      </button>`;
    }}

    function renderRuns() {{
      el.count.textContent = `${{state.runs.length}} 条记录`;
      el.list.innerHTML = state.runs.map(renderRunItem).join('');
    }}

    function updateRunListItem(run) {{
      const current = el.list.querySelector(`.run-item[data-run-id="${{cssEscape(run.run_id)}}"]`);
      if (current) current.outerHTML = renderRunItem(run);
      else el.list.insertAdjacentHTML('afterbegin', renderRunItem(run));
      el.count.textContent = `${{state.runs.length}} 条记录`;
      state.runListSignature = runListSignature(state.runs);
    }}

    function updateSelectedRunCard(previousRunId, runId) {{
      if (previousRunId) {{
        el.list.querySelector(`.run-item[data-run-id="${{cssEscape(previousRunId)}}"]`)?.classList.remove('active');
      }}
      if (runId) {{
        el.list.querySelector(`.run-item[data-run-id="${{cssEscape(runId)}}"]`)?.classList.add('active');
      }}
    }}

    function handleRunListAction(target) {{
      const action = target.closest('[data-run-delete], [data-run-stop], [data-run-pause], [data-run-resume]');
      if (!action) return false;
      const runId = action.dataset.runId;
      if (action.matches('[data-run-delete]')) handleDeleteRunClick(runId);
      else if (action.matches('[data-run-stop]')) stopRun(runId);
      else if (action.matches('[data-run-pause]')) pauseRun(runId);
      else if (action.matches('[data-run-resume]')) resumeRun(runId);
      return true;
    }}

    function handleRunListClick(event) {{
      const target = event.target instanceof Element ? event.target : null;
      if (!target) return;
      if (handleRunListAction(target)) return;
      const item = target.closest('.run-item[data-run-id]');
      if (item) selectRun(item.dataset.runId);
    }}

    function handleRunListKeydown(event) {{
      if (event.key !== 'Enter' && event.key !== ' ') return;
      const target = event.target instanceof Element ? event.target : null;
      if (!target || !target.closest('[data-run-delete], [data-run-stop], [data-run-pause], [data-run-resume]')) return;
      event.preventDefault();
      handleRunListAction(target);
    }}

    async function pauseRun(runId) {{
      if (!runId) return;
      try {{
        await fetchJson(`/runs/${{encodeURIComponent(runId)}}/pause`, jsonPost({{}}));
        await loadRuns();
        if (state.selectedRun === runId) {{
          await selectRun(runId, false);
        }}
      }} catch (error) {{
        renderError(error);
      }}
    }}

    async function resumeRun(runId) {{
      if (!runId) return;
      try {{
        await fetchJson(`/runs/${{encodeURIComponent(runId)}}/resume`, jsonPost({{}}));
        state.autoRefreshEnabled = true;
        await loadRuns();
        if (state.selectedRun === runId) {{
          await selectRun(runId, false);
        }}
        ensurePolling(runId);
      }} catch (error) {{
        renderError(error);
      }}
    }}

    async function stopRun(runId) {{
      if (!runId) return;
      try {{
        await fetchJson(`/runs/${{encodeURIComponent(runId)}}/stop`, jsonPost({{}}));
        await loadRuns();
        if (state.selectedRun === runId) {{
          await selectRun(runId, false);
        }}
      }} catch (error) {{
        renderError(error);
      }}
    }}

    async function stopCodexSessions(runId, button) {{
      if (!runId) return;
      const originalText = button ? button.textContent : '';
      try {{
        if (button) {{
          button.disabled = true;
          button.textContent = '关闭中...';
        }}
        const run = state.runs.find(item => item.run_id === runId) || {{}};
        const legacyCodexStopPath = `/runs/${{encodeURIComponent(runId)}}/codex-sessions/stop`;
        const stopPath = run.engine === 'opencode'
          ? `/runs/${{encodeURIComponent(runId)}}/cli-sessions/stop`
          : legacyCodexStopPath;
        await fetchJson(stopPath, jsonPost({{}}));
        closeCodexTerminal();
        await loadRuns();
        if (state.selectedRun === runId) {{
          await selectRun(runId, false);
        }}
      }} catch (error) {{
        if (button) {{
          button.disabled = false;
          button.textContent = originalText;
        }}
        renderError(error);
      }}
    }}

    function updateDeleteConfirmationUi() {{
      for (const button of el.list.querySelectorAll('[data-run-delete]')) {{
        const confirming = state.deleteConfirmRunId === button.dataset.runId;
        button.classList.toggle('confirming', confirming);
        button.textContent = confirming ? '确认删除？' : '删除';
        const label = confirming ? '再次点击确认删除' : '删除该任务记录';
        button.setAttribute('aria-label', label);
        button.title = label;
      }}
    }}

    function handleDeleteRunClick(runId) {{
      if (!runId) return;
      if (state.deleteConfirmRunId !== runId) {{
        state.deleteConfirmRunId = runId;
        updateDeleteConfirmationUi();
        return;
      }}
      state.deleteConfirmRunId = null;
      updateDeleteConfirmationUi();
      deleteRun(runId);
    }}

    async function deleteRun(runId) {{
      if (!runId) return;
      try {{
        await fetchJson(`/runs/${{encodeURIComponent(runId)}}`, {{ method: 'DELETE' }});
        if (state.selectedRun === runId) {{
          state.selectedRun = null;
          state.selectedFinding = null;
        }}
        await loadRuns();
        if (!state.selectedRun && state.runs.length > 0) {{
          await selectRun(state.runs[0].run_id);
        }} else if (!state.runs.length) {{
          renderEmpty('暂无记录。可以通过“启动任务”按钮、POST /runs 或 CLI/API 工作流创建任务。');
        }}
      }} catch (error) {{
        renderError(error);
      }}
    }}

    async function selectRun(runId, resetFinding = true) {{
      state.deleteConfirmRunId = null;
      const previousRunId = state.selectedRun;
      state.selectedRun = runId;
      if (resetFinding) {{
        state.selectedFinding = null;
        state.expandedManualReviewKey = null;
        state.floatingManualReviewKey = null;
      }}
      updateSelectedRunCard(previousRunId, runId);
      const summary = state.runs.find(run => run.run_id === runId);
      if (!resetFinding && state.currentRun?.run_id === runId && summary?.revision && state.currentRun.revision === summary.revision) {{
        return;
      }}
      el.title.textContent = runId;
      el.status.textContent = '正在加载详情...';
      try {{
        const [run, findings] = await Promise.all([
          fetchJson(`/runs/${{encodeURIComponent(runId)}}`),
          fetchJson(`/runs/${{encodeURIComponent(runId)}}/findings`)
        ]);
        if (state.selectedRun !== runId) return;
        renderRunDetail(run, findings);
      }} catch (error) {{
        renderError(error);
      }}
    }}

    function renderRunDetail(run, findings) {{
      state.currentRun = run;
      state.currentFindings = findings || [];
      const status = run.status || 'completed';
      const resumable = status === 'paused' || status === 'failed';
      const resumeIndex = run.resume_from_finding_index;
      const resumeFinding = run.resume_from_finding_id || '';
      const resumeHint = resumable && resumeIndex !== null && resumeIndex !== undefined
        ? '恢复时将从 finding #' + (Number(resumeIndex) + 1) + (resumeFinding ? ' (' + resumeFinding + ')' : '') + ' 重新处理。'
        : '';
      const currentHint = run.current_finding_id
        ? '当前 Finding：' + run.current_finding_id
        : '';
      const detailControls = [
        status === 'running' || status === 'pausing'
          ? `<button type="button" data-run-pause="true" data-run-id="${{esc(run.run_id)}}">暂停</button>`
          : '',
        resumable
          ? `<button type="button" data-run-resume="true" data-run-id="${{esc(run.run_id)}}">恢复</button>`
          : '',
        status === 'running' || status === 'stopping' || status === 'pausing'
          ? `<button type="button" data-run-stop="true" data-run-id="${{esc(run.run_id)}}">停止</button>`
          : ''
      ].filter(Boolean).join('');
      const runningMessage = status === 'pausing'
        ? '已请求暂停。当前 LLM 请求结束后会丢弃正在处理的 finding，并从该 finding 保存恢复点。'
        : status === 'paused'
          ? '任务已暂停，当前正在处理的 finding 已丢弃。' + resumeHint
          : status === 'failed'
            ? '任务执行失败，可点击“恢复”从断点继续。' + resumeHint
          : status === 'stopping'
        ? '已请求停止。当前 LLM 请求结束后会停止后续回合。'
        : status === 'stopped'
          ? '任务已停止，下面显示停止前已经生成的部分结果。'
          : state.autoRefreshEnabled
            ? '任务正在后台运行。自动刷新开启，每完成一次 LLM 对话，本页面会自动加载当前信息。'
            : '任务正在后台运行。自动刷新已关闭，可手动点击“刷新”加载当前信息。';
      el.status.textContent = `${{statusLabel(status)}} / ${{findings.length}} 个发现`;
      el.overview.innerHTML = '';
      el.detail.innerHTML = renderFindingWorkspace(
        run,
        findings,
        status,
        detailControls,
        runningMessage,
        currentHint,
        resumeHint,
        status === 'failed'
          ? '任务执行失败，恢复后会从首个未完成阶段继续。'
          : status !== 'completed'
            ? '任务正在运行，尚未生成可展示的漏洞发现详情。'
            : '暂无漏洞发现记录。'
      );
      bindRunExportButtons(el.detail);
      bindRunControlButtons(el.detail);
      bindFindingRows(findings);
    }}

    function rerenderRunDetailPreservingScroll() {{
      const scrollTop = el.detailScroll.scrollTop;
      renderRunDetail(state.currentRun || {{}}, state.currentFindings);
      el.detailScroll.scrollTop = scrollTop;
    }}

    function renderRunMetadataCard(run, findings, status, detailControls, runningMessage, currentHint, resumeHint) {{
      const counts = run.verdict_counts || {{}};
      const providers = run.llm_providers || {{}};
      const agents = run.agent_configs || {{}};
      const runConfig = run.config || {{}};
      const origin = runOriginLabel(run);
      const engine = run.engine || (run.config && run.config.engine) || 'builtin';
      const cliEngine = ['codex', 'opencode'].includes(engine);
      const codexActiveAgentHtml = cliEngine ? renderCodexActiveAgent(run, findings, status) : '';
      const legacyRuntimeHtml = `
          <div><strong>正方 LLM：</strong> ${{esc(providerLabel(providers.affirmative, providers.enabled))}}</div>
          <div><strong>反方 LLM：</strong> ${{esc(providerLabel(providers.negative, providers.enabled))}}</div>
          <div><strong>主持人 LLM：</strong> ${{esc(providerLabel(providers.moderator, providers.enabled))}}</div>
          <div><strong>正方 Agent：</strong> ${{esc(agentLabel(agents.affirmative))}}</div>
          <div><strong>反方 Agent：</strong> ${{esc(agentLabel(agents.negative))}}</div>
          <div><strong>主持人 Agent：</strong> ${{esc(agentLabel(agents.moderator))}}</div>
          ${{agentInstructions(agents) ? `<pre>${{esc(agentInstructions(agents))}}</pre>` : ''}}`;
      const cliRuntimeHtml = `
          <div><strong>${{engine === 'opencode' ? 'OpenCode' : 'Codex'}} 配置：</strong> ${{
            engine === 'opencode'
              ? '使用本机 provider/MCP 配置和任务角色目录中的 permission=allow。'
              : '使用项目 .codex/config.toml 中的模型、MCP 与环境变量默认配置。'
          }}</div>
          <div><strong>正方 Agent：</strong> ${{esc(agentLabel(agents.affirmative))}}</div>
          <div><strong>反方 Agent：</strong> ${{esc(agentLabel(agents.negative))}}</div>
          <div><strong>主持人 Agent：</strong> ${{esc(agentLabel(agents.moderator))}}</div>
          <div><strong>AGENTS.md 配置：</strong> ${{esc(runConfig.agents_config_id || '未记录')}}${{runConfig.agents_config_path ? ` · ${{runConfig.agents_config_path}}` : ''}}</div>`;
      return `<details class="detail metadata-section" open>
        <summary class="detail-summary">运行元数据
          <span class="chips">
            <span class="chip origin">${{esc(origin)}}</span>
            <span class="chip">${{esc(engineLabel(engine))}}</span>
            <span class="${{statusChipClass(status)}}">${{esc(statusLabel(status))}}</span>
            <span class="chip">${{esc(findings.length)}} 个发现</span>
          </span>
        </summary>
        <div class="detail-body">
          <div class="chips">
            <span class="chip origin">${{esc(origin)}}</span>
            <span class="${{statusChipClass(status)}}">${{esc(statusLabel(status))}}</span>
            <span class="chip">${{esc(findings.length)}} 个发现</span>
          </div>
          <div class="overview-summary">
            <div class="overview-metric"><div class="label">发现数</div><div class="value">${{esc(run.finding_count || findings.length)}}</div></div>
            <div class="overview-metric"><div class="label">真实漏洞</div><div class="value">${{counts.TRUE_POSITIVE || 0}}</div></div>
            <div class="overview-metric"><div class="label">误报</div><div class="value">${{counts.FALSE_POSITIVE || 0}}</div></div>
            <div class="overview-metric"><div class="label">证据不足</div><div class="value">${{counts.INCONCLUSIVE || 0}}</div></div>
          </div>
          <div class="toolbar">
            ${{detailControls}}
            <button type="button" data-run-copy-config="true" data-run-id="${{esc(run.run_id)}}">填入新任务</button>
            <button type="button" data-run-export="markdown" data-run-id="${{esc(run.run_id)}}">导出 Markdown</button>
            <button type="button" data-run-export="json" data-run-id="${{esc(run.run_id)}}">导出 JSON</button>
          </div>
          <div><strong>任务来源：</strong> ${{esc(origin)}}</div>
          <div><strong>执行引擎：</strong> ${{esc(engineLabel(engine))}}</div>
          ${{renderCodexSessionButtons(run)}}
          <div><strong>创建时间：</strong> ${{esc(fmtDate(run.created_at))}}</div>
          <div><strong>报告：</strong> <span class="path">${{esc(run.sarif_path)}}</span></div>
          <div><strong>源码：</strong> <span class="path">${{esc(run.source_path)}}</span></div>
          <div><strong>语言：</strong> ${{esc((run.languages || []).join(', '))}}</div>
          <div><strong>发现进度：</strong> ${{esc(run.completed_finding_count ?? findings.length)}} / ${{esc(run.finding_count || findings.length)}}</div>
          ${{currentHint ? `<div><strong>当前状态：</strong> ${{esc(currentHint)}}</div>` : ''}}
          ${{codexActiveAgentHtml}}
          ${{resumeHint ? `<div><strong>恢复点：</strong> ${{esc(resumeHint)}}</div>` : ''}}
          ${{cliEngine ? cliRuntimeHtml : legacyRuntimeHtml}}
          ${{run.error ? `<div class="error">${{esc(run.error)}}</div>` : `<div class="muted">${{esc(runningMessage)}}</div>`}}
          ${{run.diagnostics && run.diagnostics.length ? `<pre>${{esc(run.diagnostics.join('\\n'))}}</pre>` : ''}}
        </div>
      </details>`;
    }}

    function renderFindingsOverview(findings) {{
      return `<div class="detail findings-section" id="findings-section">
        <h3>漏洞发现</h3>
        <div class="detail-body">
          <div class="chips">
            <span class="chip">${{esc(findings.length)}} 个发现</span>
            <span class="chip">默认完整展示</span>
          </div>
          ${{findings.length ? `<div class="findings-table-wrap">
            <table>
              <thead><tr><th>状态 / 结论</th><th>规则</th><th>置信度</th><th>摘要</th><th>人工复核</th></tr></thead>
              <tbody>
                ${{findings.map(item => {{
                  const key = manualReviewKey(state.selectedRun, item.finding_id);
                  const expanded = state.expandedManualReviewKey === key;
                  return `<tr class="clickable ${{state.selectedFinding === item.finding_id ? 'active' : ''}}" data-finding-id="${{esc(item.finding_id)}}">
                    <td>${{findingStatusChip(item)}}</td>
                    <td>${{esc(item.rule_id)}}<div class="path">${{esc(item.finding_id)}}</div></td>
                    <td>${{item.finding_status === 'completed' ? esc(item.confidence) : '—'}}</td>
                    <td><span class="plain-inline">${{plainInlineText(item.summary)}}</span><div class="path">${{esc((item.source_locations || []).map(loc => loc.file + (loc.line ? ':' + loc.line : '')).join(', '))}}</div></td>
                    <td class="manual-review-cell"><button type="button" class="manual-review-toggle" data-manual-review-toggle="true" data-finding-id="${{esc(item.finding_id)}}" aria-expanded="${{expanded ? 'true' : 'false'}}">${{manualReviewButton(item.manual_review)}}</button></td>
                  </tr>
                  <tr class="manual-review-row" data-manual-review-row="${{esc(item.finding_id)}}" ${{expanded ? '' : 'hidden'}}><td colspan="5">${{renderManualReviewCard(item)}}</td></tr>`;
                }}).join('')}}
              </tbody>
            </table>
          </div>` : '<div class="muted">暂无漏洞发现。</div>'}}
        </div>
      </div>`;
    }}

    function manualReviewKey(runId, findingId) {{
      return `${{runId || ''}}:${{findingId || ''}}`;
    }}

    function manualReviewDecisionLabel(decision) {{
      return {{ TRUE_POSITIVE: '真实漏洞', FALSE_POSITIVE: '误报', INCONCLUSIVE: '证据不足' }}[decision] || '未复核';
    }}

    function manualReviewButton(review) {{
      if (!review || !review.decision) return '<span class="chip">未复核</span>';
      return `<span class="chip ${{verdictClass(review.decision)}}">${{esc(manualReviewDecisionLabel(review.decision))}}</span>`;
    }}

    function manualReviewDraft(item) {{
      const key = manualReviewKey(state.selectedRun, item.finding_id);
      const saved = item.manual_review || null;
      let draft = state.manualReviewDrafts[key];
      if (!draft) {{
        draft = {{
          decision: saved?.decision || '',
          evidence: saved?.evidence || '',
          dirty: false,
          savedUpdatedAt: saved?.updated_at || '',
          message: '',
          error: false,
        }};
        state.manualReviewDrafts[key] = draft;
      }} else if (!draft.dirty && (saved?.updated_at || '') !== draft.savedUpdatedAt) {{
        draft.decision = saved?.decision || '';
        draft.evidence = saved?.evidence || '';
        draft.savedUpdatedAt = saved?.updated_at || '';
        draft.message = '';
        draft.error = false;
      }}
      return draft;
    }}

    function renderManualReviewCard(item, surface = 'inline') {{
      const draft = manualReviewDraft(item);
      const review = item.manual_review || null;
      const radioName = `manual-review-${{state.selectedRun || ''}}-${{item.finding_id || ''}}`;
      const option = (decision, label) => `<label class="manual-review-option"><input type="radio" name="${{esc(radioName)}}" value="${{decision}}" data-manual-review-decision="true" data-finding-id="${{esc(item.finding_id)}}" ${{draft.decision === decision ? 'checked' : ''}}> ${{esc(label)}}</label>`;
      return `<div class="manual-review-card" data-manual-review-card="${{esc(item.finding_id)}}">
        <div>
          <h4>人工复核 · ${{esc(item.rule_id || item.finding_id)}}</h4>
          <div class="path">${{esc(item.finding_id)}}</div>
        </div>
        ${{item.finding_status !== 'completed' ? '<div class="muted">AI 研判尚未完成；人工记录仍可保存，后续流水线更新不会覆盖它。</div>' : ''}}
        <div class="manual-review-options" role="radiogroup" aria-label="人工复核结论">
          ${{option('TRUE_POSITIVE', '真实漏洞')}}
          ${{option('FALSE_POSITIVE', '误报')}}
          ${{option('INCONCLUSIVE', '证据不足')}}
        </div>
        <label>人工证据
          <textarea maxlength="${{MANUAL_REVIEW_EVIDENCE_MAX_LENGTH}}" data-manual-review-evidence="true" data-finding-id="${{esc(item.finding_id)}}" placeholder="输入人工确认依据、代码位置、复现情况或排除理由">${{esc(draft.evidence)}}</textarea>
        </label>
        ${{review ? `<div class="manual-review-meta">创建：${{esc(fmtDate(review.created_at))}} · 更新：${{esc(fmtDate(review.updated_at))}}</div>` : '<div class="manual-review-meta">尚未保存人工复核。</div>'}}
        <div class="toolbar">
          <button type="button" data-manual-review-save="true" data-finding-id="${{esc(item.finding_id)}}">保存复核</button>
          <button type="button" data-manual-review-cancel="true" data-review-surface="${{esc(surface)}}" data-finding-id="${{esc(item.finding_id)}}">取消</button>
          ${{review ? `<button type="button" class="danger-button" data-manual-review-clear="true" data-finding-id="${{esc(item.finding_id)}}">清除复核</button>` : ''}}
        </div>
        <div class="manual-review-status ${{draft.error ? 'error' : draft.message ? 'success' : ''}}" data-manual-review-status="${{esc(item.finding_id)}}">${{esc(draft.message || '')}}</div>
      </div>`;
    }}

    function renderFindingWorkspace(run, findings, status, detailControls, runningMessage, currentHint, resumeHint, emptyMessage) {{
      return `
        ${{renderRunMetadataCard(run, findings, status, detailControls, runningMessage, currentHint, resumeHint)}}
        <div class="selected-finding-sticky hidden" id="selected-finding-sticky"></div>
        ${{findings.length ? renderFindingsSection(findings) : `<div class="empty">${{esc(emptyMessage)}}</div>`}}
        ${{findings.length ? '<div id="finding-detail"></div>' : ''}}
      `;
    }}

    function renderSelectedFindingSticky(finding) {{
      if (!finding) return '';
      const index = selectedFindingIndex();
      const total = (state.currentFindings || []).length;
      const reviewKey = manualReviewKey(state.selectedRun, finding.finding_id);
      const reviewOpen = state.floatingManualReviewKey === reviewKey;
      return `
        <button type="button" class="finding-nav-button" data-finding-nav="prev" title="上一个漏洞" ${{index <= 0 ? 'disabled' : ''}}>‹</button>
        <div class="selected-finding-main">
          <div class="chips">
            ${{findingStatusChip(finding)}}
            <span class="chip">${{esc(index + 1)}} / ${{esc(total)}}</span>
            ${{finding.finding_status === 'completed' ? `<span class="chip">置信度 ${{esc(finding.confidence)}}</span>` : ''}}
            <span class="chip">${{esc(finding.rule_id)}}</span>
          </div>
          <div><strong>当前漏洞：</strong> <span class="plain-inline">${{plainInlineText(finding.summary || finding.finding_id || '')}}</span></div>
          <div class="path">${{esc((finding.source_locations || []).map(loc => loc.file + (loc.line ? ':' + loc.line : '')).join(', '))}}</div>
        </div>
        <div class="selected-finding-actions">
          <button type="button" class="finding-review-button" data-selected-finding-review="${{esc(finding.finding_id)}}" title="悬浮复核当前漏洞" aria-expanded="${{reviewOpen ? 'true' : 'false'}}">复核</button>
          <button type="button" class="finding-nav-button" data-finding-nav="next" title="下一个漏洞" ${{index >= total - 1 ? 'disabled' : ''}}>›</button>
        </div>
        ${{reviewOpen ? `<div class="floating-manual-review" data-floating-manual-review="${{esc(finding.finding_id)}}">${{renderManualReviewCard(finding, 'floating')}}</div>` : ''}}
      `;
    }}

    function renderFindingsSection(findings) {{
      return renderFindingsOverview(findings);
    }}

    function bindRunControlButtons(root) {{
      for (const button of root.querySelectorAll('[data-run-copy-config]')) {{
        button.addEventListener('click', event => {{
          event.stopPropagation();
          copyRunToConfig(button.dataset.runId);
        }});
      }}
      for (const button of root.querySelectorAll('[data-run-pause]')) {{
        button.addEventListener('click', event => {{
          event.stopPropagation();
          pauseRun(button.dataset.runId);
        }});
      }}
      for (const button of root.querySelectorAll('[data-run-resume]')) {{
        button.addEventListener('click', event => {{
          event.stopPropagation();
          resumeRun(button.dataset.runId);
        }});
      }}
      for (const button of root.querySelectorAll('[data-run-stop]')) {{
        button.addEventListener('click', event => {{
          event.stopPropagation();
          stopRun(button.dataset.runId);
        }});
      }}
      for (const button of root.querySelectorAll('[data-codex-terminal-role]')) {{
        button.addEventListener('click', event => {{
          event.stopPropagation();
          openCodexTerminal(button.dataset.runId, button.dataset.codexTerminalRole);
        }});
      }}
      for (const button of root.querySelectorAll('[data-codex-stop-sessions]')) {{
        button.addEventListener('click', event => {{
          event.stopPropagation();
          stopCodexSessions(button.dataset.runId, button);
        }});
      }}
    }}

    function engineLabel(engine) {{
      if (engine === 'codex') return 'Codex 三方复核';
      if (engine === 'opencode') return 'OpenCode 三方复核';
      return '内置旧流程';
    }}

    function renderCodexSessionButtons(run) {{
      const sessions = Array.isArray(run.cli_sessions) ? run.cli_sessions : (Array.isArray(run.codex_sessions) ? run.codex_sessions : []);
      if (!sessions.length) return '';
      const liveCount = sessions.filter(session => session.live).length;
      const backend = run.engine === 'opencode' ? 'OpenCode' : 'Codex';
      const roleLabels = {{ moderator: 'Moderator', affirmative: '正方', negative: '反方' }};
      return `<div><strong>CLI Sessions：</strong><div class="codex-session-buttons">
        ${{sessions.map(session => {{
          const codexLog = backend === 'Codex' && session.transport === 'exec-ephemeral-json';
          const kind = backend === 'OpenCode' || !codexLog ? '终端' : '日志';
          const title = backend === 'OpenCode'
            ? '在当前页面打开 OpenCode 隔离任务会话'
            : (codexLog ? '在当前页面打开 Codex 隔离执行日志' : '在当前页面打开原生 Codex TUI');
          return `<button type="button" title="${{title}}" data-run-id="${{esc(run.run_id)}}" data-codex-terminal-role="${{esc(session.role || '')}}" data-cli-backend="${{esc(session.backend || run.engine || '')}}">
            ${{esc(roleLabels[session.role] || session.role || backend)}}${{kind}}${{session.live ? ' · live' : ''}}
          </button>`;
        }}).join('')}}
        <button type="button" class="danger-button" title="${{backend === 'Codex' ? '关闭当前任务的全部 Codex tmux session' : '关闭当前任务的全部 OpenCode tmux session'}}" data-run-id="${{esc(run.run_id)}}" data-codex-stop-sessions="true" ${{liveCount ? '' : 'disabled'}}>
          ${{backend === 'Codex' ? '关闭全部 Codex Sessions' : '关闭全部 OpenCode Sessions'}}${{liveCount ? ` · ${{liveCount}} live` : ''}}
        </button>
      </div></div>`;
    }}

    function renderCodexActiveAgent(run, findings, status) {{
      const activeIds = run.current_finding_ids && typeof run.current_finding_ids === 'object'
        ? run.current_finding_ids
        : {{}};
      const activeRoles = Object.entries(activeIds).filter(([, findingId]) => Boolean(findingId));
      if (status === 'running' && activeRoles.length) {{
        const labels = {{ affirmative: '正方', negative: '反方', moderator: 'Moderator' }};
        return `<div><strong>当前流水线：</strong> ${{activeRoles.map(([role, findingId]) =>
          `<span class="chip status-running">${{esc(labels[role] || role)}} · ${{esc(findingId)}}</span>`
        ).join(' ')}}</div>`;
      }}
      const state = inferCodexActiveAgent(run, findings, status);
      if (!state) return '';
      const chipClass = state.active ? 'chip status-running' : 'chip';
      return `<div><strong>当前活动 Agent：</strong> <span class="${{chipClass}}">${{esc(state.agent)}}</span> <span class="muted">${{esc(state.stage)}}</span></div>`;
    }}

    function inferCodexActiveAgent(run, findings, status) {{
      const total = Number(run.finding_count || (findings || []).length || 0);
      const completed = Number((run.completed_finding_count ?? (findings || []).length) || 0);
      if (status === 'completed') {{
        return {{ agent: '无', stage: '任务已完成。', active: false }};
      }}
      if (status === 'failed') {{
        return {{ agent: '无', stage: '任务失败，未继续推进。', active: false }};
      }}
      if (status === 'paused') {{
        return {{ agent: '无', stage: '任务已暂停，恢复后从恢复点继续。', active: false }};
      }}
      if (status === 'stopped') {{
        return {{ agent: '无', stage: '任务已停止。', active: false }};
      }}
      if (!total && !(findings || []).length) {{
        return {{ agent: 'Moderator', stage: '报告拆分阶段，等待 findings.json 交付。', active: true }};
      }}
      const currentId = run.current_finding_id || '';
      const current = currentId ? (findings || []).find(item => item.finding_id === currentId) : null;
      if (!currentId || !current) {{
        if (completed < total) {{
          return {{ agent: '正方', stage: `下一个 finding 的正方验证阶段，等待 result.json 交付。`, active: true }};
        }}
        return {{ agent: 'Moderator', stage: '等待任务收尾。', active: true }};
      }}
      const delivery = current.cli_delivery && typeof current.cli_delivery === 'object'
        ? current.cli_delivery
        : (current.codex_delivery && typeof current.codex_delivery === 'object' ? current.codex_delivery : {{}});
      const findingText = `Finding：${{currentId}}`;
      if (!delivery.affirmative) {{
        return {{ agent: '正方', stage: `${{findingText}}，正方验证阶段，等待正方 result.json。`, active: true }};
      }}
      if (!delivery.negative) {{
        return {{ agent: '反方', stage: `${{findingText}}，反方复核阶段，正方已交付。`, active: true }};
      }}
      if (!delivery.moderator) {{
        return {{ agent: 'Moderator', stage: `${{findingText}}，最终裁决阶段，正反方已交付。`, active: true }};
      }}
      if (completed < total) {{
        return {{ agent: '正方', stage: '当前 finding 已裁决，等待下一个 finding 的正方验证。', active: true }};
      }}
      return {{ agent: 'Moderator', stage: '全部 finding 已裁决，等待任务完成状态刷新。', active: true }};
    }}

    function bindRunExportButtons() {{
      const root = arguments.length ? arguments[0] : el.detail;
      for (const button of root.querySelectorAll('[data-run-export]')) {{
        button.addEventListener('click', () => exportRun(button.dataset.runId, button.dataset.runExport));
      }}
    }}

    function exportRun(runId, format) {{
      if (!runId) return;
      const chosen = format === 'json' ? 'json' : 'markdown';
      const link = document.createElement('a');
      link.href = `/runs/${{encodeURIComponent(runId)}}/export?format=${{encodeURIComponent(chosen)}}`;
      link.download = `${{runId}}.${{chosen === 'json' ? 'json' : 'md'}}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
    }}

    async function openCodexTerminal(runId, role) {{
      if (!runId || !role) return;
      const url = `/runs/${{encodeURIComponent(runId)}}/cli-sessions/${{encodeURIComponent(role)}}/terminal-ui`;
      const labels = {{ moderator: 'Moderator', affirmative: '正方', negative: '反方' }};
      const run = state.runs.find(item => item.run_id === runId) || {{}};
      const sessions = Array.isArray(run.cli_sessions) ? run.cli_sessions : (Array.isArray(run.codex_sessions) ? run.codex_sessions : []);
      const session = sessions.find(item => item.role === role) || {{}};
      const backend = run.engine === 'opencode'
        ? 'OpenCode 任务会话'
        : (session.transport === 'exec-ephemeral-json' ? 'Codex 执行日志' : 'Codex TUI');
      el.codexTerminalFrameTitle.textContent = `${{labels[role] || role}} ${{backend}}`;
      el.codexTerminalFrameMeta.textContent = `${{runId}} · ${{role}}`;
      el.codexTerminalFrame.src = url;
      el.codexTerminalFrameModal.classList.add('open');
    }}

    function closeCodexTerminal() {{
      el.codexTerminalFrame.src = 'about:blank';
      el.codexTerminalFrameModal.classList.remove('open');
    }}

    function bindFindingRows(findings) {{
      for (const row of el.detail.querySelectorAll('tr[data-finding-id]')) {{
        row.addEventListener('click', () => selectFinding(row.dataset.findingId, {{ scrollToDetail: true }}));
      }}
      for (const button of el.detail.querySelectorAll('[data-manual-review-toggle]')) {{
        button.addEventListener('click', event => {{
          event.stopPropagation();
          const key = manualReviewKey(state.selectedRun, button.dataset.findingId);
          state.floatingManualReviewKey = null;
          state.expandedManualReviewKey = state.expandedManualReviewKey === key ? null : key;
          updateManualReviewExpansionUi();
          updateSelectedFindingSticky();
        }});
      }}
      bindManualReviewControls(el.detail);
      if (!findings.length) {{
        state.selectedFinding = null;
        updateSelectedFindingSticky();
        const emptyContainer = document.getElementById('finding-detail');
        if (emptyContainer) emptyContainer.innerHTML = '<div class="empty">暂无可加载的漏洞详情。</div>';
        return;
      }}
      if (state.selectedFinding && findings.some(item => item.finding_id === state.selectedFinding)) {{
        selectFinding(state.selectedFinding, {{ scrollToDetail: false }});
        return;
      }}
      state.selectedFinding = null;
      updateSelectedFindingSticky();
      const container = document.getElementById('finding-detail');
      if (container) container.innerHTML = '<div class="empty">点击上方漏洞条目后加载完整详情。</div>';
    }}

    function bindManualReviewControls(root) {{
      for (const input of root.querySelectorAll('[data-manual-review-decision]')) {{
        input.addEventListener('change', () => {{
          const item = findingSummaryById(input.dataset.findingId);
          if (!item) return;
          const draft = manualReviewDraft(item);
          draft.decision = input.value;
          draft.dirty = true;
          draft.message = '';
          draft.error = false;
          setManualReviewStatus(item.finding_id, '', false);
        }});
      }}
      for (const textarea of root.querySelectorAll('[data-manual-review-evidence]')) {{
        textarea.addEventListener('input', () => {{
          const item = findingSummaryById(textarea.dataset.findingId);
          if (!item) return;
          const draft = manualReviewDraft(item);
          draft.evidence = textarea.value;
          draft.dirty = true;
          draft.message = '';
          draft.error = false;
          setManualReviewStatus(item.finding_id, '', false);
        }});
      }}
      for (const button of root.querySelectorAll('[data-manual-review-save]')) {{
        button.addEventListener('click', () => saveManualReview(button.dataset.findingId, button));
      }}
      for (const button of root.querySelectorAll('[data-manual-review-cancel]')) {{
        button.addEventListener('click', () => cancelManualReview(button.dataset.findingId, button.dataset.reviewSurface));
      }}
      for (const button of root.querySelectorAll('[data-manual-review-clear]')) {{
        button.addEventListener('click', () => clearManualReview(button.dataset.findingId, button));
      }}
    }}

    function findingSummaryById(findingId) {{
      return (state.currentFindings || []).find(item => item.finding_id === findingId) || null;
    }}

    function updateManualReviewExpansionUi() {{
      for (const row of el.detail.querySelectorAll('[data-manual-review-row]')) {{
        const key = manualReviewKey(state.selectedRun, row.dataset.manualReviewRow);
        row.hidden = state.expandedManualReviewKey !== key;
      }}
      for (const button of el.detail.querySelectorAll('[data-manual-review-toggle]')) {{
        const key = manualReviewKey(state.selectedRun, button.dataset.findingId);
        button.setAttribute('aria-expanded', state.expandedManualReviewKey === key ? 'true' : 'false');
      }}
    }}

    function setManualReviewStatus(findingId, message, isError) {{
      const statuses = el.detail.querySelectorAll(`[data-manual-review-status="${{cssEscape(findingId)}}"]`);
      for (const status of statuses) {{
        status.textContent = message || '';
        status.classList.toggle('error', Boolean(isError));
        status.classList.toggle('success', Boolean(message) && !isError);
      }}
    }}

    function cssEscape(value) {{
      if (window.CSS && typeof window.CSS.escape === 'function') return window.CSS.escape(String(value || ''));
      return String(value || '').replace(/[^a-zA-Z0-9_-]/g, '\\$&');
    }}

    function cancelManualReview(findingId, surface = 'inline') {{
      const item = findingSummaryById(findingId);
      if (!item) return;
      const saved = item.manual_review || null;
      state.manualReviewDrafts[manualReviewKey(state.selectedRun, findingId)] = {{
        decision: saved?.decision || '',
        evidence: saved?.evidence || '',
        dirty: false,
        savedUpdatedAt: saved?.updated_at || '',
        message: '',
        error: false,
      }};
      if (surface === 'floating') {{
        state.floatingManualReviewKey = null;
        updateSelectedFindingSticky();
        return;
      }}
      state.expandedManualReviewKey = null;
      rerenderRunDetailPreservingScroll();
    }}

    async function saveManualReview(findingId, button) {{
      const item = findingSummaryById(findingId);
      if (!item) return;
      const draft = manualReviewDraft(item);
      if (!draft.decision) {{
        draft.message = '请选择人工复核结论。';
        draft.error = true;
        setManualReviewStatus(findingId, draft.message, true);
        return;
      }}
      const originalText = button.textContent;
      button.disabled = true;
      button.textContent = '保存中...';
      setManualReviewStatus(findingId, '', false);
      try {{
        const result = await fetchJson(
          `/runs/${{encodeURIComponent(state.selectedRun)}}/findings/${{encodeURIComponent(findingId)}}/manual-review`,
          jsonPut({{ decision: draft.decision, evidence: draft.evidence }})
        );
        const currentItem = findingSummaryById(findingId);
        if (currentItem) currentItem.manual_review = result.manual_review;
        if (state.currentRun) {{
          state.currentRun.manual_reviews = state.currentRun.manual_reviews || {{}};
          state.currentRun.manual_reviews[findingId] = result.manual_review;
        }}
        state.manualReviewDrafts[manualReviewKey(state.selectedRun, findingId)] = {{
          decision: result.manual_review.decision,
          evidence: result.manual_review.evidence || '',
          dirty: false,
          savedUpdatedAt: result.manual_review.updated_at || '',
          message: result.created ? '人工复核已创建。' : '人工复核已更新。',
          error: false,
        }};
        rerenderRunDetailPreservingScroll();
      }} catch (error) {{
        draft.message = error.message;
        draft.error = true;
        setManualReviewStatus(findingId, error.message, true);
        button.disabled = false;
        button.textContent = originalText;
      }}
    }}

    async function clearManualReview(findingId, button) {{
      const item = findingSummaryById(findingId);
      if (!item) return;
      const originalText = button.textContent;
      button.disabled = true;
      button.textContent = '清除中...';
      try {{
        await fetchJson(
          `/runs/${{encodeURIComponent(state.selectedRun)}}/findings/${{encodeURIComponent(findingId)}}/manual-review`,
          {{ method: 'DELETE' }}
        );
        const currentItem = findingSummaryById(findingId);
        if (currentItem) currentItem.manual_review = null;
        if (state.currentRun?.manual_reviews) delete state.currentRun.manual_reviews[findingId];
        state.manualReviewDrafts[manualReviewKey(state.selectedRun, findingId)] = {{
          decision: '', evidence: '', dirty: false, savedUpdatedAt: '', message: '人工复核已清除。', error: false,
        }};
        rerenderRunDetailPreservingScroll();
      }} catch (error) {{
        setManualReviewStatus(findingId, error.message, true);
        button.disabled = false;
        button.textContent = originalText;
      }}
    }}

    function providerLabel(value, llmEnabled) {{
      if (!value || (!value.provider_id && !value.provider_name && !value.model && !value.client_available)) {{
        return '未配置';
      }}
      const label = `${{value.provider_name || value.provider_id || '提供商'}} / ${{value.model || '模型未知'}}`;
      let status = value.status;
      if (!status) {{
        if (value.client_available) status = 'ready';
        else if (llmEnabled === false) status = 'llm_disabled';
        else status = 'client_unavailable';
      }}
      if (status === 'ready') return label;
      const statusText = {{
        llm_disabled: 'LLM 未启用',
        missing_api_key: '缺少 API key',
        client_unavailable: '客户端不可用',
        not_configured: '未配置',
      }}[status] || status.replace(/_/g, ' ');
      if (status === 'not_configured') return statusText;
      return `${{label}} (${{statusText}})`;
    }}

    function agentLabel(value) {{
      if (!value) return '默认';
      if (value.profile_id && value.path) return `${{value.profile_id}} (${{value.path}})`;
      return value.name || value.profile_id || 'Agent';
    }}

    function agentInstructions(agents) {{
      const lines = [];
      if (agents.affirmative && agents.affirmative.instructions) {{
        lines.push(`正方 / ${{agentLabel(agents.affirmative)}}：\\n${{agents.affirmative.instructions}}`);
      }}
      if (agents.negative && agents.negative.instructions) {{
        lines.push(`反方 / ${{agentLabel(agents.negative)}}：\\n${{agents.negative.instructions}}`);
      }}
      if (agents.moderator && agents.moderator.instructions) {{
        lines.push(`主持人 / ${{agentLabel(agents.moderator)}}：\\n${{agents.moderator.instructions}}`);
      }}
      return lines.join('\\n\\n');
    }}

    function isTerminalStatus(status) {{
      return status === 'completed' || status === 'failed' || status === 'stopped' || status === 'paused';
    }}

    async function selectFinding(findingId, options = {{}}) {{
      if (state.selectedFinding && state.selectedFinding !== findingId) {{
        state.floatingManualReviewKey = null;
      }}
      state.selectedFinding = findingId;
      const requestedRunId = state.selectedRun;
      markSelectedFindingRow(findingId);
      updateSelectedFindingSticky();
      const container = document.getElementById('finding-detail');
      if (!container) return;
      const cacheKey = manualReviewKey(state.selectedRun, findingId);
      const revision = state.currentRun?.revision || state.runs.find(run => run.run_id === state.selectedRun)?.revision || '';
      const cached = state.findingDetailCache[cacheKey];
      if (cached && cached.revision === revision) {{
        renderFindingDetailIntoContainer(container, cached.detail);
        if (options.scrollToDetail) scrollFindingDetailIntoView();
        return;
      }}
      container.innerHTML = '<div class="empty">正在加载发现详情...</div>';
      if (options.scrollToDetail) scrollFindingDetailIntoView();
      try {{
        const detail = await fetchJson(`/runs/${{encodeURIComponent(state.selectedRun)}}/findings/${{encodeURIComponent(findingId)}}`);
        state.findingDetailCache[cacheKey] = {{ revision: detail.revision || revision, detail }};
        const currentRevision = state.currentRun?.revision || '';
        if (state.selectedRun !== requestedRunId || state.selectedFinding !== findingId) return;
        if (detail.revision && currentRevision && detail.revision !== currentRevision) return;
        renderFindingDetailIntoContainer(container, detail);
        updateSelectedFindingSticky();
        if (options.scrollToDetail) scrollFindingDetailIntoView();
      }} catch (error) {{
        container.innerHTML = `<div class="empty error">${{esc(error.message)}}</div>`;
      }}
    }}

    function renderFindingDetailIntoContainer(container, detail) {{
      container.innerHTML = renderFindingDetail(detail);
      bindLazyFindingSections(container, detail);
    }}

    function scrollFindingDetailIntoView() {{
      const container = document.getElementById('finding-detail');
      if (!container) return;
      const sticky = document.getElementById('selected-finding-sticky');
      const stickyHeight = sticky && !sticky.classList.contains('hidden') ? sticky.offsetHeight + 12 : 0;
      const target = Math.max(0, container.offsetTop - stickyHeight);
      el.detailScroll.scrollTo({{ top: target, behavior: 'smooth' }});
    }}

    function markSelectedFindingRow(findingId) {{
      for (const row of el.detail.querySelectorAll('tr[data-finding-id]')) {{
        row.classList.toggle('active', row.dataset.findingId === findingId);
      }}
    }}

    function selectedFindingSummary() {{
      return (state.currentFindings || []).find(item => item.finding_id === state.selectedFinding) || null;
    }}

    function selectedFindingIndex() {{
      return (state.currentFindings || []).findIndex(item => item.finding_id === state.selectedFinding);
    }}

    function updateSelectedFindingSticky() {{
      const sticky = document.getElementById('selected-finding-sticky');
      if (!sticky) return;
      const finding = selectedFindingSummary();
      sticky.innerHTML = renderSelectedFindingSticky(finding);
      bindStickyFindingNav();
      updateStickyFindingVisibility();
    }}

    function bindStickyFindingNav() {{
      const sticky = document.getElementById('selected-finding-sticky');
      if (!sticky) return;
      for (const button of sticky.querySelectorAll('[data-finding-nav]')) {{
        button.addEventListener('click', () => switchFinding(button.dataset.findingNav === 'prev' ? -1 : 1));
      }}
      for (const button of sticky.querySelectorAll('[data-selected-finding-review]')) {{
        button.addEventListener('click', () => openManualReviewFromSticky(button.dataset.selectedFindingReview));
      }}
      bindManualReviewControls(sticky);
    }}

    function openManualReviewFromSticky(findingId) {{
      const item = findingSummaryById(findingId);
      if (!item) return;
      const key = manualReviewKey(state.selectedRun, findingId);
      state.floatingManualReviewKey = state.floatingManualReviewKey === key ? null : key;
      state.expandedManualReviewKey = null;
      updateManualReviewExpansionUi();
      updateSelectedFindingSticky();
    }}

    function switchFinding(delta) {{
      const findings = state.currentFindings || [];
      if (!findings.length) return;
      const index = selectedFindingIndex();
      const nextIndex = Math.min(Math.max((index < 0 ? 0 : index) + delta, 0), findings.length - 1);
      const next = findings[nextIndex];
      if (!next || next.finding_id === state.selectedFinding) return;
      selectFinding(next.finding_id, {{ scrollToDetail: true }});
    }}

    function updateStickyFindingVisibility() {{
      const sticky = document.getElementById('selected-finding-sticky');
      const section = document.getElementById('findings-section');
      if (!sticky || !section || !selectedFindingSummary()) return;
      const containerRect = el.detailScroll.getBoundingClientRect();
      const sectionRect = section.getBoundingClientRect();
      const shouldShow = sectionRect.bottom <= containerRect.top + 8;
      sticky.classList.toggle('hidden', !shouldShow);
    }}

    function findingReportEvidence(detail) {{
      return (detail.evidence_chain || []).find(item => item && (item.kind === 'REPORT' || item.source === 'input-report')) || null;
    }}

    function jsonBlock(value) {{
      try {{
        return JSON.stringify(value ?? {{}}, null, 2);
      }} catch (_error) {{
        return String(value ?? '');
      }}
    }}

    function renderLazyFindingSection(kind, title) {{
      return `<details class="detail lazy-finding-section" data-lazy-finding-section="${{esc(kind)}}">
        <summary class="detail-summary">${{esc(title)}}</summary>
        <div class="detail-body" data-lazy-finding-body="${{esc(kind)}}"><div class="muted">展开后加载。</div></div>
      </details>`;
    }}

    function renderOriginalReportBody(detail) {{
      const item = findingReportEvidence(detail);
      const data = item && item.data ? item.data : {{}};
      const locations = Array.isArray(data.locations) ? data.locations : [];
      const codeFlows = Array.isArray(data.code_flows) ? data.code_flows : [];
      const properties = data.properties && typeof data.properties === 'object' ? data.properties : null;
      const rawResult = data.raw_result && typeof data.raw_result === 'object' ? data.raw_result : null;
      const rawLines = [
        data.rule_id ? `规则：${{data.rule_id}}` : '',
        data.level ? `等级：${{data.level}}` : '',
        data.message ? `消息：${{data.message}}` : ''
      ].filter(Boolean).join('\\n');
      return `
        ${{rawLines ? `<div class="plain-text">${{rawText(rawLines)}}</div>` : '<div class="muted">未找到输入报告摘要。</div>'}}
        ${{locations.length ? `<div><strong>报告位置：</strong><div class="plain-text">${{rawText(locations.join('\\n'))}}</div></div>` : ''}}
        ${{codeFlows.length ? `<div><strong>报告代码流：</strong><pre>${{esc(codeFlows.map((flow, index) => `Flow ${{index + 1}}:\\n${{flow.join('\\n')}}`).join('\\n\\n'))}}</pre></div>` : ''}}
        ${{properties ? `<div><strong>报告 properties：</strong><pre>${{esc(jsonBlock(properties))}}</pre></div>` : ''}}
        ${{rawResult ? `<div><strong>原始 SARIF result：</strong><pre>${{esc(jsonBlock(rawResult))}}</pre></div>` : ''}}`;
    }}

    function renderOriginalReportSection(_detail) {{
      return renderLazyFindingSection('original-report', '原始报告详情');
    }}

    function uniqueDebateTurns(debate) {{
      const seen = new Set();
      return (debate || []).filter(turn => {{
        const key = [turn.role || '', turn.round_index ?? '', String(turn.claim || '').replace(/\\s+/g, ' ').trim()].join('|');
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      }});
    }}

    function conclusionWithoutEvidenceGraph(value) {{
      const text = String(value ?? '').replace(/\\r\\n?/g, '\\n');
      const markers = ['\\n### 证据串联图', '\\n### 调用链 / 数据流概览'];
      for (const marker of markers) {{
        const index = text.indexOf(marker);
        if (index >= 0) return text.slice(0, index).trim();
      }}
      return text.startsWith('### 证据串联图') || text.startsWith('### 调用链 / 数据流概览') ? '' : text.trim();
    }}

    function renderPathOverviewSection(detail) {{
      const graph = detail.evidence_graph && typeof detail.evidence_graph === 'object' ? detail.evidence_graph : null;
      if (!graph || !Array.isArray(graph.nodes) || !graph.nodes.length) return '';
      const overview = String(graph.path_overview || buildPathOverview(graph) || '').replace(/\\bev-[0-9A-Za-z_-]+\\b/g, '').trim();
      if (!overview) return '';
      return `<div class="detail">
        <h3>调用链 / 数据流概览</h3>
        <div class="detail-body">
          <pre class="path-overview">${{esc(overview)}}</pre>
        </div>
      </div>`;
    }}

    function buildPathOverview(graph) {{
      const nodes = new Map((graph.nodes || []).map(node => [String(node.id), node]));
      const edges = Array.isArray(graph.edges) ? graph.edges : [];
      const breaks = Array.isArray(graph.breaks) ? graph.breaks : [];
      const lines = [];
      lines.push(...pathCategoryLines('调用链', nodes, edges, new Set(['调用链', '调用', '定位符号']), breaks));
      lines.push('');
      lines.push(...pathCategoryLines('数据流', nodes, edges, new Set(['数据流', 'SARIF 代码流']), breaks));
      if (breaks.length) {{
        lines.push('', '未闭环点：');
        for (const item of breaks) lines.push(`- ${{cleanPathText(item.label || item.reason || '未闭环')}}`);
      }}
      return lines.join('\\n').trim();
    }}

    function pathCategoryLines(title, nodes, edges, labels, breaks) {{
      const categoryEdges = edges.filter(edge => labels.has(String(edge.label || '')) && !isContextAnchorEdge(edge, nodes));
      const lines = [`${{title}}状态：${{pathStatus(categoryEdges, breaks)}}`, ''];
      if (!categoryEdges.length) {{
        lines.push(`${{title}}：未获得可展示路径。`);
        return lines;
      }}
      let index = 1;
      for (const component of edgeComponents(categoryEdges)) {{
        lines.push(`${{title}} ${{index}}：`);
        lines.push(...verticalComponentLines(component, nodes));
        lines.push('');
        index += 1;
      }}
      while (lines[lines.length - 1] === '') lines.pop();
      return lines;
    }}

    function edgeComponents(edges) {{
      let remaining = [...edges];
      const components = [];
      while (remaining.length) {{
        const seed = remaining.shift();
        const component = [seed];
        const nodeIds = new Set([String(seed.from), String(seed.to)]);
        let changed = true;
        while (changed) {{
          changed = false;
          const next = [];
          for (const edge of remaining) {{
            const from = String(edge.from);
            const to = String(edge.to);
            if (nodeIds.has(from) || nodeIds.has(to)) {{
              component.push(edge);
              nodeIds.add(from);
              nodeIds.add(to);
              changed = true;
            }} else {{
              next.push(edge);
            }}
          }}
          remaining = next;
        }}
        components.push(component);
      }}
      return components;
    }}

    function verticalComponentLines(edges, nodes) {{
      const outgoing = new Map();
      const incoming = new Set();
      const nodeIds = [];
      for (const edge of edges) {{
        const from = String(edge.from);
        const to = String(edge.to);
        if (!outgoing.has(from)) outgoing.set(from, []);
        outgoing.get(from).push(edge);
        incoming.add(to);
        if (!nodeIds.includes(from)) nodeIds.push(from);
        if (!nodeIds.includes(to)) nodeIds.push(to);
      }}
      const starts = nodeIds.filter(id => !incoming.has(id));
      if (!starts.length && nodeIds.length) starts.push(nodeIds[0]);
      const seenEdges = new Set();
      const lines = [];
      const walk = (nodeId, depth, stack) => {{
        lines.push(`${{'  '.repeat(depth)}}${{pathNodeLabel(nodes.get(nodeId), nodeId)}}`);
        if (stack.has(nodeId)) {{
          lines.push(`${{'  '.repeat(depth + 1)}}↳ 循环调用，已在上方出现。`);
          return;
        }}
        const nextStack = new Set(stack);
        nextStack.add(nodeId);
        for (const edge of outgoing.get(nodeId) || []) {{
          const key = [edge.from, edge.to, edge.label || '', edge.status || ''].join('|');
          if (seenEdges.has(key)) continue;
          seenEdges.add(key);
          lines.push(`${{'  '.repeat(depth + 1)}}↓ ${{pathEdgeLabel(edge)}}`);
          walk(String(edge.to), depth + 1, nextStack);
        }}
      }};
      for (const start of starts) walk(start, 0, new Set());
      return lines.length ? lines : ['无可展示路径。'];
    }}

    function pathStatus(edges, breaks) {{
      if (breaks.length) return '未闭环';
      if (!edges.length) return '未获得证据';
      if (edges.some(edge => edge.status === 'break')) return '未闭环';
      if (edges.some(edge => edge.status === 'partial')) return '部分闭环';
      return '已闭环';
    }}

    function isContextAnchorEdge(edge, nodes) {{
      const source = nodes.get(String(edge.from)) || {{}};
      const target = nodes.get(String(edge.to)) || {{}};
      return ['REPORT', 'SOURCE_LOCATION'].includes(source.kind) && ['SARIF_CODE_FLOW', 'DATA_FLOW', 'CALL_CHAIN'].includes(target.kind);
    }}

    function pathEdgeLabel(edge) {{
      const label = cleanPathText(edge.label || '连接');
      if (edge.status === 'break') return `断链：${{label}}`;
      if (edge.status === 'partial') return `${{label}}（部分）`;
      return label;
    }}

    function pathNodeLabel(node, fallback) {{
      const kindLabels = {{
        REPORT: '报告',
        SOURCE_LOCATION: '源码位置',
        SARIF_CODE_FLOW: '代码流',
        DATA_FLOW: '数据流',
        CALL_CHAIN: '调用链',
        CALLER: '调用方',
        CALLEE: '被调函数',
        SYMBOL: '符号',
        BREAK: '断链'
      }};
      if (!node) return cleanPathText(fallback);
      const status = node.status === 'break' ? ' [断链]' : node.status === 'partial' ? ' [部分]' : '';
      return `[${{kindLabels[node.kind] || node.kind || '节点'}}] ${{cleanPathText(node.label || fallback)}}${{status}}`;
    }}

    function cleanPathText(value) {{
      return String(value ?? '').replace(/\\bev-[0-9A-Za-z_-]+\\b/g, '').replace(/\\s+/g, ' ').trim() || '未命名节点';
    }}

    function renderVerificationCaseSection(detail) {{
      const item = detail.verification_case && typeof detail.verification_case === 'object' ? detail.verification_case : null;
      if (!item || !Object.keys(item).length) return '';
      const proof = Array.isArray(item.required_proof) ? item.required_proof : [];
      return `<div class="detail">
        <h3>研判用例</h3>
        <div class="detail-body">
          <div><strong>漏洞类型/规则：</strong> <span class="plain-text">${{plainText(item.vulnerability_type || '未知')}}</span></div>
          <div><strong>报告消息：</strong> <span class="plain-text">${{plainText(item.reported_message || '未知')}}</span></div>
          <div><strong>报告位置：</strong> <span class="plain-text">${{plainText(item.reported_location || '未知')}}</span></div>
          <div><strong>报告源点：</strong> <span class="plain-text">${{plainText(item.reported_source || '未提取')}}</span></div>
          <div><strong>报告汇点/危险函数：</strong> <span class="plain-text">${{plainText(item.reported_sink || item.dangerous_function || '未提取')}}</span></div>
          <div><strong>报告期望路径：</strong> <span class="plain-text">${{plainText(item.expected_attack_path || '未提供 codeFlow')}}</span></div>
          ${{proof.length ? `<div><strong>证明要件：</strong><ul>${{proof.map(value => `<li><span class="plain-text">${{plainText(value)}}</span></li>`).join('')}}</ul></div>` : ''}}
        </div>
      </div>`;
    }}

    function renderScorecardSection(detail) {{
      const scorecard = detail.scorecard && typeof detail.scorecard === 'object' ? detail.scorecard : null;
      if (!scorecard || !Object.keys(scorecard).length) return '';
      const rows = [
        ['源码定位', scorecard.source_location],
        ['入口可达', scorecard.entry_reachability],
        ['调用链', scorecard.call_chain],
        ['数据流', scorecard.data_flow],
        ['输入可控性', scorecard.controllability],
        ['防护消减', scorecard.protection],
        ['影响归因', scorecard.impact],
      ];
      const rationale = Array.isArray(scorecard.rationale) ? scorecard.rationale : [];
      return `<div class="detail">
        <h3>证据评分卡</h3>
        <div class="detail-body">
          <div class="chips">
            ${{rows.map(([name, status]) => `<span class="chip">${{esc(name)}}：${{esc(statusLabel(status))}}</span>`).join('')}}
            ${{scorecard.verdict_label ? `<span class="chip">${{esc(scorecard.verdict_label)}}</span>` : ''}}
            ${{scorecard.confidence !== undefined && scorecard.confidence !== null ? `<span class="chip">评分 ${{esc(scorecard.confidence)}}</span>` : ''}}
          </div>
          ${{rationale.length ? `<div><strong>理由：</strong><ul>${{rationale.map(value => `<li><span class="plain-text">${{plainText(value)}}</span></li>`).join('')}}</ul></div>` : ''}}
        </div>
      </div>`;
    }}

    function renderEvidenceLedgerSection(detail) {{
      const ledger = Array.isArray(detail.evidence_ledger) ? detail.evidence_ledger : [];
      if (!ledger.length) return '';
      return `<div class="detail">
        <h3>证据台账</h3>
        <div class="detail-body">
          ${{ledger.map(item => `<div>
            <div class="chips">
              <span class="chip">${{esc(item.claim || item.type || item.id || '证据项')}}</span>
              <span class="chip">${{esc(statusLabel(item.status))}}</span>
              <span class="chip">${{esc(item.source || 'not-collected')}}</span>
            </div>
            ${{item.location ? `<div class="path">位置：${{esc(item.location)}}</div>` : ''}}
            ${{Array.isArray(item.evidence_ids) && item.evidence_ids.length ? `<div class="path">证据：${{esc(item.evidence_ids.join(', '))}}</div>` : ''}}
          </div>`).join('')}}
        </div>
      </div>`;
    }}

    function renderRawTurn(turn) {{
      const raw = String(turn.raw_claim || '').trim();
      const claim = String(turn.claim || '').trim();
      if (!raw || raw === claim) return '';
      return `<details class="raw-debug"><summary>原始输出</summary><pre>${{esc(raw)}}</pre></details>`;
    }}

    function renderDebateStructuredTurn(turn) {{
      const structured = turn && turn.structured && typeof turn.structured === 'object' ? turn.structured : null;
      if (!structured || !Object.keys(structured).length) return '';
      return `<details class="debate-structured" open>
        <summary>结构化材料</summary>
        <div class="detail-body">${{renderCodexStructuredContent(structured, {{ showSummary: false }})}}</div>
      </details>`;
    }}

    function statusLabel(status) {{
      const labels = {{
        confirmed: '已确认',
        candidate: '候选/部分',
        missing: '缺失',
        invalid: '无效',
        none: '未发现',
        blocks: '已阻断',
      }};
      return labels[String(status || '')] || String(status || '未知');
    }}

    function renderCodexWorkflowBody(detail) {{
      const workflow = detail.cli_workflow && typeof detail.cli_workflow === 'object'
        ? detail.cli_workflow
        : (detail.codex_workflow && typeof detail.codex_workflow === 'object' ? detail.codex_workflow : null);
      if (!workflow) return '';
      const moderator = workflow.moderator && typeof workflow.moderator === 'object' ? workflow.moderator : {{}};
      const affirmative = workflow.affirmative && typeof workflow.affirmative === 'object' ? workflow.affirmative : {{}};
      const negative = workflow.negative && typeof workflow.negative === 'object' ? workflow.negative : {{}};
      const moderatorText = moderator.final_conclusion || moderator.reasoning_summary || detail.final_conclusion || detail.reasoning_summary || '';
      return `<div>
          <strong>Moderator 总结：</strong>
          ${{markdownBlock(moderatorText || '暂无 Moderator 总结。')}}
        </div>
        ${{renderCodexRoleConclusion('正方 finding', affirmative, false)}}
        ${{renderCodexRoleConclusion('反方 finding', negative, false)}}`;
    }}

    function renderCodexWorkflowSection(detail) {{
      const workflow = detail.cli_workflow && typeof detail.cli_workflow === 'object'
        ? detail.cli_workflow
        : (detail.codex_workflow && typeof detail.codex_workflow === 'object' ? detail.codex_workflow : null);
      return workflow ? renderLazyFindingSection('cli-workflow', 'CLI 三方复核') : '';
    }}

    function renderCodexEvidenceList(label, values) {{
      const items = Array.isArray(values) ? values : [];
      if (!items.length) return '';
      return `<div class="markdown-field"><strong>${{esc(label)}}：</strong><ol class="codex-evidence-list">
        ${{items.map(item => {{
          const lines = [];
          if (item && typeof item === 'object') {{
            if (item.claim) lines.push(`**论点**：${{item.claim}}`);
            if (item.evidence) lines.push(`**证据**：${{item.evidence}}`);
            if (item.location) lines.push(`**位置**：\`${{item.location}}\``);
            if (item.tool) lines.push(`**工具**：${{item.tool}}`);
          }} else {{
            lines.push(String(item ?? ''));
          }}
          return `<li>${{markdownBlock(lines.join('\\n\\n'))}}</li>`;
        }}).join('')}}
      </ol></div>`;
    }}

    function renderLocationList(label, locations) {{
      const values = (Array.isArray(locations) ? locations : []).map(location => {{
        if (!location || typeof location !== 'object') return String(location ?? '');
        const file = location.file || '';
        const line = location.line !== undefined && location.line !== null ? `:${{location.line}}` : '';
        const column = location.column !== undefined && location.column !== null ? `:${{location.column}}` : '';
        const symbol = location.symbol ? ` — ${{location.symbol}}` : '';
        return `\`${{file}}${{line}}${{column}}\`${{symbol}}`;
      }});
      return markdownList(label, values);
    }}

    function renderCodexStructuredContent(data, options = {{}}) {{
      if (!data || typeof data !== 'object' || !Object.keys(data).length) return '';
      const showSummary = options.showSummary !== false;
      const summary = data.summary || data.reasoning_summary || data.final_conclusion || '';
      const evidence = Array.isArray(data.key_evidence) ? data.key_evidence : [];
      const limitations = Array.isArray(data.limitations) ? data.limitations : [];
      const nextSteps = Array.isArray(data.recommended_next_steps) ? data.recommended_next_steps : [];
      const disputed = Array.isArray(data.disputed_points) ? data.disputed_points : [];
      return `
        ${{showSummary ? markdownField('摘要', summary || '无摘要。') : ''}}
        ${{markdownField('攻击链', data.attack_chain)}}
        ${{markdownField('数据流', data.data_flow)}}
        ${{markdownField('防护研判', data.protection_assessment)}}
        ${{markdownField('影响研判', data.impact_assessment)}}
        ${{renderCodexEvidenceList('关键证据', evidence)}}
        ${{markdownList('限制', limitations)}}
        ${{markdownList('争议点', disputed)}}
        ${{markdownList('建议下一步', nextSteps)}}
        ${{renderLocationList('源码位置', data.source_locations)}}`;
    }}

    function renderCodexRoleConclusion(title, data, open) {{
      if (!data || !Object.keys(data).length) return `<details><summary>${{esc(title)}}：暂无结果</summary></details>`;
      return `<details ${{open ? 'open' : ''}}>
        <summary>${{esc(title)}} · ${{esc(data.position || data.verdict || 'INCONCLUSIVE')}} · 置信度 ${{esc(data.confidence ?? '')}}</summary>
        <div class="detail-body">
          ${{renderCodexStructuredContent(data)}}
          <details><summary>原始 JSON</summary><pre>${{esc(jsonBlock(data))}}</pre></details>
        </div>
      </details>`;
    }}

    function renderDebateBody(detail) {{
      const debate = uniqueDebateTurns(detail.debate || []);
      return debate.map(turn => `<div class="debate-turn">
        <strong>${{esc(roleLabel(turn.role))}} 第 ${{esc(turn.round_index)}} 回合</strong>
        ${{markdownBlock(turn.claim)}}
        ${{renderDebateStructuredTurn(turn)}}
        <div class="path">证据：${{esc((turn.evidence_ids || []).join(', '))}}</div>
        ${{renderRawTurn(turn)}}
      </div>`).join('') || '<div class="muted">暂无博弈回合记录。</div>';
    }}

    function renderEvidenceBody(detail) {{
      const evidence = detail.evidence_chain || [];
      return evidence.map(item => `<div>
        <div class="chips">
          <span class="chip">${{esc(item.evidence_id)}}</span>
          <span class="chip">${{esc(evidenceKindLabel(item.kind))}}</span>
          <span class="chip">${{esc(evidenceStrengthLabel(item.strength))}}</span>
          <span class="chip">${{esc(item.source)}}</span>
        </div>
        ${{markdownBlock(item.summary)}}
        ${{item.locations && item.locations.length ? `<div class="path">位置：${{esc(item.locations.map(locationText).join(' -> '))}}</div>` : ''}}
        ${{item.data && (item.data.requested_file || item.data.resolved_file) ? `<div class="path">路径映射：${{esc(item.data.requested_file || '')}}${{item.data.resolved_file ? ' => ' + esc(item.data.resolved_file) : ''}}</div>` : ''}}
        ${{item.snippet ? `<pre>${{esc(item.snippet)}}</pre>` : ''}}
      </div>`).join('') || '<div class="muted">暂无证据记录。</div>';
    }}

    function bindLazyFindingSections(container, detail) {{
      const renderers = {{
        'original-report': () => renderOriginalReportBody(detail),
        'cli-workflow': () => renderCodexWorkflowBody(detail),
        'debate': () => renderDebateBody(detail),
        'evidence': () => renderEvidenceBody(detail),
      }};
      for (const section of container.querySelectorAll('[data-lazy-finding-section]')) {{
        section.addEventListener('toggle', () => {{
          if (!section.open || section.dataset.lazyLoaded === 'true') return;
          const kind = section.dataset.lazyFindingSection;
          const body = section.querySelector('[data-lazy-finding-body]');
          if (!body || !renderers[kind]) return;
          body.innerHTML = renderers[kind]();
          section.dataset.lazyLoaded = 'true';
        }});
      }}
    }}

    function renderFindingDetail(detail) {{
      const conclusion = conclusionWithoutEvidenceGraph(detail.final_conclusion);
      if (detail.finding_status && detail.finding_status !== 'completed') {{
        return `
          ${{renderOriginalReportSection(detail)}}
          <div class="detail">
            <h3>发现详情</h3>
            <div class="detail-body">
              <div class="chips">
                ${{findingStatusChip(detail)}}
                <span class="chip">${{esc(detail.rule_id)}}</span>
              </div>
              <div class="muted">该漏洞报告尚未完成三方复核；任务恢复后会从首个未完成项重新处理。</div>
            </div>
          </div>
          ${{renderCodexWorkflowSection(detail)}}`;
      }}
      return `
        ${{renderOriginalReportSection(detail)}}
        <div class="detail">
          <h3>发现详情</h3>
          <div class="detail-body">
            <div class="chips">
              <span class="chip ${{verdictClass(detail.verdict)}}">${{esc(verdictLabel(detail.verdict))}}</span>
              <span class="chip">置信度 ${{esc(detail.confidence)}}</span>
              <span class="chip">${{esc(detail.rule_id)}}</span>
            </div>
            ${{markdownField('最终结论', conclusion)}}
            ${{markdownField('理由摘要', detail.reasoning_summary)}}
            ${{markdownField('防护研判', detail.protection_assessment)}}
            ${{markdownField('影响研判', detail.impact_assessment)}}
            ${{markdownList('争议点', detail.disputed_points || [])}}
          </div>
        </div>
        ${{renderCodexWorkflowSection(detail)}}
        ${{renderVerificationCaseSection(detail)}}
        ${{renderScorecardSection(detail)}}
        ${{renderPathOverviewSection(detail)}}
        ${{renderEvidenceLedgerSection(detail)}}
        ${{renderLazyFindingSection('debate', '博弈过程')}}
        ${{renderLazyFindingSection('evidence', '证据链')}}`;
    }}

    function locationText(location) {{
      if (!location) return '';
      const file = location.file || '';
      if (location.line === undefined || location.line === null) return file;
      if (location.column === undefined || location.column === null) return `${{file}}:${{location.line}}`;
      return `${{file}}:${{location.line}}:${{location.column}}`;
    }}

    function renderEmpty(message) {{
      el.title.textContent = '运行详情';
      el.status.textContent = '未选择任务';
      state.currentFindings = [];
      el.overview.innerHTML = '';
      el.detail.innerHTML = `<div class="empty">${{esc(message)}}</div>`;
    }}
    function renderError(error) {{
      el.subtitle.textContent = '加载记录失败';
      el.detail.innerHTML = `<div class="empty error">${{esc(error.message)}}</div>`;
    }}

    document.addEventListener('click', event => {{
      const target = event.target instanceof Element ? event.target : null;
      if (state.deleteConfirmRunId && !target?.closest('[data-run-delete]')) {{
        state.deleteConfirmRunId = null;
        updateDeleteConfirmationUi();
      }}
    }});

    refreshAll();
  </script>
</body>
</html>"""
