from __future__ import annotations

import json
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
from .llm import test_provider_connection
from .logging_config import DEFAULT_LOG_FILE, configure_logging, logger
from .mcp_config import DEFAULT_MCP_SERVERS_FILE, MCPServerStore
from .models import AgentConfig, RunConfig, to_jsonable
from .pipeline import RunStopped, run_judgement
from .providers import DEFAULT_PROVIDERS_FILE, ProviderStore
from .records import RunRecordStore
from .skills import DEFAULT_SKILLS_FILE, SkillSourceStore


DEFAULT_RECORDS_DIR = Path(".vuln-judger") / "runs"
LOG = logger("api")
PROMPT_ECHO_MARKERS = (
    "AGENT.md",
    "Agent 配置",
    "角色配置",
    "角色名称",
    "提示词",
    "用户要求",
    "任务要求",
    "格式要求",
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
) -> None:
    configured_log = configure_logging(log_file)
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
        "API 服务启动 host=%s port=%s records=%s providers=%s agents=%s mcp=%s skills=%s",
        host,
        port,
        store.root,
        provider_store.path,
        agent_store.root,
        mcp_store.path,
        skill_store.path,
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
    recovered = store.recover_unfinished()
    if recovered:
        LOG.info("恢复未完成运行记录 count=%s ids=%s", len(recovered), ",".join(str(item.get("run_id")) for item in recovered))
    tasks = {}
    stop_events = {}
    pause_events = {}
    tasks_lock = Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "vuln-judger/0.1"

        def do_POST(self) -> None:  # noqa: N802
            parts = _parts(self.path)
            try:
                if parts == ["runs"]:
                    payload = self._read_json()
                    run_id = _new_run_id()
                    LOG.info("收到创建任务请求 run_id=%s payload=%s", run_id, _safe_payload(payload))
                    config = _config_from_payload(payload, provider_store.path, run_id, agent_store, mcp_store.path, skill_store)
                    task = _task_from_config(config, run_id, "running")
                    stop_event = Event()
                    pause_event = Event()
                    store.save_payload(task)
                    with tasks_lock:
                        tasks[run_id] = task
                        stop_events[run_id] = stop_event
                        pause_events[run_id] = pause_event
                    Thread(
                        target=_run_task,
                        args=(config, store, tasks, stop_events, pause_events, tasks_lock, stop_event, pause_event),
                        daemon=True,
                    ).start()
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
                    result = _request_stop(tasks, stop_events, tasks_lock, parts[1])
                    if result is None:
                        self._json({"error": "运行任务未找到或已结束"}, HTTPStatus.NOT_FOUND)
                    else:
                        LOG.info("收到停止任务请求 run_id=%s status=%s", parts[1], result.get("status"))
                        store.save_payload(result)
                        self._json(result)
                    return
                if len(parts) == 3 and parts[0] == "runs" and parts[2] == "pause":
                    result = _request_pause(tasks, pause_events, tasks_lock, parts[1])
                    if result is None:
                        self._json({"error": "运行任务未找到或已结束"}, HTTPStatus.NOT_FOUND)
                    else:
                        LOG.info("收到暂停任务请求 run_id=%s status=%s", parts[1], result.get("status"))
                        store.save_payload(result)
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
                    )
                    if result is None:
                        self._json({"error": "暂停任务未找到或状态不允许恢复"}, HTTPStatus.NOT_FOUND)
                    else:
                        LOG.info("收到恢复任务请求 run_id=%s status=%s", parts[1], result.get("status"))
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
                run = store.get(parts[1])
                task = _get_task(tasks, tasks_lock, parts[1])
                active_task = task if task is not None and task.get("status") != "completed" else None
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
                        self._json(active_task)
                        return
                    if len(parts) == 3 and parts[2] == "findings":
                        self._json([_finding_summary(report) for report in active_task.get("reports", [])])
                        return
                    if len(parts) == 4 and parts[2] == "findings":
                        for report in active_task.get("reports", []):
                            if report.get("finding_id") == parts[3]:
                                self._json(report)
                                return
                        self._json({"error": "发现尚未生成或未找到"}, HTTPStatus.NOT_FOUND)
                        return
                if run is None:
                    if task is None:
                        self._json({"error": "运行记录未找到"}, HTTPStatus.NOT_FOUND)
                        return
                    if len(parts) == 2:
                        self._json(task)
                        return
                    if len(parts) == 3 and parts[2] == "findings":
                        self._json([_finding_summary(report) for report in task.get("reports", [])])
                        return
                    if len(parts) == 4 and parts[2] == "findings":
                        for report in task.get("reports", []):
                            if report.get("finding_id") == parts[3]:
                                self._json(report)
                                return
                        self._json({"error": "发现尚未生成或未找到"}, HTTPStatus.NOT_FOUND)
                        return
                    self._json({"error": "运行尚未完成"}, HTTPStatus.BAD_REQUEST)
                    return
                if len(parts) == 2:
                    self._json(_run_detail(run))
                    return
                if len(parts) == 3 and parts[2] == "findings":
                    self._json([_finding_summary(report) for report in run.get("reports", [])])
                    return
                if len(parts) == 4 and parts[2] == "findings":
                    for report in run.get("reports", []):
                        if report.get("finding_id") == parts[3]:
                            self._json(report)
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
            raw = json.dumps(to_jsonable(payload), ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "application/json; charset=utf-8")
            self.send_header("cache-control", "no-store")
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
        skills_path=skills_path,
        providers_file=providers_file,
        mcp_servers_file=mcp_servers_file,
        run_id=run_id,
        max_rounds=int(payload.get("max_rounds") or 4),
        auto_index_tools=bool(payload.get("auto_index_tools") or False),
        enable_external_tools=bool(payload.get("enable_external_tools", True)),
        enable_llm=bool(payload.get("enable_llm", False)),
        llm_model=payload.get("llm_model"),
        llm_endpoint=payload.get("llm_endpoint"),
        affirmative_provider_id=payload.get("affirmative_provider_id"),
        negative_provider_id=payload.get("negative_provider_id"),
        moderator_provider_id=payload.get("moderator_provider_id"),
        affirmative_agent=affirmative_agent,
        negative_agent=negative_agent,
        moderator_agent=moderator_agent,
    )


def _run_detail(run):
    return {
        "run_id": run.get("run_id"),
        "status": run.get("status", "completed"),
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
        "completed_finding_count": run.get("completed_finding_count", len(run.get("reports", []))),
        "current_finding_id": run.get("current_finding_id"),
        "current_finding_index": run.get("current_finding_index"),
        "resume_from_finding_id": run.get("resume_from_finding_id"),
        "resume_from_finding_index": run.get("resume_from_finding_index"),
        "config": run.get("config", {}),
    }


def _list_runs(store: RunRecordStore, tasks: dict, tasks_lock: Lock):
    records = store.list()
    with tasks_lock:
        visible_tasks = [
            dict(task)
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
        "error": error,
        "config": _config_task_snapshot(config),
        "completed_finding_count": 0,
        "current_finding_id": None,
        "current_finding_index": None,
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
) -> None:
    last_payload = None
    try:
        LOG.info("后台任务开始 run_id=%s report=%s source=%s", config.run_id, config.sarif_path, config.source_path)
        def on_progress(progress_report):
            nonlocal last_payload
            payload = to_jsonable(progress_report)
            payload["config"] = _config_task_snapshot(config)
            last_payload = payload
            status = "stopping" if stop_event.is_set() else "pausing" if pause_event.is_set() else "running"
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
            should_stop=lambda: stop_event.is_set() or pause_event.is_set(),
        )
        payload = to_jsonable(report)
        payload["config"] = _config_task_snapshot(config)
        store.save_payload(payload)
        with tasks_lock:
            tasks[report.run_id] = _task_from_report_payload(payload, "completed")
        LOG.info("后台任务完成 run_id=%s findings=%s", report.run_id, report.finding_count)
    except RunStopped as exc:
        if pause_event.is_set() and not stop_event.is_set():
            LOG.info("后台任务已暂停 run_id=%s", config.run_id)
            stopped_payload = _pause_payload(config, last_payload, str(exc))
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
            tasks[failed["run_id"]] = failed
            store.save_payload(failed)
    finally:
        with tasks_lock:
            stop_events.pop(config.run_id, None)
            pause_events.pop(config.run_id, None)


def _task_from_report_payload(payload: dict, status: str) -> dict:
    return {
        "run_id": payload.get("run_id"),
        "status": status,
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
        "error": payload.get("error"),
        "config": payload.get("config", {}),
        "completed_finding_count": payload.get("completed_finding_count", len(payload.get("reports", []))),
        "current_finding_id": payload.get("current_finding_id"),
        "current_finding_index": payload.get("current_finding_index"),
        "resume_from_finding_id": payload.get("resume_from_finding_id"),
        "resume_from_finding_index": payload.get("resume_from_finding_index"),
    }


def _config_task_snapshot(config: RunConfig) -> dict:
    return {
        "report_path": str(config.sarif_path),
        "source_path": str(config.source_path),
        "skills_path": str(config.skills_path) if config.skills_path is not None else None,
        "max_rounds": config.max_rounds,
        "auto_index_tools": config.auto_index_tools,
        "enable_external_tools": config.enable_external_tools,
        "enable_llm": config.enable_llm,
        "llm_model": config.llm_model,
        "llm_endpoint": config.llm_endpoint,
        "affirmative_provider_id": config.affirmative_provider_id,
        "negative_provider_id": config.negative_provider_id,
        "moderator_provider_id": config.moderator_provider_id,
        "affirmative_agent": to_jsonable(config.affirmative_agent) if config.affirmative_agent else None,
        "negative_agent": to_jsonable(config.negative_agent) if config.negative_agent else None,
        "moderator_agent": to_jsonable(config.moderator_agent) if config.moderator_agent else None,
    }


def _pause_payload(config: RunConfig, last_payload: Optional[dict], reason: str) -> dict:
    payload = dict(last_payload or _task_from_config(config, config.run_id or _new_run_id(), "paused"))
    reports = list(payload.get("reports") or [])
    completed_count = _bounded_int(payload.get("completed_finding_count"), default=len(reports), minimum=0, maximum=len(reports))
    resume_index = _bounded_int(
        payload.get("current_finding_index"),
        default=completed_count,
        minimum=completed_count,
        maximum=int(payload.get("finding_count") or completed_count),
    )
    resume_id = payload.get("current_finding_id") or payload.get("resume_from_finding_id")
    payload["status"] = "paused"
    payload["error"] = None
    payload["reports"] = reports[:completed_count]
    payload["completed_finding_count"] = completed_count
    payload["current_finding_id"] = None
    payload["current_finding_index"] = None
    payload["resume_from_finding_id"] = resume_id
    payload["resume_from_finding_index"] = resume_index
    payload["config"] = payload.get("config") or _config_task_snapshot(config)
    diagnostics = list(payload.get("diagnostics") or [])
    resume_text = f"finding index {resume_index}"
    if resume_id:
        resume_text += f" ({resume_id})"
    diagnostics.append(f"{reason}；任务已暂停，恢复时将从 {resume_text} 重新处理。")
    payload["diagnostics"] = diagnostics
    return payload


def _bounded_int(value, *, default: int, minimum: int, maximum: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        result = default
    return min(max(result, minimum), maximum)


def _request_stop(tasks: dict, stop_events: dict, tasks_lock: Lock, run_id: str) -> Optional[dict]:
    with tasks_lock:
        task = tasks.get(run_id)
        stop_event = stop_events.get(run_id)
        if task is None or stop_event is None:
            return None
        if task.get("status") in {"completed", "failed", "stopped"}:
            return dict(task)
        stop_event.set()
        updated = dict(task)
        updated["status"] = "stopping"
        updated["stop_requested"] = True
        tasks[run_id] = updated
        return dict(updated)


def _request_pause(tasks: dict, pause_events: dict, tasks_lock: Lock, run_id: str) -> Optional[dict]:
    with tasks_lock:
        task = tasks.get(run_id)
        pause_event = pause_events.get(run_id)
        if task is None:
            return None
        if task.get("status") == "paused":
            return dict(task)
        if pause_event is None or task.get("status") in {"completed", "failed", "stopped"}:
            return None
        pause_event.set()
        updated = dict(task)
        updated["status"] = "pausing"
        updated["pause_requested"] = True
        tasks[run_id] = updated
        return dict(updated)


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
) -> Optional[dict]:
    with tasks_lock:
        active_task = tasks.get(run_id)
        if active_task and active_task.get("status") in {"running", "pausing", "stopping"}:
            return dict(active_task)
        paused_payload = active_task if active_task and active_task.get("status") == "paused" else store.get(run_id)
        if not paused_payload or paused_payload.get("status") != "paused":
            return None
        config = _config_from_paused_payload(paused_payload, providers_file, agent_store, mcp_servers_file, skill_store)
        stop_event = Event()
        pause_event = Event()
        task = _task_from_report_payload(paused_payload, "running")
        task["status"] = "running"
        task["error"] = None
        tasks[run_id] = task
        stop_events[run_id] = stop_event
        pause_events[run_id] = pause_event
        store.save_payload(task)
    Thread(
        target=_run_task,
        args=(config, store, tasks, stop_events, pause_events, tasks_lock, stop_event, pause_event),
        daemon=True,
    ).start()
    return dict(task)


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
    config.resume_from_finding_index = _bounded_int(
        payload.get("resume_from_finding_index"),
        default=len(reports),
        minimum=0,
        maximum=int(payload.get("finding_count") or len(reports)),
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


def _finding_summary(report):
    return {
        "finding_id": report.get("finding_id"),
        "rule_id": report.get("rule_id"),
        "verdict": report.get("verdict"),
        "confidence": report.get("confidence"),
        "summary": _finding_report_summary(report),
        "final_conclusion": report.get("final_conclusion"),
        "source_locations": report.get("source_locations", []),
        "evidence_count": len(report.get("evidence_chain", [])),
        "debate_turn_count": len(report.get("debate", [])),
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
        verdict = report.get("verdict", "UNKNOWN")
        counts[verdict] = counts.get(verdict, 0) + 1
    return counts


def _export_run_markdown(run: dict) -> str:
    lines = [
        "# 漏洞研判报告",
        "",
        f"- 任务 ID：{run.get('run_id') or ''}",
        f"- 状态：{run.get('status', 'completed')}",
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
                f"- 结论：{report.get('verdict') or ''}",
                f"- 置信度：{report.get('confidence')}",
                f"- 最终结论：{report.get('final_conclusion') or ''}",
                "",
                "### 摘要",
                "",
                str(report.get("reasoning_summary") or "无"),
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
    .chip.run-delete {{ cursor: pointer; color: var(--bad); }}
    .chip.run-delete:hover {{ border-color: var(--bad); background: #fff1f0; }}
    .chip.run-stop, .chip.run-pause, .chip.run-resume {{ cursor: pointer; color: var(--accent); }}
    .chip.run-stop:hover, .chip.run-pause:hover, .chip.run-resume:hover {{ border-color: var(--accent); background: #edf7fb; }}
    .content {{ padding: 16px; display: grid; gap: 16px; }}
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
    @media (max-width: 900px) {{
      header {{ align-items: flex-start; flex-direction: column; }}
      main {{ grid-template-columns: 1fr; height: auto; min-height: 0; }}
      .pane {{ min-height: 360px; }}
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
    <section class="pane" aria-label="运行详情和提供商设置">
      <div class="pane-title">
        <h2 id="detail-title">运行详情</h2>
        <span class="muted" id="detail-status">未选择任务</span>
      </div>
      <div class="scroll">
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
          <div class="muted">配置正方、反方和主持人配置档案目录和 AGENT.md 提示词。</div>
        </div>
        <button id="close-agent-prompts" type="button" title="关闭 Agent 提示词设置">关闭</button>
      </div>
      <div class="settings-body">
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
              <label class="wide">参数 JSON<textarea id="mcp-args" placeholder='["mcp","--project","{{project}}","--log-format","json"]'></textarea></label>
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
              <label>Skill Source<select id="run-skill-source"></select></label>
              <label class="wide">Skills 路径<input id="run-skills" placeholder="fixtures/demo_sarif/skills"></label>
              <label>最大回合数<input id="run-max-rounds" type="number" min="1" value="4"></label>
              <div class="run-agent-grid">
                <label>正方提供商<select id="run-affirmative-provider"></select></label>
                <label>正方 Agent 配置档案<select id="run-affirmative-agent-profile"></select></label>
                <label>反方提供商<select id="run-negative-provider"></select></label>
                <label>反方 Agent 配置档案<select id="run-negative-agent-profile"></select></label>
                <label>主持人提供商<select id="run-moderator-provider"></select></label>
                <label>主持人 Agent 配置档案<select id="run-moderator-agent-profile"></select></label>
              </div>
            </div>
            <div class="chips">
              <label><input id="run-external-tools" type="checkbox" checked> 启用外部工具</label>
              <label><input id="run-auto-index" type="checkbox"> 自动 Atlas 构建索引</label>
              <label><input id="run-llm" type="checkbox"> 使用 LLM 博弈</label>
            </div>
            <div class="toolbar">
              <button id="start-run" type="button">启动任务</button>
              <button id="fill-demo-run" type="button">填入 SARIF 示例</button>
              <button id="fill-markdown-demo-run" type="button">填入 Markdown 示例</button>
            </div>
            <pre id="run-result">尚未启动任务。</pre>
          </div>
        </div>
      </div>
    </section>
  </div>
  <script>
    const state = {{ runs: [], selectedRun: null, selectedFinding: null, providers: [], defaults: {{}}, agentPrompts: {{}}, mcpServers: [], mcpDefaults: {{}}, skillSources: [], skillDefaults: {{}}, polling: {{}}, autoRefreshEnabled: false }};
    const el = {{
      list: document.getElementById('run-list'),
      count: document.getElementById('run-count'),
      detail: document.getElementById('detail'),
      title: document.getElementById('detail-title'),
      status: document.getElementById('detail-status'),
      subtitle: document.getElementById('subtitle'),
      providerList: document.getElementById('provider-list'),
      providersModal: document.getElementById('providers-modal'),
      agentPromptsModal: document.getElementById('agent-prompts-modal'),
      integrationsModal: document.getElementById('integrations-modal'),
      runConfigModal: document.getElementById('run-config-modal'),
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
      runSarif: document.getElementById('run-sarif'),
      runSource: document.getElementById('run-source'),
      runSkillSource: document.getElementById('run-skill-source'),
      runSkills: document.getElementById('run-skills'),
      runMaxRounds: document.getElementById('run-max-rounds'),
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
      el.runConfigModal.classList.add('open');
      await Promise.all([loadProviders(), loadAgentPrompts(), loadIntegrations()]);
    }});
    document.getElementById('close-run-config').addEventListener('click', () => {{
      el.runConfigModal.classList.remove('open');
    }});
    el.runConfigModal.addEventListener('click', (event) => {{
      if (event.target === el.runConfigModal) el.runConfigModal.classList.remove('open');
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
    document.getElementById('clear-selection').addEventListener('click', () => {{
      state.selectedRun = null;
      state.selectedFinding = null;
      renderRuns();
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
    document.getElementById('fill-demo-run').addEventListener('click', fillDemoRun);
    document.getElementById('fill-markdown-demo-run').addEventListener('click', fillMarkdownDemoRun);
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
        const heading = line.match(/^(#{1,6})\\s+(.+)$/);
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
    function verdictLabel(verdict) {{
      const labels = {{
        TRUE_POSITIVE: '真实漏洞',
        FALSE_POSITIVE: '误报',
        INCONCLUSIVE: '证据不足'
      }};
      return labels[verdict] || verdict || '未知结论';
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

    async function refreshAll() {{
      await Promise.all([loadProviders(), loadAgentPrompts(), loadIntegrations(), loadRuns()]);
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
    }}

    function enableRunLlmForSelectedProviders() {{
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

    function fillDemoRun() {{
      el.runSarif.value = 'fixtures/demo_sarif/report.sarif';
      el.runSource.value = 'fixtures/demo_sarif/source';
      el.runSkills.value = 'fixtures/demo_sarif/skills';
      el.runSkillSource.value = '';
      el.runMaxRounds.value = '4';
      el.runExternalTools.checked = false;
      el.runAutoIndex.checked = false;
      enableRunLlmForSelectedProviders();
      el.runResult.textContent = '已填入 SARIF 示例路径。';
    }}

    function fillMarkdownDemoRun() {{
      el.runSarif.value = 'fixtures/demo_markdown/report.md';
      el.runSource.value = 'fixtures/demo_sarif/source';
      el.runSkills.value = 'fixtures/demo_sarif/skills';
      el.runSkillSource.value = '';
      el.runMaxRounds.value = '4';
      el.runExternalTools.checked = false;
      el.runAutoIndex.checked = false;
      enableRunLlmForSelectedProviders();
      el.runResult.textContent = '已填入 Markdown 示例路径。';
    }}

    async function startRun() {{
      try {{
        const payload = {{
          report_path: el.runSarif.value.trim(),
          source_path: el.runSource.value.trim(),
          skill_source_id: el.runSkillSource.value || null,
          skills_path: el.runSkills.value.trim() || null,
          max_rounds: Number(el.runMaxRounds.value || 4),
          enable_external_tools: el.runExternalTools.checked,
          auto_index_tools: el.runAutoIndex.checked,
          enable_llm: el.runLlm.checked,
          affirmative_provider_id: el.runAffirmativeProvider.value || null,
          negative_provider_id: el.runNegativeProvider.value || null,
          moderator_provider_id: el.runModeratorProvider.value || null,
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
        await loadRuns();
        if (created.run_id) {{
          await selectRun(created.run_id);
          ensurePolling(created.run_id);
        }}
      }} catch (error) {{
        el.runResult.textContent = error.message;
      }}
    }}

    async function pollRun(runId) {{
      for (let attempt = 0; attempt < 1800; attempt += 1) {{
        await new Promise(resolve => setTimeout(resolve, 1000));
        if (!state.autoRefreshEnabled || !state.polling[runId]) return;
        try {{
          const run = await fetchJson(`/runs/${{encodeURIComponent(runId)}}`);
          await loadRuns();
          if (state.selectedRun === runId) {{
            await selectRun(runId, false);
          }}
          if (isTerminalStatus(run.status)) return;
          if (!state.autoRefreshEnabled || !state.polling[runId]) return;
        }} catch (_error) {{
          return;
        }}
      }}
    }}

    function ensurePolling(runId) {{
      if (!runId || !state.autoRefreshEnabled || state.polling[runId]) return;
      state.polling[runId] = true;
      pollRun(runId).finally(() => {{
        delete state.polling[runId];
        updateAutoRefreshControl();
      }});
    }}

    function runningRuns() {{
      return state.runs.filter(run => !isTerminalStatus(run.status));
    }}

    function updateAutoRefreshControl() {{
      const running = runningRuns();
      if (!running.length) {{
        state.autoRefreshEnabled = false;
        state.polling = {{}};
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
        state.polling = {{}};
        updateAutoRefreshControl();
        return;
      }}
      updateAutoRefreshControl();
      for (const run of runningRuns()) {{
        ensurePolling(run.run_id);
      }}
    }}

    async function loadRuns() {{
      el.subtitle.textContent = '正在加载记录...';
      try {{
        state.runs = await fetchJson('/runs');
        renderRuns();
        updateAutoRefreshControl();
        if (state.autoRefreshEnabled) {{
          for (const run of runningRuns()) {{
            ensurePolling(run.run_id);
          }}
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

    function renderRuns() {{
      el.count.textContent = `${{state.runs.length}} 条记录`;
      el.list.innerHTML = state.runs.map(run => {{
        const counts = run.verdict_counts || {{}};
        const status = run.status || 'completed';
        const pauseButton = status === 'running' || status === 'pausing'
          ? `<span class="chip run-pause" data-run-pause="true" data-run-id="${{esc(run.run_id)}}" role="button" tabindex="0" title="暂停该任务">暂停</span>`
          : '';
        const resumeButton = status === 'paused'
          ? `<span class="chip run-resume" data-run-resume="true" data-run-id="${{esc(run.run_id)}}" role="button" tabindex="0" title="从当前 finding 恢复任务">恢复</span>`
          : '';
        const stopButton = status === 'running' || status === 'stopping' || status === 'pausing'
          ? `<span class="chip run-stop" data-run-stop="true" data-run-id="${{esc(run.run_id)}}" role="button" tabindex="0" title="停止该任务">停止</span>`
          : '';
        return `<button class="run-item ${{state.selectedRun === run.run_id ? 'active' : ''}}" type="button" data-run-id="${{esc(run.run_id)}}">
          <div class="run-item-actions">
            ${{pauseButton}}
            ${{resumeButton}}
            ${{stopButton}}
            <span class="chip run-delete" data-run-delete="true" data-run-id="${{esc(run.run_id)}}" role="button" tabindex="0" title="删除该任务记录">删除</span>
          </div>
          <div class="run-item-headline">
            <div class="run-id">${{esc(run.run_id)}}</div>
            <div class="muted">${{esc(fmtDate(run.created_at))}}</div>
            <div class="path">${{esc(run.source_path || '')}}</div>
          </div>
          <div class="chips">
            <span class="chip">${{esc(statusLabel(status))}}</span>
            <span class="chip">${{esc(run.finding_count)}} 个发现</span>
          </div>
          <div class="chips run-verdict-chips">
            <span class="chip tp">真实 ${{counts.TRUE_POSITIVE || 0}}</span>
            <span class="chip fp">误报 ${{counts.FALSE_POSITIVE || 0}}</span>
            <span class="chip inc">不足 ${{counts.INCONCLUSIVE || 0}}</span>
          </div>
        </button>`;
      }}).join('');
      for (const button of el.list.querySelectorAll('button[data-run-id]')) {{
        button.addEventListener('click', () => selectRun(button.dataset.runId));
      }}
      for (const button of el.list.querySelectorAll('[data-run-delete]')) {{
        button.addEventListener('click', event => {{
          event.stopPropagation();
          deleteRun(button.dataset.runId);
        }});
        button.addEventListener('keydown', event => {{
          if (event.key === 'Enter' || event.key === ' ') {{
            event.preventDefault();
            event.stopPropagation();
            deleteRun(button.dataset.runId);
          }}
        }});
      }}
      for (const button of el.list.querySelectorAll('[data-run-stop]')) {{
        button.addEventListener('click', event => {{
          event.stopPropagation();
          stopRun(button.dataset.runId);
        }});
        button.addEventListener('keydown', event => {{
          if (event.key === 'Enter' || event.key === ' ') {{
            event.preventDefault();
            event.stopPropagation();
            stopRun(button.dataset.runId);
          }}
        }});
      }}
      for (const button of el.list.querySelectorAll('[data-run-pause]')) {{
        button.addEventListener('click', event => {{
          event.stopPropagation();
          pauseRun(button.dataset.runId);
        }});
        button.addEventListener('keydown', event => {{
          if (event.key === 'Enter' || event.key === ' ') {{
            event.preventDefault();
            event.stopPropagation();
            pauseRun(button.dataset.runId);
          }}
        }});
      }}
      for (const button of el.list.querySelectorAll('[data-run-resume]')) {{
        button.addEventListener('click', event => {{
          event.stopPropagation();
          resumeRun(button.dataset.runId);
        }});
        button.addEventListener('keydown', event => {{
          if (event.key === 'Enter' || event.key === ' ') {{
            event.preventDefault();
            event.stopPropagation();
            resumeRun(button.dataset.runId);
          }}
        }});
      }}
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
      state.selectedRun = runId;
      if (resetFinding) state.selectedFinding = null;
      renderRuns();
      el.title.textContent = runId;
      el.status.textContent = '正在加载详情...';
      try {{
        const [run, findings] = await Promise.all([
          fetchJson(`/runs/${{encodeURIComponent(runId)}}`),
          fetchJson(`/runs/${{encodeURIComponent(runId)}}/findings`)
        ]);
        renderRunDetail(run, findings);
      }} catch (error) {{
        renderError(error);
      }}
    }}

    function renderRunDetail(run, findings) {{
      const counts = run.verdict_counts || {{}};
      const providers = run.llm_providers || {{}};
      const agents = run.agent_configs || {{}};
      const status = run.status || 'completed';
      const resumeIndex = run.resume_from_finding_index;
      const resumeFinding = run.resume_from_finding_id || '';
      const resumeHint = status === 'paused' && resumeIndex !== null && resumeIndex !== undefined
        ? '恢复时将从 finding #' + (Number(resumeIndex) + 1) + (resumeFinding ? ' (' + resumeFinding + ')' : '') + ' 重新处理。'
        : '';
      const currentHint = run.current_finding_id
        ? '当前 Finding：' + run.current_finding_id
        : '';
      const detailControls = [
        status === 'running' || status === 'pausing'
          ? `<button type="button" data-run-pause="true" data-run-id="${{esc(run.run_id)}}">暂停</button>`
          : '',
        status === 'paused'
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
          : status === 'stopping'
        ? '已请求停止。当前 LLM 请求结束后会停止后续回合。'
        : status === 'stopped'
          ? '任务已停止，下面显示停止前已经生成的部分结果。'
          : state.autoRefreshEnabled
            ? '任务正在后台运行。自动刷新开启，每完成一次 LLM 对话，本页面会自动加载当前信息。'
            : '任务正在后台运行。自动刷新已关闭，可手动点击“刷新”加载当前信息。';
      el.status.textContent = `${{statusLabel(status)}} / ${{findings.length}} 个发现`;
      const statusCard = `
        <div class="detail">
          <h3>运行状态</h3>
          <div class="detail-body">
            <div class="chips"><span class="chip">${{esc(statusLabel(status))}}</span></div>
            <div class="toolbar">
              ${{detailControls}}
              <button type="button" data-run-export="markdown" data-run-id="${{esc(run.run_id)}}">导出 Markdown</button>
              <button type="button" data-run-export="json" data-run-id="${{esc(run.run_id)}}">导出 JSON</button>
            </div>
            <div><strong>报告：</strong> <span class="path">${{esc(run.sarif_path)}}</span></div>
            <div><strong>源码：</strong> <span class="path">${{esc(run.source_path)}}</span></div>
            <div><strong>语言：</strong> ${{esc((run.languages || []).join(', '))}}</div>
            <div><strong>发现进度：</strong> ${{esc(run.completed_finding_count ?? findings.length)}} / ${{esc(run.finding_count || findings.length)}}</div>
            ${{currentHint ? `<div><strong>当前状态：</strong> ${{esc(currentHint)}}</div>` : ''}}
            ${{resumeHint ? `<div><strong>恢复点：</strong> ${{esc(resumeHint)}}</div>` : ''}}
            <div><strong>正方 LLM：</strong> ${{esc(providerLabel(providers.affirmative, providers.enabled))}}</div>
            <div><strong>反方 LLM：</strong> ${{esc(providerLabel(providers.negative, providers.enabled))}}</div>
            <div><strong>主持人 LLM：</strong> ${{esc(providerLabel(providers.moderator, providers.enabled))}}</div>
            <div><strong>正方 Agent：</strong> ${{esc(agentLabel(agents.affirmative))}}</div>
            <div><strong>反方 Agent：</strong> ${{esc(agentLabel(agents.negative))}}</div>
            <div><strong>主持人 Agent：</strong> ${{esc(agentLabel(agents.moderator))}}</div>
            ${{agentInstructions(agents) ? `<pre>${{esc(agentInstructions(agents))}}</pre>` : ''}}
            ${{run.error ? `<div class="error">${{esc(run.error)}}</div>` : `<div class="muted">${{esc(runningMessage)}}</div>`}}
            ${{run.diagnostics && run.diagnostics.length ? `<pre>${{esc(run.diagnostics.join('\\n'))}}</pre>` : ''}}
          </div>
        </div>`;
      if (status !== 'completed') {{
        el.detail.innerHTML = statusCard + (findings.length ? renderFindingsSection(findings) : '');
        bindRunExportButtons();
        bindRunControlButtons(el.detail);
        bindFindingRows(findings);
        return;
      }}
      el.detail.innerHTML = `
        <div class="summary-grid">
          <div class="metric"><div class="label">发现数</div><div class="value">${{esc(run.finding_count)}}</div></div>
          <div class="metric"><div class="label">真实漏洞</div><div class="value">${{counts.TRUE_POSITIVE || 0}}</div></div>
          <div class="metric"><div class="label">误报</div><div class="value">${{counts.FALSE_POSITIVE || 0}}</div></div>
          <div class="metric"><div class="label">证据不足</div><div class="value">${{counts.INCONCLUSIVE || 0}}</div></div>
        </div>
        <div class="detail">
          <h3>运行元数据</h3>
          <div class="detail-body">
            <div class="toolbar">
              <button type="button" data-run-export="markdown" data-run-id="${{esc(run.run_id)}}">导出 Markdown</button>
              <button type="button" data-run-export="json" data-run-id="${{esc(run.run_id)}}">导出 JSON</button>
            </div>
            <div><strong>创建时间：</strong> ${{esc(fmtDate(run.created_at))}}</div>
            <div><strong>报告：</strong> <span class="path">${{esc(run.sarif_path)}}</span></div>
            <div><strong>源码：</strong> <span class="path">${{esc(run.source_path)}}</span></div>
            <div><strong>语言：</strong> ${{esc((run.languages || []).join(', '))}}</div>
            <div><strong>正方 LLM：</strong> ${{esc(providerLabel(providers.affirmative, providers.enabled))}}</div>
            <div><strong>反方 LLM：</strong> ${{esc(providerLabel(providers.negative, providers.enabled))}}</div>
            <div><strong>主持人 LLM：</strong> ${{esc(providerLabel(providers.moderator, providers.enabled))}}</div>
            <div><strong>正方 Agent：</strong> ${{esc(agentLabel(agents.affirmative))}}</div>
            <div><strong>反方 Agent：</strong> ${{esc(agentLabel(agents.negative))}}</div>
            <div><strong>主持人 Agent：</strong> ${{esc(agentLabel(agents.moderator))}}</div>
            ${{agentInstructions(agents) ? `<pre>${{esc(agentInstructions(agents))}}</pre>` : ''}}
            ${{run.diagnostics && run.diagnostics.length ? `<pre>${{esc(run.diagnostics.join('\\n'))}}</pre>` : ''}}
          </div>
        </div>
        ${{renderFindingsSection(findings)}}
      `;
      bindRunExportButtons();
      bindRunControlButtons(el.detail);
      bindFindingRows(findings);
    }}

    function bindRunControlButtons(root) {{
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
    }}

    function bindRunExportButtons() {{
      for (const button of el.detail.querySelectorAll('[data-run-export]')) {{
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

    function renderFindingsSection(findings) {{
      return `
        <div class="detail">
          <h3>漏洞发现</h3>
          <div class="scroll">
            <table>
              <thead><tr><th>结论</th><th>规则</th><th>置信度</th><th>摘要</th></tr></thead>
              <tbody>
                ${{findings.map(item => `<tr class="clickable" data-finding-id="${{esc(item.finding_id)}}">
                  <td><span class="chip ${{verdictClass(item.verdict)}}">${{esc(verdictLabel(item.verdict))}}</span></td>
                  <td>${{esc(item.rule_id)}}<div class="path">${{esc(item.finding_id)}}</div></td>
                  <td>${{esc(item.confidence)}}</td>
                  <td><span class="plain-inline">${{plainInlineText(item.summary)}}</span><div class="path">${{esc((item.source_locations || []).map(loc => loc.file + (loc.line ? ':' + loc.line : '')).join(', '))}}</div></td>
                </tr>`).join('')}}
              </tbody>
            </table>
          </div>
        </div>
        <div id="finding-detail"></div>`;
    }}

    function bindFindingRows(findings) {{
      for (const row of el.detail.querySelectorAll('tr[data-finding-id]')) {{
        row.addEventListener('click', () => selectFinding(row.dataset.findingId));
      }}
      if (!findings.length) return;
      const selected = state.selectedFinding && findings.some(item => item.finding_id === state.selectedFinding)
        ? state.selectedFinding
        : findings[0].finding_id;
      selectFinding(selected);
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

    async function selectFinding(findingId) {{
      state.selectedFinding = findingId;
      const container = document.getElementById('finding-detail');
      if (!container) return;
      container.innerHTML = '<div class="empty">正在加载发现详情...</div>';
      try {{
        const detail = await fetchJson(`/runs/${{encodeURIComponent(state.selectedRun)}}/findings/${{encodeURIComponent(findingId)}}`);
        container.innerHTML = renderFindingDetail(detail);
        container.scrollIntoView({{ block: 'nearest' }});
      }} catch (error) {{
        container.innerHTML = `<div class="empty error">${{esc(error.message)}}</div>`;
      }}
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

    function renderOriginalReportSection(detail) {{
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
        <div class="detail">
          <h3>原始报告详情</h3>
          <div class="detail-body">
            ${{rawLines ? `<div class="plain-text">${{rawText(rawLines)}}</div>` : '<div class="muted">未找到输入报告摘要。</div>'}}
            ${{locations.length ? `<div><strong>报告位置：</strong><div class="plain-text">${{rawText(locations.join('\\n'))}}</div></div>` : ''}}
            ${{codeFlows.length ? `<div><strong>报告代码流：</strong><pre>${{esc(codeFlows.map((flow, index) => `Flow ${{index + 1}}:\\n${{flow.join('\\n')}}`).join('\\n\\n'))}}</pre></div>` : ''}}
            ${{properties ? `<div><strong>报告 properties：</strong><pre>${{esc(jsonBlock(properties))}}</pre></div>` : ''}}
            ${{rawResult ? `<div><strong>原始 SARIF result：</strong><pre>${{esc(jsonBlock(rawResult))}}</pre></div>` : ''}}
          </div>
        </div>`;
    }}

    function renderFindingDetail(detail) {{
      const evidence = detail.evidence_chain || [];
      const debate = detail.debate || [];
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
            ${{detail.final_conclusion ? `<div><strong>最终结论：</strong> <span class="plain-text">${{plainText(detail.final_conclusion)}}</span></div>` : ''}}
            <div class="plain-text">${{plainText(detail.reasoning_summary)}}</div>
            <div><strong>防护研判：</strong> <span class="plain-text">${{plainText(detail.protection_assessment)}}</span></div>
            <div><strong>影响研判：</strong> <span class="plain-text">${{plainText(detail.impact_assessment)}}</span></div>
            ${{(detail.disputed_points || []).length ? `<div><strong>争议点：</strong><ul>${{detail.disputed_points.map(point => `<li><span class="plain-text">${{plainText(point)}}</span></li>`).join('')}}</ul></div>` : ''}}
          </div>
        </div>
        <div class="detail">
          <h3>博弈过程</h3>
          <div class="detail-body">
            ${{debate.map(turn => `<div class="debate-turn">
              <strong>${{esc(roleLabel(turn.role))}} 第 ${{esc(turn.round_index)}} 回合</strong>
              <div class="plain-text">${{plainText(turn.claim)}}</div>
              <div class="path">证据：${{esc((turn.evidence_ids || []).join(', '))}}</div>
            </div>`).join('') || '<div class="muted">暂无博弈回合记录。</div>'}}
          </div>
        </div>
        <div class="detail">
          <h3>证据链</h3>
          <div class="detail-body">
            ${{evidence.map(item => `<div>
              <div class="chips">
                <span class="chip">${{esc(item.evidence_id)}}</span>
                <span class="chip">${{esc(evidenceKindLabel(item.kind))}}</span>
                <span class="chip">${{esc(evidenceStrengthLabel(item.strength))}}</span>
                <span class="chip">${{esc(item.source)}}</span>
              </div>
              <div class="plain-text">${{plainText(item.summary)}}</div>
              ${{item.locations && item.locations.length ? `<div class="path">位置：${{esc(item.locations.map(locationText).join(' -> '))}}</div>` : ''}}
              ${{item.data && (item.data.requested_file || item.data.resolved_file) ? `<div class="path">路径映射：${{esc(item.data.requested_file || '')}}${{item.data.resolved_file ? ' => ' + esc(item.data.resolved_file) : ''}}</div>` : ''}}
              ${{item.snippet ? `<pre>${{esc(item.snippet)}}</pre>` : ''}}
            </div>`).join('') || '<div class="muted">暂无证据记录。</div>'}}
          </div>
        </div>`;
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
      el.detail.innerHTML = `<div class="empty">${{esc(message)}}</div>`;
    }}
    function renderError(error) {{
      el.subtitle.textContent = '加载记录失败';
      el.detail.innerHTML = `<div class="empty error">${{esc(error.message)}}</div>`;
    }}

    refreshAll();
  </script>
</body>
</html>"""
