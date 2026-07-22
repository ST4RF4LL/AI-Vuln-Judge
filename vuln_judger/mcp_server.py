from __future__ import annotations

import json
import re
import sys
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Lock, Thread
from typing import Any, Dict, Iterable, List, Optional, Sequence, TextIO, Tuple
from uuid import uuid4

from .agents import DEFAULT_AGENTS_DIR, AgentDirectoryStore
from .analyzers import AnalyzerSettings, AnalyzerSuite
from .api import (
    DEFAULT_RECORDS_DIR,
    _config_from_paused_payload,
    _export_run_markdown,
    _finding_detail,
    _manual_review_for,
    _pause_payload,
    _report_findings_payload,
    _resume_checkpoint_payload,
)
from .codex_runner import CLI_ENGINES, CODEX_ENGINE, OPENCODE_ENGINE, CodexDrivenRunner, CodexRunnerStopped, stop_sessions
from .debate import DebateOrchestrator
from .evidence import EvidenceCollector
from .mcp_config import DEFAULT_MCP_SERVERS_FILE
from .models import DEFAULT_SILENCE_REMINDER_MINUTES, RunConfig, SourceLocation, run_config_snapshot, to_jsonable
from .opencode_runner import OpenCodeDrivenRunner
from .pipeline import run_judgement
from .providers import DEFAULT_PROVIDERS_FILE
from .records import RunControlStore, RunRecordStore, normalize_run_origin
from .run_state import (
    FINDING_COMPLETED,
    FINDING_IN_PROGRESS,
    FINDING_PENDING,
    completed_finding_count,
    finding_report_status,
)
from .sarif import load_report
from .skills import DEFAULT_SKILLS_FILE, SkillSourceStore, load_project_context
from .source import SourceIndexer


MCP_PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "vuln-judger-mcp"
SERVER_VERSION = "0.1.0"
BUILTIN_ENGINE = "builtin"


@dataclass
class JudgerMCPSettings:
    records_dir: Path = DEFAULT_RECORDS_DIR
    providers_file: Path = DEFAULT_PROVIDERS_FILE
    mcp_servers_file: Path = DEFAULT_MCP_SERVERS_FILE
    skills_file: Path = DEFAULT_SKILLS_FILE
    agents_dir: Path = DEFAULT_AGENTS_DIR


@dataclass
class _ActiveRun:
    stop_event: Event
    thread: Thread
    owner_id: str


class JudgerMCPServer:
    def __init__(
        self,
        settings: Optional[JudgerMCPSettings] = None,
        stdin: Optional[TextIO] = None,
        stdout: Optional[TextIO] = None,
    ):
        self.settings = settings or JudgerMCPSettings()
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout
        self.records = RunRecordStore(self.settings.records_dir)
        self.control_store = RunControlStore(self.records.root)
        self.agent_store = AgentDirectoryStore(self.settings.agents_dir)
        self.skill_store = SkillSourceStore(self.settings.skills_file)
        self._active_runs: Dict[str, _ActiveRun] = {}
        self._active_runs_lock = Lock()
        self.tools = _tool_specs()

    def serve_forever(self) -> None:
        try:
            while True:
                incoming = _read_message(self.stdin)
                if incoming is None:
                    return
                message, framing = incoming
                response = self._handle_message(message)
                if response is not None:
                    _write_message(self.stdout, response, framing)
        finally:
            self.close()

    def close(self) -> None:
        with self._active_runs_lock:
            active = list(self._active_runs.items())
        for run_id, task in active:
            task.stop_event.set()
            self.control_store.request(run_id, "stop", requested_by="mcp")
            stop_sessions(self.records.get(run_id) or {})
        for _, task in active:
            task.thread.join(timeout=1)

    def _handle_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        request_id = message.get("id")
        method = str(message.get("method") or "")
        if request_id is None and method.startswith("notifications/"):
            return None
        try:
            if method == "initialize":
                return _result(
                    request_id,
                    {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                    },
                )
            if method == "ping":
                return _result(request_id, {})
            if method == "tools/list":
                return _result(request_id, {"tools": self.tools})
            if method == "tools/call":
                params = message.get("params") or {}
                name = str(params.get("name") or "")
                arguments = params.get("arguments") or {}
                return self._tool_response(request_id, name, arguments if isinstance(arguments, dict) else {})
            if method in {"resources/list", "prompts/list"}:
                key = "resources" if method == "resources/list" else "prompts"
                return _result(request_id, {key: []})
            return _error(request_id, -32601, f"Method not found: {method}")
        except Exception as exc:
            return _error(request_id, -32603, str(exc), {"traceback": traceback.format_exc(limit=8)})

    def _tool_response(self, request_id: Any, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        try:
            payload = self._call_tool(name, arguments)
            return _tool_result(request_id, payload)
        except Exception as exc:
            return _tool_result(
                request_id,
                {"error": str(exc), "tool": name, "traceback": traceback.format_exc(limit=8)},
                is_error=True,
            )

    def _call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        if name == "judge_report":
            return self._judge_report(arguments)
        if name == "one_round_judge":
            return self._one_round_judge(arguments)
        if name == "collect_evidence":
            return self._collect_evidence(arguments)
        if name == "resolve_report_locations":
            return self._resolve_report_locations(arguments)
        if name == "list_runs":
            return self._list_runs(arguments)
        if name == "get_run":
            return self._get_run(arguments)
        if name == "get_finding":
            return self._get_finding(arguments)
        if name == "export_run_markdown":
            return self._export_run_markdown(arguments)
        if name == "export_run_report":
            return self._export_run_report(arguments)
        if name == "stop_run":
            return self._stop_run(arguments)
        if name == "pause_run":
            return self._pause_run(arguments)
        if name == "resume_run":
            return self._resume_run(arguments)
        raise ValueError(f"Unknown tool: {name}")

    def _judge_report(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        engine = str(arguments.get("engine") or OPENCODE_ENGINE).strip().lower()
        if engine not in {*CLI_ENGINES, BUILTIN_ENGINE}:
            raise ValueError(f"Unsupported engine: {engine}")
        report_path = _required_path(arguments, "report_path")
        source_path = _required_path(arguments, "source_path")
        skills_path = self._skills_path(arguments)
        run_id = _optional_text(arguments.get("run_id")) or f"run-{uuid4().hex[:12]}"
        cli_engine = engine in CLI_ENGINES
        agents_config = self.agent_store.default_agents_config()
        config = RunConfig(
            sarif_path=report_path,
            source_path=source_path,
            engine=engine,
            skills_path=skills_path,
            providers_file=None if cli_engine else _optional_path(arguments.get("providers_file")) or self.settings.providers_file,
            mcp_servers_file=None if cli_engine else _optional_path(arguments.get("mcp_servers_file")) or self.settings.mcp_servers_file,
            run_id=run_id,
            max_rounds=int(arguments.get("max_rounds") or 4),
            silence_reminder_minutes=_bounded_int(
                arguments.get("silence_reminder_minutes"),
                default=DEFAULT_SILENCE_REMINDER_MINUTES,
                minimum=1,
                maximum=1440,
            ),
            auto_index_tools=False if cli_engine else bool(arguments.get("auto_index_tools", False)),
            enable_external_tools=True if cli_engine else bool(arguments.get("enable_external_tools", True)),
            enable_llm=False if cli_engine else bool(arguments.get("enable_llm", False)),
            llm_model=_optional_text(arguments.get("llm_model")) if engine == OPENCODE_ENGINE else None,
            affirmative_provider_id=None if cli_engine else _optional_text(arguments.get("affirmative_provider_id")),
            negative_provider_id=None if cli_engine else _optional_text(arguments.get("negative_provider_id")),
            moderator_provider_id=None if cli_engine else _optional_text(arguments.get("moderator_provider_id")),
            affirmative_agent=self.agent_store.agent("affirmative", _optional_text(arguments.get("affirmative_agent_profile"))),
            negative_agent=self.agent_store.agent("negative", _optional_text(arguments.get("negative_agent_profile"))),
            moderator_agent=self.agent_store.agent("moderator", _optional_text(arguments.get("moderator_agent_profile"))),
            agents_config_id=str(agents_config.get("id") or "") or None,
            agents_config_path=str(agents_config.get("resolved_path") or "") or None,
            agents_instructions=str(agents_config.get("instructions") or ""),
        )
        if cli_engine:
            if not bool(arguments.get("save", True)):
                raise ValueError("save=false is not supported by CLI engines because progress is persisted for polling")
            if bool(arguments.get("wait_for_completion", False)):
                try:
                    payload = self._run_codex_report(config)
                except Exception as exc:
                    self._record_codex_failure(config, exc)
                    raise
                return self._completed_run_result(payload, include_report=bool(arguments.get("include_report", False)))
            return self._start_codex_report(config)
        return self._run_builtin_report(config, arguments)

    def _skills_path(self, arguments: Dict[str, Any]) -> Optional[Path]:
        skills_path = _optional_path(arguments.get("skills_path"))
        skill_source_id = _optional_text(arguments.get("skill_source_id"))
        if skills_path is not None or not skill_source_id:
            return skills_path
        source = self.skill_store.get(skill_source_id)
        if source is None:
            raise ValueError(f"Unknown skill_source_id: {skill_source_id}")
        return Path(source.path).expanduser().resolve()

    def _run_builtin_report(self, config: RunConfig, arguments: Dict[str, Any]) -> Dict[str, Any]:
        report = run_judgement(config)
        saved = bool(arguments.get("save", True))
        payload = to_jsonable(report)
        payload["run_origin"] = "mcp"
        payload["engine"] = BUILTIN_ENGINE
        payload["config"] = _config_snapshot(config)
        if saved:
            self.records.save_payload(payload)
        result = _run_summary(payload)
        result["saved"] = saved
        result["record_path"] = str(self.records._path(report.run_id)) if saved else None
        if bool(arguments.get("include_report", False)):
            result["report"] = payload
        return result

    def _start_codex_report(
        self,
        config: RunConfig,
        *,
        resume_payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        run_id = str(config.run_id)
        run_origin = normalize_run_origin(resume_payload or {"run_origin": "mcp"})
        queued = dict(resume_payload or _queued_codex_payload(config))
        queued["status"] = "running" if resume_payload is not None else "queued"
        queued["run_origin"] = run_origin
        queued["error"] = None
        stop_event = Event()
        with self._active_runs_lock:
            if run_id in self._active_runs:
                raise ValueError(f"Run is already active: {run_id}")
            existing = self.records.get(run_id)
            if existing is not None and resume_payload is None:
                raise ValueError(f"Run already exists: {run_id}")
            owner_id = self.control_store.claim(
                run_id,
                origin=run_origin,
                allow_paused_takeover=resume_payload is not None,
            )
            if owner_id is None:
                raise ValueError(f"Run is already owned by another worker: {run_id}")
            thread = Thread(
                target=self._codex_run_worker,
                args=(config, stop_event, owner_id, run_origin),
                name=f"vuln-judger-mcp-{run_id}",
                daemon=True,
            )
            self._active_runs[run_id] = _ActiveRun(
                stop_event=stop_event,
                thread=thread,
                owner_id=owner_id,
            )
            try:
                self.records.save_payload(queued)
            except Exception:
                self._active_runs.pop(run_id, None)
                self.control_store.release(run_id, owner_id)
                raise
        try:
            thread.start()
        except Exception as exc:
            with self._active_runs_lock:
                self._active_runs.pop(run_id, None)
            self.control_store.release(run_id, owner_id)
            failed = dict(self.records.get(run_id) or queued)
            failed["status"] = "failed"
            failed["error"] = str(exc)
            failed["run_origin"] = run_origin
            self.records.save_payload(failed)
            raise
        result = _run_summary(queued)
        result.update(
            {
                "saved": True,
                "asynchronous": True,
                "record_path": str(self.records._path(run_id)),
                "poll": {"tool": "get_run", "arguments": {"run_id": run_id}},
                "stop": {"tool": "stop_run", "arguments": {"run_id": run_id}},
                "pause": {"tool": "pause_run", "arguments": {"run_id": run_id}},
            }
        )
        return result

    def _codex_run_worker(
        self,
        config: RunConfig,
        stop_event: Event,
        owner_id: str,
        run_origin: str,
    ) -> None:
        try:
            self._run_codex_report(
                config,
                stop_event=stop_event,
                owner_id=owner_id,
                run_origin=run_origin,
            )
        except Exception as exc:
            self._record_codex_failure(
                config,
                exc,
                stopped=stop_event.is_set(),
                run_origin=run_origin,
            )
        finally:
            self.control_store.release(str(config.run_id), owner_id)
            with self._active_runs_lock:
                self._active_runs.pop(str(config.run_id), None)

    def _run_codex_report(
        self,
        config: RunConfig,
        stop_event: Optional[Event] = None,
        owner_id: Optional[str] = None,
        run_origin: str = "mcp",
    ) -> Dict[str, Any]:
        runner = (
            OpenCodeDrivenRunner(records_dir=self.records.root)
            if config.engine == OPENCODE_ENGINE
            else CodexDrivenRunner(records_dir=self.records.root)
        )

        def requested_action() -> Optional[str]:
            if stop_event is not None and stop_event.is_set():
                return "stop"
            if owner_id is None:
                return None
            return self.control_store.requested_action(str(config.run_id), owner_id)

        try:
            payload = runner.run(
                config,
                store=self.records,
                run_origin=run_origin,
                should_stop=lambda: requested_action() is not None,
            )
        except CodexRunnerStopped:
            current = self.records.get(str(config.run_id)) or _queued_codex_payload(config)
            action = requested_action()
            return self._controlled_codex_result(config, current, action, run_origin)
        action = requested_action()
        if action is not None:
            current = self.records.get(str(config.run_id)) or payload
            return self._controlled_codex_result(config, current, action, run_origin)
        payload["run_origin"] = run_origin
        payload["engine"] = config.engine
        payload["config"] = payload.get("config") or _config_snapshot(config)
        self.records.save_payload(payload)
        return payload

    def _controlled_codex_result(
        self,
        config: RunConfig,
        current: Dict[str, Any],
        action: Optional[str],
        run_origin: str,
    ) -> Dict[str, Any]:
        stop_sessions(current)
        if action == "pause":
            paused = _pause_payload(
                config,
                current,
                "MCP worker 收到暂停请求",
                run_origin=run_origin,
            )
            self.records.save_payload(paused)
            return paused
        stopped = dict(current)
        stopped["status"] = "stopped"
        stopped["run_origin"] = run_origin
        stopped["engine"] = config.engine
        stopped["error"] = None
        self.records.save_payload(stopped)
        return stopped

    def _record_codex_failure(
        self,
        config: RunConfig,
        exc: Exception,
        *,
        stopped: bool = False,
        run_origin: str = "mcp",
    ) -> Dict[str, Any]:
        run_id = str(config.run_id)
        current = self.records.get(run_id) or _queued_codex_payload(config)
        stop_sessions(current)
        failed = dict(current)
        failed["status"] = "stopped" if stopped else "failed"
        failed["error"] = None if stopped else str(exc)
        diagnostics = list(failed.get("diagnostics") or [])
        diagnostics.append(str(exc))
        failed["diagnostics"] = diagnostics
        failed["run_origin"] = run_origin
        failed["engine"] = config.engine
        self.records.save_payload(failed)
        return failed

    def _completed_run_result(self, payload: Dict[str, Any], *, include_report: bool) -> Dict[str, Any]:
        result = _run_summary(payload)
        result.update(
            {
                "saved": True,
                "asynchronous": False,
                "record_path": str(self.records._path(str(payload.get("run_id")))),
            }
        )
        if include_report:
            result["report"] = payload
        return result

    def _one_round_judge(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        finding, findings, indexer, collector = self._collector_context(arguments)
        bundle = collector.collect(finding)
        report = DebateOrchestrator(
            max_rounds=1,
            affirmative_agent=self.agent_store.agent("affirmative", _optional_text(arguments.get("affirmative_agent_profile"))),
            negative_agent=self.agent_store.agent("negative", _optional_text(arguments.get("negative_agent_profile"))),
            moderator_agent=self.agent_store.agent("moderator", _optional_text(arguments.get("moderator_agent_profile"))),
        ).adjudicate(bundle)
        report_payload = to_jsonable(report)
        run_id = _optional_text(arguments.get("run_id")) or f"run-{uuid4().hex[:12]}"
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        run_payload = {
            "run_id": run_id,
            "status": "completed",
            "run_origin": "mcp",
            "engine": BUILTIN_ENGINE,
            "created_at": created_at,
            "source_path": str(_required_path(arguments, "source_path")),
            "sarif_path": str(_required_path(arguments, "report_path")),
            "languages": list(indexer.languages),
            "finding_count": 1,
            "source_finding_count": len(findings),
            "project_context_facts": len(collector.project_context.facts),
            "reports": [report_payload],
            "diagnostics": [f"{finding.finding_id}: {item}" for item in bundle.diagnostics],
            "llm_providers": {"enabled": False, "affirmative": {}, "negative": {}, "moderator": {}},
            "agent_configs": {
                "affirmative": to_jsonable(self.agent_store.agent("affirmative", _optional_text(arguments.get("affirmative_agent_profile")))),
                "negative": to_jsonable(self.agent_store.agent("negative", _optional_text(arguments.get("negative_agent_profile")))),
                "moderator": to_jsonable(self.agent_store.agent("moderator", _optional_text(arguments.get("moderator_agent_profile")))),
            },
            "config": {
                "engine": BUILTIN_ENGINE,
                "report_path": str(_required_path(arguments, "report_path")),
                "source_path": str(_required_path(arguments, "source_path")),
                "max_rounds": 1,
                "enable_external_tools": bool(arguments.get("enable_external_tools", True)),
            },
        }
        saved = bool(arguments.get("save", True))
        if saved:
            self.records.save_payload(run_payload)
        evidence = report_payload.get("evidence_chain") or []
        evidence_limit = int(arguments.get("evidence_limit") or 40)
        response_mode = _response_mode(arguments)
        record_path = str(self.records._path(run_id)) if saved else None
        missing = _missing_evidence(
            report_payload,
            bundle.diagnostics,
            external_tools_enabled=bool(arguments.get("enable_external_tools", True)),
        )
        result = {
            "mode": "one_round_judge",
            "response_mode": response_mode,
            "run_id": run_id,
            "run_origin": "mcp",
            "saved": saved,
            "record_path": record_path,
            "configuration": {
                "engine": BUILTIN_ENGINE,
                "max_rounds": 1,
                "enable_external_tools": bool(arguments.get("enable_external_tools", True)),
                "auto_index_tools": bool(arguments.get("auto_index_tools", False)),
                "atlas_mode": "agentic_only",
                "enable_llm": False,
                "languages": list(indexer.languages),
            },
            "finding_count": len(findings),
            "judged_finding_count": 1,
            "selected_finding": _finding_brief(finding),
            "verdict": _compact_verdict_detail(report_payload),
            "path_overview": _path_overview_payload(report_payload),
            "key_gaps": _key_gaps(missing),
            "next_actions": _next_actions(saved),
            "full_report_access": _full_report_access(run_id, str(report.finding_id), record_path, saved),
        }
        if response_mode in {"standard", "full"}:
            result.update(
                {
                    "missing_evidence": missing,
                    "evidence_summary": _evidence_summary(evidence),
                    "source_locations": report_payload.get("source_locations", []),
                    "recommended_next_steps": report_payload.get("recommended_next_steps", []),
                    "disputed_points": report_payload.get("disputed_points", []),
                    "diagnostics": run_payload["diagnostics"],
                }
            )
        if response_mode == "full":
            result["agent_configs"] = run_payload["agent_configs"]
            result["debate"] = report_payload.get("debate", [])
        include_evidence_default = response_mode == "full"
        if bool(arguments.get("include_evidence", include_evidence_default)):
            result["evidence"] = evidence[: max(0, evidence_limit)]
            result["evidence_truncated"] = len(evidence) > max(0, evidence_limit)
            result["evidence_total"] = len(evidence)
        if bool(arguments.get("include_report", False)) or response_mode == "full":
            result["report"] = report_payload
            result["run"] = run_payload
        return result

    def _collect_evidence(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        finding, findings, indexer, collector = self._collector_context(arguments)
        bundle = collector.collect(finding)
        return {
            "finding_count": len(findings),
            "selected_finding": _finding_brief(finding),
            "diagnostics": bundle.diagnostics,
            "evidence": to_jsonable(bundle.evidence),
        }

    def _resolve_report_locations(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        report_path = _required_path(arguments, "report_path")
        source_path = _required_path(arguments, "source_path")
        findings = load_report(report_path)
        indexer = SourceIndexer(source_path)
        max_snippets = int(arguments.get("max_snippets") or 12)
        snippet_count = 0
        result = []
        for finding in findings:
            locations = []
            for location in finding.locations:
                resolved = indexer.resolve_location(location)
                item = {
                    "requested": location.display(),
                    "requested_file": location.file,
                    "resolved_file": resolved.relative_path,
                    "exists": resolved.exists,
                    "line_exists": resolved.line_exists,
                    "language": resolved.language,
                    "symbol": resolved.symbol,
                    "location": to_jsonable(
                        SourceLocation(
                            file=resolved.relative_path,
                            line=resolved.requested.line,
                            column=resolved.requested.column,
                            end_line=resolved.requested.end_line,
                            end_column=resolved.requested.end_column,
                            symbol=resolved.symbol or resolved.requested.symbol,
                        )
                    ),
                }
                if resolved.snippet and snippet_count < max_snippets:
                    item["snippet"] = resolved.snippet
                    snippet_count += 1
                locations.append(item)
            result.append({**_finding_brief(finding), "locations": locations, "code_flow_count": len(finding.code_flows)})
        return {"finding_count": len(findings), "findings": result}

    def _list_runs(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        limit = int(arguments.get("limit") or 50)
        return {"runs": self.records.list()[:limit]}

    def _get_run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        run = self._load_run(arguments)
        if bool(arguments.get("include_reports", False)):
            return run
        return _run_summary(run)

    def _get_finding(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        run = self._load_run(arguments)
        finding_id = _required_text(arguments, "finding_id")
        for report in run.get("reports") or []:
            if report.get("finding_id") == finding_id:
                return _finding_detail(report, run)
        raise ValueError(f"Finding not found: {finding_id}")

    def _export_run_markdown(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        run = self._load_run(arguments)
        return {"run_id": run.get("run_id"), "markdown": _export_run_markdown(run)}

    def _export_run_report(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        run = self._load_run(arguments)
        return _structured_run_report(run, arguments)

    def _stop_run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        run_id = _required_text(arguments, "run_id")
        with self._active_runs_lock:
            active = self._active_runs.get(run_id)
        run = self.records.get(run_id)
        if run is None:
            raise ValueError(f"Run not found: {run_id}")
        if str(run.get("status") or "") in {"completed", "failed", "stopped"}:
            result = _run_summary(run)
            result["stop_requested"] = False
            result["message"] = f"Run is already {run.get('status')}: {run_id}"
            return result
        stopping = dict(run)
        stopping["status"] = "stopping"
        stopping["run_origin"] = normalize_run_origin(run)
        control_requested = self.control_store.request(
            run_id,
            "stop",
            requested_by="mcp",
            before_signal=lambda: self.records.save_payload(stopping),
        )
        if active is None and not control_requested:
            result = _run_summary(run)
            result["stop_requested"] = False
            result["message"] = f"Run is not active: {run_id}"
            return result
        if not control_requested:
            self.records.save_payload(stopping)
        if active is not None:
            active.stop_event.set()
        stop_sessions(run)
        result = _run_summary(stopping)
        result["stop_requested"] = True
        return result

    def _pause_run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        run_id = _required_text(arguments, "run_id")
        run = self.records.get(run_id)
        if run is None:
            raise ValueError(f"Run not found: {run_id}")
        status = str(run.get("status") or "")
        if status == "paused":
            result = _run_summary(run)
            result["pause_requested"] = False
            result["message"] = f"Run is already paused: {run_id}"
            return result
        if status in {"completed", "failed", "stopped"}:
            result = _run_summary(run)
            result["pause_requested"] = False
            result["message"] = f"Run is already {status}: {run_id}"
            return result
        pausing = dict(run)
        pausing["status"] = "pausing"
        pausing["pause_requested"] = True
        if not self.control_store.request(
            run_id,
            "pause",
            requested_by="mcp",
            before_signal=lambda: self.records.save_payload(pausing),
        ):
            result = _run_summary(run)
            result["pause_requested"] = False
            result["message"] = f"Run is not active: {run_id}"
            return result
        result = _run_summary(pausing)
        result["pause_requested"] = True
        return result

    def _resume_run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        run_id = _required_text(arguments, "run_id")
        run = self.records.get(run_id)
        if run is None:
            raise ValueError(f"Run not found: {run_id}")
        status = str(run.get("status") or "")
        if status not in {"paused", "failed"}:
            result = _run_summary(run)
            result["resume_started"] = False
            result["message"] = f"Run is not resumable from {status}: {run_id}"
            return result
        checkpoint = _resume_checkpoint_payload(run)
        config = _config_from_paused_payload(
            checkpoint,
            self.settings.providers_file,
            self.agent_store,
            self.settings.mcp_servers_file,
            self.skill_store,
        )
        stop_sessions(run)
        with self._active_runs_lock:
            previous = self._active_runs.get(run_id)
        if previous is not None:
            previous.thread.join(timeout=2)
        result = self._start_codex_report(config, resume_payload=checkpoint)
        result["resume_started"] = True
        return result

    def _load_run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        run_id = _required_text(arguments, "run_id")
        run = self.records.get(run_id)
        if run is None:
            raise ValueError(f"Run not found: {run_id}")
        return run

    def _collector_context(
        self, arguments: Dict[str, Any]
    ) -> Tuple[Any, Sequence[Any], SourceIndexer, EvidenceCollector]:
        report_path = _required_path(arguments, "report_path")
        source_path = _required_path(arguments, "source_path")
        findings = load_report(report_path)
        finding = _select_finding(findings, arguments)
        indexer = SourceIndexer(source_path)
        languages = list(indexer.languages)
        project_context = load_project_context(_optional_path(arguments.get("skills_path")))
        collector = EvidenceCollector(
            indexer=indexer,
            project_context=project_context,
            analyzers=AnalyzerSuite(),
            analyzer_settings=AnalyzerSettings(
                enabled=bool(arguments.get("enable_external_tools", True)),
                auto_index=bool(arguments.get("auto_index_tools", False)),
                mcp_servers_file=_optional_path(arguments.get("mcp_servers_file")) or self.settings.mcp_servers_file,
            ),
            languages=languages,
        )
        return finding, findings, indexer, collector


def serve_mcp(settings: Optional[JudgerMCPSettings] = None) -> None:
    JudgerMCPServer(settings=settings).serve_forever()


def _tool_specs() -> List[Dict[str, Any]]:
    return [
        _tool(
            "judge_report",
            "Start a vuln-judger review. The default opencode engine runs asynchronously; poll get_run with the returned run_id.",
            {
                "report_path": {"type": "string", "description": "SARIF/JSON/Markdown report path."},
                "source_path": {"type": "string", "description": "Source tree root path."},
                "engine": {
                    "type": "string",
                    "enum": [CODEX_ENGINE, OPENCODE_ENGINE, BUILTIN_ENGINE],
                    "default": OPENCODE_ENGINE,
                    "description": "codex or opencode starts the three-slot isolated CLI pipeline; builtin keeps the legacy in-process pipeline.",
                },
                "skills_path": {"type": "string", "description": "Optional project skills directory."},
                "skill_source_id": {"type": "string", "description": "Optional configured Skill Source id."},
                "mcp_servers_file": {"type": "string"},
                "max_rounds": {"type": "integer", "minimum": 1, "default": 4},
                "silence_reminder_minutes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1440,
                    "default": DEFAULT_SILENCE_REMINDER_MINUTES,
                    "description": "CLI engines only. Minutes of session silence before checking the handoff and reminding the next agent.",
                },
                "enable_external_tools": {"type": "boolean", "default": True},
                "auto_index_tools": {
                    "type": "boolean",
                    "default": False,
                    "description": "Optionally prewarm a persistent Atlas cache; Atlas MCP v1.5+ can run scoped Focus queries without a prebuilt index.",
                },
                "enable_llm": {"type": "boolean", "default": False},
                "llm_model": {"type": "string", "description": "Optional provider/model override for OpenCode."},
                "providers_file": {"type": "string"},
                "affirmative_provider_id": {"type": "string"},
                "negative_provider_id": {"type": "string"},
                "moderator_provider_id": {"type": "string"},
                "affirmative_agent_profile": {"type": "string"},
                "negative_agent_profile": {"type": "string"},
                "moderator_agent_profile": {"type": "string"},
                "save": {
                    "type": "boolean",
                    "default": True,
                    "description": "CLI engines require true so asynchronous progress can be polled.",
                },
                "wait_for_completion": {
                    "type": "boolean",
                    "default": False,
                    "description": "CLI engines only. Prefer false to avoid MCP tool timeouts.",
                },
                "include_report": {"type": "boolean", "default": False},
                "run_id": {"type": "string"},
            },
            ["report_path", "source_path"],
        ),
        _tool(
            "one_round_judge",
            "Quickly validate one finding with the legacy builtin engine, one debate round, and missing-evidence guidance.",
            {
                "report_path": {"type": "string", "description": "SARIF/JSON/Markdown report path."},
                "source_path": {"type": "string", "description": "Source tree root path."},
                "skills_path": {"type": "string", "description": "Optional project skills directory."},
                "finding_index": {"type": "integer", "minimum": 0, "default": 0},
                "finding_id": {"type": "string"},
                "rule_id": {"type": "string"},
                "enable_external_tools": {"type": "boolean", "default": True},
                "auto_index_tools": {
                    "type": "boolean",
                    "default": False,
                    "description": "Optionally prewarm a persistent Atlas cache; Atlas MCP v1.5+ can run scoped Focus queries without a prebuilt index.",
                },
                "mcp_servers_file": {"type": "string"},
                "affirmative_agent_profile": {"type": "string"},
                "negative_agent_profile": {"type": "string"},
                "moderator_agent_profile": {"type": "string"},
                "response_mode": {"type": "string", "enum": ["compact", "standard", "full"], "default": "compact"},
                "include_evidence": {"type": "boolean", "default": False},
                "evidence_limit": {"type": "integer", "minimum": 0, "default": 40},
                "include_report": {"type": "boolean", "default": False},
                "save": {"type": "boolean", "default": True},
                "run_id": {"type": "string"},
            },
            ["report_path", "source_path"],
        ),
        _tool(
            "collect_evidence",
            "Collect source, SARIF, Atlas, search and impact evidence for one finding without running debate.",
            _analysis_properties(),
            ["report_path", "source_path"],
        ),
        _tool(
            "resolve_report_locations",
            "Resolve report locations against a source tree and return snippets for validation.",
            {
                "report_path": {"type": "string"},
                "source_path": {"type": "string"},
                "max_snippets": {"type": "integer", "minimum": 0, "default": 12},
            },
            ["report_path", "source_path"],
        ),
        _tool(
            "list_runs",
            "List saved vuln-judger run records.",
            {"limit": {"type": "integer", "minimum": 1, "default": 50}},
            [],
        ),
        _tool(
            "get_run",
            "Get a saved run summary or full run report.",
            {"run_id": {"type": "string"}, "include_reports": {"type": "boolean", "default": False}},
            ["run_id"],
        ),
        _tool(
            "get_finding",
            "Get one finding report from a saved run.",
            {"run_id": {"type": "string"}, "finding_id": {"type": "string"}},
            ["run_id", "finding_id"],
        ),
        _tool(
            "export_run_markdown",
            "Export a saved run as Markdown.",
            {"run_id": {"type": "string"}},
            ["run_id"],
        ),
        _tool(
            "export_run_report",
            "Export a saved run as stable structured JSON, including pending split findings and normalized report/adjudication details.",
            {
                "run_id": {"type": "string"},
                "detail_level": {
                    "type": "string",
                    "enum": ["summary", "detail", "raw"],
                    "default": "detail",
                    "description": "detail returns Dashboard-aligned sections; raw additionally returns persisted reports and split findings.",
                },
                "finding_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional finding ids to export, in canonical report order.",
                },
                "offset": {"type": "integer", "minimum": 0, "default": 0},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
            },
            ["run_id"],
        ),
        _tool(
            "stop_run",
            "Request cancellation of an asynchronous CLI review started by this MCP server.",
            {"run_id": {"type": "string"}},
            ["run_id"],
        ),
        _tool(
            "pause_run",
            "Pause an asynchronous CLI review and persist a resumable checkpoint.",
            {"run_id": {"type": "string"}},
            ["run_id"],
        ),
        _tool(
            "resume_run",
            "Resume a paused or failed asynchronous CLI review from its first incomplete stage.",
            {"run_id": {"type": "string"}},
            ["run_id"],
        ),
    ]


def _analysis_properties() -> Dict[str, Any]:
    return {
        "report_path": {"type": "string"},
        "source_path": {"type": "string"},
        "skills_path": {"type": "string"},
        "finding_index": {"type": "integer", "minimum": 0},
        "finding_id": {"type": "string"},
        "rule_id": {"type": "string"},
        "enable_external_tools": {"type": "boolean", "default": True},
        "auto_index_tools": {
            "type": "boolean",
            "default": False,
            "description": "Optionally prewarm a persistent Atlas cache; Atlas MCP v1.5+ can run scoped Focus queries without a prebuilt index.",
        },
        "mcp_servers_file": {"type": "string"},
    }


def _tool(name: str, description: str, properties: Dict[str, Any], required: Sequence[str]) -> Dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": list(required),
            "additionalProperties": False,
        },
    }

def _read_message(stdin: TextIO) -> Optional[Tuple[Dict[str, Any], str]]:
    raw_line = stdin.buffer.readline() if hasattr(stdin, "buffer") else stdin.readline().encode("utf-8")
    while raw_line in {b"\n", b"\r\n"}:
        raw_line = stdin.buffer.readline() if hasattr(stdin, "buffer") else stdin.readline().encode("utf-8")
    if not raw_line:
        return None
    if raw_line.lower().startswith(b"content-length:"):
        headers = [raw_line]
        while True:
            line = stdin.buffer.readline() if hasattr(stdin, "buffer") else stdin.readline().encode("utf-8")
            if not line:
                return None
            if line in {b"\n", b"\r\n"}:
                break
            headers.append(line)
        length = _content_length(headers)
        body = stdin.buffer.read(length) if hasattr(stdin, "buffer") else stdin.read(length).encode("utf-8")
        return json.loads(body.decode("utf-8")), "header"
    return json.loads(raw_line.decode("utf-8")), "line"


def _write_message(stdout: TextIO, message: Dict[str, Any], framing: str) -> None:
    raw = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if framing == "header":
        stdout.buffer.write(f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii") + raw)
        stdout.buffer.flush()
    else:
        stdout.write(raw.decode("utf-8") + "\n")
        stdout.flush()


def _content_length(headers: Iterable[bytes]) -> int:
    for header in headers:
        name, _, value = header.partition(b":")
        if name.strip().lower() == b"content-length":
            return int(value.strip())
    raise ValueError("Missing Content-Length header")


def _bounded_int(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        result = default
    return min(max(result, minimum), maximum)


def _result(request_id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    error = {"code": code, "message": message}
    if data:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _tool_result(request_id: Any, payload: Any, is_error: bool = False) -> Dict[str, Any]:
    return _result(
        request_id,
        {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(to_jsonable(payload), ensure_ascii=False, indent=2, sort_keys=True),
                }
            ],
            "isError": is_error,
        },
    )


def _required_path(arguments: Dict[str, Any], key: str) -> Path:
    value = _required_text(arguments, key)
    return Path(value).expanduser().resolve()


def _optional_path(value: Any) -> Optional[Path]:
    text = _optional_text(value)
    return Path(text).expanduser().resolve() if text else None


def _required_text(arguments: Dict[str, Any], key: str) -> str:
    value = _optional_text(arguments.get(key))
    if not value:
        raise ValueError(f"{key} is required")
    return value


def _optional_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None

def _select_finding(findings: Sequence[Any], arguments: Dict[str, Any]) -> Any:
    if not findings:
        raise ValueError("Report contains no findings")
    finding_id = _optional_text(arguments.get("finding_id"))
    if finding_id:
        for finding in findings:
            if finding.finding_id == finding_id:
                return finding
        raise ValueError(f"finding_id not found: {finding_id}")
    rule_id = _optional_text(arguments.get("rule_id"))
    if rule_id:
        for finding in findings:
            if finding.rule_id == rule_id:
                return finding
        raise ValueError(f"rule_id not found: {rule_id}")
    index = int(arguments.get("finding_index") or 0)
    if index < 0 or index >= len(findings):
        raise ValueError(f"finding_index out of range: {index}")
    return findings[index]


def _finding_brief(finding: Any) -> Dict[str, Any]:
    return {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "level": finding.level,
        "message": finding.message,
        "locations": [location.display() for location in finding.locations],
    }


def _verdict_detail(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "finding_id": report.get("finding_id"),
        "rule_id": report.get("rule_id"),
        "verdict": report.get("verdict"),
        "confidence": report.get("confidence"),
        "reasoning_summary": report.get("reasoning_summary"),
        "final_conclusion": report.get("final_conclusion"),
        "protection_assessment": report.get("protection_assessment"),
        "impact_assessment": report.get("impact_assessment"),
    }


def _response_mode(arguments: Dict[str, Any]) -> str:
    mode = str(arguments.get("response_mode") or "compact").strip().lower()
    if mode not in {"compact", "standard", "full"}:
        raise ValueError(f"Unsupported response_mode: {mode}")
    return mode


def _compact_verdict_detail(report: Dict[str, Any]) -> Dict[str, Any]:
    conclusion = _without_path_overview(str(report.get("final_conclusion") or ""))
    summary = str(report.get("reasoning_summary") or "").strip() or conclusion
    label = _extract_final_label(conclusion) or _verdict_label(str(report.get("verdict") or ""))
    return {
        "finding_id": report.get("finding_id"),
        "rule_id": report.get("rule_id"),
        "verdict": report.get("verdict"),
        "label": label,
        "confidence": report.get("confidence"),
        "summary": _short_text(summary),
        "conclusion": _short_text(conclusion),
    }


def _without_path_overview(text: str) -> str:
    value = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    for marker in ("\n### 调用链 / 数据流概览", "\n### 证据串联图"):
        if marker in value:
            return value.split(marker, 1)[0].strip()
    if value.startswith("### 调用链 / 数据流概览") or value.startswith("### 证据串联图"):
        return ""
    return value.strip()


def _extract_final_label(text: str) -> str:
    match = re.search(r"【([^】]{1,20})】", str(text or ""))
    return match.group(1).strip() if match else ""


def _verdict_label(verdict: str) -> str:
    return {
        "TRUE_POSITIVE": "真实漏洞",
        "FALSE_POSITIVE": "误报",
        "INCONCLUSIVE": "证据不足",
    }.get(str(verdict or ""), str(verdict or ""))


def _short_text(text: str, limit: int = 700) -> str:
    value = _clean_response_text(text)
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


def _path_overview_payload(report: Dict[str, Any]) -> Dict[str, Any]:
    graph = report.get("evidence_graph") if isinstance(report.get("evidence_graph"), dict) else {}
    overview = _clean_response_text(graph.get("path_overview") or "")
    breaks = _overview_breaks(graph, overview)
    call_chain = _overview_block(overview, "调用链状态", "数据流状态")
    data_flow = _overview_block(overview, "数据流状态", "未闭环点：")
    return {
        "status": _overview_status(call_chain, data_flow, breaks),
        "call_chain": call_chain or "调用链：未获得可展示路径。",
        "data_flow": data_flow or "数据流：未获得可展示路径。",
        "breaks": breaks,
    }


def _overview_block(text: str, start_marker: str, end_marker: str) -> str:
    value = str(text or "")
    start = value.find(start_marker)
    if start < 0:
        return ""
    end = value.find(end_marker, start + len(start_marker))
    block = value[start:] if end < 0 else value[start:end]
    return _clean_response_text(block)


def _overview_breaks(graph: Dict[str, Any], overview: str) -> List[str]:
    result: List[str] = []
    for item in graph.get("breaks") or []:
        if isinstance(item, dict):
            reason = _clean_response_text(item.get("label") or item.get("reason") or "")
            if reason:
                result.append(reason)
    if not result and "未闭环点：" in overview:
        tail = overview.split("未闭环点：", 1)[1]
        for line in tail.splitlines():
            stripped = line.strip()
            if stripped.startswith("-"):
                result.append(_clean_response_text(stripped[1:].strip()))
    return _dedupe_strings(result)


def _overview_status(call_chain: str, data_flow: str, breaks: Sequence[str]) -> str:
    combined = "\n".join([call_chain, data_flow])
    if breaks or "未闭环" in combined or "断链" in combined:
        return "未闭环"
    if "部分闭环" in combined or "部分" in combined:
        return "部分闭环"
    if "已闭环" in combined:
        return "已闭环"
    return "未获得证据"


def _key_gaps(missing: Sequence[Dict[str, Any]], limit: int = 5) -> List[str]:
    gaps = []
    for item in missing:
        summary = _clean_response_text(item.get("summary") if isinstance(item, dict) else item)
        if summary:
            gaps.append(summary)
        if len(gaps) >= limit:
            break
    return _dedupe_strings(gaps)


def _next_actions(saved: bool) -> List[str]:
    actions = [
        "需要结构化消费整个 run 时，调用 export_run_report 导出状态、结论和详情。",
        "需要更多细节时，优先调用 get_finding 读取完整 finding 报告。",
        "需要人读报告时，调用 export_run_markdown 导出完整 Markdown。",
    ]
    if not saved:
        actions.insert(0, "当前未保存 run；如需后续访问完整报告，请重新调用 one_round_judge 并设置 save=true。")
    return actions


def _full_report_access(run_id: str, finding_id: str, record_path: Optional[str], saved: bool) -> Dict[str, Any]:
    return {
        "available": saved,
        "record_path": record_path,
        "mcp_get_run": {"tool": "get_run", "arguments": {"run_id": run_id, "include_reports": True}} if saved else None,
        "mcp_get_finding": {"tool": "get_finding", "arguments": {"run_id": run_id, "finding_id": finding_id}} if saved else None,
        "mcp_export_report": {
            "tool": "export_run_report",
            "arguments": {"run_id": run_id, "detail_level": "detail"},
        }
        if saved
        else None,
        "mcp_export_markdown": {"tool": "export_run_markdown", "arguments": {"run_id": run_id}} if saved else None,
    }


def _clean_response_text(value: Any) -> str:
    text = str(value or "")
    text = re.sub(r"\bev-[0-9A-Za-z_-]+\b", "", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _dedupe_strings(items: Sequence[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _evidence_summary(evidence: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    by_kind: Dict[str, int] = {}
    by_source: Dict[str, int] = {}
    by_strength: Dict[str, int] = {}
    key_evidence = []
    for item in evidence:
        kind = str(item.get("kind") or "UNKNOWN")
        source = str(item.get("source") or "unknown")
        strength = str(item.get("strength") or "UNKNOWN")
        by_kind[kind] = by_kind.get(kind, 0) + 1
        by_source[source] = by_source.get(source, 0) + 1
        by_strength[strength] = by_strength.get(strength, 0) + 1
        if len(key_evidence) < 12 and (
            kind
            in {
                "REPORT",
                "SOURCE_LOCATION",
                "SARIF_CODE_FLOW",
                "DATA_FLOW",
                "CALL_CHAIN",
                "TOOL_DIAGNOSTIC",
            }
            or source.startswith("atlas")
        ):
            key_evidence.append(
                {
                    "evidence_id": item.get("evidence_id"),
                    "kind": kind,
                    "source": source,
                    "strength": strength,
                    "summary": item.get("summary"),
                    "locations": item.get("locations", []),
                }
            )
    return {
        "total": len(evidence),
        "by_kind": by_kind,
        "by_source": by_source,
        "by_strength": by_strength,
        "key_evidence": key_evidence,
    }


def _missing_evidence(
    report: Dict[str, Any],
    diagnostics: Sequence[str],
    external_tools_enabled: bool = True,
) -> List[Dict[str, Any]]:
    evidence = report.get("evidence_chain") or []
    missing: List[Dict[str, Any]] = []
    if not _has_evidence_kind(evidence, "SOURCE_LOCATION", require_line=True):
        missing.append(
            {
                "type": "source_location",
                "summary": "缺少可解析到源码树的具体文件/行号证据。",
                "suggestion": "先调用 resolve_report_locations 校验报告路径，必要时补充正确 source_path 或报告行号。",
            }
        )
    if not _has_meaningful_evidence(evidence, {"SARIF_CODE_FLOW", "DATA_FLOW", "CALL_CHAIN"}):
        missing.append(
            {
                "type": "flow_or_call_chain",
                "summary": "缺少中等以上强度的数据流或调用链闭环证据。",
                "suggestion": "优先补充 SARIF codeFlows；或确认 Atlas MCP 可用后通过 collect_evidence 获取 Focus trace/calls，必要时预热持久缓存。",
            }
        )
    if external_tools_enabled and not _has_atlas_success(evidence):
        missing.append(
            {
                "type": "atlas_evidence",
                "summary": "未获得成功的 Atlas MCP 语义证据。",
                "suggestion": "确认 Atlas MCP 配置可用；必要时开启 auto_index_tools 预热 Atlas 持久缓存。",
            }
        )
    if _has_evidence_kind(evidence, "PROTECTION"):
        missing.append(
            {
                "type": "protection_validation",
                "summary": "存在校验、鉴权、消毒或过滤相关防护证据，尚需验证是否覆盖攻击路径。",
                "suggestion": "检查防护代码与报告位置的数据关系，补充可绕过或不可绕过的源码证据。",
            }
        )
    if not _has_evidence_kind(evidence, "IMPACT") and not _has_evidence_kind(evidence, "PROJECT_CONTEXT"):
        missing.append(
            {
                "type": "impact_context",
                "summary": "缺少资产、权限边界或业务影响上下文。",
                "suggestion": "补充项目 Skill/上下文，说明可达汇点对应的数据资产或权限影响。",
            }
        )
    for point in report.get("disputed_points") or []:
        if point and not any(point == item.get("summary") for item in missing):
            missing.append({"type": "disputed_point", "summary": point, "suggestion": "按该争议点补充证据后重新运行 one_round_judge。"})
    for diagnostic in diagnostics:
        missing.append({"type": "diagnostic", "summary": diagnostic, "suggestion": "先处理该工具或配置诊断，再重新快速验证。"})
    for step in report.get("recommended_next_steps") or []:
        missing.append({"type": "next_step", "summary": step, "suggestion": step})
    return _dedupe_missing(missing)


def _has_evidence_kind(evidence: Sequence[Dict[str, Any]], kind: str, require_line: bool = False) -> bool:
    for item in evidence:
        if item.get("kind") != kind:
            continue
        if not require_line:
            return True
        if item.get("data", {}).get("line_exists") or item.get("data", {}).get("indexed_files"):
            return True
    return False


def _has_meaningful_evidence(evidence: Sequence[Dict[str, Any]], kinds: set[str]) -> bool:
    for item in evidence:
        if item.get("kind") not in kinds:
            continue
        if item.get("source") == "code-search":
            continue
        if item.get("strength") in {"STRONG", "MEDIUM"}:
            return True
    return False


def _has_atlas_success(evidence: Sequence[Dict[str, Any]]) -> bool:
    return any(str(item.get("source") or "").startswith("atlas") and item.get("data", {}).get("mcp_success") for item in evidence)


def _dedupe_missing(items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    result = []
    for item in items:
        marker = (item.get("type"), item.get("summary"))
        if marker in seen:
            continue
        seen.add(marker)
        result.append(dict(item))
    return result


def _config_snapshot(config: RunConfig) -> Dict[str, Any]:
    return run_config_snapshot(config)


def _queued_codex_payload(config: RunConfig) -> Dict[str, Any]:
    cli_name = "OpenCode" if config.engine == OPENCODE_ENGINE else "Codex"
    return {
        "run_id": config.run_id,
        "status": "queued",
        "run_origin": "mcp",
        "engine": config.engine,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_path": str(config.source_path),
        "sarif_path": str(config.sarif_path),
        "languages": [],
        "finding_count": 0,
        "project_context_facts": 0,
        "reports": [],
        "diagnostics": [f"{cli_name}-driven MCP run queued."],
        "llm_providers": {"enabled": False, "engine": config.engine},
        "agent_configs": {
            "affirmative": to_jsonable(config.affirmative_agent) if config.affirmative_agent else None,
            "negative": to_jsonable(config.negative_agent) if config.negative_agent else None,
            "moderator": to_jsonable(config.moderator_agent) if config.moderator_agent else None,
        },
        "completed_finding_count": 0,
        "current_finding_id": None,
        "current_finding_index": None,
        "current_finding_ids": {},
        "resume_from_finding_id": None,
        "resume_from_finding_index": 0,
        "config": _config_snapshot(config),
    }


def _run_summary(run: Dict[str, Any]) -> Dict[str, Any]:
    reports = run.get("reports") or []
    counts: Dict[str, int] = {}
    finding_summaries = []
    for report in reports:
        finding_status = finding_report_status(report)
        if finding_status == FINDING_COMPLETED:
            verdict = str(report.get("verdict") or "UNKNOWN")
            counts[verdict] = counts.get(verdict, 0) + 1
        finding_summaries.append(
            {
                "finding_id": report.get("finding_id"),
                "rule_id": report.get("rule_id"),
                "finding_status": finding_status,
                "verdict": report.get("verdict"),
                "confidence": report.get("confidence"),
                "summary": report.get("reasoning_summary"),
                "source_locations": report.get("source_locations", []),
                "manual_review": _manual_review_for(run, report.get("finding_id")),
            }
        )
    return {
        "run_id": run.get("run_id"),
        "status": run.get("status", "completed"),
        "engine": run.get("engine") or (run.get("config") or {}).get("engine") or BUILTIN_ENGINE,
        "run_origin": normalize_run_origin(run),
        "created_at": run.get("created_at"),
        "source_path": run.get("source_path"),
        "sarif_path": run.get("sarif_path"),
        "languages": run.get("languages", []),
        "finding_count": run.get("finding_count", len(reports)),
        "completed_finding_count": run.get("completed_finding_count", completed_finding_count(reports)),
        "current_finding_id": run.get("current_finding_id"),
        "current_finding_index": run.get("current_finding_index"),
        "current_finding_ids": run.get("current_finding_ids") or {},
        "verdict_counts": counts,
        "manual_review_count": len(run.get("manual_reviews") or {}),
        "findings": finding_summaries,
        "diagnostics": run.get("diagnostics", []),
        "error": run.get("error"),
    }


def _structured_run_report(run: Dict[str, Any], arguments: Dict[str, Any]) -> Dict[str, Any]:
    detail_level = str(arguments.get("detail_level") or "detail").strip().lower()
    if detail_level not in {"summary", "detail", "raw"}:
        raise ValueError("detail_level must be summary, detail, or raw")
    offset = _export_integer_argument(arguments, "offset", default=0, minimum=0)
    limit = _export_integer_argument(arguments, "limit", default=20, minimum=1, maximum=100)

    canonical, canonical_source, split_origin = _canonical_export_findings(run)
    requested_ids = _export_finding_ids(arguments.get("finding_ids"))
    canonical_ids = [str(item.get("finding_id") or "") for item, _ in canonical]
    if requested_ids is not None:
        unknown = [finding_id for finding_id in requested_ids if finding_id not in canonical_ids]
        if unknown:
            raise ValueError(f"Finding not found: {', '.join(unknown)}")
        requested = set(requested_ids)
        matched = [item for item in canonical if str(item[0].get("finding_id") or "") in requested]
    else:
        matched = canonical

    all_statuses = [_export_finding_status(run, split, report) for split, report in canonical]
    selected = matched[offset : offset + limit]
    exported_findings = [
        _export_finding(run, split, report, detail_level)
        for split, report in selected
    ]
    status_counts = {
        FINDING_COMPLETED: all_statuses.count(FINDING_COMPLETED),
        FINDING_IN_PROGRESS: all_statuses.count(FINDING_IN_PROGRESS),
        FINDING_PENDING: all_statuses.count(FINDING_PENDING),
    }
    verdict_counts: Dict[str, int] = {}
    for _, report in canonical:
        if not isinstance(report, dict) or finding_report_status(report) != FINDING_COMPLETED:
            continue
        verdict = str(report.get("verdict") or "UNKNOWN")
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

    declared_count = _safe_nonnegative_int(run.get("finding_count"), len(canonical))
    matched_count = len(matched)
    next_offset = offset + len(selected) if offset + len(selected) < matched_count else None
    return {
        "schema_version": 1,
        "detail_level": detail_level,
        "run": {
            "run_id": run.get("run_id"),
            "status": run.get("status", "completed"),
            "engine": run.get("engine") or (run.get("config") or {}).get("engine") or BUILTIN_ENGINE,
            "run_origin": normalize_run_origin(run),
            "created_at": run.get("created_at"),
            "updated_at": run.get("updated_at"),
            "source_path": run.get("source_path"),
            "sarif_path": run.get("sarif_path"),
            "languages": _json_copy(run.get("languages") or []),
            "finding_count": declared_count,
            "completed_finding_count": status_counts[FINDING_COMPLETED],
            "current_finding_id": run.get("current_finding_id"),
            "current_finding_index": run.get("current_finding_index"),
            "current_finding_ids": _json_copy(run.get("current_finding_ids") or {}),
            "resume_from_finding_id": run.get("resume_from_finding_id"),
            "resume_from_finding_index": run.get("resume_from_finding_index"),
            "verdict_counts": verdict_counts,
            "manual_review_count": len(run.get("manual_reviews") or {}),
            "diagnostics": _json_copy(run.get("diagnostics") or []),
            "error": run.get("error"),
        },
        "coverage": {
            "source": canonical_source,
            "split_origin": split_origin,
            "total": len(canonical),
            "declared_total": declared_count,
            "canonical_complete": declared_count == 0 or len(canonical) >= declared_count,
            "matched": matched_count,
            "returned": len(exported_findings),
            "offset": offset,
            "limit": limit,
            "next_offset": next_offset,
            "completed": status_counts[FINDING_COMPLETED],
            "in_progress": status_counts[FINDING_IN_PROGRESS],
            "pending": status_counts[FINDING_PENDING],
            "missing_detail": sum(1 for _, report in canonical if not isinstance(report, dict)),
        },
        "findings": exported_findings,
    }


def _canonical_export_findings(
    run: Dict[str, Any],
) -> Tuple[List[Tuple[Dict[str, Any], Optional[Dict[str, Any]]]], str, Optional[str]]:
    reports = [item for item in run.get("reports") or [] if isinstance(item, dict)]
    reports_by_id = {
        str(report.get("finding_id") or ""): report
        for report in reports
        if str(report.get("finding_id") or "")
    }
    payload = _report_findings_payload(run)
    raw_findings = payload.get("findings") if isinstance(payload, dict) else None
    split_findings = [item for item in raw_findings or [] if isinstance(item, dict)]
    if not split_findings:
        return [(dict(report), report) for report in reports], "reports", None

    canonical: List[Tuple[Dict[str, Any], Optional[Dict[str, Any]]]] = []
    included = set()
    for item in split_findings:
        finding_id = str(item.get("finding_id") or "")
        canonical.append((item, reports_by_id.get(finding_id)))
        if finding_id:
            included.add(finding_id)
    for report in reports:
        finding_id = str(report.get("finding_id") or "")
        if finding_id not in included:
            canonical.append((dict(report), report))
    origin = str(payload.get("origin") or "").strip() or None
    return canonical, "report_findings", origin


def _export_finding(
    run: Dict[str, Any],
    split: Dict[str, Any],
    report: Optional[Dict[str, Any]],
    detail_level: str,
) -> Dict[str, Any]:
    finding_id = str(split.get("finding_id") or (report or {}).get("finding_id") or "")
    status = _export_finding_status(run, split, report)
    conclusion = None
    if isinstance(report, dict):
        conclusion = {
            "verdict": report.get("verdict"),
            "confidence": report.get("confidence"),
            "reasoning_summary": report.get("reasoning_summary"),
            "final_conclusion": report.get("final_conclusion"),
        }
    item: Dict[str, Any] = {
        "finding_id": finding_id,
        "rule_id": split.get("rule_id") or (report or {}).get("rule_id"),
        "status": status,
        "conclusion": conclusion,
        "report_detail_available": bool(_normalized_report_detail(split, report)),
        "finding_detail_available": isinstance(report, dict),
        "missing_detail_reason": _missing_detail_reason(status) if not isinstance(report, dict) else None,
        "manual_review": _json_copy(_manual_review_for(run, finding_id)),
        "report_detail": None,
        "finding_detail": None,
    }
    if detail_level in {"detail", "raw"}:
        item["report_detail"] = _normalized_report_detail(split, report)
        item["finding_detail"] = _normalized_finding_detail(report) if isinstance(report, dict) else None
    if detail_level == "raw":
        item["raw"] = {
            "split_finding": _json_copy(split),
            "report": _json_copy(report),
        }
    return item


def _normalized_report_detail(
    split: Dict[str, Any], report: Optional[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    report_evidence = None
    if isinstance(report, dict):
        for evidence in report.get("evidence_chain") or []:
            if isinstance(evidence, dict) and (
                evidence.get("kind") == "REPORT" or evidence.get("source") == "input-report"
            ):
                report_evidence = evidence
                break
    data = report_evidence.get("data") if isinstance(report_evidence, dict) else {}
    data = data if isinstance(data, dict) else {}
    detail = {
        "rule_id": split.get("rule_id") or data.get("rule_id") or (report or {}).get("rule_id"),
        "level": split.get("level") or data.get("level"),
        "message": split.get("message") or data.get("message") or (report_evidence or {}).get("summary"),
        "locations": _json_copy(split.get("locations") or data.get("locations") or (report_evidence or {}).get("locations") or []),
        "code_flows": _json_copy(split.get("code_flows") or data.get("code_flows") or []),
        "properties": _json_copy(data.get("properties")),
        "raw_result": _json_copy(data.get("raw_result")),
    }
    if not any(value not in (None, "", [], {}) for value in detail.values()):
        return None
    return detail


def _normalized_finding_detail(report: Dict[str, Any]) -> Dict[str, Any]:
    workflow = report.get("cli_workflow") if isinstance(report.get("cli_workflow"), dict) else {}
    if not workflow and isinstance(report.get("codex_workflow"), dict):
        workflow = report["codex_workflow"]
    role_conclusions = {
        role: _normalized_role_conclusion(workflow.get(role))
        for role in ("affirmative", "negative", "moderator")
    }
    return {
        "reasoning_summary": report.get("reasoning_summary"),
        "final_conclusion": report.get("final_conclusion"),
        "source_locations": _json_copy(report.get("source_locations") or []),
        "protection_assessment": report.get("protection_assessment"),
        "impact_assessment": report.get("impact_assessment"),
        "disputed_points": _json_copy(report.get("disputed_points") or []),
        "recommended_next_steps": _json_copy(report.get("recommended_next_steps") or []),
        "verification_case": _json_copy(report.get("verification_case") or {}),
        "scorecard": _json_copy(report.get("scorecard") or {}),
        "evidence_graph": _json_copy(report.get("evidence_graph") or {}),
        "evidence_ledger": _json_copy(report.get("evidence_ledger") or []),
        "role_conclusions": role_conclusions,
    }


def _normalized_role_conclusion(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, dict) or not value:
        return None
    keys = (
        "position",
        "verdict",
        "confidence",
        "summary",
        "reasoning_summary",
        "final_conclusion",
        "attack_chain",
        "data_flow",
        "protection_assessment",
        "impact_assessment",
        "key_evidence",
        "limitations",
        "disputed_points",
        "recommended_next_steps",
        "source_locations",
    )
    return {key: _json_copy(value.get(key)) for key in keys if key in value}


def _export_finding_status(
    run: Dict[str, Any], split: Dict[str, Any], report: Optional[Dict[str, Any]]
) -> str:
    if isinstance(report, dict):
        return finding_report_status(report)
    run_status = str(run.get("status") or "").strip().lower()
    if run_status not in {"queued", "starting", "running", "pausing", "stopping"}:
        return FINDING_PENDING
    finding_id = str(split.get("finding_id") or "")
    current_ids = run.get("current_finding_ids") if isinstance(run.get("current_finding_ids"), dict) else {}
    active_ids = {str(value or "") for value in current_ids.values()}
    active_ids.add(str(run.get("current_finding_id") or ""))
    return FINDING_IN_PROGRESS if finding_id and finding_id in active_ids else FINDING_PENDING


def _missing_detail_reason(status: str) -> str:
    if status == FINDING_IN_PROGRESS:
        return "adjudication_in_progress"
    if status == FINDING_COMPLETED:
        return "completed_report_missing"
    return "adjudication_not_started"


def _export_finding_ids(value: Any) -> Optional[List[str]]:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError("finding_ids must be an array of non-empty strings")
    result = []
    for item in value:
        finding_id = str(item).strip() if isinstance(item, str) else ""
        if not finding_id:
            raise ValueError("finding_ids must be an array of non-empty strings")
        if finding_id not in result:
            result.append(finding_id)
    return result


def _export_integer_argument(
    arguments: Dict[str, Any], key: str, *, default: int, minimum: int, maximum: Optional[int] = None
) -> int:
    value = arguments.get(key, default)
    if isinstance(value, bool):
        raise ValueError(f"{key} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be an integer") from exc
    if parsed < minimum or (maximum is not None and parsed > maximum):
        suffix = f" and at most {maximum}" if maximum is not None else ""
        raise ValueError(f"{key} must be at least {minimum}{suffix}")
    return parsed


def _safe_nonnegative_int(value: Any, default: int) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return max(0, default)


def _json_copy(value: Any) -> Any:
    if value is None:
        return None
    return json.loads(json.dumps(value, ensure_ascii=False))
