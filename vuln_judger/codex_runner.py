from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import pty
import queue
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import termios
import threading
import time
import uuid
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol, Sequence

from .agents import DEFAULT_AFFIRMATIVE_AGENT, DEFAULT_MODERATOR_AGENT, DEFAULT_NEGATIVE_AGENT
from .logging_config import logger
from .models import (
    DEFAULT_SILENCE_REMINDER_MINUTES,
    REPORT_FINDINGS_SCHEMA,
    AgentConfig,
    Finding,
    RunConfig,
    SourceLocation,
    run_config_snapshot,
    to_jsonable,
)
from .records import RunRecordStore
from .run_state import (
    FINDING_COMPLETED,
    FINDING_IN_PROGRESS,
    FINDING_PENDING,
    completed_finding_count,
    finding_report_completed,
    first_incomplete_finding_index,
)
from .sarif import parse_sarif, sarif_grouping_is_ambiguous, validate_sarif_report
from .source import SourceIndexer


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CODEX_WORKSPACES_DIR = REPO_ROOT / ".workspaces" / "runs"
CODEX_ENGINE = "codex"
OPENCODE_ENGINE = "opencode"
CLI_ENGINES = frozenset({CODEX_ENGINE, OPENCODE_ENGINE})
CODEX_ROLES = ("moderator", "affirmative", "negative")
CODEX_AGENT_FILE_NAMES = ("AGENTS.md", "AGENT.md")
LOCAL_SARIF_FINDINGS_ORIGIN = "local_sarif"
SILENCE_REMINDER_PROMPT = "上一个agent已完成输出，请确认并继续任务"
LOG = logger("codex_runner")
ROLE_LABELS = {
    "moderator": "Moderator",
    "affirmative": "正方",
    "negative": "反方",
}
VERDICTS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "INCONCLUSIVE"}
PIPELINE_ROLES = ("affirmative", "negative", "moderator")
PIPELINE_DOWNSTREAM_ROLES = ("moderator", "negative", "affirmative")
PIPELINE_ACTIVE_STATUSES = {"dispatching", "running"}
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
CODEX_ACTIVE_PROGRESS_RE = re.compile(
    r"\((?:(?:\d+h\s+)?(?:\d+m\s+)?)\d+s\s*[•·]\s*esc to interrupt\)",
    re.IGNORECASE,
)
CODEX_BACKGROUND_RUNNING_RE = re.compile(
    r"\b\d+\s+background terminals?\s+running\b",
    re.IGNORECASE,
)
CODEX_STARTUP_MARKERS = (
    "Starting MCP server",
    "Starting MCP servers",
)


class CodexRunnerError(RuntimeError):
    pass


class CodexRunnerStopped(RuntimeError):
    pass


class CliSession(Protocol):
    role: str

    def info(self) -> Any: ...

    def start(self) -> None: ...

    def is_live(self) -> bool: ...

    def stop(self) -> None: ...

    def send(self, text: str) -> None: ...

    def capture(self, lines: int = 240) -> str: ...

    def activity_snapshot(self) -> tuple[str, bool]: ...

    def failure_message(self) -> Optional[str]: ...

    def task_finished(self) -> bool: ...

    def accept_output(self) -> None: ...


@dataclass
class CodexSessionInfo:
    role: str
    session_name: str
    window_name: str
    target: str
    cwd: str
    backend: str = CODEX_ENGINE
    transport: str = "tmux-tui"
    event_log: Optional[str] = None


class CodexTmuxSession:
    def __init__(
        self,
        *,
        role: str,
        run_id: str,
        cwd: Path,
        source_path: Path,
        run_dir: Path,
        command: str,
    ) -> None:
        self.role = role
        self.run_id = run_id
        self.cwd = cwd.resolve()
        self.source_path = source_path.resolve()
        self.run_dir = run_dir.resolve()
        self.command = command
        self.session_name = _safe_tmux_name(f"vj-{run_id}-{role}")
        self.window_name = "codex"
        self.target = f"{self.session_name}:{self.window_name}"
        self._task_started = False

    def info(self) -> CodexSessionInfo:
        return CodexSessionInfo(
            role=self.role,
            session_name=self.session_name,
            window_name=self.window_name,
            target=self.target,
            cwd=str(self.cwd),
        )

    def start(self) -> None:
        if self.is_live():
            if _tmux_window_live(self.session_name, self.window_name):
                return
            _run_tmux(["tmux", "kill-session", "-t", self.session_name], timeout=10, check=False)
        yolo = _env_flag("VULN_JUDGER_CODEX_YOLO", default=True)
        LOG.info(
            "Codex session 启动",
            extra={
                "event": "codex.session.start",
                "run_id": self.run_id,
                "role": self.role,
                "session_name": self.session_name,
                "cwd": str(self.cwd),
                "source_path": str(self.source_path),
                "run_dir": str(self.run_dir),
                "yolo": yolo,
            },
        )
        args = [
            "tmux",
            "new-session",
            "-d",
            "-s",
            self.session_name,
            "-n",
            self.window_name,
            "-c",
            str(self.cwd),
            *self._codex_args(),
        ]
        _run_tmux(args, timeout=30)
        self._accept_trust_prompt()
        self._wait_until_input_ready()
        LOG.info(
            "Codex session ready",
            extra={
                "event": "codex.session.ready",
                "run_id": self.run_id,
                "role": self.role,
                "session_name": self.session_name,
            },
        )

    def is_live(self) -> bool:
        return _run_tmux(
            ["tmux", "has-session", "-t", self.session_name],
            timeout=5,
            check=False,
        ).returncode == 0

    def stop(self) -> None:
        if self.is_live():
            _run_tmux(["tmux", "kill-session", "-t", self.session_name], timeout=10)
            LOG.info(
                "Codex session stopped",
                extra={
                    "event": "codex.session.stop",
                    "run_id": self.run_id,
                    "role": self.role,
                    "session_name": self.session_name,
                },
            )

    def send(self, text: str) -> None:
        text = _normalize_cli_prompt(text)
        if not text:
            raise CodexRunnerError("Codex prompt 不能为空")
        started = not self.is_live()
        if started:
            self.start()
        else:
            self._restart_tui()
        baseline = self.capture(lines=120)
        self._task_started = False
        LOG.info(
            "Codex prompt 发送",
            extra={
                "event": "codex.prompt.send",
                "run_id": self.run_id,
                "role": self.role,
                "session_name": self.session_name,
                "text_chars": len(text),
                "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()[:16],
            },
        )
        buffer_name = _safe_tmux_name(f"{self.session_name}-input")
        _send_text_to_tmux_target(self.target, buffer_name, text)
        self._wait_until_task_started(baseline)

    def capture(self, lines: int = 240) -> str:
        if not _tmux_target_live(self.target):
            return ""
        result = _run_tmux(
            ["tmux", "capture-pane", "-p", "-S", f"-{max(1, min(lines, 2000))}", "-t", self.target],
            timeout=10,
            check=False,
        )
        return result.stdout or ""

    def activity_snapshot(self) -> tuple[str, bool]:
        capture = self.capture()
        return capture, _session_busy(capture)

    def failure_message(self) -> Optional[str]:
        if self._task_started and not _tmux_target_live(self.target):
            return f"Codex TUI 在任务执行期间退出：{self.target}"
        return None

    def task_finished(self) -> bool:
        if not self._task_started:
            return False
        capture = self.capture(lines=160)
        return bool(capture.strip() and not _session_busy(capture) and self._input_ready(capture))

    def accept_output(self) -> None:
        return None

    def _codex_args(self) -> List[str]:
        args = [
            self.command,
            "--cd",
            str(self.cwd),
            "--add-dir",
            str(REPO_ROOT),
            "--add-dir",
            str(self.source_path),
            "--add-dir",
            str(self.run_dir),
            "--no-alt-screen",
        ]
        if _env_flag("VULN_JUDGER_CODEX_YOLO", default=True):
            args.append("--dangerously-bypass-approvals-and-sandbox")
        else:
            args.extend(
                [
                    "--sandbox",
                    os.environ.get("VULN_JUDGER_CODEX_SANDBOX", "workspace-write"),
                    "--ask-for-approval",
                    os.environ.get("VULN_JUDGER_CODEX_APPROVAL", "never"),
                ]
            )
        return args

    def _restart_tui(self) -> None:
        if not _tmux_target_live(self.target):
            if self.is_live():
                _run_tmux(["tmux", "kill-session", "-t", self.session_name], timeout=10, check=False)
            self.start()
        _run_tmux(
            [
                "tmux",
                "respawn-pane",
                "-k",
                "-t",
                self.target,
                "-c",
                str(self.cwd),
                *self._codex_args(),
            ],
            timeout=30,
        )
        _run_tmux(["tmux", "clear-history", "-t", self.target], timeout=10, check=False)
        self._accept_trust_prompt()
        self._wait_until_input_ready()

    def _accept_trust_prompt(self) -> None:
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            text = self.capture(lines=80)
            if self._accept_trust_prompt_if_visible(text):
                return
            if text.strip():
                return
            time.sleep(0.25)

    def _wait_until_input_ready(self) -> None:
        deadline = time.monotonic() + float(os.environ.get("VULN_JUDGER_CODEX_READY_TIMEOUT", "120"))
        stable_samples = 0
        last_text = ""
        while time.monotonic() < deadline:
            text = self.capture(lines=120)
            last_text = text
            if self._accept_trust_prompt_if_visible(text):
                stable_samples = 0
                time.sleep(0.5)
                continue
            if self._input_ready(text):
                stable_samples += 1
                if stable_samples >= 3:
                    return
            else:
                stable_samples = 0
            time.sleep(0.5)
        startup = next((marker for marker in CODEX_STARTUP_MARKERS if marker in last_text), "none")
        raise CodexRunnerError(f"Codex session did not become input-ready: {self.target}; startup_marker={startup}")

    def _wait_until_task_started(self, baseline: str) -> None:
        deadline = time.monotonic() + float(os.environ.get("VULN_JUDGER_CODEX_TASK_START_TIMEOUT", "30"))
        last_text = baseline
        while time.monotonic() < deadline:
            text = self.capture(lines=160)
            last_text = text
            if _session_busy(text):
                self._task_started = True
                return
            if not _tmux_target_live(self.target):
                raise CodexRunnerError(f"Codex TUI 提交 prompt 后退出：{self.target}")
            time.sleep(0.1)
        raise CodexRunnerError(f"Codex TUI 未启动任务：{self.target}；{last_text[-1200:]}")

    def _input_ready(self, text: str) -> bool:
        return bool(
            text.strip()
            and not _session_busy(text)
            and not any(marker in text for marker in CODEX_STARTUP_MARKERS)
        )

    def _accept_trust_prompt_if_visible(self, text: str) -> bool:
        markers = (
            "allow codex to work in this folder",
            "do you trust the contents of this directory",
            "do you trust the files in this folder",
            "2. no, quit",
        )
        if any(marker in text.lower() for marker in markers):
            _run_tmux(["tmux", "send-keys", "-t", self.target, _codex_submit_key()], timeout=5)
            return True
        return False


@dataclass
class _PipelineFinding:
    index: int
    finding: Finding
    brief_path: Path
    result_paths: Dict[str, Path]
    data: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    stages: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    preserved_report: Optional[Dict[str, Any]] = None


@dataclass
class _ActivePipelineStage:
    role: str
    item: _PipelineFinding
    attempt_id: str
    future: Future[Dict[str, Any]]


class CliDrivenRunner:
    engine = CODEX_ENGINE
    cli_name = "Codex"
    session_description = "Codex TUI"

    def __init__(
        self,
        *,
        records_dir: Path,
        runs_dir: Path,
    ) -> None:
        self.records_dir = records_dir.expanduser().resolve()
        self.runs_dir = runs_dir.expanduser().resolve()

    def run(
        self,
        config: RunConfig,
        *,
        store: RunRecordStore,
        run_origin: str = "web",
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        self._configure(config)
        run_id = config.run_id or _new_run_id()
        source_path = config.source_path.expanduser().resolve()
        report_path = config.sarif_path.expanduser().resolve()
        run_dir = self.runs_dir / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        self._prepare_run_dir(run_dir)
        (run_dir / "input").mkdir(exist_ok=True)
        (run_dir / "findings").mkdir(exist_ok=True)

        source_indexer = SourceIndexer(source_path)
        languages = list(source_indexer.languages)
        created_at = config.created_at or _now()
        agent_configs = _codex_agent_configs(config)
        session_dirs = self._prepare_agent_dirs(run_dir, agent_configs, source_path)
        sessions = self._sessions(run_id, source_path, run_dir, session_dirs)
        payload = _base_payload(
            config,
            run_id,
            created_at,
            languages,
            run_dir,
            sessions,
            agent_configs,
            run_origin,
            engine=self.engine,
        )

        def emit(status: str, **updates: Any) -> None:
            payload.update(updates)
            _refresh_cli_session_payload(payload, sessions, self.engine)
            payload["status"] = status
            payload["updated_at"] = _now()
            store.save_payload(payload)
            if progress_callback is not None:
                progress_callback(dict(payload))

        def check_stop() -> None:
            if should_stop is not None and should_stop():
                raise CodexRunnerStopped(f"任务 {run_id} 已中断")

        def watchdog_event(event: Dict[str, Any]) -> None:
            workflow = dict(payload.get("cli_workflow") or payload.get("codex_workflow") or {})
            watchdog = dict(workflow.get("watchdog") or {})
            kind = str(event.get("kind") or "")
            if kind == "reminder":
                watchdog["reminder_count"] = int(watchdog.get("reminder_count") or 0) + 1
            watchdog["last_event"] = dict(event)
            workflow["watchdog"] = watchdog
            role = str(event.get("role") or "")
            role_label = ROLE_LABELS.get(role, role)
            diagnostic = f"{role_label} session 达到静默提醒时间，已发送继续任务提醒。"
            emit(
                "running",
                cli_workflow=workflow,
                diagnostics=[*payload.get("diagnostics", []), diagnostic],
            )

        emit(
            "running",
            diagnostics=[f"{self.cli_name}-driven session 元数据已创建，正在启动三方 {self.session_description}。"],
        )
        for session in sessions.values():
            check_stop()
            session.start()
            emit(
                "running",
                diagnostics=[
                    *payload.get("diagnostics", []),
                    f"{ROLE_LABELS.get(session.role, session.role)} {self.cli_name} session 已启动。",
                ],
            )
        emit("running", diagnostics=[f"{self.cli_name}-driven 任务已启动，正在准备漏洞报告。"])

        report_text, local_findings, parse_error, moderation_reason = _parse_report_locally(report_path)
        input_payload = _input_payload(
            config,
            report_path,
            source_path,
            run_dir,
            source_indexer,
            report_text=report_text,
            parsed_findings=local_findings,
            parse_error=parse_error,
            moderation_reason=moderation_reason,
        )
        (run_dir / "input" / "task.json").write_text(
            json.dumps(input_payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        check_stop()

        findings_path = run_dir / "findings.json"
        resume_findings = config.created_at is not None and findings_path.exists()
        copied_findings = bool(config.reused_findings_payload) and not resume_findings
        moderator_report_prompt = _moderator_report_prompt(input_payload, findings_path)

        def validate_report_findings(data: Dict[str, Any]) -> None:
            _validate_report_findings_output(data, report_path)

        if resume_findings:
            findings_data = _wait_json(
                findings_path,
                should_stop=should_stop,
                reminder_session=sessions["moderator"],
                stage_prompt=moderator_report_prompt,
                silence_reminder_seconds=config.silence_reminder_minutes * 60,
                watchdog_callback=watchdog_event,
                validator=validate_report_findings,
                complete_on_valid=self.engine == OPENCODE_ENGINE,
            )
        elif copied_findings:
            findings_data = _persist_findings_payload(findings_path, config.reused_findings_payload)
        elif moderation_reason is None:
            findings_data = _persist_local_sarif_findings(findings_path, local_findings)
        else:
            findings_path.unlink(missing_ok=True)
            sessions["moderator"].send(moderator_report_prompt)
            findings_data = _wait_json(
                findings_path,
                should_stop=should_stop,
                reminder_session=sessions["moderator"],
                stage_prompt=moderator_report_prompt,
                silence_reminder_seconds=config.silence_reminder_minutes * 60,
                watchdog_callback=watchdog_event,
                validator=validate_report_findings,
                complete_on_valid=self.engine == OPENCODE_ENGINE,
            )
        if moderation_reason == "markdown" and not copied_findings:
            findings_data = _finalize_markdown_findings(findings_path, findings_data, report_text)
        findings = _findings_from_persisted(findings_data, report_path)
        finding_briefs = _persist_finding_briefs(findings, source_indexer, run_dir)
        reports = _reconcile_finding_reports(findings, config.resume_reports)
        completed_count = completed_finding_count(reports)
        start_index = first_incomplete_finding_index(reports, len(findings))
        payload["finding_count"] = len(findings)
        payload["reports"] = reports
        payload.pop("report_findings", None)
        payload["completed_finding_count"] = completed_count
        payload["resume_from_finding_index"] = start_index
        payload["resume_from_finding_id"] = findings[start_index].finding_id if start_index < len(findings) else None
        payload["cli_workflow"]["findings_path"] = str(findings_path)
        preparation_origin = (
            "reused" if config.reuse_findings_from_run_id else str(findings_data.get("origin") or "moderator")
        )
        payload["cli_workflow"]["report_preparation_origin"] = preparation_origin
        if config.reuse_findings_from_run_id:
            payload["cli_workflow"]["reused_findings_from_run_id"] = config.reuse_findings_from_run_id
        if self.engine == CODEX_ENGINE:
            payload["codex_workflow"] = payload["cli_workflow"]
        if copied_findings:
            preparation_message = f"已复用任务 {config.reuse_findings_from_run_id} 的报告拆分结果"
        elif resume_findings and config.reuse_findings_from_run_id:
            preparation_message = f"复用磁盘中来自任务 {config.reuse_findings_from_run_id} 的报告拆分结果"
        elif preparation_origin == LOCAL_SARIF_FINDINGS_ORIGIN:
            preparation_message = "复用磁盘中的本地 SARIF 解析结果" if resume_findings else "已直接复用本地 SARIF 解析结果"
        else:
            split_action = "复用磁盘中的" if resume_findings else "已拆分并持久化"
            preparation_message = f"Moderator {split_action} finding"
        emit(
            "running",
            diagnostics=[
                *payload.get("diagnostics", []),
                f"{preparation_message}，共 {len(findings)} 个 finding；{completed_count} 个已完成，"
                f"{len(findings) - completed_count} 个未完成。",
            ],
        )
        reports = self._run_finding_pipeline(
            findings=findings,
            finding_briefs=finding_briefs,
            reports=reports,
            run_dir=run_dir,
            source_path=source_path,
            sessions=sessions,
            config=config,
            emit=emit,
            check_stop=check_stop,
            should_stop=should_stop,
            watchdog_event=watchdog_event,
            payload=payload,
        )

        payload["reports"] = reports
        payload["completed_finding_count"] = completed_finding_count(reports)
        payload["current_finding_id"] = None
        payload["current_finding_index"] = None
        payload["current_finding_ids"] = {}
        payload["resume_from_finding_id"] = None
        payload["resume_from_finding_index"] = len(findings)
        emit("completed")
        return payload

    def _run_finding_pipeline(
        self,
        *,
        findings: Sequence[Finding],
        finding_briefs: Dict[str, Path],
        reports: List[Dict[str, Any]],
        run_dir: Path,
        source_path: Path,
        sessions: Dict[str, CliSession],
        config: RunConfig,
        emit: Callable[..., None],
        check_stop: Callable[[], None],
        should_stop: Optional[Callable[[], bool]],
        watchdog_event: Callable[[Dict[str, Any]], None],
        payload: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        items = _initialize_pipeline_findings(
            findings,
            finding_briefs,
            run_dir,
            reports,
            resume=bool(config.created_at is not None or config.resume_reports),
        )
        ready: Dict[str, deque[int]] = {role: deque() for role in PIPELINE_ROLES}
        active: Dict[str, _ActivePipelineStage] = {}
        watchdog_events: queue.Queue[Dict[str, Any]] = queue.Queue()
        abort_event = threading.Event()

        for item in items:
            next_role = _next_pipeline_role(item)
            if next_role is not None:
                item.stages[next_role]["status"] = "ready"
                ready[next_role].append(item.index)

        def stopped() -> bool:
            return abort_event.is_set() or (should_stop is not None and should_stop())

        def persist() -> None:
            nonlocal reports
            for item in items:
                reports = _replace_finding_report(reports, item.index, _pipeline_report(item))
            current_ids = {
                role: active[role].item.finding.finding_id
                for role in PIPELINE_ROLES
                if role in active
            }
            current = next(
                (active[role].item for role in PIPELINE_DOWNSTREAM_ROLES if role in active),
                None,
            )
            resume_index = first_incomplete_finding_index(reports, len(findings))
            workflow = dict(payload.get("cli_workflow") or payload.get("codex_workflow") or {})
            workflow["pipeline"] = _pipeline_snapshot(items, ready, active)
            updates: Dict[str, Any] = {
                "reports": reports,
                "completed_finding_count": completed_finding_count(reports),
                "current_finding_ids": current_ids,
                "current_finding_id": current.finding.finding_id if current else None,
                "current_finding_index": current.index if current else None,
                "resume_from_finding_index": resume_index,
                "resume_from_finding_id": (
                    findings[resume_index].finding_id if resume_index < len(findings) else None
                ),
                "cli_workflow": workflow,
            }
            if self.engine == CODEX_ENGINE:
                updates["codex_workflow"] = workflow
            emit("running", **updates)

        def execute_stage(
            role: str,
            item: _PipelineFinding,
            prompt: str,
            attempt_id: str,
        ) -> Dict[str, Any]:
            session = sessions[role]
            previous_path = (
                item.brief_path
                if role == "affirmative"
                else item.result_paths["affirmative"]
                if role == "negative"
                else item.result_paths["negative"]
            )
            def validate(result: Dict[str, Any]) -> None:
                _validate_and_stamp_pipeline_output(
                    result,
                    output_path=item.result_paths[role],
                    finding_id=item.finding.finding_id,
                    role=role,
                    attempt_id=attempt_id,
                )

            result = _wait_json(
                item.result_paths[role],
                should_stop=stopped,
                reminder_session=session,
                previous_output_path=previous_path,
                stage_prompt=prompt,
                silence_reminder_seconds=config.silence_reminder_minutes * 60,
                watchdog_callback=watchdog_events.put,
                validator=validate,
                complete_on_valid=self.engine == OPENCODE_ENGINE,
            )
            return result

        def can_dispatch(role: str) -> bool:
            if role in active or not ready[role]:
                return False
            if role == "affirmative" and len(ready["negative"]) >= 1:
                return False
            if role == "negative" and len(ready["moderator"]) >= 1:
                return False
            return True

        executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix=f"vj-{self.engine}-pipeline")
        persist()
        try:
            while any(_next_pipeline_role(item) is not None for item in items):
                check_stop()
                changed = False

                while True:
                    try:
                        event = watchdog_events.get_nowait()
                    except queue.Empty:
                        break
                    watchdog_event(event)

                for role in PIPELINE_DOWNSTREAM_ROLES:
                    running = active.get(role)
                    if running is None or not running.future.done():
                        continue
                    item = running.item
                    try:
                        result = running.future.result()
                    except CodexRunnerStopped:
                        item.stages[role]["status"] = "interrupted"
                        item.stages[role]["completed_at"] = _now()
                        active.pop(role, None)
                        changed = True
                        raise
                    except Exception:
                        item.stages[role]["status"] = "failed"
                        item.stages[role]["completed_at"] = _now()
                        active.pop(role, None)
                        changed = True
                        raise
                    item.data[role] = result
                    item.stages[role]["status"] = "succeeded"
                    item.stages[role]["completed_at"] = _now()
                    active.pop(role, None)
                    next_role = _role_after(role)
                    if next_role is not None:
                        item.stages[next_role]["status"] = "ready"
                        ready[next_role].append(item.index)
                    changed = True

                for role in PIPELINE_DOWNSTREAM_ROLES:
                    if not can_dispatch(role):
                        continue
                    item = items[ready[role].popleft()]
                    _clear_pipeline_from(item, role)
                    attempt_id = uuid.uuid4().hex
                    stage = item.stages[role]
                    stage["status"] = "dispatching"
                    stage["attempt"] = int(stage.get("attempt") or 0) + 1
                    stage["attempt_id"] = attempt_id
                    stage["started_at"] = _now()
                    stage["completed_at"] = None
                    prompt = _pipeline_stage_prompt(
                        role=role,
                        item=item,
                        source_path=source_path,
                        attempt_id=attempt_id,
                    )
                    try:
                        sessions[role].send(prompt)
                    except Exception:
                        stage["status"] = "failed"
                        stage["completed_at"] = _now()
                        raise
                    stage["status"] = "running"
                    future = executor.submit(execute_stage, role, item, prompt, attempt_id)
                    active[role] = _ActivePipelineStage(role, item, attempt_id, future)
                    changed = True

                if changed:
                    persist()
                    continue
                if not active and any(ready[role] for role in PIPELINE_ROLES):
                    raise CodexRunnerError("三级流水线调度停滞，存在 ready stage 但没有可执行任务")
                time.sleep(0.1)
        except BaseException:
            abort_event.set()
            for running in active.values():
                running.future.cancel()
                stage = running.item.stages[running.role]
                if stage.get("status") in PIPELINE_ACTIVE_STATUSES:
                    stage["status"] = "interrupted"
                    stage["completed_at"] = _now()
            executor.shutdown(wait=True, cancel_futures=True)
            persist()
            raise
        else:
            executor.shutdown(wait=True)
            persist()
        return reports

    def _prepare_run_dir(self, run_dir: Path) -> None:
        raise NotImplementedError

    def _configure(self, config: RunConfig) -> None:
        return None

    def _prepare_agent_dirs(
        self,
        run_dir: Path,
        agent_configs: Dict[str, AgentConfig],
        source_path: Path,
    ) -> Dict[str, Path]:
        raise NotImplementedError

    def _sessions(
        self,
        run_id: str,
        source_path: Path,
        run_dir: Path,
        session_dirs: Dict[str, Path],
    ) -> Dict[str, CliSession]:
        raise NotImplementedError


class CodexDrivenRunner(CliDrivenRunner):
    def __init__(
        self,
        *,
        records_dir: Path,
        codex_runs_dir: Optional[Path] = None,
        codex_command: Optional[str] = None,
    ) -> None:
        runs_dir = (
            codex_runs_dir.expanduser().resolve()
            if codex_runs_dir is not None
            else Path(os.environ.get("VULN_JUDGER_CODEX_WORKSPACES_DIR", DEFAULT_CODEX_WORKSPACES_DIR)).expanduser().resolve()
        )
        super().__init__(records_dir=records_dir, runs_dir=runs_dir)
        self.codex_runs_dir = self.runs_dir
        self.codex_command = codex_command or os.environ.get("VULN_JUDGER_CODEX_COMMAND") or shutil.which("codex") or "codex"

    def _prepare_run_dir(self, run_dir: Path) -> None:
        _ensure_codex_project_trust(run_dir)

    def _prepare_agent_dirs(
        self,
        run_dir: Path,
        agent_configs: Dict[str, AgentConfig],
        source_path: Path,
    ) -> Dict[str, Path]:
        return _prepare_codex_agent_dirs(run_dir, agent_configs, source_path)

    def _sessions(
        self,
        run_id: str,
        source_path: Path,
        run_dir: Path,
        session_dirs: Dict[str, Path],
    ) -> Dict[str, CliSession]:
        return {
            role: CodexTmuxSession(
                role=role,
                run_id=run_id,
                cwd=session_dirs[role],
                source_path=source_path,
                run_dir=run_dir,
                command=self.codex_command,
            )
            for role in CODEX_ROLES
        }


def _codex_agent_configs(config: RunConfig) -> Dict[str, AgentConfig]:
    return {
        "moderator": config.moderator_agent or DEFAULT_MODERATOR_AGENT,
        "affirmative": config.affirmative_agent or DEFAULT_AFFIRMATIVE_AGENT,
        "negative": config.negative_agent or DEFAULT_NEGATIVE_AGENT,
    }


def _prepare_codex_agent_dirs(
    run_dir: Path,
    agent_configs: Dict[str, AgentConfig],
    source_path: Path,
) -> Dict[str, Path]:
    session_dirs: Dict[str, Path] = {}
    for role in CODEX_ROLES:
        role_dir = run_dir / "sessions" / role
        role_dir.mkdir(parents=True, exist_ok=True)
        _ensure_codex_project_trust(role_dir)
        agent_text = _codex_agent_file_text(
            role=role,
            agent=agent_configs[role],
            source_path=source_path,
            run_dir=run_dir,
        )
        for file_name in CODEX_AGENT_FILE_NAMES:
            (role_dir / file_name).write_text(agent_text + "\n", encoding="utf-8")
        LOG.info(
            "Codex Agent 文件写入",
            extra={
                "event": "codex.agent_file.write",
                "role": role,
                "agent_profile": agent_configs[role].profile_id or agent_configs[role].name,
                "session_dir": str(role_dir),
                "files": list(CODEX_AGENT_FILE_NAMES),
            },
        )
        session_dirs[role] = role_dir
    return session_dirs


def _codex_agent_file_text(*, role: str, agent: AgentConfig, source_path: Path, run_dir: Path) -> str:
    return _cli_agent_file_text(
        role=role,
        agent=agent,
        source_path=source_path,
        run_dir=run_dir,
        cli_name="Codex",
    )


def _cli_agent_file_text(
    *,
    role: str,
    agent: AgentConfig,
    source_path: Path,
    run_dir: Path,
    cli_name: str,
) -> str:
    role_label = ROLE_LABELS.get(role, role)
    profile = agent.profile_id or agent.name or role_label
    instructions = (agent.instructions or "").strip() or "围绕当前阶段任务进行可复核的漏洞报告复核。"
    return (
        f"# vuln-judger {cli_name} Agent\n\n"
        f"- 角色：{role_label}\n"
        f"- Agent 配置档案：{profile}\n"
        f"- 源码根目录：{source_path}\n"
        f"- 共享任务工作目录：{run_dir}\n\n"
        "## 会话约束\n\n"
        f"- 这份 AGENTS.md 是本 {cli_name} session 的持续行为约束；后续每轮 prompt 只描述当前阶段、输入文件和输出 schema。\n"
        f"- 模型、MCP、skills 和 provider 都由 {cli_name} 当前默认配置加载；不要要求 vuln-judger 在 prompt 中动态提供这些配置。\n"
        "- 如 Atlas MCP 可用，开始代码图谱检索前先确认或打开源码根目录，不要把本 session 工作目录误当成待审源码。\n"
        "- 只写入当前 prompt 指定的 JSON 输出文件，以及共享任务工作目录中的必要临时文件。\n"
        "- 结论必须基于报告、源码、Atlas、rg/grep 或可复核工具输出；区分已证实证据、候选证据和未闭环缺口。\n\n"
        "## 角色配置\n\n"
        f"{instructions}\n"
    ).strip()


def capture_session(session_name: str, lines: int = 240) -> str:
    if not _safe_tmux_ref(session_name):
        raise CodexRunnerError("invalid session name")
    result = _run_tmux(
        ["tmux", "capture-pane", "-p", "-S", f"-{max(1, min(lines, 2000))}", "-t", session_name],
        check=False,
    )
    return result.stdout or ""


def send_session_input(session_name: str, text: str) -> None:
    if not _safe_tmux_ref(session_name):
        raise CodexRunnerError("invalid session name")
    if not text or len(text) > 20000:
        raise CodexRunnerError("input must contain 1-20000 characters")
    buffer_name = _safe_tmux_name(f"{session_name}-web-input")
    _send_text_to_tmux_target(session_name, buffer_name, text)


def _send_text_to_tmux_target(target: str, buffer_name: str, text: str) -> None:
    normalized = str(text).replace("\r\n", "\n").replace("\r", "\n")
    load = subprocess.run(
        ["tmux", "load-buffer", "-b", buffer_name, "-"],
        input=normalized,
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if load.returncode != 0:
        raise CodexRunnerError((load.stderr or load.stdout or "tmux load-buffer failed").strip())
    # Bracketed paste with LF preservation avoids WSL/Codex treating prompt newlines as submit keys.
    paste = _run_tmux(["tmux", "paste-buffer", "-d", "-p", "-r", "-b", buffer_name, "-t", target], timeout=10, check=False)
    if paste.returncode != 0:
        fallback = _run_tmux(["tmux", "paste-buffer", "-d", "-b", buffer_name, "-t", target], timeout=10, check=False)
        if fallback.returncode != 0:
            raise CodexRunnerError((fallback.stderr or paste.stderr or fallback.stdout or paste.stdout or "tmux paste-buffer failed").strip())
    time.sleep(float(os.environ.get("VULN_JUDGER_CODEX_PASTE_SETTLE", "0.75")))
    _run_tmux(["tmux", "send-keys", "-t", target, _codex_submit_key()], timeout=10)


def _codex_submit_key() -> str:
    return os.environ.get("VULN_JUDGER_CODEX_SUBMIT_KEY", "C-m")


def session_live(session_name: str) -> bool:
    if not _safe_tmux_ref(session_name):
        return False
    # `has-session -t session:window` only validates the session portion. On WSL
    # this made a missing OpenCode `:tui` window look alive, after which the Web
    # terminal attached to whichever window happened to be current (often server).
    return (
        _run_tmux(
            ["tmux", "list-panes", "-t", session_name],
            timeout=5,
            check=False,
        ).returncode
        == 0
    )


def stop_sessions(payload: Dict[str, Any]) -> None:
    for session in _payload_sessions(payload):
        name = str(session.get("session_name") or "")
        if _safe_tmux_ref(name) and session_live(name):
            _run_tmux(["tmux", "kill-session", "-t", name], check=False)


def _payload_sessions(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    sessions = payload.get("cli_sessions")
    if not isinstance(sessions, list):
        sessions = payload.get("codex_sessions")
    if isinstance(sessions, list):
        return [item for item in sessions if isinstance(item, dict)]
    workflow = payload.get("cli_workflow") if isinstance(payload.get("cli_workflow"), dict) else {}
    if not workflow and isinstance(payload.get("codex_workflow"), dict):
        workflow = payload["codex_workflow"]
    sessions = workflow.get("sessions")
    if isinstance(sessions, list):
        return [item for item in sessions if isinstance(item, dict)]
    return []


def attach_session_websocket(handler: Any, session_name: str, *, read_only: bool = False) -> None:
    if not _safe_tmux_ref(session_name):
        handler.send_error(404, "invalid Codex session")
        return
    if not session_live(session_name):
        handler.send_error(404, "Codex session is not running")
        return
    if not _websocket_accept(handler):
        return
    _bridge_tmux_websocket(handler.connection, session_name, read_only=read_only)


def _websocket_accept(handler: Any) -> bool:
    key = handler.headers.get("Sec-WebSocket-Key")
    upgrade = handler.headers.get("Upgrade", "").lower()
    connection = handler.headers.get("Connection", "").lower()
    if not key or upgrade != "websocket" or "upgrade" not in connection:
        handler.send_error(400, "invalid websocket handshake")
        return False
    accept = base64.b64encode(hashlib.sha1((key + WEBSOCKET_GUID).encode("ascii")).digest()).decode("ascii")
    handler.send_response(101)
    handler.send_header("Upgrade", "websocket")
    handler.send_header("Connection", "Upgrade")
    handler.send_header("Sec-WebSocket-Accept", accept)
    handler.end_headers()
    handler.close_connection = True
    return True


def _ws_send_frame(sock: socket.socket, payload: bytes, opcode: int = 2) -> None:
    payload = bytes(payload)
    header = bytearray([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header.append(length)
    elif length < 65536:
        header.extend([126, (length >> 8) & 0xFF, length & 0xFF])
    else:
        header.append(127)
        header.extend(length.to_bytes(8, "big"))
    sock.sendall(bytes(header) + payload)


def _ws_recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("websocket closed")
        data.extend(chunk)
    return bytes(data)


def _ws_recv_frame(sock: socket.socket) -> tuple[int, bytes]:
    header = _ws_recv_exact(sock, 2)
    opcode = header[0] & 0x0F
    length = header[1] & 0x7F
    masked = bool(header[1] & 0x80)
    if length == 126:
        length = int.from_bytes(_ws_recv_exact(sock, 2), "big")
    elif length == 127:
        length = int.from_bytes(_ws_recv_exact(sock, 8), "big")
    mask = _ws_recv_exact(sock, 4) if masked else b""
    payload = bytearray(_ws_recv_exact(sock, length)) if length else bytearray()
    if masked:
        for index, value in enumerate(payload):
            payload[index] = value ^ mask[index % 4]
    return opcode, bytes(payload)


def _set_terminal_size(fd: int, rows: int, cols: int) -> None:
    rows = min(max(int(rows), 1), 200)
    cols = min(max(int(cols), 2), 500)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def _pty_env() -> dict[str, str]:
    env = os.environ.copy()
    if env.get("TERM", "dumb") == "dumb":
        env["TERM"] = "xterm-256color"
    return env


def _bridge_tmux_websocket(sock: socket.socket, session_name: str, *, read_only: bool = False) -> None:
    master_fd, slave_fd = pty.openpty()
    proc: Optional[subprocess.Popen[bytes]] = None
    try:
        _set_terminal_size(slave_fd, 24, 80)
        proc = subprocess.Popen(
            ["tmux", "-u", "attach-session", "-t", session_name],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            preexec_fn=os.setsid,
            env=_pty_env(),
        )
        os.close(slave_fd)
        slave_fd = -1
        flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        while True:
            readable, _, _ = select.select([sock, master_fd], [], [], 0.25)
            if master_fd in readable:
                try:
                    data = os.read(master_fd, 65536)
                except BlockingIOError:
                    data = b""
                if data:
                    _ws_send_frame(sock, data, opcode=2)
                elif proc.poll() is not None:
                    break
            if sock in readable:
                opcode, payload = _ws_recv_frame(sock)
                if opcode == 8:
                    break
                if opcode == 9:
                    _ws_send_frame(sock, payload, opcode=10)
                    continue
                if opcode != 1:
                    continue
                message = json.loads(payload.decode("utf-8"))
                if message.get("type") == "input" and not read_only:
                    raw = str(message.get("data", "")).encode("utf-8")
                    for offset in range(0, len(raw), 1024):
                        os.write(master_fd, raw[offset : offset + 1024])
                elif message.get("type") == "resize":
                    _set_terminal_size(master_fd, int(message.get("rows", 24)), int(message.get("cols", 80)))
                    if proc.poll() is None:
                        os.kill(proc.pid, signal.SIGWINCH)
            if proc.poll() is not None:
                break
    except (ConnectionError, OSError, json.JSONDecodeError, ValueError):
        pass
    finally:
        try:
            _ws_send_frame(sock, b"", opcode=8)
        except OSError:
            pass
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        if slave_fd >= 0:
            try:
                os.close(slave_fd)
            except OSError:
                pass
        try:
            os.close(master_fd)
        except OSError:
            pass


def _run_tmux(args: Sequence[str], timeout: int = 10, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise CodexRunnerError("tmux is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise CodexRunnerError(f"tmux command timed out: {' '.join(args)}") from exc
    if check and result.returncode != 0:
        raise CodexRunnerError((result.stderr or result.stdout or f"tmux failed: {' '.join(args)}").strip())
    return result


def _tmux_window_live(session_name: str, window_name: str) -> bool:
    result = _run_tmux(
        ["tmux", "list-windows", "-t", session_name, "-F", "#{window_name}"],
        timeout=5,
        check=False,
    )
    return result.returncode == 0 and window_name in (result.stdout or "").splitlines()


def _tmux_target_live(target: str) -> bool:
    return _run_tmux(
        ["tmux", "list-panes", "-t", target],
        timeout=5,
        check=False,
    ).returncode == 0


def _wait_for_cli_task_start(
    *,
    label: str,
    started_path: Path,
    event_path: Path,
    exit_path: Path,
    is_running: Callable[[], bool],
) -> None:
    """Wait until the detached tmux shell proves it actually started."""

    try:
        timeout = float(os.environ.get("VULN_JUDGER_CLI_START_TIMEOUT", "5"))
    except ValueError:
        timeout = 5.0
    deadline = time.monotonic() + max(timeout, 0.1)
    running = False
    while time.monotonic() < deadline:
        if started_path.exists() or exit_path.exists():
            return
        try:
            if event_path.exists() and event_path.stat().st_size > 0:
                return
        except OSError:
            pass
        running = is_running()
        time.sleep(0.05)
    state = "run 窗口仍存在" if running or is_running() else "run 窗口已退出"
    raise CodexRunnerError(f"{label} 任务未确认启动（{state}）：{started_path}")


def _env_flag(name: str, *, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off", ""}


def _ensure_codex_project_trust(path: Path, config_path: Optional[Path] = None) -> None:
    trusted_path = str(path.expanduser().resolve())
    codex_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")).expanduser()
    target = (config_path or codex_home / "config.toml").expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    text = target.read_text(encoding="utf-8") if target.exists() else ""
    header = f"[projects.{json.dumps(trusted_path)}]"
    block_re = re.compile(rf"({re.escape(header)}\n)(.*?)(?=\n\[|\Z)", re.DOTALL)
    match = block_re.search(text)
    if match is None:
        separator = "\n\n" if text.strip() else ""
        text = f"{text.rstrip()}{separator}{header}\ntrust_level = \"trusted\"\n"
    else:
        body = match.group(2)
        if re.search(r"(?m)^trust_level\s*=", body):
            body = re.sub(r'(?m)^trust_level\s*=.*$', 'trust_level = "trusted"', body)
        else:
            body = f"{body.rstrip()}\ntrust_level = \"trusted\"\n"
        text = f"{text[:match.start(2)]}{body}{text[match.end(2):]}"
    target.write_text(text, encoding="utf-8")


def _wait_json(
    path: Path,
    *,
    should_stop: Optional[Callable[[], bool]],
    timeout_seconds: Optional[float] = None,
    reminder_session: Optional[CliSession] = None,
    previous_output_path: Optional[Path] = None,
    stage_prompt: Optional[str] = None,
    silence_reminder_seconds: Optional[float] = None,
    watchdog_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    validator: Optional[Callable[[Dict[str, Any]], None]] = None,
    complete_on_valid: bool = False,
    poll_interval_seconds: float = 1.0,
    activity_poll_seconds: float = 30.0,
) -> Dict[str, Any]:
    timeout = _step_timeout_seconds(timeout_seconds)
    silence_interval = max(
        float(
            silence_reminder_seconds
            if silence_reminder_seconds is not None
            else DEFAULT_SILENCE_REMINDER_MINUTES * 60
        ),
        0.0,
    )
    LOG.info(
        "等待 Codex JSON 输出",
        extra={
            "event": "codex.output.wait",
            "output_path": str(path),
            "timeout_seconds": timeout,
            "silence_reminder_seconds": silence_interval,
            "role": reminder_session.role if reminder_session is not None else None,
        },
    )
    now = time.monotonic()
    deadline = now + timeout if timeout is not None else None
    silence_deadline = now + silence_interval if silence_interval > 0 else None
    next_activity_check = now
    last_capture: Optional[str] = None
    last_error = ""
    while True:
        if should_stop is not None and should_stop():
            raise CodexRunnerStopped("Codex-driven task stopped")
        data, last_error = _read_json_object(path)
        if data is not None and validator is not None:
            try:
                validator(data)
            except (CodexRunnerError, TypeError, ValueError) as exc:
                data = None
                last_error = str(exc)
        task_finished = _cli_task_finished(reminder_session)
        if data is not None and (complete_on_valid or task_finished is not False):
            if complete_on_valid:
                _accept_cli_output(reminder_session)
            LOG.info(
                "Codex JSON 输出就绪",
                extra={"event": "codex.output.ready", "output_path": str(path)},
            )
            return data

        if reminder_session is not None:
            failure_method = getattr(reminder_session, "failure_message", None)
            failure = failure_method() if callable(failure_method) else None
            if failure:
                raise CodexRunnerError(f"CLI session 执行失败：{failure}")
            task_finished = _cli_task_finished(reminder_session)
            if data is None and task_finished is True:
                raise CodexRunnerError(
                    f"CLI session 已结束但未生成合法 JSON：{path}；最后错误：{last_error}"
                )

        now = time.monotonic()
        if deadline is not None and now >= deadline:
            LOG.warning(
                "等待 Codex JSON 输出超时",
                extra={
                    "event": "codex.output.timeout",
                    "output_path": str(path),
                    "timeout_seconds": timeout,
                    "last_error": last_error,
                },
            )
            raise CodexRunnerError(f"等待 Codex 输出超时：{path}；最后错误：{last_error}")

        if reminder_session is not None and silence_deadline is not None:
            if now >= next_activity_check:
                activity, busy = _cli_activity_snapshot(reminder_session) if reminder_session.is_live() else ("", False)
                if last_capture is not None and (activity != last_capture or busy):
                    silence_deadline = now + silence_interval
                last_capture = activity
                next_activity_check = now + max(float(activity_poll_seconds), 0.01)

            if now >= silence_deadline:
                data, last_error = _read_json_object(path)
                if data is not None and validator is not None:
                    try:
                        validator(data)
                    except (CodexRunnerError, TypeError, ValueError) as exc:
                        data = None
                        last_error = str(exc)
                if data is not None and (complete_on_valid or _cli_task_finished(reminder_session) is not False):
                    if complete_on_valid:
                        _accept_cli_output(reminder_session)
                    LOG.info(
                        "Codex JSON 输出就绪",
                        extra={"event": "codex.output.ready", "output_path": str(path)},
                    )
                    return data
                _handle_silence_deadline(
                    path=path,
                    session=reminder_session,
                    previous_output_path=previous_output_path,
                    stage_prompt=stage_prompt,
                    watchdog_callback=watchdog_callback,
                )
                now = time.monotonic()
                silence_deadline = now + silence_interval
                next_activity_check = now + max(float(activity_poll_seconds), 0.01)
                last_capture = _cli_activity_snapshot(reminder_session)[0] if reminder_session.is_live() else ""

        time.sleep(max(float(poll_interval_seconds), 0.01))


def _cli_task_finished(session: Optional[CliSession]) -> Optional[bool]:
    if session is None:
        return None
    method = getattr(session, "task_finished", None)
    if not callable(method):
        return None
    return bool(method())


def _accept_cli_output(session: Optional[CliSession]) -> None:
    if session is None:
        return
    method = getattr(session, "accept_output", None)
    if callable(method):
        method()


def _handle_silence_deadline(
    *,
    path: Path,
    session: CliSession,
    previous_output_path: Optional[Path],
    stage_prompt: Optional[str],
    watchdog_callback: Optional[Callable[[Dict[str, Any]], None]],
) -> None:
    current_data, _ = _read_json_object(path)
    if current_data is not None:
        return
    event: Optional[Dict[str, Any]] = None
    try:
        if session.is_live():
            previous_data, _ = _read_json_object(previous_output_path)
            _, busy = _cli_activity_snapshot(session)
            current_data, _ = _read_json_object(path)
            if current_data is None and previous_data is not None and not busy:
                session.send(SILENCE_REMINDER_PROMPT)
                event = {
                    "kind": "reminder",
                    "role": session.role,
                    "output_path": str(path),
                    "previous_output_path": str(previous_output_path),
                    "at": _now(),
                }
    except (CodexRunnerError, OSError, subprocess.SubprocessError) as exc:
        LOG.warning(
            "Codex 静默看门狗发送失败",
            extra={
                "event": "codex.silence_watchdog.send_failed",
                "role": session.role,
                "output_path": str(path),
                "error": str(exc),
            },
        )
        return

    if event is None:
        LOG.info(
            "Codex 静默计时器已重置",
            extra={
                "event": "codex.silence_watchdog.reset",
                "role": session.role,
                "output_path": str(path),
            },
        )
        return
    LOG.info(
        "Codex 静默看门狗已处理",
        extra={
            "event": f"codex.silence_watchdog.{event['kind']}",
            "role": session.role,
            "output_path": str(path),
        },
    )
    if watchdog_callback is not None:
        watchdog_callback(event)


def _session_busy(text: str) -> bool:
    return bool(CODEX_ACTIVE_PROGRESS_RE.search(text) or CODEX_BACKGROUND_RUNNING_RE.search(text))


def _cli_activity_snapshot(session: CliSession) -> tuple[str, bool]:
    snapshot = getattr(session, "activity_snapshot", None)
    if callable(snapshot):
        return snapshot()
    capture = session.capture()
    return capture, _session_busy(capture)


def _read_json_object(path: Optional[Path]) -> tuple[Optional[Dict[str, Any]], str]:
    if path is None:
        return None, "未提供输出文件路径"
    if not path.exists():
        return None, "文件不存在"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return None, str(exc)
    if not isinstance(data, dict):
        return None, "JSON root is not an object"
    return data, ""


def _step_timeout_seconds(explicit: Optional[float]) -> Optional[float]:
    value: Any = explicit
    if value is None:
        value = os.environ.get("VULN_JUDGER_CLI_STEP_TIMEOUT") or os.environ.get("VULN_JUDGER_CODEX_STEP_TIMEOUT")
    if value in (None, ""):
        return None
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        return None
    return timeout if timeout > 0 else None


def _parse_report_locally(report_path: Path) -> tuple[str, List[Finding], str, Optional[str]]:
    report_text = report_path.read_text(encoding="utf-8", errors="replace")
    if report_path.suffix.lower() in {".md", ".markdown"}:
        return report_text, [], "", "markdown"
    try:
        data = json.loads(report_text)
    except json.JSONDecodeError as exc:
        return report_text, [], str(exc), "parse_failed"
    issues = validate_sarif_report(data)
    if issues:
        return report_text, [], "；".join(issues), "parse_failed"
    findings = parse_sarif(data)
    if sarif_grouping_is_ambiguous(data, findings):
        return report_text, findings, "", "grouping_ambiguous"
    return report_text, findings, "", None


def _input_payload(
    config: RunConfig,
    report_path: Path,
    source_path: Path,
    run_dir: Path,
    source_indexer: SourceIndexer,
    *,
    report_text: str,
    parsed_findings: Sequence[Finding],
    parse_error: str,
    moderation_reason: Optional[str],
) -> Dict[str, Any]:
    return {
        "run_id": config.run_id,
        "report_path": str(report_path),
        "source_path": str(source_path),
        "skills_path": str(config.skills_path) if config.skills_path else None,
        "run_dir": str(run_dir),
        "max_rounds": config.max_rounds,
        "parsed_findings": [_finding_to_prompt_payload(item, source_indexer) for item in parsed_findings],
        "parse_error": parse_error,
        "moderation_reason": moderation_reason,
        "report_excerpt": report_text[:60000],
        "report_truncated": len(report_text) > 60000,
    }


def _moderator_report_prompt(input_payload: Dict[str, Any], findings_path: Path) -> str:
    return (
        "当前阶段：报告拆分。请遵循本 session 初始 AGENTS.md 中的 Moderator 角色约束；本阶段只处理输入漏洞报告，不做最终真假裁决。\n"
        "请完整理解报告，将其拆分为独立 finding。SARIF 已解析结果如果存在，可以作为候选；Markdown/raw 报告需要你自行拆分。\n"
        "输出必须写入下面 JSON 文件，不能只在终端回答：\n"
        f"{findings_path}\n\n"
        "JSON schema：\n"
        "{\n"
        "  \"findings\": [\n"
        "    {\n"
        "      \"finding_id\": \"稳定且简短的 id\",\n"
        "      \"rule_id\": \"规则或漏洞类型\",\n"
        "      \"message\": \"报告原始描述摘要\",\n"
        "      \"level\": \"error|warning|note|unknown\",\n"
        "      \"locations\": [{\"file\":\"相对或报告路径\",\"line\":1,\"column\":1,\"symbol\":\"可选\"}],\n"
        "      \"code_flows\": [[{\"file\":\"...\",\"line\":1}]],\n"
        "      \"report_markdown\": \"该 finding 对应的报告原文片段；单 finding 时可留空\"\n"
        "    }\n"
        "  ]\n"
        "}\n\n"
        "约束：不要新增报告没有支持的事实。若报告只有一个 finding，report_markdown 可留空，调度器会从源文件精确补齐；"
        "不要手工复制整份报告，也不要对 report_markdown 与源文件做逐字节相等校验。多 finding 时仅保留各自对应的原文片段。\n"
        "输入任务 JSON：\n"
        "```json\n"
        + json.dumps(input_payload, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n```\n"
        "完成后只需确认已写入文件。"
    )


def _worker_prompt(
    *,
    role: str,
    finding: Finding,
    source_path: Path,
    brief_path: Path,
    result_path: Path,
    peer_result_path: Optional[Path],
    round_index: int,
    attempt_id: str,
) -> str:
    is_affirmative = role == "affirmative"
    peer = f"\n上一阶段正方结果文件：{peer_result_path}\n反方可以读取它进行质疑，但必须先独立复核源码证据。" if peer_result_path else ""
    return (
        f"当前阶段：第 {round_index} 个 finding 的{'正方验证' if is_affirmative else '反方复核'}。请遵循本 session 初始 AGENTS.md 中的 {ROLE_LABELS[role]} 角色约束。\n"
        f"源码根目录：{source_path}\n"
        f"finding brief：{brief_path}\n"
        f"{peer}\n"
        "请围绕报告文件、行号、符号和调用邻域使用本 Codex 会话可用工具补证；Atlas MCP 如可用，先确认目标源码根目录后再检索。\n"
        "输出必须写入 JSON 文件，不能只在终端回答：\n"
        f"{result_path}\n\n"
        "JSON schema：\n"
        "{\n"
        f"  \"role\": \"{role}\",\n"
        f"  \"finding_id\": \"{finding.finding_id}\",\n"
        f"  \"attempt_id\": \"{attempt_id}\",\n"
        "  \"position\": \"TRUE_POSITIVE|FALSE_POSITIVE|INCONCLUSIVE\",\n"
        "  \"confidence\": 0.0,\n"
        "  \"summary\": \"结论性材料，给 Web 默认展示\",\n"
        "  \"key_evidence\": [{\"claim\":\"...\",\"evidence\":\"...\",\"location\":\"file:line\",\"tool\":\"atlas|rg|source|report\"}],\n"
        "  \"source_locations\": [{\"file\":\"...\",\"line\":1,\"column\":1,\"symbol\":\"可选\"}],\n"
        "  \"attack_chain\": \"入口到汇点路径，若不存在说明缺口\",\n"
        "  \"data_flow\": \"源到汇数据流，若不存在说明缺口\",\n"
        "  \"limitations\": [\"仍未闭环的限制\"],\n"
        "  \"recommended_next_steps\": [\"建议补证或修复动作\"]\n"
        "}\n\n"
        "结果必须是合法 JSON object。完成后只需确认已写入文件。"
    )


def _moderator_final_prompt(
    *,
    finding: Finding,
    source_path: Path,
    brief_path: Path,
    affirmative_result: Path,
    negative_result: Path,
    final_path: Path,
    attempt_id: str,
) -> str:
    return (
        "当前阶段：最终裁决。请遵循本 session 初始 AGENTS.md 中的 Moderator 角色约束，基于正方和反方已保存的结果做最终裁决。\n"
        f"源码根目录：{source_path}\n"
        f"finding brief：{brief_path}\n"
        f"正方结果：{affirmative_result}\n"
        f"反方结果：{negative_result}\n"
        "你必须读取两个 JSON，检查双方是否引用真实源码/Atlas/rg/报告证据，识别证据跳跃和未闭环点。\n"
        "最终输出必须写入 JSON 文件，不能只在终端回答：\n"
        f"{final_path}\n\n"
        "JSON schema：\n"
        "{\n"
        "  \"role\": \"moderator\",\n"
        f"  \"finding_id\": \"{finding.finding_id}\",\n"
        f"  \"attempt_id\": \"{attempt_id}\",\n"
        "  \"verdict\": \"TRUE_POSITIVE|FALSE_POSITIVE|INCONCLUSIVE\",\n"
        "  \"confidence\": 0.0,\n"
        "  \"reasoning_summary\": \"Web 默认展示的最终摘要\",\n"
        "  \"final_conclusion\": \"包含结论标签、关键证据、双方分歧、未闭环点的中文 Markdown\",\n"
        "  \"disputed_points\": [\"...\"],\n"
        "  \"protection_assessment\": \"防护/消减判断\",\n"
        "  \"impact_assessment\": \"影响判断\",\n"
        "  \"source_locations\": [{\"file\":\"...\",\"line\":1,\"column\":1,\"symbol\":\"可选\"}],\n"
        "  \"recommended_next_steps\": [\"...\"]\n"
        "}\n\n"
        "只依据已有结果和可复核源码证据裁决，不新增没有证据支持的漏洞事实。"
    )


def _persist_local_sarif_findings(path: Path, findings: Sequence[Finding]) -> Dict[str, Any]:
    data = {
        "origin": LOCAL_SARIF_FINDINGS_ORIGIN,
        "findings": [to_jsonable(finding) for finding in findings],
    }
    return _persist_findings_payload(path, data)


def _persist_findings_payload(path: Path, data: Dict[str, Any]) -> Dict[str, Any]:
    persisted = json.loads(json.dumps(data, ensure_ascii=False))
    temporary_path = path.with_name(f".{path.name}.tmp")
    temporary_path.write_text(
        json.dumps(persisted, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary_path, path)
    return persisted


def _finalize_markdown_findings(path: Path, data: Dict[str, Any], report_text: str) -> Dict[str, Any]:
    raw_findings = data.get("findings")
    if not isinstance(raw_findings, list) or len(raw_findings) != 1 or not isinstance(raw_findings[0], dict):
        return data
    finalized = dict(data)
    finding = dict(raw_findings[0])
    finding["report_markdown"] = report_text
    finalized["findings"] = [finding]
    return _persist_findings_payload(path, finalized)


def _normalized_findings_payload(
    findings: Sequence[Finding],
    *,
    origin: str,
    reused_from_run_id: Optional[str] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "schema": REPORT_FINDINGS_SCHEMA,
        "origin": origin or "unknown",
        "finding_count": len(findings),
        "findings": [to_jsonable(finding) for finding in findings],
    }
    if reused_from_run_id:
        payload["reused_from_run_id"] = reused_from_run_id
    return payload


def _findings_from_persisted(data: Dict[str, Any], report_path: Path) -> List[Finding]:
    if data.get("origin") != LOCAL_SARIF_FINDINGS_ORIGIN and data.get("schema") != REPORT_FINDINGS_SCHEMA:
        return _findings_from_moderator(data, report_path)
    raw = data.get("findings")
    if not isinstance(raw, list) or not raw:
        raise CodexRunnerError("本地 SARIF findings.json 缺少 findings 数组")
    findings = [_finding_from_local_payload(item) for item in raw if isinstance(item, dict)]
    if not findings:
        raise CodexRunnerError("本地 SARIF findings.json 未包含有效 finding")
    return findings


def _validate_report_findings_output(data: Dict[str, Any], report_path: Path) -> None:
    """Require a complete, reusable report-split artifact before advancing the pipeline."""

    findings = _findings_from_persisted(data, report_path)
    seen_ids: set[str] = set()
    duplicate_ids: set[str] = set()
    for finding in findings:
        if finding.finding_id in seen_ids:
            duplicate_ids.add(finding.finding_id)
        seen_ids.add(finding.finding_id)
    if duplicate_ids:
        raise CodexRunnerError(f"Moderator findings.json 包含重复 finding_id：{', '.join(sorted(duplicate_ids))}")


def _finding_from_local_payload(item: Dict[str, Any]) -> Finding:
    return Finding(
        finding_id=str(item.get("finding_id") or "finding"),
        rule_id=str(item.get("rule_id") or "unknown-rule"),
        message=str(item.get("message") or ""),
        level=str(item.get("level") or "unknown"),
        locations=[_location_from_dict(location) for location in item.get("locations") or [] if isinstance(location, dict)],
        code_flows=[
            [_location_from_dict(location) for location in flow if isinstance(location, dict)]
            for flow in item.get("code_flows") or []
            if isinstance(flow, list)
        ],
        properties=dict(item.get("properties") or {}) if isinstance(item.get("properties"), dict) else {},
        raw=dict(item.get("raw") or {}) if isinstance(item.get("raw"), dict) else {},
    )


def _findings_from_moderator(data: Dict[str, Any], report_path: Path) -> List[Finding]:
    raw = data.get("findings")
    if not isinstance(raw, list) or not raw:
        raise CodexRunnerError("Moderator findings.json 缺少 findings 数组")
    findings: List[Finding] = []
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            continue
        finding_id = str(item.get("finding_id") or f"finding-{index}").strip() or f"finding-{index}"
        findings.append(
            Finding(
                finding_id=_safe_finding_id(finding_id),
                rule_id=str(item.get("rule_id") or f"codex-finding-{index}"),
                message=str(item.get("message") or item.get("title") or f"Codex finding {index}"),
                level=str(item.get("level") or "unknown"),
                locations=[_location_from_dict(loc) for loc in item.get("locations") or [] if isinstance(loc, dict)],
                code_flows=[
                    [_location_from_dict(loc) for loc in flow if isinstance(loc, dict)]
                    for flow in item.get("code_flows") or []
                    if isinstance(flow, list)
                ],
                properties={"source_report": str(report_path), "codex_moderated": True},
                raw={"format": "codex_moderated_finding", "report_markdown": str(item.get("report_markdown") or ""), "moderator": item},
            )
        )
    if not findings:
        raise CodexRunnerError("Moderator findings.json 未包含有效 finding")
    return findings


def _base_payload(
    config: RunConfig,
    run_id: str,
    created_at: str,
    languages: List[str],
    run_dir: Path,
    sessions: Dict[str, CliSession],
    agent_configs: Dict[str, AgentConfig],
    run_origin: str,
    *,
    engine: str,
) -> Dict[str, Any]:
    session_payload = [to_jsonable(session.info()) for session in sessions.values()]
    resume_reports = [dict(report) for report in config.resume_reports if isinstance(report, dict)]
    resume_index = first_incomplete_finding_index(resume_reports, len(resume_reports))
    workflow = {
        "engine": engine,
        "run_dir": str(run_dir),
        "sessions": session_payload,
        "schedule": "3-stage pipeline: affirmative -> negative -> moderator (3 isolated CLI slots)",
        "pipeline": {
            "version": 1,
            "context_mode": "isolated-per-finding-stage",
            "slot_count": 3,
            "buffer_capacity": 1,
            "slots": {role: None for role in PIPELINE_ROLES},
            "queue_depths": {role: 0 for role in PIPELINE_ROLES},
            "stage_completed_counts": {role: 0 for role in PIPELINE_ROLES},
        },
        "watchdog": {
            "silence_reminder_minutes": config.silence_reminder_minutes,
            "reminder_count": 0,
            "prompt_redelivery_count": 0,
        },
    }
    payload = {
        "run_id": run_id,
        "status": "running",
        "run_origin": run_origin,
        "engine": engine,
        "created_at": created_at,
        "source_path": str(config.source_path),
        "sarif_path": str(config.sarif_path),
        "languages": languages,
        "finding_count": len(resume_reports),
        "project_context_facts": 0,
        "reports": resume_reports,
        "report_findings": dict(config.reused_findings_payload),
        "diagnostics": list(config.resume_diagnostics or []),
        "llm_providers": {"enabled": False, "engine": engine},
        "agent_configs": {role: to_jsonable(agent_configs[role]) for role in CODEX_ROLES},
        "completed_finding_count": completed_finding_count(resume_reports),
        "current_finding_id": None,
        "current_finding_index": None,
        "current_finding_ids": {},
        "resume_from_finding_id": (
            resume_reports[resume_index].get("finding_id") if resume_index < len(resume_reports) else None
        ),
        "resume_from_finding_index": resume_index,
        "config": {**run_config_snapshot(config), "engine": engine},
        "cli_sessions": session_payload,
        "cli_workflow": workflow,
    }
    if engine == CODEX_ENGINE:
        payload["codex_sessions"] = session_payload
        payload["codex_workflow"] = workflow
    return payload


def _refresh_cli_session_payload(
    payload: Dict[str, Any],
    sessions: Dict[str, CliSession],
    engine: str,
) -> None:
    session_payload = [to_jsonable(session.info()) for session in sessions.values()]
    workflow = dict(payload.get("cli_workflow") or payload.get("codex_workflow") or {})
    workflow["engine"] = engine
    workflow["sessions"] = session_payload
    payload["cli_sessions"] = session_payload
    payload["cli_workflow"] = workflow
    if engine == CODEX_ENGINE:
        payload["codex_sessions"] = session_payload
        payload["codex_workflow"] = workflow


def _initialize_pipeline_findings(
    findings: Sequence[Finding],
    finding_briefs: Dict[str, Path],
    run_dir: Path,
    reports: Sequence[Dict[str, Any]],
    *,
    resume: bool,
) -> List[_PipelineFinding]:
    items: List[_PipelineFinding] = []
    for index, finding in enumerate(findings):
        finding_dir = run_dir / "findings" / _safe_path_part(finding.finding_id)
        result_paths = {
            "affirmative": finding_dir / "affirmative" / "result.json",
            "negative": finding_dir / "negative" / "result.json",
            "moderator": finding_dir / "moderator" / "final.json",
        }
        for path in result_paths.values():
            path.parent.mkdir(parents=True, exist_ok=True)
        existing = dict(reports[index]) if index < len(reports) and isinstance(reports[index], dict) else {}
        workflow = existing.get("cli_workflow") if isinstance(existing.get("cli_workflow"), dict) else {}
        if not workflow and isinstance(existing.get("codex_workflow"), dict):
            workflow = existing["codex_workflow"]
        pipeline = workflow.get("pipeline") if isinstance(workflow.get("pipeline"), dict) else {}
        previous_stages = pipeline.get("stages") if isinstance(pipeline.get("stages"), dict) else {}
        data: Dict[str, Dict[str, Any]] = {}
        stages: Dict[str, Dict[str, Any]] = {}

        for role in PIPELINE_ROLES:
            if not resume:
                result_paths[role].unlink(missing_ok=True)
            candidate, _ = _read_json_object(result_paths[role]) if resume else (None, "")
            if candidate is not None:
                try:
                    _validate_pipeline_output(
                        candidate,
                        finding_id=finding.finding_id,
                        role=role,
                        attempt_id=None,
                        strict_identity=False,
                    )
                except CodexRunnerError:
                    result_paths[role].unlink(missing_ok=True)
                    candidate = None
            if candidate is None and isinstance(workflow.get(role), dict) and workflow.get(role):
                candidate = dict(workflow[role])
                try:
                    _validate_pipeline_output(
                        candidate,
                        finding_id=finding.finding_id,
                        role=role,
                        attempt_id=None,
                        strict_identity=False,
                    )
                except CodexRunnerError:
                    candidate = None
            if candidate is not None:
                data[role] = candidate
                if not result_paths[role].exists():
                    _write_json_object(result_paths[role], candidate)

            previous = previous_stages.get(role) if isinstance(previous_stages.get(role), dict) else {}
            stages[role] = {
                "status": "succeeded" if candidate is not None else "pending",
                "attempt": max(_integer(previous.get("attempt"), 0), 0),
                "attempt_id": previous.get("attempt_id"),
                "output_path": str(result_paths[role]),
                "started_at": previous.get("started_at"),
                "completed_at": previous.get("completed_at") if candidate is not None else None,
            }

        if "affirmative" not in data:
            data.pop("negative", None)
            data.pop("moderator", None)
            result_paths["negative"].unlink(missing_ok=True)
            result_paths["moderator"].unlink(missing_ok=True)
        elif "negative" not in data:
            data.pop("moderator", None)
            result_paths["moderator"].unlink(missing_ok=True)
        for role in PIPELINE_ROLES:
            if role not in data:
                stages[role]["status"] = "pending"
                stages[role]["completed_at"] = None

        preserved = existing if existing and finding_report_completed(existing) else None
        items.append(
            _PipelineFinding(
                index=index,
                finding=finding,
                brief_path=finding_briefs[finding.finding_id],
                result_paths=result_paths,
                data=data,
                stages=stages,
                preserved_report=preserved,
            )
        )
    return items


def _next_pipeline_role(item: _PipelineFinding) -> Optional[str]:
    if item.preserved_report is not None and finding_report_completed(item.preserved_report):
        return None
    for role in PIPELINE_ROLES:
        if role not in item.data:
            return role
    return None


def _role_after(role: str) -> Optional[str]:
    try:
        index = PIPELINE_ROLES.index(role)
    except ValueError:
        return None
    return PIPELINE_ROLES[index + 1] if index + 1 < len(PIPELINE_ROLES) else None


def _clear_pipeline_from(item: _PipelineFinding, role: str) -> None:
    start = PIPELINE_ROLES.index(role)
    item.preserved_report = None
    for downstream in PIPELINE_ROLES[start:]:
        item.data.pop(downstream, None)
        item.result_paths[downstream].unlink(missing_ok=True)
        stage = item.stages[downstream]
        stage["status"] = "pending"
        stage["attempt_id"] = None
        stage["started_at"] = None
        stage["completed_at"] = None


def _pipeline_stage_prompt(
    *,
    role: str,
    item: _PipelineFinding,
    source_path: Path,
    attempt_id: str,
) -> str:
    if role == "moderator":
        return _moderator_final_prompt(
            finding=item.finding,
            source_path=source_path,
            brief_path=item.brief_path,
            affirmative_result=item.result_paths["affirmative"],
            negative_result=item.result_paths["negative"],
            final_path=item.result_paths["moderator"],
            attempt_id=attempt_id,
        )
    return _worker_prompt(
        role=role,
        finding=item.finding,
        source_path=source_path,
        brief_path=item.brief_path,
        result_path=item.result_paths[role],
        peer_result_path=item.result_paths["affirmative"] if role == "negative" else None,
        round_index=item.index + 1,
        attempt_id=attempt_id,
    )


def _pipeline_report(item: _PipelineFinding) -> Dict[str, Any]:
    if item.preserved_report is not None and finding_report_completed(item.preserved_report):
        return dict(item.preserved_report)
    affirmative = item.data.get("affirmative")
    negative = item.data.get("negative")
    final = item.data.get("moderator")
    if final is not None and affirmative is not None and negative is not None:
        report = _final_report(item.finding, affirmative, negative, final)
    elif affirmative is not None or negative is not None:
        report = _partial_report(item.finding, affirmative, negative, None)
    else:
        report = _pending_report(item.finding)
        if any(stage.get("status") in PIPELINE_ACTIVE_STATUSES for stage in item.stages.values()):
            report["finding_status"] = FINDING_IN_PROGRESS
    workflow = dict(report.get("cli_workflow") or {})
    workflow["pipeline"] = {
        "version": 1,
        "stages": {role: dict(item.stages[role]) for role in PIPELINE_ROLES},
    }
    report["cli_workflow"] = workflow
    report["codex_workflow"] = workflow
    report["finding_stage"] = _finding_stage(item)
    return report


def _finding_stage(item: _PipelineFinding) -> str:
    if item.preserved_report is not None and finding_report_completed(item.preserved_report):
        return "completed"
    if "moderator" in item.data:
        return "completed"
    for role in PIPELINE_DOWNSTREAM_ROLES:
        status = str(item.stages[role].get("status") or "pending")
        if status in {"running", "failed", "interrupted"}:
            return f"{role}_{status}"
    next_role = _next_pipeline_role(item)
    return f"{next_role}_ready" if next_role else "completed"


def _pipeline_snapshot(
    items: Sequence[_PipelineFinding],
    ready: Dict[str, deque[int]],
    active: Dict[str, _ActivePipelineStage],
) -> Dict[str, Any]:
    return {
        "version": 1,
        "context_mode": "isolated-per-finding-stage",
        "slot_count": 3,
        "buffer_capacity": 1,
        "slots": {
            role: active[role].item.finding.finding_id if role in active else None
            for role in PIPELINE_ROLES
        },
        "queue_depths": {role: len(ready[role]) for role in PIPELINE_ROLES},
        "stage_completed_counts": {
            role: sum(1 for item in items if role in item.data) for role in PIPELINE_ROLES
        },
    }


def _validate_pipeline_output(
    data: Dict[str, Any],
    *,
    finding_id: str,
    role: str,
    attempt_id: Optional[str],
    strict_identity: bool,
) -> None:
    actual_finding = str(data.get("finding_id") or "")
    actual_role = str(data.get("role") or "")
    actual_attempt = str(data.get("attempt_id") or "")
    if (strict_identity or actual_finding) and actual_finding != finding_id:
        raise CodexRunnerError(f"stage 输出 finding_id 不匹配：期望 {finding_id}，实际 {actual_finding or '<missing>'}")
    if (strict_identity or actual_role) and actual_role != role:
        raise CodexRunnerError(f"stage 输出 role 不匹配：期望 {role}，实际 {actual_role or '<missing>'}")
    if attempt_id is not None and actual_attempt != attempt_id:
        raise CodexRunnerError(
            f"stage 输出 attempt_id 不匹配：期望 {attempt_id}，实际 {actual_attempt or '<missing>'}"
        )
    decision_key = "verdict" if role == "moderator" else "position"
    decision = str(data.get(decision_key) or "")
    if decision and decision not in VERDICTS:
        raise CodexRunnerError(f"stage 输出 {decision_key} 非法：{decision}")
    if not decision:
        raise CodexRunnerError(f"stage 输出缺少 {decision_key}")
    if "confidence" in data:
        try:
            confidence = float(data["confidence"])
        except (TypeError, ValueError) as exc:
            raise CodexRunnerError("stage 输出 confidence 必须是数字") from exc
        if not 0.0 <= confidence <= 1.0:
            raise CodexRunnerError("stage 输出 confidence 必须位于 0 到 1")
    elif strict_identity:
        raise CodexRunnerError("stage 输出缺少 confidence")


def _validate_and_stamp_pipeline_output(
    data: Dict[str, Any],
    *,
    output_path: Path,
    finding_id: str,
    role: str,
    attempt_id: str,
) -> None:
    """Validate the stage identity and backfill only an omitted scheduler attempt ID.

    The result path is deleted before dispatch, so a newly-created JSON with the
    expected finding and role belongs to the current stage.  Some OpenCode
    versions nevertheless omit the mechanical ``attempt_id`` field even when
    every substantive result field is complete.  Treating that omission as a
    non-completion leaves the prompt worker alive and lets it keep responding.
    A supplied but mismatched ID remains a hard failure, which preserves stale
    output protection.
    """

    _validate_pipeline_output(
        data,
        finding_id=finding_id,
        role=role,
        attempt_id=None,
        strict_identity=True,
    )
    actual_attempt = str(data.get("attempt_id") or "")
    if actual_attempt and actual_attempt != attempt_id:
        raise CodexRunnerError(
            f"stage 输出 attempt_id 不匹配：期望 {attempt_id}，实际 {actual_attempt}"
        )
    if not actual_attempt:
        data["attempt_id"] = attempt_id
        _write_json_object(output_path, data)


def _write_json_object(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _integer(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _final_report(
    finding: Finding,
    affirmative: Dict[str, Any],
    negative: Dict[str, Any],
    final: Dict[str, Any],
) -> Dict[str, Any]:
    verdict = str(final.get("verdict") or "INCONCLUSIVE")
    if verdict not in VERDICTS:
        verdict = "INCONCLUSIVE"
    confidence = _float(final.get("confidence"), 0.5)
    workflow = {
        "affirmative": affirmative,
        "negative": negative,
        "moderator": final,
    }
    return {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "finding_status": FINDING_COMPLETED,
        "verdict": verdict,
        "confidence": round(confidence, 2),
        "reasoning_summary": str(final.get("reasoning_summary") or final.get("summary") or ""),
        "final_conclusion": str(final.get("final_conclusion") or final.get("reasoning_summary") or ""),
        "evidence_chain": _evidence_chain(finding, affirmative, negative, final),
        "debate": _debate_turns(affirmative, negative, final),
        "disputed_points": _string_list(final.get("disputed_points")),
        "protection_assessment": str(final.get("protection_assessment") or ""),
        "impact_assessment": str(final.get("impact_assessment") or ""),
        "source_locations": [
            to_jsonable(item)
            for item in (_source_locations_from_payload(final.get("source_locations")) or finding.locations)
        ],
        "recommended_next_steps": _string_list(final.get("recommended_next_steps")),
        "evidence_graph": {},
        "verification_case": _verification_case(finding),
        "evidence_ledger": [],
        "scorecard": {},
        "cli_workflow": workflow,
        "codex_workflow": workflow,
    }


def _partial_report(
    finding: Finding,
    affirmative: Optional[Dict[str, Any]],
    negative: Optional[Dict[str, Any]],
    final: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    if final:
        return _final_report(finding, affirmative or {}, negative or {}, final)
    position = (negative or affirmative or {}).get("position") or "INCONCLUSIVE"
    if position not in VERDICTS:
        position = "INCONCLUSIVE"
    summary = str((negative or affirmative or {}).get("summary") or "Codex worker 正在复核。")
    workflow = {
        "affirmative": affirmative or {},
        "negative": negative or {},
        "moderator": final or {},
    }
    return {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "finding_status": FINDING_IN_PROGRESS,
        "verdict": position,
        "confidence": _float((negative or affirmative or {}).get("confidence"), 0.3),
        "reasoning_summary": summary,
        "final_conclusion": summary,
        "evidence_chain": _evidence_chain(finding, affirmative or {}, negative or {}, final or {}),
        "debate": _debate_turns(affirmative or {}, negative or {}, final or {}),
        "disputed_points": [],
        "protection_assessment": "",
        "impact_assessment": "",
        "source_locations": [to_jsonable(item) for item in finding.locations],
        "recommended_next_steps": [],
        "evidence_graph": {},
        "verification_case": _verification_case(finding),
        "evidence_ledger": [],
        "scorecard": {},
        "cli_workflow": workflow,
        "codex_workflow": workflow,
    }


def _pending_report(finding: Finding) -> Dict[str, Any]:
    workflow = {
        "affirmative": {},
        "negative": {},
        "moderator": {},
    }
    return {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "finding_status": FINDING_PENDING,
        "verdict": None,
        "confidence": None,
        "reasoning_summary": finding.message,
        "final_conclusion": "",
        "evidence_chain": _evidence_chain(finding, {}, {}, {}),
        "debate": [],
        "disputed_points": [],
        "protection_assessment": "",
        "impact_assessment": "",
        "source_locations": [to_jsonable(item) for item in finding.locations],
        "recommended_next_steps": [],
        "evidence_graph": {},
        "verification_case": _verification_case(finding),
        "evidence_ledger": [],
        "scorecard": {},
        "cli_workflow": workflow,
        "codex_workflow": workflow,
    }


def _reconcile_finding_reports(
    findings: Sequence[Finding],
    resume_reports: Sequence[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    previous = {
        str(report.get("finding_id")): dict(report)
        for report in resume_reports
        if isinstance(report, dict) and report.get("finding_id")
    }
    reports: List[Dict[str, Any]] = []
    for finding in findings:
        existing = previous.get(finding.finding_id)
        if existing is not None and finding_report_completed(existing):
            existing["finding_status"] = FINDING_COMPLETED
            reports.append(existing)
        elif existing is not None:
            existing["finding_id"] = finding.finding_id
            existing["rule_id"] = finding.rule_id
            existing["finding_status"] = FINDING_PENDING
            reports.append(existing)
        else:
            reports.append(_pending_report(finding))
    return reports


def _replace_finding_report(
    reports: Sequence[Dict[str, Any]],
    index: int,
    report: Dict[str, Any],
) -> List[Dict[str, Any]]:
    updated = [dict(item) for item in reports]
    updated[index] = dict(report)
    return updated


def _reset_incomplete_finding_outputs(finding_dir: Path) -> None:
    for relative_path in (
        Path("affirmative") / "result.json",
        Path("negative") / "result.json",
        Path("moderator") / "final.json",
    ):
        (finding_dir / relative_path).unlink(missing_ok=True)


def _evidence_chain(
    finding: Finding,
    affirmative: Dict[str, Any],
    negative: Dict[str, Any],
    final: Dict[str, Any],
) -> List[Dict[str, Any]]:
    items = [
        {
            "evidence_id": f"{finding.finding_id}-report",
            "kind": "REPORT",
            "strength": "STRONG",
            "summary": finding.message,
            "source": "input-report",
            "locations": [to_jsonable(item) for item in finding.locations],
            "snippet": finding.raw.get("report_markdown") if isinstance(finding.raw, dict) else None,
            "data": {
                "rule_id": finding.rule_id,
                "level": finding.level,
                "message": finding.message,
                "locations": [item.display() for item in finding.locations],
                "code_flows": [[item.display() for item in flow] for flow in finding.code_flows],
            },
        }
    ]
    for role, data in (("affirmative", affirmative), ("negative", negative), ("moderator", final)):
        if not data:
            continue
        items.append(
            {
                "evidence_id": f"{finding.finding_id}-{role}",
                "kind": "PROJECT_CONTEXT",
                "strength": "MEDIUM",
                "summary": str(data.get("summary") or data.get("reasoning_summary") or data.get("final_conclusion") or "")[:800],
                "source": f"codex-{role}",
                "locations": [to_jsonable(item) for item in _source_locations_from_payload(data.get("source_locations"))],
                "snippet": None,
                "data": data,
            }
        )
    return items


def _debate_turns(affirmative: Dict[str, Any], negative: Dict[str, Any], final: Dict[str, Any]) -> List[Dict[str, Any]]:
    turns: List[Dict[str, Any]] = []
    if affirmative:
        turns.append(
            {
                "role": "AFFIRMATIVE",
                "round_index": 1,
                "claim": str(affirmative.get("summary") or ""),
                "evidence_ids": [],
                "resolved": False,
                "structured": affirmative,
            }
        )
    if negative:
        turns.append(
            {
                "role": "NEGATIVE",
                "round_index": 1,
                "claim": str(negative.get("summary") or ""),
                "evidence_ids": [],
                "resolved": False,
                "structured": negative,
            }
        )
    if final:
        turns.append(
            {
                "role": "MODERATOR",
                "round_index": 1,
                "claim": str(final.get("final_conclusion") or final.get("reasoning_summary") or ""),
                "evidence_ids": [],
                "resolved": True,
                "structured": final,
            }
        )
    return turns


def _persist_finding_briefs(
    findings: Sequence[Finding],
    source_indexer: SourceIndexer,
    run_dir: Path,
) -> Dict[str, Path]:
    paths: Dict[str, Path] = {}
    for finding in findings:
        finding_dir = run_dir / "findings" / _safe_path_part(finding.finding_id)
        finding_dir.mkdir(parents=True, exist_ok=True)
        brief_path = finding_dir / "brief.json"
        brief_path.write_text(
            json.dumps(
                _finding_to_prompt_payload(finding, source_indexer),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        paths[finding.finding_id] = brief_path
    return paths


def _finding_to_prompt_payload(finding: Finding, source_indexer: SourceIndexer) -> Dict[str, Any]:
    contexts = []
    for location in finding.locations[:8]:
        resolved = source_indexer.resolve_location(location)
        contexts.append(
            {
                "reported": location.display(),
                "resolved_file": resolved.relative_path,
                "exists": resolved.exists,
                "line_exists": resolved.line_exists,
                "symbol": resolved.symbol,
                "snippet": (resolved.snippet or "")[:2400],
            }
        )
    return {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "message": finding.message,
        "level": finding.level,
        "locations": [to_jsonable(item) for item in finding.locations],
        "code_flows": [[to_jsonable(item) for item in flow] for flow in finding.code_flows],
        "properties": finding.properties,
        "raw": finding.raw,
        "source_context": contexts,
    }


def _verification_case(finding: Finding) -> Dict[str, Any]:
    primary = finding.primary_location.display() if finding.primary_location else ""
    return {
        "vulnerability_type": finding.rule_id,
        "reported_message": finding.message,
        "reported_location": primary,
        "reported_source": "",
        "reported_sink": "",
        "dangerous_function": "",
        "expected_attack_path": "由 Codex 正反方和 Moderator 复核。",
        "required_proof": ["源码定位", "入口可达性", "调用链", "数据流", "影响", "防护消减"],
    }


def _source_locations_from_payload(value: Any) -> List[SourceLocation]:
    if not isinstance(value, list):
        return []
    result = []
    for item in value:
        if isinstance(item, dict):
            result.append(_location_from_dict(item))
    return result


def _location_from_dict(data: Dict[str, Any]) -> SourceLocation:
    return SourceLocation(
        file=str(data.get("file") or data.get("path") or ""),
        line=_optional_int(data.get("line")),
        column=_optional_int(data.get("column")),
        end_line=_optional_int(data.get("end_line")),
        end_column=_optional_int(data.get("end_column")),
        symbol=str(data.get("symbol")) if data.get("symbol") is not None else None,
    )


def _safe_tmux_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "-", value)[:80].strip("-")
    return cleaned or "vj-session"


def _normalize_cli_prompt(value: str) -> str:
    """Use LF for persisted/API prompts while leaving terminal Enter handling separate."""

    return str(value).replace("\r\n", "\n").replace("\r", "\n")


def _safe_tmux_ref(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{1,80}(?::[A-Za-z0-9_-]{1,80})?", value or ""))


def _safe_path_part(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value)[:120].strip("-") or "finding"


def _safe_finding_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]+", "-", value)[:160].strip("-") or "finding"


def _string_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value:
        return [str(value)]
    return []


def _float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _optional_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _new_run_id() -> str:
    return f"run-{int(time.time())}-{os.getpid()}"
