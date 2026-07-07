from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import pty
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import termios
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from .agents import DEFAULT_AFFIRMATIVE_AGENT, DEFAULT_MODERATOR_AGENT, DEFAULT_NEGATIVE_AGENT
from .logging_config import logger
from .models import AgentConfig, Finding, RunConfig, SourceLocation, to_jsonable
from .records import RunRecordStore
from .sarif import ReportPreparationError, load_report
from .source import SourceIndexer, detect_project_languages


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CODEX_WORKSPACES_DIR = REPO_ROOT / ".workspaces" / "runs"
CODEX_ENGINE = "codex"
CODEX_ROLES = ("moderator", "affirmative", "negative")
CODEX_AGENT_FILE_NAMES = ("AGENTS.md", "AGENT.md")
LOG = logger("codex_runner")
ROLE_LABELS = {
    "moderator": "Moderator",
    "affirmative": "正方",
    "negative": "反方",
}
VERDICTS = {"TRUE_POSITIVE", "FALSE_POSITIVE", "INCONCLUSIVE"}
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
CODEX_STARTUP_MARKERS = (
    "Starting MCP server",
    "Starting MCP servers",
)
CODEX_ACTIVE_PROGRESS_RE = re.compile(
    r"\((?:(?:\d+h\s+)?(?:\d+m\s+)?)\d+s\s*[•·]\s*esc to interrupt\)",
    re.IGNORECASE,
)
CODEX_BACKGROUND_RUNNING_RE = re.compile(
    r"\b\d+\s+background terminals?\s+running\b",
    re.IGNORECASE,
)


class CodexRunnerError(RuntimeError):
    pass


class CodexRunnerStopped(RuntimeError):
    pass


@dataclass
class CodexSessionInfo:
    role: str
    session_name: str
    window_name: str
    target: str
    cwd: str


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
            return
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
        if yolo:
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
        if not self.is_live():
            self.start()
        self._wait_until_input_ready()
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

    def capture(self, lines: int = 240) -> str:
        if not self.is_live():
            return ""
        result = _run_tmux(
            ["tmux", "capture-pane", "-p", "-S", f"-{max(1, min(lines, 2000))}", "-t", self.target],
            timeout=10,
            check=False,
        )
        return result.stdout or ""

    def _accept_trust_prompt(self) -> None:
        deadline = time.monotonic() + 12
        markers = (
            "allow codex to work in this folder",
            "do you trust the contents of this directory",
            "do you trust the files in this folder",
            "2. no, quit",
        )
        while time.monotonic() < deadline:
            text = self.capture(lines=80).lower()
            if any(marker in text for marker in markers):
                _run_tmux(["tmux", "send-keys", "-t", self.target, _codex_submit_key()], timeout=5)
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
            busy = bool(CODEX_ACTIVE_PROGRESS_RE.search(text) or CODEX_BACKGROUND_RUNNING_RE.search(text))
            if text.strip() and not busy and not any(marker in text for marker in CODEX_STARTUP_MARKERS):
                stable_samples += 1
                if stable_samples >= 3:
                    return
            else:
                stable_samples = 0
            time.sleep(0.5)
        startup = next((marker for marker in CODEX_STARTUP_MARKERS if marker in last_text), "none")
        raise CodexRunnerError(f"Codex session did not become input-ready: {self.target}; startup_marker={startup}")

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


class CodexDrivenRunner:
    def __init__(
        self,
        *,
        records_dir: Path,
        codex_runs_dir: Optional[Path] = None,
        codex_command: Optional[str] = None,
    ) -> None:
        self.records_dir = records_dir.expanduser().resolve()
        self.codex_runs_dir = (
            codex_runs_dir.expanduser().resolve()
            if codex_runs_dir is not None
            else Path(os.environ.get("VULN_JUDGER_CODEX_WORKSPACES_DIR", DEFAULT_CODEX_WORKSPACES_DIR)).expanduser().resolve()
        )
        self.codex_command = codex_command or os.environ.get("VULN_JUDGER_CODEX_COMMAND") or shutil.which("codex") or "codex"

    def run(
        self,
        config: RunConfig,
        *,
        store: RunRecordStore,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        run_id = config.run_id or _new_run_id()
        source_path = config.source_path.expanduser().resolve()
        report_path = config.sarif_path.expanduser().resolve()
        run_dir = self.codex_runs_dir / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        _ensure_codex_project_trust(run_dir)
        (run_dir / "input").mkdir(exist_ok=True)
        (run_dir / "findings").mkdir(exist_ok=True)

        languages = list(detect_project_languages(source_path).languages)
        created_at = config.created_at or _now()
        agent_configs = _codex_agent_configs(config)
        session_dirs = _prepare_codex_agent_dirs(run_dir, agent_configs, source_path)
        sessions = self._sessions(run_id, source_path, run_dir, session_dirs)
        payload = _base_payload(config, run_id, created_at, languages, run_dir, sessions, agent_configs)

        def emit(status: str, **updates: Any) -> None:
            payload.update(updates)
            payload["status"] = status
            payload["updated_at"] = _now()
            store.save_payload(payload)
            if progress_callback is not None:
                progress_callback(dict(payload))

        def check_stop() -> None:
            if should_stop is not None and should_stop():
                raise CodexRunnerStopped(f"任务 {run_id} 已中断")

        emit("running", diagnostics=["Codex-driven session 元数据已创建，正在启动三方 Codex TUI。"])
        for session in sessions.values():
            check_stop()
            session.start()
            emit(
                "running",
                diagnostics=[
                    *payload.get("diagnostics", []),
                    f"{ROLE_LABELS.get(session.role, session.role)} Codex session 已启动。",
                ],
            )
        emit("running", diagnostics=["Codex-driven 任务已启动，等待 Moderator 处理漏洞报告。"])

        input_payload = _input_payload(config, report_path, source_path, run_dir)
        (run_dir / "input" / "task.json").write_text(
            json.dumps(input_payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        check_stop()

        findings_path = run_dir / "findings.json"
        sessions["moderator"].send(_moderator_report_prompt(input_payload, findings_path))
        findings_data = _wait_json(findings_path, should_stop=should_stop)
        findings = _findings_from_moderator(findings_data, report_path)
        payload["finding_count"] = len(findings)
        payload["codex_workflow"]["findings_path"] = str(findings_path)
        emit("running", diagnostics=[*payload.get("diagnostics", []), f"Moderator 已拆分 {len(findings)} 个待复核 finding。"])

        reports: List[Dict[str, Any]] = list(config.resume_reports or [])
        start_index = max(int(config.resume_from_finding_index or 0), len(reports))
        for finding_index, finding in enumerate(findings):
            if finding_index < start_index:
                continue
            check_stop()
            payload["current_finding_id"] = finding.finding_id
            payload["current_finding_index"] = finding_index
            payload["resume_from_finding_id"] = finding.finding_id
            payload["resume_from_finding_index"] = finding_index
            emit("running")

            finding_dir = run_dir / "findings" / _safe_path_part(finding.finding_id)
            finding_dir.mkdir(parents=True, exist_ok=True)
            brief_path = finding_dir / "brief.json"
            brief_path.write_text(
                json.dumps(_finding_to_prompt_payload(finding, source_path), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            affirmative_dir = finding_dir / "affirmative"
            negative_dir = finding_dir / "negative"
            moderator_dir = finding_dir / "moderator"
            affirmative_dir.mkdir(exist_ok=True)
            negative_dir.mkdir(exist_ok=True)
            moderator_dir.mkdir(exist_ok=True)

            affirmative_result = affirmative_dir / "result.json"
            sessions["affirmative"].send(
                _worker_prompt(
                    role="affirmative",
                    finding=finding,
                    source_path=source_path,
                    brief_path=brief_path,
                    result_path=affirmative_result,
                    peer_result_path=None,
                    round_index=finding_index + 1,
                )
            )
            affirmative_data = _wait_json(affirmative_result, should_stop=should_stop)
            reports_preview = reports + [_partial_report(finding, affirmative_data, None, None)]
            emit("running", reports=reports_preview, completed_finding_count=len(reports))

            negative_result = negative_dir / "result.json"
            sessions["negative"].send(
                _worker_prompt(
                    role="negative",
                    finding=finding,
                    source_path=source_path,
                    brief_path=brief_path,
                    result_path=negative_result,
                    peer_result_path=affirmative_result,
                    round_index=finding_index + 1,
                )
            )
            negative_data = _wait_json(negative_result, should_stop=should_stop)
            reports_preview = reports + [_partial_report(finding, affirmative_data, negative_data, None)]
            emit("running", reports=reports_preview, completed_finding_count=len(reports))

            final_result = moderator_dir / "final.json"
            sessions["moderator"].send(
                _moderator_final_prompt(
                    finding=finding,
                    source_path=source_path,
                    brief_path=brief_path,
                    affirmative_result=affirmative_result,
                    negative_result=negative_result,
                    final_path=final_result,
                )
            )
            final_data = _wait_json(final_result, should_stop=should_stop)
            reports.append(_final_report(finding, affirmative_data, negative_data, final_data))
            emit(
                "running",
                reports=reports,
                completed_finding_count=len(reports),
                resume_from_finding_index=len(reports),
            )

        payload["reports"] = reports
        payload["completed_finding_count"] = len(reports)
        payload["current_finding_id"] = None
        payload["current_finding_index"] = None
        payload["resume_from_finding_id"] = None
        payload["resume_from_finding_index"] = len(reports)
        emit("completed")
        return payload

    def _sessions(
        self,
        run_id: str,
        source_path: Path,
        run_dir: Path,
        session_dirs: Dict[str, Path],
    ) -> Dict[str, CodexTmuxSession]:
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
    role_label = ROLE_LABELS.get(role, role)
    profile = agent.profile_id or agent.name or role_label
    instructions = (agent.instructions or "").strip() or "围绕当前阶段任务进行可复核的漏洞报告复核。"
    return (
        "# vuln-judger Codex Agent\n\n"
        f"- 角色：{role_label}\n"
        f"- Agent 配置档案：{profile}\n"
        f"- 源码根目录：{source_path}\n"
        f"- 共享任务工作目录：{run_dir}\n\n"
        "## 会话约束\n\n"
        "- 这份 AGENTS.md 是本 Codex session 的持续行为约束；后续每轮 prompt 只描述当前阶段、输入文件和输出 schema。\n"
        "- 模型、MCP、skills 和 provider 都由 Codex 当前默认配置加载；不要要求 vuln-judger 在 prompt 中动态提供这些配置。\n"
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
    return _run_tmux(["tmux", "has-session", "-t", session_name], check=False).returncode == 0


def stop_sessions(payload: Dict[str, Any]) -> None:
    for session in _payload_sessions(payload):
        name = str(session.get("session_name") or "")
        if _safe_tmux_ref(name) and session_live(name):
            _run_tmux(["tmux", "kill-session", "-t", name], check=False)


def _payload_sessions(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    sessions = payload.get("codex_sessions")
    if isinstance(sessions, list):
        return [item for item in sessions if isinstance(item, dict)]
    workflow = payload.get("codex_workflow") if isinstance(payload.get("codex_workflow"), dict) else {}
    sessions = workflow.get("sessions")
    if isinstance(sessions, list):
        return [item for item in sessions if isinstance(item, dict)]
    return []


def attach_session_websocket(handler: Any, session_name: str) -> None:
    if not _safe_tmux_ref(session_name):
        handler.send_error(404, "invalid Codex session")
        return
    if not session_live(session_name):
        handler.send_error(404, "Codex session is not running")
        return
    if not _websocket_accept(handler):
        return
    _bridge_tmux_websocket(handler.connection, session_name)


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


def _bridge_tmux_websocket(sock: socket.socket, session_name: str) -> None:
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
                if message.get("type") == "input":
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
    timeout_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    timeout = timeout_seconds or int(os.environ.get("VULN_JUDGER_CODEX_STEP_TIMEOUT", "3600"))
    LOG.info(
        "等待 Codex JSON 输出",
        extra={"event": "codex.output.wait", "output_path": str(path), "timeout_seconds": timeout},
    )
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        if should_stop is not None and should_stop():
            raise CodexRunnerStopped("Codex-driven task stopped")
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    LOG.info(
                        "Codex JSON 输出就绪",
                        extra={"event": "codex.output.ready", "output_path": str(path)},
                    )
                    return data
                last_error = "JSON root is not an object"
            except json.JSONDecodeError as exc:
                last_error = str(exc)
        time.sleep(1)
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


def _input_payload(config: RunConfig, report_path: Path, source_path: Path, run_dir: Path) -> Dict[str, Any]:
    report_text = report_path.read_text(encoding="utf-8", errors="replace")
    parsed_findings: List[Dict[str, Any]] = []
    parse_error = ""
    try:
        parsed_findings = [_finding_to_prompt_payload(item, source_path) for item in load_report(report_path)]
    except (ReportPreparationError, json.JSONDecodeError, OSError, ValueError) as exc:
        parse_error = str(exc)
    return {
        "run_id": config.run_id,
        "report_path": str(report_path),
        "source_path": str(source_path),
        "skills_path": str(config.skills_path) if config.skills_path else None,
        "run_dir": str(run_dir),
        "max_rounds": config.max_rounds,
        "parsed_findings": parsed_findings,
        "parse_error": parse_error,
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
        "      \"report_markdown\": \"保留该 finding 的完整报告上下文\"\n"
        "    }\n"
        "  ]\n"
        "}\n\n"
        "约束：不要新增报告没有支持的事实；如果无法拆分则输出一个 finding，report_markdown 放完整报告。\n"
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
        f"  \"finding_id\": \"{finding.finding_id}\",\n"
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
    sessions: Dict[str, CodexTmuxSession],
    agent_configs: Dict[str, AgentConfig],
) -> Dict[str, Any]:
    session_payload = [to_jsonable(session.info()) for session in sessions.values()]
    return {
        "run_id": run_id,
        "status": "running",
        "run_origin": "web",
        "engine": CODEX_ENGINE,
        "created_at": created_at,
        "source_path": str(config.source_path),
        "sarif_path": str(config.sarif_path),
        "languages": languages,
        "finding_count": 0,
        "project_context_facts": 0,
        "reports": [],
        "diagnostics": list(config.resume_diagnostics or []),
        "llm_providers": {"enabled": False, "engine": CODEX_ENGINE},
        "agent_configs": {role: to_jsonable(agent_configs[role]) for role in CODEX_ROLES},
        "completed_finding_count": len(config.resume_reports or []),
        "current_finding_id": None,
        "current_finding_index": None,
        "resume_from_finding_id": None,
        "resume_from_finding_index": int(config.resume_from_finding_index or 0),
        "config": {
            "engine": CODEX_ENGINE,
            "report_path": str(config.sarif_path),
            "source_path": str(config.source_path),
            "skills_path": str(config.skills_path) if config.skills_path else None,
            "max_rounds": config.max_rounds,
            "enable_external_tools": True,
        },
        "codex_sessions": session_payload,
        "codex_workflow": {
            "engine": CODEX_ENGINE,
            "run_dir": str(run_dir),
            "sessions": session_payload,
            "schedule": "moderator report processing -> affirmative -> negative -> moderator final",
        },
    }


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
    return {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
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
        "codex_workflow": {
            "affirmative": affirmative,
            "negative": negative,
            "moderator": final,
        },
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
    return {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
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
        "codex_workflow": {
            "affirmative": affirmative or {},
            "negative": negative or {},
            "moderator": final or {},
        },
    }


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


def _finding_to_prompt_payload(finding: Finding, source_path: Path) -> Dict[str, Any]:
    indexer = SourceIndexer(source_path)
    contexts = []
    for location in finding.locations[:8]:
        resolved = indexer.resolve_location(location)
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
