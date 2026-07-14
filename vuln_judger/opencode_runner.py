from __future__ import annotations

import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from .codex_runner import (
    CODEX_AGENT_FILE_NAMES,
    CODEX_ROLES,
    OPENCODE_ENGINE,
    REPO_ROOT,
    CliDrivenRunner,
    CliSession,
    CodexRunnerError,
    _cli_agent_file_text,
    _normalize_cli_prompt,
    _run_tmux,
    _safe_tmux_name,
    _wait_for_cli_task_start,
)
from .logging_config import logger
from .models import AgentConfig, RunConfig
from .opencode_prompt_client import submit_prompt_async


DEFAULT_OPENCODE_WORKSPACES_DIR = REPO_ROOT / ".workspaces" / "runs"
OPENCODE_PERMISSION_CONFIG = {"permission": "allow"}
LOG = logger("opencode_runner")


@dataclass(frozen=True)
class OpenCodeCapabilities:
    version: str
    attach_mini: bool = True


@dataclass
class OpenCodeSessionInfo:
    role: str
    session_name: str
    window_name: str
    target: str
    cwd: str
    backend: str
    transport: str
    server_url: str
    server_target: str
    provider_session_id: Optional[str]
    version: str
    event_log: Optional[str]


class OpenCodeTmuxSession:
    """Hosts OpenCode in tmux while prompts use its local HTTP API."""

    def __init__(
        self,
        *,
        role: str,
        run_id: str,
        cwd: Path,
        source_path: Path,
        run_dir: Path,
        command: str,
        capabilities: OpenCodeCapabilities,
        model: Optional[str] = None,
    ) -> None:
        self.role = role
        self.run_id = run_id
        self.cwd = cwd.expanduser().resolve()
        self.source_path = source_path.expanduser().resolve()
        self.run_dir = run_dir.expanduser().resolve()
        self.command = command
        self.capabilities = capabilities
        self.model = (model or "").strip() or None
        self.session_name = _safe_tmux_name(f"vj-{run_id}-{role}")
        self.window_name = "tui"
        self.target = f"{self.session_name}:{self.window_name}"
        self.server_target = f"{self.session_name}:server"
        self.run_target = f"{self.session_name}:run"
        self.config_path = self.cwd / ".opencode" / "opencode.json"
        self.logs_dir = self.cwd / ".vuln-judger-opencode"
        self.server_log = self.logs_dir / "server.log"
        self.state_path = self.logs_dir / "session.json"
        self._sequence = 0
        self._current_prompt_path: Optional[Path] = None
        self._current_request_path: Optional[Path] = None
        self._current_started_path: Optional[Path] = None
        self._current_event_path: Optional[Path] = None
        self._current_exit_path: Optional[Path] = None
        self._provider_session_id: Optional[str] = None
        self._session_recovery_attempted = False
        self._port = _free_local_port()
        self._load_state()

    @property
    def server_url(self) -> str:
        return f"http://127.0.0.1:{self._port}"

    def info(self) -> OpenCodeSessionInfo:
        self._refresh_provider_session_id()
        return OpenCodeSessionInfo(
            role=self.role,
            session_name=self.session_name,
            window_name=self.window_name,
            target=self.target,
            cwd=str(self.cwd),
            backend=OPENCODE_ENGINE,
            transport="serve+prompt-api",
            server_url=self.server_url,
            server_target=self.server_target,
            provider_session_id=self._provider_session_id,
            version=self.capabilities.version,
            event_log=str(self._current_event_path) if self._current_event_path else None,
        )

    def start(self) -> None:
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        if self.is_live() and _server_healthy(self.server_url):
            if _tmux_target_live(self.run_target):
                _run_tmux(["tmux", "kill-window", "-t", self.run_target], timeout=10, check=False)
            provider_changed = self._ensure_provider_session(validate=True)
            self._save_state()
            self._ensure_tui(restart=provider_changed)
            return
        if _tmux_target_live(self.session_name):
            _run_tmux(["tmux", "kill-session", "-t", self.session_name], check=False)
        self._port = _free_local_port()
        command = _shell_command(
            [
                "env",
                f"OPENCODE_CONFIG={self.config_path}",
                f"OPENCODE_CONFIG_CONTENT={_permission_config_content()}",
                self.command,
                "serve",
                "--hostname",
                "127.0.0.1",
                "--port",
                str(self._port),
            ]
        )
        command = f"{command} >> {shlex.quote(str(self.server_log))} 2>&1"
        _run_tmux(
            [
                "tmux",
                "new-session",
                "-d",
                "-s",
                self.session_name,
                "-n",
                "server",
                "-c",
                str(self.cwd),
                "sh",
                "-lc",
                command,
            ],
            timeout=30,
        )
        timeout = float(os.environ.get("VULN_JUDGER_OPENCODE_READY_TIMEOUT", "30"))
        if not _wait_for_server(self.server_url, timeout):
            self.stop()
            detail = _tail_text(self.server_log, 30)
            raise CodexRunnerError(f"OpenCode server 未就绪：{self.server_url}; {detail}")
        self._ensure_provider_session(validate=True)
        self._save_state()
        self._ensure_tui()
        LOG.info(
            "OpenCode server ready",
            extra={
                "event": "opencode.server.ready",
                "run_id": self.run_id,
                "role": self.role,
                "server_url": self.server_url,
            },
        )

    def is_live(self) -> bool:
        return _tmux_target_live(self.server_target)

    def stop(self) -> None:
        if _tmux_target_live(self.session_name):
            _run_tmux(["tmux", "kill-session", "-t", self.session_name], timeout=10, check=False)

    def send(self, text: str) -> None:
        text = _normalize_cli_prompt(text)
        if not text:
            raise CodexRunnerError("OpenCode prompt 不能为空")
        if not self.is_live():
            self.start()
        if _tmux_target_live(self.run_target):
            raise CodexRunnerError(f"OpenCode session 正在执行任务：{self.role}")
        self._rotate_provider_session()
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self._session_recovery_attempted = False
        self._launch_prompt(text)

    def _launch_prompt(self, text: str) -> None:
        self._refresh_provider_session_id()
        if not self._provider_session_id:
            provider_changed = self._ensure_provider_session()
            self._ensure_tui(restart=provider_changed)
        self._sequence += 1
        prompt_path = self.logs_dir / f"prompt-{self._sequence:04d}.txt"
        request_path = self.logs_dir / f"request-{self._sequence:04d}.json"
        event_path = self.logs_dir / f"events-{self._sequence:04d}.ndjson"
        started_path = self.logs_dir / f"started-{self._sequence:04d}.txt"
        exit_path = self.logs_dir / f"exit-{self._sequence:04d}.txt"
        prompt_path.write_text(text, encoding="utf-8")
        request_payload: Dict[str, Any] = {"parts": [{"type": "text", "text": text}]}
        model_parts = _split_opencode_model(self.model)
        if model_parts:
            provider_id, model_id = model_parts
            request_payload["model"] = {
                "providerID": provider_id,
                "modelID": model_id,
            }
        request_path.write_text(
            json.dumps(request_payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        event_path.unlink(missing_ok=True)
        started_path.unlink(missing_ok=True)
        exit_path.unlink(missing_ok=True)

        prompt_client = Path(__file__).with_name("opencode_prompt_client.py").resolve()
        args = [
            sys.executable,
            str(prompt_client),
            "--server-url",
            self.server_url,
            "--session-id",
            self._provider_session_id,
            "--directory",
            str(self.cwd),
            "--request-file",
            str(request_path),
        ]
        # In the reported WSL setup, `opencode run --attach` launched from a
        # detached tmux pane accepted the prompt but did not reliably start the
        # agent response. Submit through the already healthy local server instead;
        # the prompt stays out of argv and the worker remains observable in tmux.
        invocation = _shell_command(args)
        shell = (
            f"set +e; printf '%s\\n' \"$$\" > {shlex.quote(str(started_path))}; "
            f"{invocation} "
            f"> {shlex.quote(str(event_path))} 2>&1; status=$?; "
            f"printf '%s\\n' \"$status\" > {shlex.quote(str(exit_path))}; exit \"$status\""
        )
        self._current_event_path = event_path
        self._current_exit_path = exit_path
        self._current_prompt_path = prompt_path
        self._current_request_path = request_path
        self._current_started_path = started_path
        _run_tmux(
            [
                "tmux",
                "new-window",
                "-d",
                "-t",
                self.session_name,
                "-n",
                "run",
                "-c",
                str(self.cwd),
                "sh",
                "-lc",
                shell,
            ],
            timeout=15,
        )
        _wait_for_cli_task_start(
            label=f"OpenCode {self.role}",
            started_path=started_path,
            event_path=event_path,
            exit_path=exit_path,
            is_running=lambda: _tmux_target_live(self.run_target),
        )
        self._save_state()
        LOG.info(
            "OpenCode prompt sent",
            extra={
                "event": "opencode.prompt.send",
                "run_id": self.run_id,
                "role": self.role,
                "provider_session_id": self._provider_session_id,
                "prompt_path": str(prompt_path),
            },
        )

    def capture(self, lines: int = 240) -> str:
        parts = []
        if self._current_event_path:
            parts.append(_tail_text(self._current_event_path, lines))
        if self.server_log.exists():
            parts.append(_tail_text(self.server_log, min(lines, 80)))
        return "\n".join(part for part in parts if part)

    def activity_snapshot(self) -> tuple[str, bool]:
        self._refresh_provider_session_id()
        self._ensure_tui()
        token = ""
        if self._current_event_path and self._current_event_path.exists():
            stat = self._current_event_path.stat()
            token = f"{stat.st_size}:{stat.st_mtime_ns}:{self._provider_session_id or ''}"
        return token, _tmux_target_live(self.run_target)

    def failure_message(self) -> Optional[str]:
        if _tmux_target_live(self.run_target):
            return None
        if (
            self._current_started_path
            and self._current_started_path.exists()
            and (self._current_exit_path is None or not self._current_exit_path.exists())
        ):
            detail = _tail_text(self._current_event_path, 30) if self._current_event_path else ""
            return f"OpenCode prompt 请求异常终止，未写入退出码；{detail}"
        if self._current_exit_path is None or not self._current_exit_path.exists():
            return None
        try:
            exit_code = int(self._current_exit_path.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return None
        if exit_code == 0:
            return None
        detail = _tail_text(self._current_event_path, 30) if self._current_event_path else ""
        lowered = detail.lower()
        invalid_session = self._provider_session_id and "session" in lowered and any(
            marker in lowered for marker in ("not found", "does not exist", "invalid session", "unknown session")
        )
        if invalid_session and not self._session_recovery_attempted and self._current_prompt_path:
            try:
                prompt = self._current_prompt_path.read_text(encoding="utf-8")
            except OSError:
                prompt = ""
            if prompt:
                self._session_recovery_attempted = True
                self._provider_session_id = None
                self._current_prompt_path = None
                self._current_request_path = None
                self._current_started_path = None
                self._current_event_path = None
                self._current_exit_path = None
                self._ensure_provider_session()
                self._ensure_tui(restart=True)
                self._save_state()
                self._launch_prompt(prompt)
                return None
        return f"OpenCode prompt 退出码 {exit_code}；{detail}"

    def task_finished(self) -> bool:
        return bool(
            not _tmux_target_live(self.run_target)
            and (
                (self._current_exit_path and self._current_exit_path.exists())
                or (self._current_started_path and self._current_started_path.exists())
            )
        )

    def _load_state(self) -> None:
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(state, dict):
            return
        try:
            self._sequence = max(int(state.get("sequence") or 0), 0)
        except (TypeError, ValueError):
            self._sequence = 0
        self._provider_session_id = _text(state.get("provider_session_id"))
        port = state.get("port")
        if isinstance(port, int) and 0 < port < 65536:
            self._port = port
        event_log = _text(state.get("event_log"))
        started_log = _text(state.get("started_log"))
        exit_log = _text(state.get("exit_log"))
        prompt_log = _text(state.get("prompt_log"))
        request_log = _text(state.get("request_log"))
        self._current_prompt_path = Path(prompt_log) if prompt_log else None
        self._current_request_path = Path(request_log) if request_log else None
        self._current_started_path = Path(started_log) if started_log else None
        self._current_event_path = Path(event_log) if event_log else None
        self._current_exit_path = Path(exit_log) if exit_log else None

    def _save_state(self) -> None:
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "sequence": self._sequence,
            "port": self._port,
            "server_url": self.server_url,
            "provider_session_id": self._provider_session_id,
            "prompt_log": str(self._current_prompt_path) if self._current_prompt_path else None,
            "request_log": str(self._current_request_path) if self._current_request_path else None,
            "started_log": str(self._current_started_path) if self._current_started_path else None,
            "event_log": str(self._current_event_path) if self._current_event_path else None,
            "exit_log": str(self._current_exit_path) if self._current_exit_path else None,
            "version": self.capabilities.version,
        }
        self.state_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def _refresh_provider_session_id(self) -> None:
        if self._provider_session_id:
            self._ensure_tui()
            return
        if not self._current_event_path or not self._current_event_path.exists():
            return
        try:
            lines = self._current_event_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return
        for line in lines:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            session_id = _find_session_id(event)
            if session_id:
                changed = session_id != self._provider_session_id
                self._provider_session_id = session_id
                self._save_state()
                self._ensure_tui(restart=changed)
                return

    def _ensure_provider_session(self, *, validate: bool = False) -> bool:
        if self._provider_session_id and (
            not validate or _opencode_session_exists(self.server_url, self._provider_session_id)
        ):
            return False
        self._provider_session_id = _create_opencode_session(
            self.server_url,
            title=f"vuln-judger {self.run_id} {self.role}",
            directory=self.cwd,
            model=self.model,
        )
        return True

    def _rotate_provider_session(self) -> None:
        self._provider_session_id = _create_opencode_session(
            self.server_url,
            title=f"vuln-judger {self.run_id} {self.role} task-{self._sequence + 1}",
            directory=self.cwd,
            model=self.model,
        )
        self._save_state()
        # Keep the same tmux pane so an already-open Dashboard WebSocket does not
        # fall back to the server window when the provider session changes.
        self._ensure_tui(restart=True)

    def _ensure_tui(self, *, restart: bool = False) -> None:
        if not self._provider_session_id or not _tmux_target_live(self.server_target):
            return
        _ensure_opencode_tui_window(
            session_name=self.session_name,
            cwd=self.cwd,
            server_url=self.server_url,
            provider_session_id=self._provider_session_id,
            command=self.command,
            config_path=self.config_path,
            mini=self.capabilities.attach_mini,
            restart=restart,
        )


class OpenCodeDrivenRunner(CliDrivenRunner):
    engine = OPENCODE_ENGINE
    cli_name = "OpenCode"
    session_description = "OpenCode server"

    def __init__(
        self,
        *,
        records_dir: Path,
        opencode_runs_dir: Optional[Path] = None,
        opencode_command: Optional[str] = None,
    ) -> None:
        runs_dir = (
            opencode_runs_dir.expanduser().resolve()
            if opencode_runs_dir is not None
            else Path(
                os.environ.get("VULN_JUDGER_OPENCODE_WORKSPACES_DIR", DEFAULT_OPENCODE_WORKSPACES_DIR)
            ).expanduser().resolve()
        )
        super().__init__(records_dir=records_dir, runs_dir=runs_dir)
        self.opencode_command = (
            opencode_command
            or os.environ.get("VULN_JUDGER_OPENCODE_COMMAND")
            or shutil.which("opencode")
            or "opencode"
        )
        self.capabilities: Optional[OpenCodeCapabilities] = None
        self.model: Optional[str] = None

    def _configure(self, config: RunConfig) -> None:
        self.model = config.llm_model or os.environ.get("VULN_JUDGER_OPENCODE_MODEL")

    def _prepare_run_dir(self, run_dir: Path) -> None:
        self.capabilities = probe_opencode(self.opencode_command)

    def _prepare_agent_dirs(
        self,
        run_dir: Path,
        agent_configs: Dict[str, AgentConfig],
        source_path: Path,
    ) -> Dict[str, Path]:
        session_dirs: Dict[str, Path] = {}
        for role in CODEX_ROLES:
            role_dir = run_dir / "sessions" / role
            role_dir.mkdir(parents=True, exist_ok=True)
            agent_text = _cli_agent_file_text(
                role=role,
                agent=agent_configs[role],
                source_path=source_path,
                run_dir=run_dir,
                cli_name="OpenCode",
            )
            for file_name in CODEX_AGENT_FILE_NAMES:
                (role_dir / file_name).write_text(agent_text + "\n", encoding="utf-8")
            config_path = role_dir / ".opencode" / "opencode.json"
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(
                json.dumps(
                    {"$schema": "https://opencode.ai/config.json", **OPENCODE_PERMISSION_CONFIG},
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            session_dirs[role] = role_dir
        return session_dirs

    def _sessions(
        self,
        run_id: str,
        source_path: Path,
        run_dir: Path,
        session_dirs: Dict[str, Path],
    ) -> Dict[str, CliSession]:
        if self.capabilities is None:
            raise CodexRunnerError("OpenCode capabilities 尚未探测")
        return {
            role: OpenCodeTmuxSession(
                role=role,
                run_id=run_id,
                cwd=session_dirs[role],
                source_path=source_path,
                run_dir=run_dir,
                command=self.opencode_command,
                capabilities=self.capabilities,
                model=self.model,
            )
            for role in CODEX_ROLES
        }


def probe_opencode(command: str) -> OpenCodeCapabilities:
    version_result = _run_opencode([command, "--version"], timeout=15)
    attach_result = _run_opencode([command, "attach", "--help"], timeout=15)
    attach_help = f"{attach_result.stdout}\n{attach_result.stderr}"
    attach_missing = [flag for flag in ("--dir", "--session") if flag not in attach_help]
    if attach_missing:
        raise CodexRunnerError(f"OpenCode attach 缺少必要能力：{', '.join(attach_missing)}")
    if "--mini" not in attach_help:
        raise CodexRunnerError("OpenCode attach 缺少可捕获的 --mini TUI；请升级 OpenCode")
    return OpenCodeCapabilities(
        version=(version_result.stdout or version_result.stderr or "unknown").strip(),
        attach_mini=True,
    )


def _run_opencode(args: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise CodexRunnerError("opencode is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise CodexRunnerError(f"OpenCode 命令超时：{' '.join(args)}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "OpenCode command failed").strip()
        raise CodexRunnerError(detail)
    return result


def _permission_config_content() -> str:
    return json.dumps(OPENCODE_PERMISSION_CONFIG, separators=(",", ":"))


def ensure_opencode_tui(session: Dict[str, Any]) -> str:
    session_name = _text(session.get("session_name"))
    cwd_text = _text(session.get("cwd"))
    server_url = _text(session.get("server_url"))
    provider_session_id = _text(session.get("provider_session_id"))
    if not all((session_name, cwd_text, server_url)):
        raise CodexRunnerError("OpenCode TUI 元数据不完整")
    if not server_url.startswith(("http://127.0.0.1:", "http://localhost:")):
        raise CodexRunnerError("OpenCode server URL 必须指向本机")
    cwd = Path(cwd_text).expanduser().resolve()
    if not cwd.is_dir():
        raise CodexRunnerError(f"OpenCode session 目录不存在：{cwd}")
    target = f"{session_name}:tui"
    if _tmux_target_live(target):
        return target
    if not provider_session_id:
        raise CodexRunnerError("OpenCode session ID 尚未生成")
    command = os.environ.get("VULN_JUDGER_OPENCODE_COMMAND") or shutil.which("opencode") or "opencode"
    attach_help = _run_opencode([command, "attach", "--help"], timeout=15)
    if "--mini" not in f"{attach_help.stdout}\n{attach_help.stderr}":
        raise CodexRunnerError("OpenCode attach 缺少可捕获的 --mini TUI；请升级 OpenCode")
    return _ensure_opencode_tui_window(
        session_name=session_name,
        cwd=cwd,
        server_url=server_url,
        provider_session_id=provider_session_id,
        command=command,
        config_path=cwd / ".opencode" / "opencode.json",
        mini=True,
    )


def send_opencode_session_message(session: Dict[str, Any], text: str) -> Dict[str, str]:
    server_url = _text(session.get("server_url"))
    session_id = _text(session.get("provider_session_id"))
    cwd_text = _text(session.get("cwd"))
    if not all((server_url, session_id, cwd_text)):
        raise CodexRunnerError("OpenCode session 元数据不完整")
    if not server_url.startswith(("http://127.0.0.1:", "http://localhost:")):
        raise CodexRunnerError("OpenCode server URL 必须指向本机")
    cwd = Path(cwd_text).expanduser().resolve()
    if not cwd.is_dir():
        raise CodexRunnerError(f"OpenCode session 目录不存在：{cwd}")
    normalized = _normalize_cli_prompt(text)
    if not normalized:
        raise CodexRunnerError("OpenCode message 不能为空")
    timeout_raw = os.environ.get("VULN_JUDGER_OPENCODE_MANUAL_PROMPT_TIMEOUT", "10")
    try:
        timeout = max(float(timeout_raw), 0.1)
    except ValueError as exc:
        raise CodexRunnerError(
            f"VULN_JUDGER_OPENCODE_MANUAL_PROMPT_TIMEOUT 无效：{timeout_raw}"
        ) from exc
    try:
        message_id = submit_prompt_async(
            server_url=server_url,
            session_id=session_id,
            directory=str(cwd),
            payload={"parts": [{"type": "text", "text": normalized}]},
            timeout=timeout,
        )
    except RuntimeError as exc:
        raise CodexRunnerError(str(exc)) from exc
    return {
        "message_id": message_id,
        "session_id": session_id,
        "target": f"{session.get('session_name')}:tui",
    }


def _ensure_opencode_tui_window(
    *,
    session_name: str,
    cwd: Path,
    server_url: str,
    provider_session_id: str,
    command: str,
    config_path: Path,
    mini: bool,
    restart: bool = False,
) -> str:
    target = f"{session_name}:tui"
    target_live = _tmux_target_live(target)
    if target_live and not restart:
        return target
    server_target = f"{session_name}:server"
    if not _tmux_target_live(server_target):
        raise CodexRunnerError(f"OpenCode server session 未运行：{server_target}")
    args = [
        "env",
        f"OPENCODE_CONFIG={config_path}",
        f"OPENCODE_CONFIG_CONTENT={_permission_config_content()}",
        command,
        "attach",
        server_url,
        "--dir",
        str(cwd),
        "--session",
        provider_session_id,
    ]
    if mini:
        args.append("--mini")
    if target_live:
        _run_tmux(
            [
                "tmux",
                "respawn-pane",
                "-k",
                "-t",
                target,
                "-c",
                str(cwd),
                *args,
            ],
            timeout=15,
        )
    else:
        _run_tmux(
            [
                "tmux",
                "new-window",
                "-d",
                "-t",
                session_name,
                "-n",
                "tui",
                "-c",
                str(cwd),
                *args,
            ],
            timeout=15,
        )
    _wait_for_opencode_tui(target)
    return target


def _shell_command(args: list[str]) -> str:
    return " ".join(shlex.quote(str(arg)) for arg in args)


def _tmux_target_live(target: str) -> bool:
    return _run_tmux(["tmux", "list-panes", "-t", target], timeout=5, check=False).returncode == 0


def _wait_for_opencode_tui(target: str) -> None:
    timeout = float(os.environ.get("VULN_JUDGER_OPENCODE_TUI_READY_TIMEOUT", "10"))
    deadline = time.monotonic() + max(timeout, 0.1)
    detail = ""
    while time.monotonic() < deadline:
        result = _run_tmux(
            ["tmux", "capture-pane", "-p", "-t", target],
            timeout=5,
            check=False,
        )
        if result.returncode == 0 and (result.stdout or "").strip():
            return
        detail = (result.stderr or result.stdout or "").strip()
        time.sleep(0.1)
    suffix = f"；{detail}" if detail else ""
    raise CodexRunnerError(f"OpenCode TUI 未在超时内生成可捕获画面：{target}{suffix}")


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_server(url: str, timeout: float) -> bool:
    deadline = time.monotonic() + max(timeout, 0.1)
    while time.monotonic() < deadline:
        if _server_healthy(url):
            return True
        time.sleep(0.2)
    return False


def _server_healthy(url: str) -> bool:
    try:
        with urllib.request.urlopen(f"{url}/global/health", timeout=1) as response:
            return 200 <= response.status < 300
    except (OSError, urllib.error.URLError):
        return False


def _opencode_session_exists(url: str, session_id: str) -> bool:
    encoded_id = urllib.parse.quote(session_id, safe="")
    try:
        with urllib.request.urlopen(f"{url}/session/{encoded_id}", timeout=3) as response:
            return 200 <= response.status < 300
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        raise CodexRunnerError(f"OpenCode session 校验失败：HTTP {exc.code}") from exc
    except (OSError, urllib.error.URLError) as exc:
        raise CodexRunnerError(f"OpenCode session 校验失败：{exc}") from exc


def _split_opencode_model(model: Optional[str]) -> Optional[tuple[str, str]]:
    value = (model or "").strip()
    if not value:
        return None
    provider_id, separator, model_id = value.partition("/")
    if not separator or not provider_id.strip() or not model_id.strip():
        raise CodexRunnerError("OpenCode model 必须使用 provider/model 格式")
    return provider_id.strip(), model_id.strip()


def _create_opencode_session(
    url: str,
    *,
    title: str,
    directory: Path,
    model: Optional[str],
) -> str:
    body: Dict[str, Any] = {"title": title}
    model_parts = _split_opencode_model(model)
    if model_parts:
        provider_id, model_id = model_parts
        body["model"] = {"providerID": provider_id, "id": model_id}
    query = urllib.parse.urlencode({"directory": str(directory)})
    request = urllib.request.Request(
        f"{url}/session?{query}",
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise CodexRunnerError(f"OpenCode session 创建失败：HTTP {exc.code}") from exc
    except (OSError, urllib.error.URLError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CodexRunnerError(f"OpenCode session 创建失败：{exc}") from exc
    session_id = _text(payload.get("id")) if isinstance(payload, dict) else None
    if not session_id:
        raise CodexRunnerError("OpenCode session 创建失败：响应缺少 id")
    return session_id


def _find_session_id(value: Any) -> Optional[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).replace("_", "").lower()
            if normalized == "sessionid" and isinstance(item, str) and item.strip():
                return item.strip()
        for item in value.values():
            found = _find_session_id(item)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_session_id(item)
            if found:
                return found
    return None


def _tail_text(path: Optional[Path], lines: int) -> str:
    if path is None:
        return ""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            values = deque(handle, maxlen=max(1, lines))
    except OSError:
        return ""
    return "".join(values).rstrip("\n")


def _text(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    return text or None
