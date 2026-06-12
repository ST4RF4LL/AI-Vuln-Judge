from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Sequence


class MCPError(RuntimeError):
    pass


DEFAULT_MCP_TIMEOUT_SECONDS = 120


class MCPStdioClient:
    """Minimal newline-delimited MCP stdio client used by Atlas 1.3.x."""

    def __init__(self, command: Sequence[str], cwd: Path, timeout: Optional[int] = None, env: Optional[Dict[str, str]] = None):
        self.command = list(command)
        self.cwd = cwd
        self.timeout = _timeout_seconds(timeout)
        self.env = dict(env or {})
        self._process: Optional[subprocess.Popen[str]] = None
        self._messages: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._reader: Optional[threading.Thread] = None
        self._next_id = 0

    def __enter__(self) -> "MCPStdioClient":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def start(self) -> None:
        if self._process is not None:
            return
        self._process = subprocess.Popen(
            self.command,
            cwd=str(self.cwd),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env={**os.environ, **self.env},
        )
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        response = self.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "vuln-judger", "version": "0.1"},
            },
        )
        if response.get("error"):
            raise MCPError(f"MCP initialize failed: {response['error']}")
        self.notify("notifications/initialized", {})

    def initialize(self) -> Dict[str, Any]:
        # Kept for callers that want symmetry with other clients; start() already initializes.
        if self._process is None:
            self.start()
        return {"initialized": True}

    def list_tools(self) -> Sequence[Dict[str, Any]]:
        response = self.request("tools/list", {})
        result = response.get("result") or {}
        return result.get("tools") or []

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": arguments}, label=f"tools/call:{name}")

    def request(self, method: str, params: Optional[Dict[str, Any]] = None, label: Optional[str] = None) -> Dict[str, Any]:
        process = self._require_process()
        self._next_id += 1
        request_id = self._next_id
        message: Dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self._write(message)
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise MCPError(f"MCP server exited with code {process.returncode}")
            try:
                received = self._messages.get(timeout=min(0.2, max(0.01, deadline - time.monotonic())))
            except queue.Empty:
                continue
            if received.get("id") == request_id:
                return received
        request_name = label or method
        raise MCPError(f"MCP request timed out after {self.timeout}s: {request_name}")

    def notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        message: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._write(message)

    def close(self) -> None:
        process = self._process
        self._process = None
        if process is None:
            return
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
        if process.stdout is not None:
            try:
                process.stdout.close()
            except OSError:
                pass
        if self._reader is not None:
            self._reader.join(timeout=0.2)

    def _require_process(self) -> subprocess.Popen[str]:
        if self._process is None or self._process.stdin is None:
            raise MCPError("MCP server is not started")
        return self._process

    def _write(self, message: Dict[str, Any]) -> None:
        process = self._require_process()
        assert process.stdin is not None
        process.stdin.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
        process.stdin.flush()

    def _read_loop(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        for raw in process.stdout:
            raw = raw.strip()
            if not raw:
                continue
            try:
                self._messages.put(json.loads(raw))
            except json.JSONDecodeError:
                self._messages.put({"jsonrpc": "2.0", "error": {"message": raw[:500]}})


def _timeout_seconds(value: Optional[int]) -> int:
    if value is not None:
        return max(1, int(value))
    raw = os.environ.get("VULN_JUDGER_MCP_TIMEOUT") or os.environ.get("VULN_JUDGER_ATLAS_MCP_TIMEOUT")
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            return DEFAULT_MCP_TIMEOUT_SECONDS
    return DEFAULT_MCP_TIMEOUT_SECONDS
