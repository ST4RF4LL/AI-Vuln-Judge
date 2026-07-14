from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional


def send_prompt(
    *,
    server_url: str,
    session_id: str,
    directory: str,
    payload: Dict[str, Any],
    timeout: Optional[float],
) -> Any:
    """Durably admit a prompt, resume the agent loop, and wait for its assistant turn."""

    prompt_text = _normalize_newlines(_payload_text(payload))
    encoded_session = urllib.parse.quote(session_id, safe="")
    base_url = server_url.rstrip("/")
    deadline = time.monotonic() + timeout if timeout is not None else None
    admission = _request_json(
        f"{base_url}/api/session/{encoded_session}/prompt",
        method="POST",
        payload={
            "prompt": {"text": prompt_text},
            "delivery": "queue",
            "resume": True,
        },
        timeout=_request_timeout(deadline, session_id),
        session_id=session_id,
        operation="prompt admission",
    )
    admitted = admission.get("data") if isinstance(admission, dict) else None
    message_id = admitted.get("id") if isinstance(admitted, dict) else None
    if not isinstance(message_id, str) or not message_id:
        raise RuntimeError(f"OpenCode session {session_id} prompt admission response is missing id")

    query = urllib.parse.urlencode({"directory": directory})
    messages_url = f"{base_url}/session/{encoded_session}/message?{query}"
    status_url = f"{base_url}/session/status?{query}"
    start_deadline = time.monotonic() + _agent_start_timeout()
    started = False
    idle_since: Optional[float] = None

    while True:
        request_timeout = _request_timeout(deadline, session_id)
        messages = _request_json(
            messages_url,
            timeout=request_timeout,
            session_id=session_id,
            operation="message polling",
        )
        assistant = _assistant_for_prompt(messages, message_id)
        if assistant is not None:
            started = True
            info = assistant.get("info") if isinstance(assistant, dict) else None
            if isinstance(info, dict) and info.get("error"):
                raise RuntimeError(
                    f"OpenCode session {session_id} assistant failed: "
                    f"{json.dumps(info['error'], ensure_ascii=False)}"
                )
            completed = isinstance(info, dict) and (
                isinstance(info.get("time"), dict) and info["time"].get("completed") is not None
                or bool(info.get("finish"))
            )
            if completed:
                return {"admission": admitted, "assistant": assistant}

        statuses = _request_json(
            status_url,
            timeout=_request_timeout(deadline, session_id),
            session_id=session_id,
            operation="status polling",
        )
        status = statuses.get(session_id) if isinstance(statuses, dict) else None
        status_type = status.get("type") if isinstance(status, dict) else "idle"
        if status_type in {"busy", "retry"}:
            started = True
            idle_since = None
        elif status_type == "idle":
            idle_since = idle_since or time.monotonic()

        now = time.monotonic()
        if not started and now >= start_deadline:
            raise RuntimeError(
                f"OpenCode session {session_id} accepted prompt {message_id} but agent loop did not start; "
                "prompt newlines were normalized to LF"
            )
        if started and idle_since is not None and now - idle_since >= 5:
            detail = "without creating an assistant response" if assistant is None else "before the assistant completed"
            raise RuntimeError(
                f"OpenCode session {session_id} returned to idle {detail} for prompt {message_id}"
            )
        time.sleep(_poll_interval())


def _request_json(
    url: str,
    *,
    session_id: str,
    operation: str,
    timeout: float,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
) -> Any:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        headers={"content-type": "application/json", "accept": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", errors="replace").strip()
        except OSError:
            detail = ""
        marker = " not found" if exc.code == 404 else ""
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(
            f"OpenCode session {session_id}{marker}; {operation} HTTP {exc.code}{suffix}"
        ) from exc
    except (OSError, urllib.error.URLError) as exc:
        raise RuntimeError(f"OpenCode session {session_id} {operation} failed: {exc}") from exc
    if not raw.strip():
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"OpenCode session {session_id} {operation} returned invalid JSON: {exc}"
        ) from exc


def _request_timeout(deadline: Optional[float], session_id: str) -> float:
    if deadline is None:
        return 10.0
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError(f"OpenCode session {session_id} prompt timed out")
    return max(min(remaining, 10.0), 0.1)


def _assistant_for_prompt(messages: Any, message_id: str) -> Optional[Dict[str, Any]]:
    if not isinstance(messages, list):
        return None
    for message in reversed(messages):
        if not isinstance(message, dict):
            continue
        info = message.get("info")
        if (
            isinstance(info, dict)
            and info.get("role") == "assistant"
            and info.get("parentID") == message_id
        ):
            return message
    return None


def _payload_text(payload: Dict[str, Any]) -> str:
    parts = payload.get("parts")
    if not isinstance(parts, list):
        raise RuntimeError("OpenCode prompt request is missing parts")
    texts = [
        str(part.get("text"))
        for part in parts
        if isinstance(part, dict) and part.get("type") == "text" and part.get("text") is not None
    ]
    if not texts:
        raise RuntimeError("OpenCode prompt request does not contain text")
    return "\n".join(texts)


def _normalize_newlines(value: str) -> str:
    return str(value).replace("\r\n", "\n").replace("\r", "\n")


def _agent_start_timeout() -> float:
    raw = os.environ.get("VULN_JUDGER_OPENCODE_AGENT_START_TIMEOUT", "15")
    try:
        return max(float(raw), 0.1)
    except ValueError as exc:
        raise RuntimeError(f"Invalid VULN_JUDGER_OPENCODE_AGENT_START_TIMEOUT: {raw}") from exc


def _poll_interval() -> float:
    raw = os.environ.get("VULN_JUDGER_OPENCODE_POLL_INTERVAL", "0.25")
    try:
        return max(float(raw), 0.01)
    except ValueError as exc:
        raise RuntimeError(f"Invalid VULN_JUDGER_OPENCODE_POLL_INTERVAL: {raw}") from exc


def _load_payload(path: Path) -> Dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"OpenCode prompt request file is invalid: {path}: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("parts"), list):
        raise RuntimeError(f"OpenCode prompt request file is missing parts: {path}")
    return payload


def _timeout() -> Optional[float]:
    raw = os.environ.get("VULN_JUDGER_OPENCODE_PROMPT_TIMEOUT")
    if raw in (None, ""):
        return None
    try:
        timeout = float(raw)
    except ValueError as exc:
        raise RuntimeError(f"Invalid VULN_JUDGER_OPENCODE_PROMPT_TIMEOUT: {raw}") from exc
    return timeout if timeout > 0 else None


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Submit a prompt to a local OpenCode server")
    parser.add_argument("--server-url", required=True)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--request-file", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        payload = _load_payload(args.request_file)
        raw_text = _payload_text(payload)
        print(
            json.dumps(
                {
                    "type": "prompt_request_started",
                    "sessionID": args.session_id,
                    "characters": len(raw_text),
                    "cr_count_before_normalization": raw_text.count("\r"),
                    "newline_mode": "lf",
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
        response = send_prompt(
            server_url=args.server_url,
            session_id=args.session_id,
            directory=args.directory,
            payload=payload,
            timeout=_timeout(),
        )
    except RuntimeError as exc:
        print(
            json.dumps(
                {"type": "prompt_request_error", "sessionID": args.session_id, "error": str(exc)},
                ensure_ascii=False,
            ),
            flush=True,
        )
        return 1

    print(
        json.dumps(
            {"type": "prompt_response", "sessionID": args.session_id, "response": response},
            ensure_ascii=False,
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
