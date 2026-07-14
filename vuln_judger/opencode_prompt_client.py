from __future__ import annotations

import argparse
import json
import os
import sys
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
    """Submit one prompt through the OpenCode server without invoking its CLI frontend."""

    encoded_session = urllib.parse.quote(session_id, safe="")
    query = urllib.parse.urlencode({"directory": directory})
    request = urllib.request.Request(
        f"{server_url.rstrip('/')}/session/{encoded_session}/message?{query}",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"content-type": "application/json", "accept": "application/json"},
        method="POST",
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
            f"OpenCode session {session_id}{marker}; prompt HTTP {exc.code}{suffix}"
        ) from exc
    except (OSError, urllib.error.URLError) as exc:
        raise RuntimeError(f"OpenCode session {session_id} prompt request failed: {exc}") from exc

    if not raw.strip():
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"OpenCode session {session_id} returned invalid JSON: {exc}") from exc


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

    print(
        json.dumps(
            {"type": "prompt_request_started", "sessionID": args.session_id},
            ensure_ascii=False,
        ),
        flush=True,
    )
    try:
        response = send_prompt(
            server_url=args.server_url,
            session_id=args.session_id,
            directory=args.directory,
            payload=_load_payload(args.request_file),
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
