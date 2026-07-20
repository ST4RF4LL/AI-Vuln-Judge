from __future__ import annotations

import fcntl
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from uuid import uuid4

from .models import RunReport, to_jsonable
from .run_state import (
    FINDING_COMPLETED,
    completed_finding_count,
    finding_report_status,
    first_incomplete_finding_index,
    mark_incomplete_findings_pending,
)


class RunRecordStore:
    def __init__(self, root: Path):
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.locks_root = self.root / ".locks"
        self.locks_root.mkdir(parents=True, exist_ok=True)

    def save(self, report: RunReport) -> Dict[str, Any]:
        payload = to_jsonable(report)
        return self.save_payload(payload)

    def save_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        run_id = str(payload.get("run_id") or "run-unknown")
        lock_file = self._lock_record(run_id)
        try:
            path = self._path(run_id)
            current = self._read_path(path)
            if current is not None:
                payload["manual_reviews"] = _manual_reviews(current)
            elif not isinstance(payload.get("manual_reviews"), dict):
                payload["manual_reviews"] = {}
            self._write_path(path, payload)
        finally:
            _unlock_file(lock_file)
        return payload

    def update_manual_review(
        self,
        run_id: str,
        finding_id: str,
        *,
        decision: str,
        evidence: str,
    ) -> Optional[Tuple[Dict[str, Any], bool]]:
        lock_file = self._lock_record(run_id)
        try:
            path = self._path(run_id)
            payload = self._read_path(path)
            if payload is None:
                return None
            reviews = _manual_reviews(payload)
            existing = reviews.get(finding_id) if isinstance(reviews.get(finding_id), dict) else {}
            created = not bool(existing)
            now = _now()
            review = {
                "schema_version": 1,
                "decision": decision,
                "evidence": evidence,
                "created_at": existing.get("created_at") or now,
                "updated_at": now,
            }
            reviews[finding_id] = review
            payload["manual_reviews"] = reviews
            self._write_path(path, payload)
            return dict(review), created
        finally:
            _unlock_file(lock_file)

    def delete_manual_review(self, run_id: str, finding_id: str) -> Optional[bool]:
        lock_file = self._lock_record(run_id)
        try:
            path = self._path(run_id)
            payload = self._read_path(path)
            if payload is None:
                return None
            reviews = _manual_reviews(payload)
            deleted = reviews.pop(finding_id, None) is not None
            payload["manual_reviews"] = reviews
            if deleted:
                self._write_path(path, payload)
            return deleted
        finally:
            _unlock_file(lock_file)

    @staticmethod
    def _read_path(path: Path) -> Optional[Dict[str, Any]]:
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        return payload if isinstance(payload, dict) else None

    @staticmethod
    def _write_path(path: Path, payload: Dict[str, Any]) -> None:
        tmp_path = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        try:
            tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            tmp_path.replace(path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def get(self, run_id: str) -> Optional[Dict[str, Any]]:
        path = self._path(run_id)
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def delete(self, run_id: str) -> bool:
        lock_file = self._lock_record(run_id)
        try:
            path = self._path(run_id)
            existed = path.exists()
            if existed:
                path.unlink()
        finally:
            _unlock_file(lock_file)
        RunControlStore(self.root).delete(run_id)
        return existed

    def list(self) -> List[Dict[str, Any]]:
        records = []
        for path in sorted(self.root.glob("run-*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            records.append(_summary(payload))
        records.sort(key=lambda item: item.get("created_at") or "", reverse=True)
        return records

    def recover_unfinished(self) -> List[Dict[str, Any]]:
        recovered = []
        control_store = RunControlStore(self.root)
        for path in sorted(self.root.glob("run-*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            status = str(payload.get("status") or "completed")
            if status not in {"running", "pausing", "queued", "stopping"}:
                continue
            if control_store.has_live_owner(str(payload.get("run_id") or path.stem)):
                continue
            if status == "stopping":
                updated = _stopped_after_restart(payload)
            else:
                updated = _paused_after_restart(payload)
            self.save_payload(updated)
            recovered.append(updated)
        return recovered

    def _path(self, run_id: str) -> Path:
        safe = _safe_run_id(run_id)
        return self.root / f"{safe}.json"

    def _lock_record(self, run_id: str):
        lock_file = (self.locks_root / f"{_safe_run_id(run_id)}.lock").open("a+", encoding="utf-8")
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        return lock_file


class RunControlStore:
    """Cross-process pause/stop commands and a single-worker ownership lease."""

    ACTIONS = {"pause", "stop"}

    def __init__(self, records_root: Path):
        self.root = records_root.expanduser().resolve() / ".control"
        self.root.mkdir(parents=True, exist_ok=True)

    def claim(
        self,
        run_id: str,
        *,
        origin: str,
        allow_paused_takeover: bool = False,
    ) -> Optional[str]:
        owner_id = uuid4().hex
        lock_file, state = self._locked_state(run_id)
        try:
            current_owner = str(state.get("owner_id") or "")
            current_pid = _optional_int(state.get("owner_pid"))
            current_live = bool(current_owner and current_pid and _pid_alive(current_pid))
            can_take_over = allow_paused_takeover and state.get("action") == "pause"
            if current_live and not can_take_over:
                return None
            generation = int(state.get("generation") or 0) + 1
            state.update(
                {
                    "run_id": run_id,
                    "owner_id": owner_id,
                    "owner_pid": os.getpid(),
                    "owner_origin": origin,
                    "generation": generation,
                    "action": None,
                    "claimed_at": _now(),
                    "released_at": None,
                }
            )
            self._write_state(run_id, state)
            return owner_id
        finally:
            self._unlock(lock_file)

    def request(
        self,
        run_id: str,
        action: str,
        *,
        requested_by: str,
        before_signal: Optional[Callable[[], None]] = None,
    ) -> bool:
        action = str(action or "").strip().lower()
        if action not in self.ACTIONS:
            raise ValueError(f"Unsupported run control action: {action}")
        lock_file, state = self._locked_state(run_id)
        try:
            owner_id = str(state.get("owner_id") or "")
            owner_pid = _optional_int(state.get("owner_pid"))
            if not owner_id or not owner_pid or not _pid_alive(owner_pid):
                return False
            if before_signal is not None:
                before_signal()
            state.update(
                {
                    "action": action,
                    "requested_by": requested_by,
                    "requested_at": _now(),
                    "command_id": uuid4().hex,
                }
            )
            self._write_state(run_id, state)
            return True
        finally:
            self._unlock(lock_file)

    def requested_action(self, run_id: str, owner_id: str) -> Optional[str]:
        lock_file, state = self._locked_state(run_id)
        try:
            if str(state.get("owner_id") or "") != owner_id:
                return None
            action = str(state.get("action") or "").strip().lower()
            return action if action in self.ACTIONS else None
        finally:
            self._unlock(lock_file)

    def has_live_owner(self, run_id: str) -> bool:
        lock_file, state = self._locked_state(run_id)
        try:
            owner_id = str(state.get("owner_id") or "")
            owner_pid = _optional_int(state.get("owner_pid"))
            return bool(owner_id and owner_pid and _pid_alive(owner_pid))
        finally:
            self._unlock(lock_file)

    def release(self, run_id: str, owner_id: str) -> bool:
        lock_file, state = self._locked_state(run_id)
        try:
            if str(state.get("owner_id") or "") != owner_id:
                return False
            state.update(
                {
                    "last_action": state.get("action"),
                    "owner_id": None,
                    "owner_pid": None,
                    "action": None,
                    "released_at": _now(),
                }
            )
            self._write_state(run_id, state)
            return True
        finally:
            self._unlock(lock_file)

    def delete(self, run_id: str) -> None:
        lock_file, _state = self._locked_state(run_id)
        try:
            self._state_path(run_id).unlink(missing_ok=True)
        finally:
            self._unlock(lock_file)

    def _locked_state(self, run_id: str):
        lock_path = self._lock_path(run_id)
        lock_file = lock_path.open("a+", encoding="utf-8")
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        path = self._state_path(run_id)
        try:
            state = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        except (json.JSONDecodeError, OSError):
            state = {}
        if not isinstance(state, dict):
            state = {}
        return lock_file, state

    @staticmethod
    def _unlock(lock_file) -> None:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        finally:
            lock_file.close()

    def _write_state(self, run_id: str, state: Dict[str, Any]) -> None:
        path = self._state_path(run_id)
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        try:
            temporary.write_text(
                json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)

    def _state_path(self, run_id: str) -> Path:
        return self.root / f"{_safe_run_id(run_id)}.json"

    def _lock_path(self, run_id: str) -> Path:
        return self.root / f".{_safe_run_id(run_id)}.lock"


def _summary(payload: Dict[str, Any]) -> Dict[str, Any]:
    verdict_counts: Dict[str, int] = {}
    for report in payload.get("reports", []):
        if finding_report_status(report) != FINDING_COMPLETED:
            continue
        verdict = report.get("verdict", "UNKNOWN")
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
    workflow = payload.get("cli_workflow") if isinstance(payload.get("cli_workflow"), dict) else {}
    if not workflow and isinstance(payload.get("codex_workflow"), dict):
        workflow = payload["codex_workflow"]
    sessions = payload.get("cli_sessions") or payload.get("codex_sessions") or workflow.get("sessions") or []
    return {
        "run_id": payload.get("run_id"),
        "status": payload.get("status", "completed"),
        "engine": payload.get("engine") or (payload.get("config") or {}).get("engine") or "builtin",
        "run_origin": normalize_run_origin(payload),
        "created_at": payload.get("created_at"),
        "source_path": payload.get("source_path"),
        "sarif_path": payload.get("sarif_path"),
        "languages": payload.get("languages", []),
        "finding_count": payload.get("finding_count", 0),
        "project_context_facts": payload.get("project_context_facts", 0),
        "diagnostic_count": len(payload.get("diagnostics", [])),
        "verdict_counts": verdict_counts,
        "manual_review_count": len(_manual_reviews(payload)),
        "completed_finding_count": payload.get(
            "completed_finding_count",
            completed_finding_count(payload.get("reports", [])),
        ),
        "current_finding_id": payload.get("current_finding_id"),
        "current_finding_index": payload.get("current_finding_index"),
        "current_finding_ids": payload.get("current_finding_ids") or {},
        "resume_from_finding_id": payload.get("resume_from_finding_id"),
        "resume_from_finding_index": payload.get("resume_from_finding_index"),
        "cli_sessions": sessions,
        "codex_sessions": (payload.get("codex_sessions") or sessions) if payload.get("engine") == "codex" else [],
    }


def normalize_run_origin(payload: Dict[str, Any]) -> str:
    origin = str(payload.get("run_origin") or payload.get("origin") or payload.get("task_origin") or "").strip().lower()
    if origin in {"web", "mcp"}:
        return origin
    config = payload.get("config")
    if isinstance(config, dict) and config:
        return "web"
    if "source_finding_count" in payload:
        return "mcp"
    return "unknown"


def _paused_after_restart(payload: Dict[str, Any]) -> Dict[str, Any]:
    updated = dict(payload)
    reports = mark_incomplete_findings_pending(
        updated.get("reports") or [],
        updated.get("completed_finding_count"),
    )
    completed_count = completed_finding_count(reports)
    engine = str(updated.get("engine") or (updated.get("config") or {}).get("engine") or "builtin")
    if engine not in {"codex", "opencode"}:
        reports = reports[:completed_count]
    finding_count = _bounded_int(
        updated.get("finding_count"),
        default=len(reports),
        minimum=max(completed_count, len(reports)),
        maximum=10**9,
    )
    resume_index = first_incomplete_finding_index(reports, finding_count)
    resume_report = reports[resume_index] if resume_index < len(reports) else {}
    updated["status"] = "paused"
    updated["reports"] = reports
    updated["completed_finding_count"] = completed_count
    updated["resume_from_finding_id"] = (
        resume_report.get("finding_id")
        or updated.get("current_finding_id")
        or updated.get("resume_from_finding_id")
    )
    updated["resume_from_finding_index"] = resume_index
    updated["current_finding_id"] = None
    updated["current_finding_index"] = None
    updated["current_finding_ids"] = {}
    updated["error"] = None
    diagnostics = list(updated.get("diagnostics") or [])
    diagnostics.append(f"{_now()} 服务重启时发现任务未完成，已保存为暂停状态，可从恢复点继续。")
    updated["diagnostics"] = diagnostics
    return updated


def _stopped_after_restart(payload: Dict[str, Any]) -> Dict[str, Any]:
    updated = dict(payload)
    updated["status"] = "stopped"
    updated["current_finding_id"] = None
    updated["current_finding_index"] = None
    updated["current_finding_ids"] = {}
    updated["error"] = None
    diagnostics = list(updated.get("diagnostics") or [])
    diagnostics.append(f"{_now()} 服务重启时发现任务正在停止，已标记为已停止。")
    updated["diagnostics"] = diagnostics
    return updated


def _bounded_int(value, *, default: int, minimum: int, maximum: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        result = default
    return min(max(result, minimum), maximum)


def _optional_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _manual_reviews(payload: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    value = payload.get("manual_reviews")
    if not isinstance(value, dict):
        return {}
    return {
        str(finding_id): dict(review)
        for finding_id, review in value.items()
        if finding_id and isinstance(review, dict)
    }


def _unlock_file(lock_file) -> None:
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    finally:
        lock_file.close()


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _safe_run_id(run_id: str) -> str:
    return "".join(ch for ch in str(run_id) if ch.isalnum() or ch in {"-", "_"}) or "run-unknown"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
