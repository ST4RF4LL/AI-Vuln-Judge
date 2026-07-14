from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
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

    def save(self, report: RunReport) -> Dict[str, Any]:
        payload = to_jsonable(report)
        return self.save_payload(payload)

    def save_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        path = self._path(str(payload.get("run_id") or "run-unknown"))
        tmp_path = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        try:
            tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            tmp_path.replace(path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()
        return payload

    def get(self, run_id: str) -> Optional[Dict[str, Any]]:
        path = self._path(run_id)
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def delete(self, run_id: str) -> bool:
        path = self._path(run_id)
        if not path.exists():
            return False
        path.unlink()
        return True

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
        for path in sorted(self.root.glob("run-*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            status = str(payload.get("status") or "completed")
            if status not in {"running", "pausing", "queued", "stopping"}:
                continue
            if status == "stopping":
                updated = _stopped_after_restart(payload)
            else:
                updated = _paused_after_restart(payload)
            self.save_payload(updated)
            recovered.append(updated)
        return recovered

    def _path(self, run_id: str) -> Path:
        safe = "".join(ch for ch in run_id if ch.isalnum() or ch in {"-", "_"})
        return self.root / f"{safe}.json"


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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
