from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import RunReport, to_jsonable


class RunRecordStore:
    def __init__(self, root: Path):
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, report: RunReport) -> Dict[str, Any]:
        payload = to_jsonable(report)
        return self.save_payload(payload)

    def save_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        path = self._path(str(payload.get("run_id") or "run-unknown"))
        tmp_path = path.with_name(path.name + ".tmp")
        tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp_path.replace(path)
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
        verdict = report.get("verdict", "UNKNOWN")
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
    return {
        "run_id": payload.get("run_id"),
        "status": payload.get("status", "completed"),
        "created_at": payload.get("created_at"),
        "source_path": payload.get("source_path"),
        "sarif_path": payload.get("sarif_path"),
        "languages": payload.get("languages", []),
        "finding_count": payload.get("finding_count", 0),
        "project_context_facts": payload.get("project_context_facts", 0),
        "diagnostic_count": len(payload.get("diagnostics", [])),
        "verdict_counts": verdict_counts,
        "completed_finding_count": payload.get("completed_finding_count", len(payload.get("reports", []))),
        "current_finding_id": payload.get("current_finding_id"),
        "current_finding_index": payload.get("current_finding_index"),
        "resume_from_finding_id": payload.get("resume_from_finding_id"),
        "resume_from_finding_index": payload.get("resume_from_finding_index"),
    }


def _paused_after_restart(payload: Dict[str, Any]) -> Dict[str, Any]:
    updated = dict(payload)
    reports = list(updated.get("reports") or [])
    completed_count = _bounded_int(updated.get("completed_finding_count"), default=len(reports), minimum=0, maximum=len(reports))
    finding_count = _bounded_int(updated.get("finding_count"), default=completed_count, minimum=completed_count, maximum=10**9)
    resume_index = _bounded_int(
        updated.get("current_finding_index"),
        default=_bounded_int(updated.get("resume_from_finding_index"), default=completed_count, minimum=completed_count, maximum=finding_count),
        minimum=completed_count,
        maximum=finding_count,
    )
    updated["status"] = "paused"
    updated["reports"] = reports[:completed_count]
    updated["completed_finding_count"] = completed_count
    updated["resume_from_finding_id"] = updated.get("current_finding_id") or updated.get("resume_from_finding_id")
    updated["resume_from_finding_index"] = resume_index
    updated["current_finding_id"] = None
    updated["current_finding_index"] = None
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
