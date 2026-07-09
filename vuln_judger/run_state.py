from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence


FINDING_PENDING = "pending"
FINDING_IN_PROGRESS = "in_progress"
FINDING_COMPLETED = "completed"
FINDING_STATUSES = {FINDING_PENDING, FINDING_IN_PROGRESS, FINDING_COMPLETED}


def finding_report_status(report: Dict[str, Any]) -> str:
    status = str(report.get("finding_status") or "").strip().lower()
    if status in FINDING_STATUSES:
        return status
    workflow = report.get("codex_workflow") if isinstance(report.get("codex_workflow"), dict) else {}
    if workflow.get("moderator"):
        return FINDING_COMPLETED
    if workflow.get("affirmative") or workflow.get("negative"):
        return FINDING_IN_PROGRESS
    if report.get("verdict") not in (None, ""):
        return FINDING_COMPLETED
    return FINDING_PENDING


def finding_report_completed(report: Dict[str, Any]) -> bool:
    return finding_report_status(report) == FINDING_COMPLETED


def completed_finding_count(reports: Sequence[Dict[str, Any]]) -> int:
    return sum(1 for report in reports if finding_report_completed(report))


def mark_incomplete_findings_pending(
    reports: Sequence[Dict[str, Any]],
    completed_count_hint: Optional[int] = None,
) -> List[Dict[str, Any]]:
    has_explicit_status = any(
        str(report.get("finding_status") or "").strip().lower() in FINDING_STATUSES
        for report in reports
    )
    hinted_completed = max(0, int(completed_count_hint or 0))
    normalized = []
    for index, report in enumerate(reports):
        item = dict(report)
        if not has_explicit_status and completed_count_hint is not None:
            item["finding_status"] = FINDING_COMPLETED if index < hinted_completed else FINDING_PENDING
        elif not finding_report_completed(item):
            item["finding_status"] = FINDING_PENDING
        normalized.append(item)
    return normalized


def first_incomplete_finding_index(
    reports: Sequence[Dict[str, Any]], finding_count: Optional[int] = None
) -> int:
    for index, report in enumerate(reports):
        if not finding_report_completed(report):
            return index
    total = max(len(reports), int(finding_count or 0))
    return min(len(reports), total)
