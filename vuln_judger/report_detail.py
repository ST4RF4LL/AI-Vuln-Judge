from __future__ import annotations

import copy
from typing import Any, Dict

from .models import Finding


def report_markdown(finding: Finding) -> str:
    raw = finding.raw if isinstance(finding.raw, dict) else {}
    detail = finding.report_detail if isinstance(finding.report_detail, dict) else {}
    fragments = detail.get("fragments")
    if isinstance(fragments, list):
        content = "".join(
            str(fragment.get("content") or "")
            for fragment in fragments
            if isinstance(fragment, dict)
        )
        if content:
            return content
    return str(raw.get("markdown") or raw.get("report_markdown") or "")


def report_evidence_summary(finding: Finding) -> str:
    properties = finding.properties if isinstance(finding.properties, dict) else {}
    markdown = report_markdown(finding)
    locations = [location.display() for location in finding.locations]
    if markdown:
        start_line = properties.get("markdown_start_line")
        end_line = properties.get("markdown_end_line")
        range_text = f"；原始行号 {start_line}-{end_line}" if start_line and end_line else ""
        if properties.get("source_report_format") == "sarif":
            indices = properties.get("sarif_result_indices") or []
            index_text = f"；SARIF results {indices}" if indices else ""
            return f"输入 SARIF 经 Moderator 分组后的单漏洞报告：{finding.message or finding.rule_id}{index_text}"
        return f"输入 Markdown 单漏洞报告：{finding.message or finding.rule_id}{range_text}"

    summary = f"输入报告发现：{finding.rule_id}（{finding.level}）"
    if finding.message:
        summary += f"，消息：{finding.message}"
    if locations:
        summary += f"，位置：{'; '.join(locations[:5])}"
    if finding.code_flows:
        summary += f"，报告内代码流 {len(finding.code_flows)} 条"
    return summary


def report_evidence_data(finding: Finding) -> Dict[str, Any]:
    properties = copy.deepcopy(finding.properties) if isinstance(finding.properties, dict) else {}
    raw_result = copy.deepcopy(finding.raw) if isinstance(finding.raw, dict) else {}
    detail = copy.deepcopy(finding.report_detail) if isinstance(finding.report_detail, dict) else {}
    markdown = report_markdown(finding)
    return {
        "source_format": properties.get("source_format") or detail.get("format") or "sarif",
        "source_report_format": properties.get("source_report_format"),
        "source_report": properties.get("source_report"),
        "source_artifact": copy.deepcopy(properties.get("source_artifact") or detail.get("source_artifact")),
        "temporary_markdown_report": properties.get("temporary_markdown_report"),
        "markdown_start_line": properties.get("markdown_start_line"),
        "markdown_end_line": properties.get("markdown_end_line"),
        "sarif_result_indices": copy.deepcopy(properties.get("sarif_result_indices")),
        "segment_ids": copy.deepcopy(properties.get("segment_ids")),
        "markdown_report": markdown,
        "rule_id": finding.rule_id,
        "vulnerability_type": finding.vulnerability_type,
        "level": finding.level,
        "message": finding.message,
        "locations": [location.display() for location in finding.locations],
        "location_details": [
            {
                "file": location.file,
                "line": location.line,
                "column": location.column,
                "end_line": location.end_line,
                "end_column": location.end_column,
                "symbol": location.symbol,
            }
            for location in finding.locations
        ],
        "code_flows": [[location.display() for location in flow] for flow in finding.code_flows],
        "code_flow_details": [
            [
                {
                    "file": location.file,
                    "line": location.line,
                    "column": location.column,
                    "end_line": location.end_line,
                    "end_column": location.end_column,
                    "symbol": location.symbol,
                }
                for location in flow
            ]
            for flow in finding.code_flows
        ],
        "location_count": len(finding.locations),
        "code_flow_count": len(finding.code_flows),
        "properties": properties,
        "raw_result": raw_result,
        "report_detail": detail,
    }
