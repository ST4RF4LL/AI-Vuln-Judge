from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import unquote, urlparse

from .models import Finding, SourceLocation


def load_report(path: Path) -> List[Finding]:
    suffix = path.suffix.lower()
    if suffix in {".md", ".markdown"}:
        return parse_markdown_report(path.read_text(encoding="utf-8", errors="replace"))
    if suffix in {".sarif", ".json"}:
        return load_sarif(path)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    try:
        return parse_sarif(json.loads(text))
    except json.JSONDecodeError:
        return parse_markdown_report(text)


def load_sarif(path: Path) -> List[Finding]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    return parse_sarif(data)


def parse_sarif(data: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    for run_index, run in enumerate(data.get("runs", [])):
        rules = _rules_by_id(run)
        for result_index, result in enumerate(run.get("results", [])):
            rule_id = str(result.get("ruleId") or result.get("rule", {}).get("id") or "unknown-rule")
            rule = rules.get(rule_id, {})
            message = _message_text(result.get("message")) or _message_text(rule.get("fullDescription")) or rule_id
            locations = [_location_from_sarif(location) for location in result.get("locations", [])]
            locations = [location for location in locations if location is not None]
            code_flows = _code_flows(result)
            properties = dict(rule.get("properties") or {})
            properties.update(result.get("properties") or {})
            finding_id = _finding_id(run_index, result_index, rule_id, locations, message)
            findings.append(
                Finding(
                    finding_id=finding_id,
                    rule_id=rule_id,
                    message=message,
                    level=str(result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"),
                    locations=locations,
                    code_flows=code_flows,
                    properties=properties,
                    raw=result,
                )
            )
    return findings


def parse_markdown_report(text: str) -> List[Finding]:
    findings: List[Finding] = []
    sections = _markdown_sections(text)
    for result_index, section in enumerate(sections):
        finding = _finding_from_markdown_section(result_index, section)
        if finding is not None:
            findings.append(finding)
    if findings:
        return findings
    fallback = _MarkdownSection(title="Markdown 报告", lines=text.splitlines(), start_line=1)
    finding = _finding_from_markdown_section(0, fallback, allow_loose=True)
    return [finding] if finding is not None else []


def _rules_by_id(run: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    by_id: Dict[str, Dict[str, Any]] = {}
    for extension in run.get("tool", {}).get("extensions", []):
        for rule in extension.get("rules", []):
            if "id" in rule:
                by_id[str(rule["id"])] = rule
    for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
        if "id" in rule:
            by_id[str(rule["id"])] = rule
    return by_id


def _message_text(message: Optional[Dict[str, Any]]) -> str:
    if not message:
        return ""
    return str(message.get("text") or message.get("markdown") or "")


def _location_from_sarif(location: Dict[str, Any]) -> Optional[SourceLocation]:
    physical = location.get("physicalLocation") or {}
    artifact = physical.get("artifactLocation") or {}
    uri = artifact.get("uri")
    if not uri:
        return None
    region = physical.get("region") or {}
    return SourceLocation(
        file=_normalize_uri(str(uri)),
        line=_optional_int(region.get("startLine")),
        column=_optional_int(region.get("startColumn")),
        end_line=_optional_int(region.get("endLine")),
        end_column=_optional_int(region.get("endColumn")),
    )


def _code_flows(result: Dict[str, Any]) -> List[List[SourceLocation]]:
    flows: List[List[SourceLocation]] = []
    for code_flow in result.get("codeFlows", []):
        for thread_flow in code_flow.get("threadFlows", []):
            flow_locations: List[SourceLocation] = []
            for item in thread_flow.get("locations", []):
                location = _location_from_sarif(item.get("location") or {})
                if location is not None:
                    flow_locations.append(location)
            if flow_locations:
                flows.append(flow_locations)
    return flows


def _optional_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_uri(uri: str) -> str:
    parsed = urlparse(uri)
    if parsed.scheme == "file":
        return unquote(parsed.path.lstrip("/")) if parsed.netloc else unquote(parsed.path)
    return unquote(uri).replace("\\", "/")


def _finding_id(
    run_index: int,
    result_index: int,
    rule_id: str,
    locations: Iterable[SourceLocation],
    message: str,
) -> str:
    seed = {
        "run": run_index,
        "result": result_index,
        "rule": rule_id,
        "locations": [location.display() for location in locations],
        "message": message,
    }
    digest = hashlib.sha256(json.dumps(seed, sort_keys=True).encode("utf-8")).hexdigest()
    return digest[:16]


@dataclasses.dataclass
class _MarkdownSection:
    title: str
    lines: List[str]
    start_line: int


_MARKDOWN_HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*$")
_MARKDOWN_KEY_VALUE_RE = re.compile(
    r"^\s*(?:[-*+]\s*)?(?:\*\*)?([A-Za-z\u4e00-\u9fff][A-Za-z0-9\u4e00-\u9fff _/\-]{0,48})(?:\*\*)?\s*[:：]\s*(.*?)\s*$"
)
_LOCATION_EXTENSIONS = (
    "java",
    "pyi",
    "pyx",
    "cpp",
    "cxx",
    "hpp",
    "hxx",
    "py",
    "cc",
    "hh",
    "c",
    "h",
)
_LOCATION_RE = re.compile(
    r"(?P<file>(?:[A-Za-z]:)?(?:[A-Za-z0-9_.@+~\-/]+/)*[A-Za-z0-9_.@+~\-]+"
    r"\.(?:"
    + "|".join(_LOCATION_EXTENSIONS)
    + r"))"
    r"(?![A-Za-z0-9_])"
    r"(?:(?::|#L)(?P<line>\d+)(?::(?P<column>\d+))?"
    r"|(?:\s*,?\s*(?:line|Line)\s+(?P<line_word>\d+))"
    r"(?:\s*,?\s*(?:column|col|Column|Col)\s+(?P<column_word>\d+))?"
    r"|(?:\s*,?\s*第\s*(?P<line_cn>\d+)\s*行)"
    r"(?:\s*,?\s*第?\s*(?P<column_cn>\d+)\s*列)?)?"
)
_RULE_KEYS = {"rule", "ruleid", "check", "checkid", "id", "cwe", "cweid", "vulnerabilitytype"}
_MESSAGE_KEYS = {"message", "description", "summary", "details", "title", "issue"}
_LEVEL_KEYS = {"severity", "level", "priority", "risk"}
_LOCATION_KEYS = {"location", "locations", "file", "path", "sourcefile", "source", "sink"}
_LINE_KEYS = {"line", "linenumber", "startline"}
_COLUMN_KEYS = {"column", "col", "startcolumn"}
_FLOW_KEYS = {
    "codeflow",
    "codeflows",
    "dataflow",
    "dataflows",
    "flow",
    "flows",
    "trace",
    "callchain",
    "callpath",
    "executionpath",
}
_FLOW_HEADINGS = {
    "code flow",
    "code flows",
    "data flow",
    "data flows",
    "trace",
    "call chain",
    "call path",
    "execution path",
    "代码流",
    "数据流",
    "污点流",
    "调用链",
    "调用路径",
    "执行路径",
    "路径",
    "轨迹",
}
_MARKDOWN_KEY_ALIASES = {
    "规则": "rule",
    "规则id": "rule",
    "检测规则": "rule",
    "检查项": "rule",
    "漏洞类型": "vulnerabilitytype",
    "漏洞": "vulnerabilitytype",
    "消息": "message",
    "描述": "description",
    "摘要": "summary",
    "详情": "details",
    "标题": "title",
    "问题": "issue",
    "严重性": "severity",
    "严重等级": "severity",
    "等级": "level",
    "级别": "level",
    "优先级": "priority",
    "风险": "risk",
    "风险等级": "risk",
    "位置": "location",
    "位置列表": "locations",
    "文件": "file",
    "文件路径": "path",
    "路径": "path",
    "源码文件": "sourcefile",
    "源文件": "sourcefile",
    "源点": "source",
    "汇点": "sink",
    "行": "line",
    "行号": "line",
    "起始行": "startline",
    "列": "column",
    "列号": "column",
    "起始列": "startcolumn",
    "代码流": "codeflow",
    "数据流": "dataflow",
    "污点流": "dataflow",
    "流": "flow",
    "轨迹": "trace",
    "调用链": "callchain",
    "调用路径": "callpath",
    "执行路径": "executionpath",
}


def _markdown_sections(text: str) -> List[_MarkdownSection]:
    sections: List[_MarkdownSection] = []
    current: Optional[_MarkdownSection] = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        heading = _MARKDOWN_HEADING_RE.match(line)
        if heading:
            level = len(heading.group(1))
            title = _clean_markdown_inline(heading.group(2))
            if current is not None and _is_flow_heading(title):
                current.lines.append(f"代码流：{title}")
                continue
            if _is_finding_heading(level, title):
                if current is not None:
                    sections.append(current)
                current = _MarkdownSection(title=title, lines=[], start_line=line_number)
                continue
        if current is not None:
            current.lines.append(line)
    if current is not None:
        sections.append(current)
    if sections:
        return sections
    return [_MarkdownSection(title="Markdown 报告", lines=text.splitlines(), start_line=1)] if text.strip() else []


def _is_finding_heading(level: int, title: str) -> bool:
    lowered = title.lower()
    if _is_flow_heading(title):
        return False
    if level <= 2:
        return True
    return any(
        term in lowered
        for term in ("finding", "issue", "vulnerability", "result", "alert", "rule", "cwe-", "发现", "问题", "漏洞", "结果", "告警", "规则")
    )


def _is_flow_heading(title: str) -> bool:
    normalized = re.sub(r"\s+", " ", title.strip().lower())
    return normalized in _FLOW_HEADINGS


def _finding_from_markdown_section(
    result_index: int,
    section: _MarkdownSection,
    allow_loose: bool = False,
) -> Optional[Finding]:
    rule_id: Optional[str] = None
    message: Optional[str] = None
    level = "warning"
    locations: List[SourceLocation] = []
    code_flows: List[List[SourceLocation]] = []
    current_flow: List[SourceLocation] = []
    fields: Dict[str, str] = {}
    explicit_finding_field = False
    in_flow = False

    for line in section.lines:
        heading = _MARKDOWN_HEADING_RE.match(line)
        if heading:
            title = _clean_markdown_inline(heading.group(2))
            if _is_flow_heading(title):
                if current_flow:
                    code_flows.append(_dedupe_locations(current_flow))
                current_flow = []
                in_flow = True
                continue
            in_flow = False

        key_value = _markdown_key_value(line)
        if key_value is not None:
            key, value = key_value
            normalized_key = _normalize_markdown_key(key)
            fields[normalized_key] = value
            if normalized_key in _RULE_KEYS:
                rule_id = value.strip()
                explicit_finding_field = True
            elif normalized_key in _MESSAGE_KEYS:
                message = value.strip()
                explicit_finding_field = True
            elif normalized_key in _LEVEL_KEYS:
                level = value.strip().lower() or level
                explicit_finding_field = True
            elif normalized_key in _LINE_KEYS:
                locations = _apply_line_to_last_location(locations, _optional_int(value))
                explicit_finding_field = True
            elif normalized_key in _COLUMN_KEYS:
                locations = _apply_column_to_last_location(locations, _optional_int(value))
                explicit_finding_field = True

            parsed_locations = _parse_markdown_locations(value)
            if normalized_key in _FLOW_KEYS:
                if current_flow:
                    code_flows.append(_dedupe_locations(current_flow))
                current_flow = parsed_locations
                in_flow = True
                explicit_finding_field = True
                continue
            if normalized_key in _LOCATION_KEYS:
                locations.extend(parsed_locations)
                if in_flow:
                    current_flow.extend(parsed_locations)
                explicit_finding_field = True
                continue
            if in_flow and parsed_locations:
                current_flow.extend(parsed_locations)
            continue

        parsed_locations = _parse_markdown_locations(line)
        if parsed_locations:
            if in_flow:
                current_flow.extend(parsed_locations)
            else:
                locations.extend(parsed_locations)

    if current_flow:
        code_flows.append(_dedupe_locations(current_flow))
    code_flows = [flow for flow in code_flows if flow]
    locations = _dedupe_locations(locations)
    if not locations and code_flows:
        locations = [code_flows[-1][-1]]

    if not rule_id:
        rule_id = _rule_id_from_markdown_title(section.title)
    if not message:
        message = _first_markdown_sentence(section.lines) or section.title or rule_id
    if not (locations or code_flows or explicit_finding_field or allow_loose):
        return None
    if not (locations or code_flows) and not explicit_finding_field:
        return None

    properties = {
        "format": "markdown",
        "section_title": section.title,
        "section_start_line": section.start_line,
    }
    properties.update({f"markdown_{key}": value for key, value in fields.items()})
    finding_id = _finding_id(0, result_index, rule_id, locations, message)
    return Finding(
        finding_id=finding_id,
        rule_id=rule_id,
        message=message,
        level=level,
        locations=locations,
        code_flows=code_flows,
        properties=properties,
        raw={
            "format": "markdown",
            "section_title": section.title,
            "section_start_line": section.start_line,
            "body": "\n".join(section.lines),
        },
    )


def _markdown_key_value(line: str) -> Optional[tuple[str, str]]:
    cleaned = line.strip()
    if cleaned.startswith("|") and cleaned.endswith("|"):
        cells = [cell.strip() for cell in cleaned.strip("|").split("|")]
        if len(cells) >= 2 and cells[0] and not set(cells[0]) <= {"-"}:
            return _clean_markdown_inline(cells[0]), _clean_markdown_inline(cells[1])
    match = _MARKDOWN_KEY_VALUE_RE.match(line)
    if not match:
        return None
    return _clean_markdown_inline(match.group(1)), _clean_markdown_inline(match.group(2))


def _parse_markdown_locations(value: str) -> List[SourceLocation]:
    locations: List[SourceLocation] = []
    for match in _LOCATION_RE.finditer(value):
        raw_file = match.group("file")
        line = _optional_int(match.group("line") or match.group("line_word") or match.group("line_cn"))
        column = _optional_int(match.group("column") or match.group("column_word") or match.group("column_cn"))
        locations.append(SourceLocation(file=_normalize_markdown_file(raw_file), line=line, column=column))
    return _dedupe_locations(locations)


def _normalize_markdown_file(raw_file: str) -> str:
    normalized = _normalize_uri(raw_file.strip().strip("`\"'"))
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _apply_line_to_last_location(locations: List[SourceLocation], line: Optional[int]) -> List[SourceLocation]:
    if line is None or not locations:
        return locations
    latest = locations[-1]
    if latest.line is not None:
        return locations
    updated = SourceLocation(file=latest.file, line=line, column=latest.column)
    return locations[:-1] + [updated]


def _apply_column_to_last_location(locations: List[SourceLocation], column: Optional[int]) -> List[SourceLocation]:
    if column is None or not locations:
        return locations
    latest = locations[-1]
    if latest.column is not None:
        return locations
    updated = SourceLocation(file=latest.file, line=latest.line, column=column)
    return locations[:-1] + [updated]


def _dedupe_locations(locations: List[SourceLocation]) -> List[SourceLocation]:
    seen = set()
    result: List[SourceLocation] = []
    for location in locations:
        key = location.display()
        if key in seen:
            continue
        seen.add(key)
        result.append(location)
    return result


def _rule_id_from_markdown_title(title: str) -> str:
    cleaned = _clean_markdown_inline(title)
    cleaned = re.sub(r"^\s*(?:finding|issue|result|alert)\s*#?\d*\s*[:\-]\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^\s*(?:发现|问题|结果|告警|漏洞)\s*#?\d*\s*[:：\-]\s*", "", cleaned)
    cleaned = re.sub(r"^\s*\[[^\]]+\]\s*", "", cleaned).strip()
    return cleaned or "markdown-finding"


def _first_markdown_sentence(lines: List[str]) -> str:
    for line in lines:
        if _MARKDOWN_HEADING_RE.match(line) or _markdown_key_value(line) is not None:
            continue
        cleaned = _clean_markdown_inline(line).strip()
        cleaned = re.sub(r"^\s*[-*+]\s*", "", cleaned).strip()
        if cleaned and not cleaned.startswith("```"):
            return cleaned
    return ""


def _normalize_markdown_key(key: str) -> str:
    compact = re.sub(r"[\s_/\-:：]+", "", key.strip().lower())
    if compact in _MARKDOWN_KEY_ALIASES:
        return _MARKDOWN_KEY_ALIASES[compact]
    return re.sub(r"[^a-z0-9]", "", compact)


def _clean_markdown_inline(value: str) -> str:
    cleaned = value.strip()
    cleaned = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", cleaned)
    cleaned = cleaned.replace("**", "").replace("__", "")
    return cleaned.strip("` \t")
