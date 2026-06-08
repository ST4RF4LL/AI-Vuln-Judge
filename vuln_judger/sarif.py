from __future__ import annotations

import dataclasses
import copy
import hashlib
import json
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import unquote, urlparse

from .agents import DEFAULT_MODERATOR_AGENT
from .llm import LLMClient
from .models import AgentConfig
from .models import Finding, SourceLocation


@dataclasses.dataclass
class PreparedReport:
    original_path: Path
    effective_path: Path
    diagnostics: List[str]
    temporary: bool = False


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


def prepare_report_for_processing(
    path: Path,
    moderator_client: Optional[LLMClient] = None,
    moderator_agent: Optional[AgentConfig] = None,
) -> PreparedReport:
    """Normalize report input to SARIF without modifying the original file."""
    report_path = path.expanduser().resolve()
    suffix = report_path.suffix.lower()
    diagnostics: List[str] = []
    if suffix in {".md", ".markdown"}:
        text = report_path.read_text(encoding="utf-8", errors="replace")
        sarif_data, conversion_diagnostics = moderator_markdown_to_sarif(
            text,
            source_name=str(report_path),
            moderator_client=moderator_client,
            moderator_agent=moderator_agent,
        )
        diagnostics.extend(conversion_diagnostics)
        sarif_data, repairs = moderator_review_sarif(sarif_data)
        diagnostics.extend(f"Moderator 修复 Markdown 转换结果：{item}" for item in repairs)
        issues = validate_sarif_report(sarif_data)
        temp_path = _write_temp_sarif(sarif_data, report_path)
        diagnostics.append(f"Moderator 已将 Markdown 报告转换为临时 SARIF：{temp_path}")
        diagnostics.append(_validation_diagnostic(issues))
        return PreparedReport(report_path, temp_path, diagnostics, temporary=True)

    try:
        data = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        text = report_path.read_text(encoding="utf-8", errors="replace")
        sarif_data, conversion_diagnostics = moderator_markdown_to_sarif(
            text,
            source_name=str(report_path),
            moderator_client=moderator_client,
            moderator_agent=moderator_agent,
        )
        diagnostics.extend(conversion_diagnostics)
        sarif_data, repairs = moderator_review_sarif(sarif_data)
        diagnostics.extend(f"Moderator 修复 Markdown 转换结果：{item}" for item in repairs)
        issues = validate_sarif_report(sarif_data)
        temp_path = _write_temp_sarif(sarif_data, report_path)
        diagnostics.append(f"Moderator 将非 JSON 文本报告转换为临时 SARIF：{temp_path}")
        diagnostics.append(_validation_diagnostic(issues))
        return PreparedReport(report_path, temp_path, diagnostics, temporary=True)

    reviewed, repairs = moderator_review_sarif(data)
    issues = validate_sarif_report(reviewed)
    diagnostics.append(_validation_diagnostic(issues))
    if repairs:
        temp_path = _write_temp_sarif(reviewed, report_path)
        diagnostics.extend(f"Moderator 修复 SARIF 读取异常：{item}" for item in repairs)
        diagnostics.append(f"Moderator 已将修复后的 SARIF 写入临时文件：{temp_path}")
        return PreparedReport(report_path, temp_path, diagnostics, temporary=True)
    return PreparedReport(report_path, report_path, diagnostics, temporary=False)


def moderator_markdown_to_sarif(
    text: str,
    source_name: str = "markdown-report",
    moderator_client: Optional[LLMClient] = None,
    moderator_agent: Optional[AgentConfig] = None,
) -> tuple[Dict[str, Any], List[str]]:
    diagnostics: List[str] = []
    if moderator_client is None:
        diagnostics.append("Moderator LLM 不可用，使用确定性 Markdown 解析兜底生成 SARIF")
        return markdown_to_sarif(text, source_name=source_name), diagnostics
    system, user = _markdown_to_sarif_prompt(text, source_name, moderator_agent)
    response = moderator_client.complete(system, user)
    if not response:
        diagnostics.append("Moderator LLM 未返回 Markdown 转换结果，使用确定性 Markdown 解析兜底生成 SARIF")
        return markdown_to_sarif(text, source_name=source_name), diagnostics
    sarif_data = _extract_json_object(response)
    if sarif_data is None:
        diagnostics.append("Moderator LLM Markdown 转换结果不是合法 JSON，使用确定性 Markdown 解析兜底生成 SARIF")
        return markdown_to_sarif(text, source_name=source_name), diagnostics
    sarif_data, repairs = moderator_review_sarif(sarif_data)
    diagnostics.extend(f"Moderator 修复 LLM SARIF：{item}" for item in repairs)
    issues = validate_sarif_report(sarif_data)
    if issues:
        repaired = _repair_llm_sarif_with_moderator(
            moderator_client,
            text=text,
            source_name=source_name,
            previous_sarif=sarif_data,
            issues=issues,
            moderator_agent=moderator_agent,
        )
        if repaired is not None:
            repaired, repair_items = moderator_review_sarif(repaired)
            repaired_issues = validate_sarif_report(repaired)
            if not repaired_issues:
                diagnostics.append("Moderator LLM 已根据 SARIF 验证问题修正 Markdown 转换结果")
                diagnostics.extend(f"Moderator 修复 LLM SARIF：{item}" for item in repair_items)
                return repaired, diagnostics
            diagnostics.append("Moderator LLM 修正后的 SARIF 仍未通过验证：" + "；".join(repaired_issues))
        diagnostics.append("Moderator LLM SARIF 未通过格式验证：" + "；".join(issues))
        diagnostics.append("使用确定性 Markdown 解析兜底生成 SARIF")
        return markdown_to_sarif(text, source_name=source_name), diagnostics
    diagnostics.append("Moderator LLM 已解读 Markdown 并生成 SARIF")
    return sarif_data, diagnostics


def markdown_to_sarif(text: str, source_name: str = "markdown-report") -> Dict[str, Any]:
    findings = parse_markdown_report(text)
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for finding in findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": {"text": finding.rule_id},
                "fullDescription": {"text": finding.message},
                "properties": {"sourceFormat": "markdown"},
            },
        )
        result: Dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": finding.level or "warning",
            "message": {"text": finding.message},
            "locations": [_location_to_sarif(location) for location in finding.locations],
            "properties": dict(finding.properties),
        }
        result["properties"].update(
            {
                "source_format": "markdown",
                "source_report": source_name,
                "moderator_converted": True,
            }
        )
        if finding.code_flows:
            result["codeFlows"] = [_code_flow_to_sarif(flow) for flow in finding.code_flows]
        results.append(result)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vuln-judger-moderator",
                        "informationUri": "https://github.com/ST4RF4LL/AI-Vuln-Judge",
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [{"executionSuccessful": True, "properties": {"inputFormat": "markdown"}}],
                "results": results,
            }
        ],
    }


def validate_sarif_report(data: Dict[str, Any]) -> List[str]:
    issues: List[str] = []
    if not isinstance(data, dict):
        return ["SARIF 顶层不是 JSON object"]
    if str(data.get("version") or "") != "2.1.0":
        issues.append("SARIF version 不是 2.1.0")
    runs = data.get("runs")
    if not isinstance(runs, list) or not runs:
        issues.append("SARIF 缺少 runs")
        return issues
    result_count = 0
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            issues.append(f"runs[{run_index}] 不是 object")
            continue
        results = run.get("results")
        if not isinstance(results, list):
            issues.append(f"runs[{run_index}] 缺少 results 数组")
            continue
        result_count += len(results)
        for result_index, result in enumerate(results):
            if not isinstance(result, dict):
                issues.append(f"runs[{run_index}].results[{result_index}] 不是 object")
                continue
            if not str(result.get("ruleId") or "").strip():
                issues.append(f"runs[{run_index}].results[{result_index}] 缺少 ruleId")
            message = _message_text(result.get("message"))
            if _looks_like_bad_report_text(message):
                issues.append(f"runs[{run_index}].results[{result_index}] message 为空或疑似 Markdown 表格分隔线")
            locations = result.get("locations")
            if locations is not None and not isinstance(locations, list):
                issues.append(f"runs[{run_index}].results[{result_index}] locations 不是数组")
    if result_count == 0:
        issues.append("SARIF results 为空")
    return issues


def moderator_review_sarif(data: Dict[str, Any]) -> tuple[Dict[str, Any], List[str]]:
    reviewed = copy.deepcopy(data)
    repairs: List[str] = []
    if not isinstance(reviewed, dict):
        return reviewed, repairs
    for run_index, run in enumerate(reviewed.get("runs") or []):
        if not isinstance(run, dict):
            continue
        for result_index, result in enumerate(run.get("results") or []):
            if not isinstance(result, dict):
                continue
            props = result.get("properties")
            if not isinstance(props, dict):
                props = {}
                result["properties"] = props
            message = _message_text(result.get("message"))
            if _looks_like_bad_report_text(message):
                replacement = _message_from_sarif_result(result)
                result["message"] = {"text": replacement}
                repairs.append(f"runs[{run_index}].results[{result_index}] message 修正为：{replacement}")
            rule_id = str(result.get("ruleId") or "").strip()
            if _looks_like_bad_report_text(rule_id) or rule_id in {"unknown-rule", "markdown-finding", "Markdown 报告"}:
                replacement_rule = _rule_from_sarif_result(result)
                if replacement_rule:
                    result["ruleId"] = replacement_rule
                    repairs.append(f"runs[{run_index}].results[{result_index}] ruleId 修正为：{replacement_rule}")
            locations = result.get("locations")
            if not locations:
                repaired_locations = _locations_from_sarif_properties(props)
                if repaired_locations:
                    result["locations"] = repaired_locations
                    repairs.append(f"runs[{run_index}].results[{result_index}] locations 从 Markdown 字段补齐")
            props["moderator_reviewed"] = True
            if repairs:
                props["moderator_repairs"] = list(repairs)
    return reviewed, repairs


def _markdown_to_sarif_prompt(
    text: str,
    source_name: str,
    moderator_agent: Optional[AgentConfig],
) -> tuple[str, str]:
    agent = moderator_agent or DEFAULT_MODERATOR_AGENT
    agent_instructions = (agent.instructions or "").strip()
    system = (
        f"你是 {agent.name or '中立 Moderator'}，负责把静态漏洞 Markdown 报告转换为 SARIF 2.1.0。"
        "你必须阅读整份 Markdown，提取漏洞类型、漏洞描述、危险函数/危险 API、文件路径、行列号、严重性、调用链/数据流。"
        "不要把 Markdown 表格分隔线、表头或格式说明当作漏洞消息。"
        "只输出一个合法 JSON object，不要输出 Markdown、代码块、解释或额外文本。"
    )
    if agent_instructions:
        system += f"\nModerator 配置：\n{agent_instructions}"
    user = (
        "请将下面 Markdown 报告转换为 SARIF 2.1.0 JSON。\n"
        "必须满足：\n"
        "1. 顶层包含 version='2.1.0' 和 runs 数组。\n"
        "2. 每个漏洞放入 runs[0].results[]，必须包含 ruleId、message.text、level、locations。\n"
        "3. ruleId 优先使用漏洞类型、规则 ID、CWE/CVE 或报告标题，不要使用表格分隔线。\n"
        "4. message.text 必须是具体漏洞描述，优先包含漏洞类型、危险函数和影响，不要使用 '|------|-----|'、表头或空文本。\n"
        "5. 文件路径放入 locations[].physicalLocation.artifactLocation.uri；行列号放入 region.startLine/startColumn。\n"
        "6. 调用链、数据流或代码流放入 codeFlows[].threadFlows[].locations[].location。\n"
        "7. 在 properties 中保留 source_format='markdown'、source_report、moderator_converted=true，"
        "并尽量保留 markdown_vulnerabilitytype、markdown_dangerousfunction、markdown_description 等字段。\n\n"
        f"source_report: {source_name}\n\n"
        "Markdown 报告开始：\n"
        f"{text}\n"
        "Markdown 报告结束。"
    )
    return system, user


def _repair_llm_sarif_with_moderator(
    moderator_client: LLMClient,
    text: str,
    source_name: str,
    previous_sarif: Dict[str, Any],
    issues: List[str],
    moderator_agent: Optional[AgentConfig],
) -> Optional[Dict[str, Any]]:
    agent = moderator_agent or DEFAULT_MODERATOR_AGENT
    system = (
        f"你是 {agent.name or '中立 Moderator'}，负责修复 Markdown 转换出的 SARIF。"
        "只输出修复后的合法 SARIF JSON object，不要输出 Markdown、代码块、解释或额外文本。"
    )
    user = (
        "上一次 SARIF 转换未通过格式验证，请基于原始 Markdown 修复。\n"
        "验证问题：\n- "
        + "\n- ".join(issues)
        + "\n\n原始 Markdown：\n"
        + text
        + "\n\n上一次 SARIF JSON：\n"
        + json.dumps(previous_sarif, ensure_ascii=False, indent=2, sort_keys=True)
        + f"\n\nsource_report: {source_name}"
    )
    response = moderator_client.complete(system, user)
    if not response:
        return None
    return _extract_json_object(response)


def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    cleaned = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, flags=re.IGNORECASE | re.DOTALL)
    if fenced:
        cleaned = fenced.group(1).strip()
    elif not cleaned.startswith("{"):
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start >= 0 and end > start:
            cleaned = cleaned[start : end + 1]
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


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
    if _should_parse_markdown_as_single_report(text, sections):
        document = _single_markdown_section(text)
        finding = _finding_from_markdown_section(0, document, allow_loose=True)
        return [finding] if finding is not None else []
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
_MARKDOWN_SYMBOL_RE = re.compile(
    r"`(?P<symbol>[A-Za-z_~][\w:~]*(?:::[A-Za-z_~][\w:~]*)*)\s*\([^`]*\)`"
)
_RULE_KEYS = {"rule", "ruleid", "check", "checkid", "id", "cwe", "cweid", "vulnerabilitytype"}
_MESSAGE_KEYS = {"message", "description", "summary", "details", "title", "issue"}
_LEVEL_KEYS = {"severity", "level", "priority", "risk"}
_LOCATION_KEYS = {"location", "locations", "file", "path", "sourcefile", "source", "sink"}
_LINE_KEYS = {"line", "linenumber", "startline"}
_COLUMN_KEYS = {"column", "col", "startcolumn"}
_CONTEXT_KEYS = {
    "dangerousfunction",
    "dangerousapi",
    "sinkfunction",
    "sinkapi",
    "rootcause",
    "impact",
}
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
_REPORT_SECTION_HEADINGS = {
    "summary",
    "overview",
    "description",
    "details",
    "affected code",
    "affected files",
    "affected components",
    "root cause",
    "cause",
    "impact",
    "confirmed impact",
    "evidence",
    "proof of concept",
    "poc",
    "reproduction",
    "recommended fix",
    "recommendation",
    "recommendations",
    "remediation",
    "fix",
    "fixes",
    "mitigation",
    "exploitability",
    "rce status",
    "摘要",
    "概述",
    "描述",
    "详情",
    "受影响代码",
    "受影响文件",
    "影响",
    "确认影响",
    "根因",
    "根本原因",
    "证据",
    "复现",
    "修复建议",
    "建议修复",
    "缓解措施",
    "利用条件",
}
_REFERENCE_SECTION_HEADINGS = {
    "evidence",
    "references",
    "reference",
    "artifacts",
    "attachments",
    "proof of concept",
    "poc",
    "related files",
    "supporting files",
    "证据",
    "参考",
    "参考资料",
    "附件",
    "相关文件",
    "复现材料",
}
_MARKDOWN_KEY_ALIASES = {
    "规则": "rule",
    "规则id": "rule",
    "检测规则": "rule",
    "检查项": "rule",
    "漏洞类型": "vulnerabilitytype",
    "漏洞名称": "title",
    "漏洞描述": "description",
    "漏洞": "vulnerabilitytype",
    "危险函数": "dangerousfunction",
    "危险方法": "dangerousfunction",
    "危险调用": "dangerousfunction",
    "危险api": "dangerousapi",
    "危险API": "dangerousapi",
    "汇点函数": "sinkfunction",
    "汇点api": "sinkapi",
    "汇点API": "sinkapi",
    "根因": "rootcause",
    "根本原因": "rootcause",
    "影响": "impact",
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


def _is_explicit_finding_heading(title: str) -> bool:
    lowered = title.lower()
    return any(
        term in lowered
        for term in ("finding", "issue", "vulnerability", "result", "alert", "rule", "cwe-", "cve-", "发现", "问题", "漏洞", "结果", "告警", "规则")
    )


def _is_report_section_heading(title: str) -> bool:
    normalized = re.sub(r"[\s_/\-:：]+", " ", title.strip().lower())
    normalized = re.sub(r"[^a-z0-9\u4e00-\u9fff ]", "", normalized).strip()
    return normalized in _REPORT_SECTION_HEADINGS


def _is_reference_section_heading(title: str) -> bool:
    normalized = re.sub(r"[\s_/\-:：]+", " ", title.strip().lower())
    normalized = re.sub(r"[^a-z0-9\u4e00-\u9fff ]", "", normalized).strip()
    return normalized in _REFERENCE_SECTION_HEADINGS


def _should_parse_markdown_as_single_report(text: str, sections: List[_MarkdownSection]) -> bool:
    if len(sections) <= 1:
        return False
    headings = [
        (len(match.group(1)), _clean_markdown_inline(match.group(2)))
        for line in text.splitlines()
        if (match := _MARKDOWN_HEADING_RE.match(line))
    ]
    if any(_is_explicit_finding_heading(title) for _level, title in headings):
        return False
    top_level_count = sum(1 for level, _title in headings if level == 1)
    report_section_count = sum(1 for level, title in headings if level >= 2 and _is_report_section_heading(title))
    return top_level_count == 1 and report_section_count >= 2


def _single_markdown_section(text: str) -> _MarkdownSection:
    title = "Markdown 报告"
    start_line = 1
    for line_number, line in enumerate(text.splitlines(), start=1):
        heading = _MARKDOWN_HEADING_RE.match(line)
        if heading:
            title = _clean_markdown_inline(heading.group(2)) or title
            start_line = line_number
            break
    return _MarkdownSection(title=title, lines=text.splitlines(), start_line=start_line)


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
    in_reference_section = False
    table_headers: List[str] = []

    def apply_key_value(key: str, value: str) -> None:
        nonlocal rule_id, message, level, locations, code_flows, current_flow, in_flow, explicit_finding_field
        key = _clean_markdown_inline(key)
        value = _clean_markdown_inline(value)
        if not key or _is_markdown_table_separator_cell(key):
            return
        normalized_key = _normalize_markdown_key(key)
        if not normalized_key:
            return
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
        elif normalized_key in _CONTEXT_KEYS:
            explicit_finding_field = True

        parsed_locations = _parse_markdown_locations(value)
        if normalized_key in _FLOW_KEYS:
            if current_flow:
                code_flows.append(_dedupe_locations(current_flow))
            current_flow = parsed_locations
            in_flow = True
            explicit_finding_field = True
            return
        if normalized_key in _LOCATION_KEYS:
            locations.extend(parsed_locations)
            if in_flow:
                current_flow.extend(parsed_locations)
            explicit_finding_field = True
            return
        if in_flow and parsed_locations:
            current_flow.extend(parsed_locations)

    for line in section.lines:
        heading = _MARKDOWN_HEADING_RE.match(line)
        if heading:
            title = _clean_markdown_inline(heading.group(2))
            in_reference_section = _is_reference_section_heading(title)
            if _is_flow_heading(title):
                if current_flow:
                    code_flows.append(_dedupe_locations(current_flow))
                current_flow = []
                in_flow = True
                continue
            in_flow = False
            table_headers = []

        table_cells = _markdown_table_cells(line)
        if table_cells is not None:
            if _is_markdown_table_separator_row(table_cells):
                continue
            if table_headers:
                for index, value in enumerate(table_cells):
                    if index >= len(table_headers):
                        break
                    apply_key_value(table_headers[index], value)
                continue
            if _looks_like_markdown_table_header(table_cells):
                table_headers = table_cells
                continue

        key_value = _markdown_key_value(line)
        if key_value is not None:
            key, value = key_value
            apply_key_value(key, value)
            continue

        parsed_locations = _parse_markdown_locations(line)
        if parsed_locations:
            if in_flow:
                current_flow.extend(parsed_locations)
            elif not in_reference_section:
                locations.extend(parsed_locations)

    if current_flow:
        code_flows.append(_dedupe_locations(current_flow))
    code_flows = [flow for flow in code_flows if flow]
    locations = _dedupe_locations(locations)
    if not locations and code_flows:
        locations = [code_flows[-1][-1]]

    if not rule_id:
        rule_id = fields.get("vulnerabilitytype") or fields.get("rule") or _rule_id_from_markdown_title(section.title)
    if not message:
        message = _message_from_markdown_fields(fields) or _first_markdown_sentence(section.lines) or section.title or rule_id
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
        cells = _markdown_table_cells(cleaned) or []
        if _is_markdown_table_separator_row(cells):
            return None
        if len(cells) >= 2 and cells[0] and _is_known_markdown_key(cells[0]):
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
        symbol = _markdown_symbol_from_context(value[match.end() :]) or _markdown_symbol_from_context(value)
        locations.append(SourceLocation(file=_normalize_markdown_file(raw_file), line=line, column=column, symbol=symbol))
    return _dedupe_locations(locations)


def _markdown_symbol_from_context(value: str) -> Optional[str]:
    for match in _MARKDOWN_SYMBOL_RE.finditer(value):
        symbol = match.group("symbol").strip()
        if "." in symbol and "::" not in symbol:
            continue
        return symbol
    return None


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
    updated = SourceLocation(
        file=latest.file,
        line=line,
        column=latest.column,
        end_line=latest.end_line,
        end_column=latest.end_column,
        symbol=latest.symbol,
    )
    return locations[:-1] + [updated]


def _apply_column_to_last_location(locations: List[SourceLocation], column: Optional[int]) -> List[SourceLocation]:
    if column is None or not locations:
        return locations
    latest = locations[-1]
    if latest.column is not None:
        return locations
    updated = SourceLocation(
        file=latest.file,
        line=latest.line,
        column=column,
        end_line=latest.end_line,
        end_column=latest.end_column,
        symbol=latest.symbol,
    )
    return locations[:-1] + [updated]


def _dedupe_locations(locations: List[SourceLocation]) -> List[SourceLocation]:
    seen = set()
    result: List[SourceLocation] = []
    for location in locations:
        key = (location.display(), location.symbol)
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
        table_cells = _markdown_table_cells(line)
        if (
            _MARKDOWN_HEADING_RE.match(line)
            or _markdown_key_value(line) is not None
            or (table_cells is not None and (_is_markdown_table_separator_row(table_cells) or _looks_like_markdown_table_header(table_cells)))
        ):
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


def _markdown_table_cells(line: str) -> Optional[List[str]]:
    cleaned = line.strip()
    if not (cleaned.startswith("|") and cleaned.endswith("|")):
        return None
    return [_clean_markdown_inline(cell.strip()) for cell in cleaned.strip("|").split("|")]


def _is_markdown_table_separator_row(cells: List[str]) -> bool:
    return bool(cells) and all(_is_markdown_table_separator_cell(cell) for cell in cells if cell)


def _is_markdown_table_separator_cell(cell: str) -> bool:
    return bool(re.fullmatch(r":?-{2,}:?", cell.strip()))


def _looks_like_markdown_table_header(cells: List[str]) -> bool:
    return sum(1 for cell in cells if _is_known_markdown_key(cell)) >= 2


def _is_known_markdown_key(key: str) -> bool:
    normalized = _normalize_markdown_key(key)
    known = _RULE_KEYS | _MESSAGE_KEYS | _LEVEL_KEYS | _LOCATION_KEYS | _LINE_KEYS | _COLUMN_KEYS | _FLOW_KEYS | _CONTEXT_KEYS
    return normalized in known


def _message_from_markdown_fields(fields: Dict[str, str]) -> str:
    for key in ("message", "description", "summary", "details", "title", "issue"):
        value = fields.get(key)
        if value and not _looks_like_bad_report_text(value):
            return value
    parts = []
    if fields.get("vulnerabilitytype"):
        parts.append(f"漏洞类型：{fields['vulnerabilitytype']}")
    danger = fields.get("dangerousfunction") or fields.get("dangerousapi") or fields.get("sinkfunction") or fields.get("sinkapi")
    if danger:
        parts.append(f"危险函数：{danger}")
    if fields.get("rootcause"):
        parts.append(f"根因：{fields['rootcause']}")
    if fields.get("impact"):
        parts.append(f"影响：{fields['impact']}")
    return "；".join(parts)


def _looks_like_bad_report_text(value: str) -> bool:
    cleaned = _clean_markdown_inline(str(value or "")).strip()
    if not cleaned:
        return True
    if _markdown_table_cells(cleaned) is not None and _is_markdown_table_separator_row(_markdown_table_cells(cleaned) or []):
        return True
    return bool(re.fullmatch(r"\|?\s*:?-{2,}:?(?:\s*\|\s*:?-{2,}:?)+\s*\|?", cleaned))


def _message_from_sarif_result(result: Dict[str, Any]) -> str:
    props = result.get("properties") if isinstance(result.get("properties"), dict) else {}
    fields = {
        key.removeprefix("markdown_"): str(value)
        for key, value in props.items()
        if isinstance(key, str) and key.startswith("markdown_") and value is not None
    }
    message = _message_from_markdown_fields(fields)
    if message:
        return message
    rule_id = str(result.get("ruleId") or "").strip()
    if rule_id and not _looks_like_bad_report_text(rule_id):
        return rule_id
    return "Moderator 修复后的 SARIF 发现缺少原始描述，需人工复核报告内容。"


def _rule_from_sarif_result(result: Dict[str, Any]) -> str:
    props = result.get("properties") if isinstance(result.get("properties"), dict) else {}
    for key in ("markdown_rule", "markdown_vulnerabilitytype", "markdown_title", "markdown_cwe", "markdown_cweid"):
        value = str(props.get(key) or "").strip()
        if value and not _looks_like_bad_report_text(value):
            return value
    message = _message_from_sarif_result(result)
    return re.sub(r"\s+", "-", message.lower())[:80] if message else ""


def _locations_from_sarif_properties(props: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw_file = props.get("markdown_file") or props.get("markdown_path") or props.get("markdown_sourcefile")
    if not raw_file:
        return []
    location = SourceLocation(
        file=_normalize_markdown_file(str(raw_file)),
        line=_optional_int(props.get("markdown_line") or props.get("markdown_startline")),
        column=_optional_int(props.get("markdown_column") or props.get("markdown_startcolumn")),
    )
    return [_location_to_sarif(location)]


def _location_to_sarif(location: SourceLocation) -> Dict[str, Any]:
    region: Dict[str, Any] = {}
    if location.line is not None:
        region["startLine"] = location.line
    if location.column is not None:
        region["startColumn"] = location.column
    if location.end_line is not None:
        region["endLine"] = location.end_line
    if location.end_column is not None:
        region["endColumn"] = location.end_column
    physical: Dict[str, Any] = {"artifactLocation": {"uri": location.file}}
    if region:
        physical["region"] = region
    return {"physicalLocation": physical}


def _code_flow_to_sarif(flow: List[SourceLocation]) -> Dict[str, Any]:
    return {
        "threadFlows": [
            {
                "locations": [
                    {
                        "location": _location_to_sarif(location),
                    }
                    for location in flow
                ]
            }
        ]
    }


def _write_temp_sarif(data: Dict[str, Any], original_path: Path) -> Path:
    safe_stem = re.sub(r"[^A-Za-z0-9_.-]+", "-", original_path.stem)[:40] or "report"
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        suffix=".sarif",
        prefix=f"vuln-judger-{safe_stem}-",
        delete=False,
    ) as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        return Path(handle.name)


def _validation_diagnostic(issues: List[str]) -> str:
    if not issues:
        return "Moderator SARIF 格式验证通过"
    return "Moderator SARIF 格式验证发现问题：" + "；".join(issues)
