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


MARKDOWN_TO_SARIF_RETRIES = 3


@dataclasses.dataclass
class PreparedReport:
    original_path: Path
    effective_path: Path
    diagnostics: List[str]
    temporary: bool = False


class ReportPreparationError(RuntimeError):
    """Raised when a report cannot be normalized into valid SARIF."""


def load_report(path: Path) -> List[Finding]:
    suffix = path.suffix.lower()
    if suffix in {".md", ".markdown"}:
        raise ReportPreparationError("Markdown 报告必须先由 Moderator LLM 转换为 SARIF")
    if suffix in {".sarif", ".json"}:
        return load_sarif(path)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    try:
        return parse_sarif(json.loads(text))
    except json.JSONDecodeError:
        raise ReportPreparationError("非 JSON 报告必须先由 Moderator LLM 转换为 SARIF") from None


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
        if issues:
            raise ReportPreparationError("Moderator LLM SARIF 未通过格式验证：" + "；".join(issues))
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
        if issues:
            raise ReportPreparationError("Moderator LLM SARIF 未通过格式验证：" + "；".join(issues))
        temp_path = _write_temp_sarif(sarif_data, report_path)
        diagnostics.append(f"Moderator 将非 JSON 文本报告转换为临时 SARIF：{temp_path}")
        diagnostics.append(_validation_diagnostic(issues))
        return PreparedReport(report_path, temp_path, diagnostics, temporary=True)

    reviewed, repairs = moderator_review_sarif(data)
    issues = validate_sarif_report(reviewed)
    diagnostics.append(_validation_diagnostic(issues))
    if issues:
        raise ReportPreparationError("SARIF 格式验证失败：" + "；".join(issues))
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
        raise ReportPreparationError("Moderator LLM 不可用，无法将 Markdown 报告转换为 SARIF")
    system, user = _markdown_to_sarif_prompt(text, source_name, moderator_agent)
    attempts = MARKDOWN_TO_SARIF_RETRIES + 1
    last_error = "unknown error"
    for attempt in range(1, attempts + 1):
        attempt_diagnostics: List[str] = []
        try:
            sarif_data = _moderator_markdown_to_sarif_once(
                text=text,
                source_name=source_name,
                moderator_client=moderator_client,
                moderator_agent=moderator_agent,
                system=system,
                user=user,
                diagnostics=attempt_diagnostics,
            )
        except ReportPreparationError as exc:
            last_error = str(exc)
            diagnostics.extend(attempt_diagnostics)
            if attempt < attempts:
                diagnostics.append(
                    f"Moderator LLM Markdown 转 SARIF 第 {attempt}/{attempts} 次失败，准备重试：{last_error}"
                )
                continue
            diagnostics.append(f"Moderator LLM Markdown 转 SARIF 第 {attempt}/{attempts} 次失败：{last_error}")
            break
        diagnostics.extend(attempt_diagnostics)
        if attempt > 1:
            diagnostics.append(f"Moderator LLM Markdown 转 SARIF 第 {attempt}/{attempts} 次尝试成功")
        diagnostics.append("Moderator LLM 已解读 Markdown 并生成 SARIF")
        return sarif_data, diagnostics
    raise ReportPreparationError(f"Moderator LLM Markdown 转 SARIF 在 {attempts} 次尝试后仍失败：{last_error}")


def _moderator_markdown_to_sarif_once(
    text: str,
    source_name: str,
    moderator_client: LLMClient,
    moderator_agent: Optional[AgentConfig],
    system: str,
    user: str,
    diagnostics: List[str],
) -> Dict[str, Any]:
    response = _complete_moderator_llm(moderator_client, system, user, "Moderator LLM Markdown 转换")
    if not response:
        raise ReportPreparationError("Moderator LLM 未返回 Markdown 转换结果")
    sarif_data = _extract_json_object(response)
    if sarif_data is None:
        raise ReportPreparationError("Moderator LLM Markdown 转换结果不是合法 JSON")
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
                return repaired
            diagnostics.append("Moderator LLM 修正后的 SARIF 仍未通过验证：" + "；".join(repaired_issues))
        diagnostics.append("Moderator LLM SARIF 未通过格式验证：" + "；".join(issues))
        raise ReportPreparationError("Moderator LLM SARIF 未通过格式验证：" + "；".join(issues))
    return sarif_data


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
    response = _complete_moderator_llm(moderator_client, system, user, "Moderator LLM SARIF 修复")
    if not response:
        return None
    return _extract_json_object(response)


def _complete_moderator_llm(moderator_client: LLMClient, system: str, user: str, action: str) -> Optional[str]:
    try:
        return moderator_client.complete(system, user)
    except Exception as exc:
        raise ReportPreparationError(f"{action} 调用失败：{exc}") from exc


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

def _message_from_report_properties(fields: Dict[str, str]) -> str:
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
    cleaned = str(value or "").strip()
    if not cleaned:
        return True
    return bool(re.fullmatch(r"\|?\s*:?-{2,}:?(?:\s*\|\s*:?-{2,}:?)+\s*\|?", cleaned))


def _message_from_sarif_result(result: Dict[str, Any]) -> str:
    props = result.get("properties") if isinstance(result.get("properties"), dict) else {}
    fields = {
        key.removeprefix("markdown_"): str(value)
        for key, value in props.items()
        if isinstance(key, str) and key.startswith("markdown_") and value is not None
    }
    message = _message_from_report_properties(fields)
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
        file=_normalize_uri(str(raw_file).strip().strip("`\"'")),
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
