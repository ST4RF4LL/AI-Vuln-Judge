from __future__ import annotations

import dataclasses
import copy
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import unquote, urlparse
from uuid import uuid4

from .agents import DEFAULT_MODERATOR_AGENT
from .llm import LLMClient
from .models import AgentConfig
from .models import Finding, SourceLocation
from .vulnerability_types import OTHER_VULNERABILITY_TYPE, infer_vulnerability_type
from .source import SourceIndexer


MARKDOWN_MODERATION_RETRIES = 3
SARIF_MODERATION_RETRIES = 2
DEFAULT_GENERATED_REPORTS_TMP_DIR = Path(".vuln-judger") / "tmp"


@dataclasses.dataclass
class PreparedReport:
    original_path: Path
    effective_path: Path
    diagnostics: List[str]
    temporary: bool = False
    findings: Optional[List[Finding]] = None
    temporary_paths: List[Path] = dataclasses.field(default_factory=list)


@dataclasses.dataclass(frozen=True)
class ModeratedMarkdownReport:
    title: str
    markdown: str


@dataclasses.dataclass(frozen=True)
class ModeratedSarifReport:
    title: str
    result_indices: List[int]
    markdown: str


class ReportPreparationError(RuntimeError):
    """Raised when a report cannot be prepared for processing."""


def load_report(path: Path) -> List[Finding]:
    suffix = path.suffix.lower()
    if suffix in {".md", ".markdown"}:
        raise ReportPreparationError("Markdown 报告必须先由 Moderator LLM 整理为单漏洞 Markdown 报告")
    if suffix in {".sarif", ".json"}:
        return load_sarif(path)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    try:
        return parse_sarif(json.loads(text))
    except json.JSONDecodeError:
        raise ReportPreparationError("非 JSON 报告必须先由 Moderator LLM 整理为单漏洞报告") from None


def load_sarif(path: Path) -> List[Finding]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    return parse_sarif(data)


def prepare_report_for_processing(
    path: Path,
    moderator_client: Optional[LLMClient] = None,
    moderator_agent: Optional[AgentConfig] = None,
    source_path: Optional[Path] = None,
    source_indexer: Optional[SourceIndexer] = None,
) -> PreparedReport:
    """Prepare a report without modifying the original file."""
    report_path = path.expanduser().resolve()
    suffix = report_path.suffix.lower()
    diagnostics: List[str] = []
    if suffix in {".md", ".markdown"}:
        text = report_path.read_text(encoding="utf-8", errors="replace")
        findings, temp_paths, markdown_diagnostics = moderator_prepare_markdown_report(
            text,
            source_name=str(report_path),
            moderator_client=moderator_client,
            moderator_agent=moderator_agent,
        )
        diagnostics.extend(markdown_diagnostics)
        diagnostics.append(f"Moderator 已将 Markdown 报告整理为 {len(findings)} 个持久单漏洞 Markdown 报告")
        return PreparedReport(
            report_path,
            temp_paths[0] if temp_paths else report_path,
            diagnostics,
            temporary=bool(temp_paths),
            findings=findings,
            temporary_paths=temp_paths,
        )

    report_text = report_path.read_text(encoding="utf-8", errors="replace")
    try:
        data = json.loads(report_text)
    except json.JSONDecodeError:
        findings, temp_paths, markdown_diagnostics = moderator_prepare_markdown_report(
            report_text,
            source_name=str(report_path),
            moderator_client=moderator_client,
            moderator_agent=moderator_agent,
        )
        diagnostics.extend(markdown_diagnostics)
        diagnostics.append(f"Moderator 已将非 JSON 文本报告整理为 {len(findings)} 个持久单漏洞 Markdown 报告")
        return PreparedReport(
            report_path,
            temp_paths[0] if temp_paths else report_path,
            diagnostics,
            temporary=bool(temp_paths),
            findings=findings,
            temporary_paths=temp_paths,
        )

    reviewed, repairs = moderator_review_sarif(data)
    issues = validate_sarif_report(reviewed)
    diagnostics.append(_validation_diagnostic(issues))
    if issues:
        if moderator_client is None:
            raise ReportPreparationError("SARIF 格式验证失败：" + "；".join(issues))
        findings, temp_paths, parse_diagnostics = moderator_prepare_markdown_report(
            report_text,
            source_name=str(report_path),
            moderator_client=moderator_client,
            moderator_agent=moderator_agent,
        )
        diagnostics.extend(parse_diagnostics)
        diagnostics.append(f"Moderator 已将解析失败的 SARIF 整理为 {len(findings)} 个持久单漏洞 Markdown 报告")
        return PreparedReport(
            report_path,
            temp_paths[0] if temp_paths else report_path,
            diagnostics,
            temporary=bool(temp_paths),
            findings=findings,
            temporary_paths=temp_paths,
        )
    diagnostics.extend(f"Moderator 修复 SARIF 读取异常：{item}" for item in repairs)
    source_findings = parse_sarif(reviewed)
    grouping_ambiguous = sarif_grouping_is_ambiguous(reviewed, source_findings)
    if moderator_client is not None and source_path is not None and grouping_ambiguous:
        try:
            findings, temp_paths, sarif_diagnostics = moderator_prepare_sarif_report(
                reviewed,
                report_path,
                source_path,
                moderator_client=moderator_client,
                moderator_agent=moderator_agent,
                source_indexer=source_indexer,
            )
        except ReportPreparationError as exc:
            diagnostics.append(f"Moderator SARIF 预处理失败，回退原始 SARIF：{exc}")
        else:
            diagnostics.extend(sarif_diagnostics)
            diagnostics.append(f"Moderator 已将 SARIF 报告整理为 {len(findings)} 个持久单漏洞 Markdown 报告")
            return PreparedReport(
                report_path,
                temp_paths[0] if temp_paths else report_path,
                diagnostics,
                temporary=bool(temp_paths),
                findings=findings,
                temporary_paths=temp_paths,
            )
    elif not grouping_ambiguous:
        diagnostics.append("合法 SARIF 已在本地解析，直接按原始 results 处理")
    elif moderator_client is None:
        diagnostics.append("SARIF 分组存在歧义，但 Moderator LLM 未启用，按原始 results 处理")
    elif source_path is None:
        diagnostics.append("SARIF 分组存在歧义，但未提供源码路径，按原始 results 处理")
    if repairs:
        temp_path = _write_temp_sarif(reviewed, report_path)
        diagnostics.append(f"Moderator 已将修复后的 SARIF 写入临时文件：{temp_path}")
        return PreparedReport(report_path, temp_path, diagnostics, temporary=True, findings=source_findings)
    return PreparedReport(report_path, report_path, diagnostics, temporary=False, findings=source_findings)


def moderator_prepare_markdown_report(
    text: str,
    source_name: str = "markdown-report",
    moderator_client: Optional[LLMClient] = None,
    moderator_agent: Optional[AgentConfig] = None,
) -> tuple[List[Finding], List[Path], List[str]]:
    diagnostics: List[str] = []
    if moderator_client is None:
        raise ReportPreparationError("Moderator LLM 不可用，无法整理 Markdown 报告")
    reports = _moderator_markdown_reports_with_retries(
        moderator_client,
        _markdown_moderation_prompt(text, source_name, moderator_agent),
        action="Moderator LLM Markdown 整理",
        diagnostics=diagnostics,
    )
    findings, temp_paths = _write_moderated_markdown_findings(reports, Path(source_name))
    diagnostics.append(f"Moderator LLM 已读取完整 Markdown 并生成 {len(findings)} 个单漏洞报告")
    return findings, temp_paths, diagnostics


def _moderator_markdown_reports_with_retries(
    moderator_client: LLMClient,
    prompts: tuple[str, str],
    action: str,
    diagnostics: List[str],
) -> List[ModeratedMarkdownReport]:
    system, user = prompts
    attempts = MARKDOWN_MODERATION_RETRIES + 1
    last_error = "unknown error"
    for attempt in range(1, attempts + 1):
        try:
            response = _complete_moderator_llm(moderator_client, system, user, action)
            if not response:
                raise ReportPreparationError("Moderator LLM 未返回 Markdown 整理结果")
            data = _extract_json_object(response)
            if data is None:
                plain_report = _plain_markdown_report_from_response(response)
                if plain_report is None:
                    raise ReportPreparationError("Moderator LLM Markdown 整理结果不是合法 JSON object")
                reports = [plain_report]
            else:
                reports = _moderated_markdown_reports_from_response(data)
            if not reports:
                raise ReportPreparationError("Moderator LLM Markdown 整理结果未包含有效 reports[].markdown")
        except ReportPreparationError as exc:
            last_error = str(exc)
            if attempt < attempts:
                diagnostics.append(f"{action} 第 {attempt}/{attempts} 次失败，准备重试：{last_error}")
                continue
            diagnostics.append(f"{action} 第 {attempt}/{attempts} 次失败：{last_error}")
            break
        if attempt > 1:
            diagnostics.append(f"{action} 第 {attempt}/{attempts} 次尝试成功")
        return reports
    raise ReportPreparationError(f"{action} 在 {attempts} 次尝试后仍失败：{last_error}")


def _markdown_moderation_prompt(
    text: str,
    source_name: str,
    moderator_agent: Optional[AgentConfig],
) -> tuple[str, str]:
    agent = moderator_agent or DEFAULT_MODERATOR_AGENT
    agent_instructions = (agent.instructions or "").strip()
    system = (
        f"你是 {agent.name or '中立 Moderator'}，负责读取完整 Markdown 静态漏洞报告，"
        "并整理成若干份可直接交给正反方研判的单漏洞 Markdown 报告。"
        "不要返回行号范围，不要把 Markdown 转换为 SARIF，不要输出正反方结论或真实漏洞/误报判定。"
        "只输出 JSON object，不要输出代码块、额外解释或 SARIF。"
    )
    if agent_instructions:
        system += f"\nModerator 配置：\n{agent_instructions}"
    user = (
        "请完整读取下面 Markdown 报告，按独立漏洞生成单漏洞 Markdown 报告。\n"
        "输出要求：\n"
        "1. 输出 JSON 格式：{\"reports\":[{\"title\":\"...\",\"markdown\":\"# ...\"}]}。\n"
        "2. 每个 reports[].markdown 必须是一份完整单漏洞报告，保留原始报告中的规则、描述、文件路径、行号、代码块、表格行、调用链、数据流、影响和待核验缺口。\n"
        "3. 如果原报告只有一个漏洞或无法可靠拆分，输出一份包含完整原始上下文的单漏洞报告。\n"
        "4. 不要输出 start_line、end_line、line_range 或任何只供本地切片的字段；由你直接生成最终 Markdown 报告正文。\n"
        "5. 不要新增没有原文支持的漏洞事实，不要做最终真实漏洞/误报裁决。\n\n"
        f"source_report: {source_name}\n\n"
        "Markdown 报告原文开始：\n"
        + text
        + "\nMarkdown 报告原文结束。"
    )
    return system, user


def _moderated_markdown_reports_from_response(data: Dict[str, Any]) -> List[ModeratedMarkdownReport]:
    raw_reports = data.get("reports")
    if raw_reports is None:
        raw_reports = data.get("findings") or data.get("vulnerabilities")
    if isinstance(raw_reports, (dict, str)):
        raw_reports = [raw_reports]
    if not isinstance(raw_reports, list):
        raise ReportPreparationError("Moderator LLM Markdown 整理 JSON 缺少 reports 数组")
    reports: List[ModeratedMarkdownReport] = []
    for report_index, item in enumerate(raw_reports, start=1):
        title = f"Markdown moderated finding {report_index}"
        markdown = ""
        if isinstance(item, str):
            markdown = item.strip()
            title = _markdown_title(markdown) or title
        elif isinstance(item, dict):
            title = str(item.get("title") or item.get("name") or item.get("heading") or title).strip()
            markdown = str(
                item.get("markdown")
                or item.get("report")
                or item.get("body")
                or item.get("content")
                or item.get("analysis")
                or ""
            ).strip()
        if not markdown:
            continue
        reports.append(ModeratedMarkdownReport(title=title or f"Markdown moderated finding {report_index}", markdown=markdown))
    return reports


def _plain_markdown_report_from_response(text: str) -> Optional[ModeratedMarkdownReport]:
    cleaned = text.strip()
    fenced = re.fullmatch(r"```(?:markdown|md)?\s*(.*?)\s*```", cleaned, flags=re.IGNORECASE | re.DOTALL)
    if fenced:
        cleaned = fenced.group(1).strip()
    if not re.search(r"^\s*#{1,6}\s+\S+", cleaned, flags=re.MULTILINE):
        return None
    if len(cleaned) < 40 and "\n" not in cleaned:
        return None
    return ModeratedMarkdownReport(title=_markdown_title(cleaned) or "Markdown moderated finding 1", markdown=cleaned)


def _markdown_title(markdown: str) -> str:
    for line in markdown.splitlines():
        heading = re.match(r"^\s*#{1,6}\s+(.+?)\s*$", line)
        if heading:
            return heading.group(1).strip()
    for line in markdown.splitlines():
        cleaned = line.strip()
        if cleaned:
            return cleaned[:120]
    return ""


def _write_moderated_markdown_findings(
    reports: Sequence[ModeratedMarkdownReport],
    original_path: Path,
) -> tuple[List[Finding], List[Path]]:
    findings: List[Finding] = []
    temp_paths: List[Path] = []
    for index, report in enumerate(reports, start=1):
        body = report.markdown.rstrip() + "\n"
        temp_path = _write_temp_markdown(body, original_path, index)
        temp_paths.append(temp_path)
        title = report.title or _markdown_title(body) or f"Markdown finding {index}"
        finding_id = _moderated_markdown_finding_id(original_path, index, report, body)
        findings.append(
            Finding(
                finding_id=finding_id,
                rule_id=f"markdown-finding-{index}",
                message=title,
                level="warning",
                locations=[],
                code_flows=[],
                properties={
                    "source_format": "markdown",
                    "source_report_format": "markdown",
                    "source_report": str(original_path),
                    "temporary_markdown_report": str(temp_path),
                    "moderator_markdown_preprocessed": True,
                    "generated_report_persisted": True,
                },
                raw={
                    "format": "markdown_moderated_report",
                    "source_report": str(original_path),
                    "temporary_report": str(temp_path),
                    "finding_index": index,
                    "title": title,
                    "markdown": body,
                },
                vulnerability_type=infer_vulnerability_type(
                    rule_id=f"markdown-finding-{index}",
                    message=title,
                    extra_text=body,
                ),
            )
        )
    if not findings:
        raise ReportPreparationError("Moderator LLM 未生成任何可处理的 Markdown 单漏洞报告")
    return findings, temp_paths


def _moderated_markdown_finding_id(original_path: Path, index: int, report: ModeratedMarkdownReport, body: str) -> str:
    seed = {
        "path": str(original_path),
        "index": index,
        "title": report.title,
        "body": body,
    }
    digest = hashlib.sha256(json.dumps(seed, sort_keys=True).encode("utf-8")).hexdigest()
    return digest[:16]


def _write_temp_markdown(text: str, original_path: Path, index: int) -> Path:
    safe_stem = re.sub(r"[^A-Za-z0-9_.-]+", "-", original_path.stem)[:40] or "report"
    tmp_dir = _generated_reports_tmp_dir()
    tmp_dir.mkdir(parents=True, exist_ok=True)
    for _attempt in range(10):
        path = tmp_dir / f"vuln-judger-{safe_stem}-finding-{index}-{uuid4().hex[:12]}.md"
        try:
            with path.open("x", encoding="utf-8") as handle:
                handle.write(text)
        except FileExistsError:
            continue
        return path.resolve()
    path = tmp_dir / f"vuln-judger-{safe_stem}-finding-{index}-{uuid4().hex}.md"
    with path.open("x", encoding="utf-8") as handle:
        handle.write(text)
    return path.resolve()


def _generated_reports_tmp_dir() -> Path:
    configured = os.environ.get("VULN_JUDGER_TMP_DIR")
    if configured:
        return Path(configured).expanduser()
    return DEFAULT_GENERATED_REPORTS_TMP_DIR


def moderator_prepare_sarif_report(
    sarif_data: Dict[str, Any],
    report_path: Path,
    source_path: Path,
    moderator_client: LLMClient,
    moderator_agent: Optional[AgentConfig] = None,
    source_indexer: Optional[SourceIndexer] = None,
) -> tuple[List[Finding], List[Path], List[str]]:
    diagnostics: List[str] = []
    source_findings = parse_sarif(sarif_data)
    if not source_findings:
        raise ReportPreparationError("SARIF 报告没有可供 Moderator 整理的 results")
    reports = _moderator_sarif_reports_with_retries(
        sarif_data=sarif_data,
        source_findings=source_findings,
        report_path=report_path,
        source_path=source_path,
        moderator_client=moderator_client,
        moderator_agent=moderator_agent,
        source_indexer=source_indexer,
        diagnostics=diagnostics,
    )
    findings, temp_paths = _write_moderated_sarif_findings(reports, source_findings, report_path)
    diagnostics.append(f"Moderator LLM 已结合源码整理 SARIF 并生成 {len(findings)} 个独立漏洞报告")
    return findings, temp_paths, diagnostics


def _moderator_sarif_reports_with_retries(
    sarif_data: Dict[str, Any],
    source_findings: Sequence[Finding],
    report_path: Path,
    source_path: Path,
    moderator_client: LLMClient,
    moderator_agent: Optional[AgentConfig],
    source_indexer: Optional[SourceIndexer],
    diagnostics: List[str],
) -> List[ModeratedSarifReport]:
    system, user = _sarif_moderation_prompt(
        sarif_data,
        source_findings,
        report_path,
        source_path,
        moderator_agent,
        source_indexer=source_indexer,
    )
    attempts = SARIF_MODERATION_RETRIES + 1
    last_error = "unknown error"
    for attempt in range(1, attempts + 1):
        try:
            response = _complete_moderator_llm(moderator_client, system, user, "Moderator LLM SARIF 预处理")
            if not response:
                raise ReportPreparationError("Moderator LLM 未返回 SARIF 预处理结果")
            data = _extract_json_object(response)
            if data is None:
                raise ReportPreparationError("Moderator LLM SARIF 预处理结果不是合法 JSON object")
            reports = _moderated_sarif_reports_from_response(data, len(source_findings))
            if not reports:
                raise ReportPreparationError("Moderator LLM SARIF 预处理结果未包含有效 reports")
        except ReportPreparationError as exc:
            last_error = str(exc)
            if attempt < attempts:
                diagnostics.append(f"Moderator LLM SARIF 预处理第 {attempt}/{attempts} 次失败，准备重试：{last_error}")
                continue
            diagnostics.append(f"Moderator LLM SARIF 预处理第 {attempt}/{attempts} 次失败：{last_error}")
            break
        if attempt > 1:
            diagnostics.append(f"Moderator LLM SARIF 预处理第 {attempt}/{attempts} 次尝试成功")
        return reports
    raise ReportPreparationError(f"Moderator LLM SARIF 预处理在 {attempts} 次尝试后仍失败：{last_error}")


def _sarif_moderation_prompt(
    sarif_data: Dict[str, Any],
    source_findings: Sequence[Finding],
    report_path: Path,
    source_path: Path,
    moderator_agent: Optional[AgentConfig],
    *,
    source_indexer: Optional[SourceIndexer] = None,
) -> tuple[str, str]:
    agent = moderator_agent or DEFAULT_MODERATOR_AGENT
    agent_instructions = (agent.instructions or "").strip()
    system = (
        f"你是 {agent.name or '中立 Moderator'}，负责预处理 SARIF 静态漏洞报告。"
        "你必须结合 SARIF result、codeFlow 和项目源码片段，判断哪些 result 属于同一个独立漏洞，"
        "并整理成若干份可直接交给正反方研判的单漏洞 Markdown 报告。"
        "不要只做关键词匹配；不要丢弃 SARIF 中的路径、消息、代码流和源码上下文；"
        "只输出 JSON object，不要输出代码块、额外解释或 SARIF。"
    )
    if agent_instructions:
        system += f"\nModerator 配置：\n{agent_instructions}"
    payload = {
        "source_report": str(report_path),
        "source_root": str(source_path.expanduser().resolve()),
        "sarif_tool": _sarif_tool_name(sarif_data),
        "results": _sarif_results_for_moderator(source_findings, source_path, source_indexer=source_indexer),
    }
    user = (
        "请读取下面 SARIF 结果和源码上下文，拆分/合并为独立漏洞报告。\n"
        "输出要求：\n"
        "1. 输出 JSON 格式：{\"reports\":[{\"title\":\"...\",\"result_indices\":[0],\"markdown\":\"# ...\"}]}。\n"
        "2. result_indices 必须引用下方 results[].result_index，使用 0-based 编号；同一漏洞可包含多个 result_index。\n"
        "3. markdown 必须是一份完整单漏洞报告，保留 SARIF 原始消息、位置、codeFlow、相关源码片段、Moderator 对分组/拆分的依据和仍需正反方核验的缺口。\n"
        "4. 不要输出正反方结论，不要判定真实漏洞/误报；这里只做报告拆分整理。\n"
        "5. 如果无法确认多个 result 属于同一漏洞，应拆成多份报告而不是强行合并。\n\n"
        "SARIF 与源码上下文 JSON：\n"
        + json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    )
    return system, user


def _sarif_tool_name(sarif_data: Dict[str, Any]) -> str:
    runs = sarif_data.get("runs") if isinstance(sarif_data, dict) else []
    if not isinstance(runs, list) or not runs:
        return ""
    first = runs[0] if isinstance(runs[0], dict) else {}
    tool = first.get("tool") if isinstance(first.get("tool"), dict) else {}
    driver = tool.get("driver") if isinstance(tool.get("driver"), dict) else {}
    return str(driver.get("name") or "")


def _sarif_results_for_moderator(
    source_findings: Sequence[Finding],
    source_path: Path,
    *,
    source_indexer: Optional[SourceIndexer] = None,
) -> List[Dict[str, Any]]:
    indexer = source_indexer or SourceIndexer(source_path)
    results: List[Dict[str, Any]] = []
    for result_index, finding in enumerate(source_findings):
        results.append(
            {
                "result_index": result_index,
                "rule_id": finding.rule_id,
                "level": finding.level,
                "message": finding.message,
                "locations": [location.display() for location in finding.locations],
                "code_flows": [[location.display() for location in flow] for flow in finding.code_flows[:4]],
                "properties": _compact_mapping(finding.properties, limit=20),
                "raw_result": _compact_mapping(finding.raw, limit=30),
                "source_context": _source_context_for_moderator(indexer, finding),
            }
        )
    return results


def _source_context_for_moderator(indexer: SourceIndexer, finding: Finding) -> List[Dict[str, Any]]:
    locations: List[SourceLocation] = []
    locations.extend(finding.locations)
    for flow in finding.code_flows[:3]:
        locations.extend(flow[:8])
    result: List[Dict[str, Any]] = []
    seen = set()
    for location in locations:
        marker = location.display()
        if marker in seen:
            continue
        seen.add(marker)
        resolved = indexer.resolve_location(location)
        result.append(
            {
                "reported": location.display(),
                "resolved_file": resolved.relative_path,
                "exists": resolved.exists,
                "line_exists": resolved.line_exists,
                "symbol": resolved.symbol,
                "snippet": (resolved.snippet or "")[:1800],
            }
        )
        if len(result) >= 12:
            break
    return result


def _compact_mapping(value: Any, limit: int = 20, text_limit: int = 1200) -> Any:
    if isinstance(value, dict):
        compact: Dict[str, Any] = {}
        for key, item in list(value.items())[:limit]:
            compact[str(key)[:120]] = _compact_mapping(item, limit=limit, text_limit=text_limit)
        return compact
    if isinstance(value, list):
        return [_compact_mapping(item, limit=limit, text_limit=text_limit) for item in value[:limit]]
    if isinstance(value, str):
        return value[:text_limit]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:text_limit]


def _moderated_sarif_reports_from_response(data: Dict[str, Any], finding_count: int) -> List[ModeratedSarifReport]:
    raw_reports = data.get("reports")
    if raw_reports is None:
        raw_reports = data.get("findings") or data.get("vulnerabilities")
    if not isinstance(raw_reports, list):
        raise ReportPreparationError("Moderator LLM SARIF 预处理 JSON 缺少 reports 数组")
    reports: List[ModeratedSarifReport] = []
    for report_index, item in enumerate(raw_reports, start=1):
        if not isinstance(item, dict):
            continue
        markdown = str(item.get("markdown") or item.get("report") or item.get("body") or "").strip()
        if not markdown:
            continue
        indices = _sarif_result_indices_from_item(item, finding_count, fallback_index=report_index - 1)
        title = str(item.get("title") or item.get("name") or f"SARIF moderated finding {report_index}").strip()
        reports.append(ModeratedSarifReport(title=title or f"SARIF moderated finding {report_index}", result_indices=indices, markdown=markdown))
    return reports


def _sarif_result_indices_from_item(item: Dict[str, Any], finding_count: int, fallback_index: int) -> List[int]:
    raw = (
        item.get("result_indices")
        or item.get("resultIndexes")
        or item.get("sarif_result_indices")
        or item.get("sarifResultIndices")
        or item.get("result_index")
        or item.get("resultIndex")
    )
    if raw is None:
        raw_values: List[Any] = []
    elif isinstance(raw, list):
        raw_values = raw
    else:
        raw_values = [raw]
    indices: List[int] = []
    for value in raw_values:
        try:
            index = int(value)
        except (TypeError, ValueError):
            continue
        if 0 <= index < finding_count and index not in indices:
            indices.append(index)
    if not indices and 0 <= fallback_index < finding_count:
        indices.append(fallback_index)
    return indices


def _write_moderated_sarif_findings(
    reports: Sequence[ModeratedSarifReport],
    source_findings: Sequence[Finding],
    original_path: Path,
) -> tuple[List[Finding], List[Path]]:
    findings: List[Finding] = []
    temp_paths: List[Path] = []
    for index, report in enumerate(reports, start=1):
        selected = [source_findings[result_index] for result_index in report.result_indices if 0 <= result_index < len(source_findings)]
        if not selected and source_findings:
            selected = [source_findings[min(index - 1, len(source_findings) - 1)]]
        body = report.markdown.rstrip() + "\n"
        temp_path = _write_temp_markdown(body, original_path, index)
        temp_paths.append(temp_path)
        locations = _dedupe_source_locations(location for finding in selected for location in finding.locations)
        code_flows = [flow for finding in selected for flow in finding.code_flows]
        rule_id = selected[0].rule_id if len(selected) == 1 else f"moderated-sarif-finding-{index}"
        level = _strongest_level(finding.level for finding in selected) or "warning"
        finding_id = _moderated_sarif_finding_id(original_path, index, report, body)
        findings.append(
            Finding(
                finding_id=finding_id,
                rule_id=rule_id,
                message=report.title,
                level=level,
                locations=locations,
                code_flows=code_flows,
                properties={
                    "source_format": "markdown",
                    "source_report_format": "sarif",
                    "source_report": str(original_path),
                    "temporary_markdown_report": str(temp_path),
                    "sarif_result_indices": list(report.result_indices),
                    "moderator_sarif_preprocessed": True,
                },
                raw={
                    "format": "sarif_moderated_markdown",
                    "source_report": str(original_path),
                    "temporary_report": str(temp_path),
                    "finding_index": index,
                    "title": report.title,
                    "sarif_result_indices": list(report.result_indices),
                    "markdown": body,
                    "source_sarif_results": [finding.raw for finding in selected],
                },
                vulnerability_type=_moderated_vulnerability_type(
                    rule_id=rule_id,
                    title=report.title,
                    body=body,
                    selected=selected,
                ),
            )
        )
    if not findings:
        raise ReportPreparationError("Moderator LLM 未生成任何可处理的 SARIF 单漏洞报告")
    return findings, temp_paths


def _dedupe_source_locations(locations: Iterable[SourceLocation]) -> List[SourceLocation]:
    result: List[SourceLocation] = []
    seen = set()
    for location in locations:
        marker = (location.file, location.line, location.column, location.end_line, location.end_column, location.symbol)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(location)
    return result


def _strongest_level(levels: Iterable[str]) -> str:
    rank = {"error": 4, "warning": 3, "note": 2, "none": 1}
    strongest = ""
    strongest_rank = -1
    for level in levels:
        normalized = str(level or "").lower()
        current_rank = rank.get(normalized, 0)
        if current_rank > strongest_rank:
            strongest = str(level or "")
            strongest_rank = current_rank
    return strongest


def _moderated_sarif_finding_id(original_path: Path, index: int, report: ModeratedSarifReport, body: str) -> str:
    seed = {
        "path": str(original_path),
        "index": index,
        "result_indices": list(report.result_indices),
        "title": report.title,
        "body": body,
    }
    digest = hashlib.sha256(json.dumps(seed, sort_keys=True).encode("utf-8")).hexdigest()
    return digest[:16]


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


def _complete_moderator_llm(moderator_client: LLMClient, system: str, user: str, action: str) -> Optional[str]:
    try:
        return moderator_client.complete(system, user)
    except Exception as exc:
        raise ReportPreparationError(f"{action} 调用失败：{exc}") from exc


def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    cleaned = text.strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)\s*```", cleaned, flags=re.IGNORECASE | re.DOTALL)
    if fenced:
        cleaned = fenced.group(1).strip()
    elif not cleaned.startswith(("{", "[")):
        starts = [position for position in (cleaned.find("{"), cleaned.find("[")) if position >= 0]
        start = min(starts) if starts else -1
        end = max(cleaned.rfind("}"), cleaned.rfind("]"))
        if start >= 0 and end > start:
            cleaned = cleaned[start : end + 1]
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        return None
    if isinstance(data, list):
        return {"findings": data}
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
                    vulnerability_type=infer_vulnerability_type(
                        rule_id=rule_id,
                        message=message,
                        properties=properties,
                        raw=result,
                    ),
                )
            )
    return findings


def _moderated_vulnerability_type(
    *,
    rule_id: str,
    title: str,
    body: str,
    selected: Sequence[Finding],
) -> str:
    inferred = infer_vulnerability_type(rule_id=rule_id, message=title, extra_text=body)
    if inferred != OTHER_VULNERABILITY_TYPE:
        return inferred
    types = {finding.vulnerability_type for finding in selected if finding.vulnerability_type}
    return types.pop() if len(types) == 1 else inferred


def sarif_grouping_is_ambiguous(
    data: Dict[str, Any],
    findings: Optional[Sequence[Finding]] = None,
) -> bool:
    """Return whether SARIF results carry evidence that a 1:1 finding mapping is unsafe."""
    raw_results = [
        result
        for run in data.get("runs", [])
        if isinstance(run, dict)
        for result in run.get("results", [])
        if isinstance(result, dict)
    ]
    parsed_findings = list(findings) if findings is not None else parse_sarif(data)
    if not raw_results or len(raw_results) != len(parsed_findings):
        return True

    seen_signatures = set()
    for finding in parsed_findings:
        signature = (
            finding.rule_id,
            finding.message,
            tuple(location.display() for location in finding.locations),
            tuple(tuple(location.display() for location in flow) for flow in finding.code_flows),
        )
        if signature in seen_signatures:
            return True
        seen_signatures.add(signature)

    seen_markers = set()
    for result in raw_results:
        markers = []
        correlation_guid = str(result.get("correlationGuid") or "").strip()
        if correlation_guid:
            markers.append(("correlationGuid", correlation_guid))
        for field in ("fingerprints", "partialFingerprints"):
            values = result.get(field)
            if not isinstance(values, dict):
                continue
            markers.extend(
                (field, str(name), str(value))
                for name, value in values.items()
                if str(value).strip()
            )
        if any(marker in seen_markers for marker in markers):
            return True
        seen_markers.update(markers)
    return False


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
    if not isinstance(message, dict):
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
        if not isinstance(value, str):
            return None
        match = re.search(r"\d+", value)
        return int(match.group(0)) if match else None


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
