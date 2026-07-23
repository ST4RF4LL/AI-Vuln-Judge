from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from .analyzers import AnalyzerSettings, AnalyzerSuite
from .models import CodeEvidence, EvidenceKind, EvidenceStrength, Finding, ProjectContext
from .source import SourceIndexer, detect_language, evidence_id, supported_language_for_finding


IMPACT_TERMS = {
    "sql": "可通过 SQL 注入造成数据窃取或未授权数据修改",
    "injection": "可能造成命令执行、查询篡改或策略绕过，具体取决于危险汇点类型",
    "command": "可能造成远程命令执行或本地权限滥用",
    "exec": "可能造成远程命令执行或本地权限滥用",
    "path": "可能通过路径穿越造成未授权文件读取或写入",
    "traversal": "可能通过路径穿越造成未授权文件读取或写入",
    "xxe": "可能通过 XML 实体扩展造成文件泄露或服务端请求伪造",
    "ssrf": "可能对内部服务发起服务端请求伪造",
    "deserialize": "可能造成任意对象构造或远程代码执行",
    "deserialization": "可能造成任意对象构造或远程代码执行",
    "xss": "可能造成客户端脚本执行和会话失陷",
    "auth": "可能造成鉴权绕过或权限提升",
    "permission": "可能造成鉴权绕过或权限提升",
    "buffer": "可能造成内存破坏、拒绝服务或本地代码执行",
    "overflow": "可能造成内存破坏、拒绝服务或本地代码执行",
    "dos": "可能造成拒绝服务",
}


@dataclass
class EvidenceBundle:
    finding: Finding
    evidence: List[CodeEvidence]
    diagnostics: List[str]


class EvidenceCollector:
    def __init__(
        self,
        indexer: SourceIndexer,
        project_context: ProjectContext,
        analyzers: AnalyzerSuite,
        analyzer_settings: AnalyzerSettings,
        languages: Sequence[str],
    ):
        self.indexer = indexer
        self.project_context = project_context
        self.analyzers = analyzers
        self.analyzer_settings = analyzer_settings
        self.languages = [language.lower() for language in languages]

    def collect(self, finding: Finding) -> EvidenceBundle:
        evidence: List[CodeEvidence] = []
        diagnostics: List[str] = []
        if not supported_language_for_finding(finding, self.languages):
            language = detect_language(finding.primary_location.file) if finding.primary_location else "unknown"
            diagnostics.append(f"发现所属语言 {language} 不在当前配置语言范围内：{self.languages}")
        evidence.append(self._source_root_evidence(finding))
        evidence.append(self._report_evidence(finding))
        for location in finding.locations:
            evidence.append(self.indexer.evidence_for_location(finding, location))
        evidence.extend(self.indexer.evidence_for_code_flows(finding))
        evidence.extend(self.indexer.source_sink_evidence(finding))
        evidence.extend(self.indexer.protection_evidence(finding))
        evidence.extend(self._impact_evidence(finding))
        evidence.extend(self._project_context_evidence(finding))
        evidence.extend(self.analyzers.analyze(finding, self.indexer, self.analyzer_settings))
        evidence.extend(self._affirmative_evidence_hunting_evidence(finding, evidence))
        return EvidenceBundle(finding=finding, evidence=_dedupe_evidence(evidence), diagnostics=diagnostics)

    def _source_root_evidence(self, finding: Finding) -> CodeEvidence:
        source_root = self.indexer.source_root
        exists = source_root.exists()
        is_dir = source_root.is_dir()
        atlas_db = source_root / ".atlas" / "atlas.db"
        summary = f"任务源码根目录已配置：{source_root}"
        if exists and is_dir:
            summary += "；目录存在"
        elif exists:
            summary += "；路径存在但不是目录"
        else:
            summary += "；目录不存在"
        profile = self.indexer.language_profile
        counts_text = ", ".join(f"{language}={count}" for language, count in profile.file_counts.items() if count)
        if counts_text:
            summary += f"；自动检测语言：{', '.join(self.languages)}（{counts_text}）"
        elif profile.fallback_used:
            summary += f"；未检测到支持语言，使用支持语言兜底：{', '.join(self.languages)}"
        else:
            summary += f"；自动检测语言：{', '.join(self.languages) or '未指定'}"
        summary += "；Atlas 数据库" + ("存在" if atlas_db.exists() else "不存在")
        return CodeEvidence(
            evidence_id=evidence_id(finding.finding_id, "source-root", str(source_root)),
            kind=EvidenceKind.SOURCE_ROOT,
            strength=EvidenceStrength.STRONG if exists and is_dir else EvidenceStrength.WEAK,
            summary=summary,
            source="task-config",
            data={
                "source_root": str(source_root),
                "source_root_exists": exists,
                "source_root_is_dir": is_dir,
                "languages": list(self.languages),
                "language_file_counts": dict(profile.file_counts),
                "language_total_supported_files": profile.total_supported_files,
                "language_detection_fallback": profile.fallback_used,
                "atlas_database": str(atlas_db),
                "atlas_database_exists": atlas_db.exists(),
            },
        )

    def _report_evidence(self, finding: Finding) -> CodeEvidence:
        raw_result = dict(finding.raw)
        properties = dict(finding.properties)
        markdown_report = str(raw_result.get("markdown") or "") if properties.get("source_format") == "markdown" else ""
        locations = [location.display() for location in finding.locations]
        if markdown_report:
            start_line = properties.get("markdown_start_line")
            end_line = properties.get("markdown_end_line")
            range_text = f"；原始行号 {start_line}-{end_line}" if start_line and end_line else ""
            if properties.get("source_report_format") == "sarif":
                indices = properties.get("sarif_result_indices") or []
                index_text = f"；SARIF results {indices}" if indices else ""
                summary = f"输入 SARIF 经 Moderator 整理后的单漏洞报告：{finding.message or finding.rule_id}{index_text}"
            else:
                summary = f"输入 Markdown 单漏洞报告：{finding.message or finding.rule_id}{range_text}"
        else:
            summary = f"输入报告发现：{finding.rule_id}（{finding.level}）"
            if finding.message:
                summary += f"，消息：{finding.message}"
            if locations:
                summary += f"，位置：{'; '.join(locations[:5])}"
            if finding.code_flows:
                summary += f"，报告内代码流 {len(finding.code_flows)} 条"
        return CodeEvidence(
            evidence_id=evidence_id(finding.finding_id, "input-report"),
            kind=EvidenceKind.REPORT,
            strength=EvidenceStrength.STRONG,
            summary=summary,
            source="input-report",
            locations=list(finding.locations),
            snippet=markdown_report or None,
            data={
                "source_format": properties.get("source_format") or "sarif",
                "source_report_format": properties.get("source_report_format"),
                "source_report": properties.get("source_report"),
                "temporary_markdown_report": properties.get("temporary_markdown_report"),
                "markdown_start_line": properties.get("markdown_start_line"),
                "markdown_end_line": properties.get("markdown_end_line"),
                "sarif_result_indices": properties.get("sarif_result_indices"),
                "markdown_report": markdown_report,
                "rule_id": finding.rule_id,
                "vulnerability_type": finding.vulnerability_type,
                "level": finding.level,
                "message": finding.message,
                "locations": [location.display() for location in finding.locations],
                "code_flows": [[location.display() for location in flow] for flow in finding.code_flows],
                "location_count": len(finding.locations),
                "code_flow_count": len(finding.code_flows),
                "properties": properties,
                "raw_result": raw_result,
            },
        )

    def _impact_evidence(self, finding: Finding) -> List[CodeEvidence]:
        text = f"{finding.rule_id} {finding.message} {' '.join(map(str, finding.properties.values()))}".lower()
        impacts = []
        for term, impact in IMPACT_TERMS.items():
            if term in text and impact not in impacts:
                impacts.append(impact)
        if not impacts:
            impacts.append("安全影响取决于可利用性、数据敏感性以及危险汇点是否可达")
        return [
            CodeEvidence(
                evidence_id=evidence_id(finding.finding_id, "impact"),
                kind=EvidenceKind.IMPACT,
                strength=EvidenceStrength.MEDIUM if len(impacts) > 1 or "取决于" not in impacts[0] else EvidenceStrength.WEAK,
                summary="潜在影响：" + "; ".join(impacts[:3]),
                source="impact-mapper",
                data={"impacts": impacts},
            )
        ]

    def _project_context_evidence(self, finding: Finding) -> List[CodeEvidence]:
        terms = [finding.rule_id, finding.message]
        terms.extend(location.file for location in finding.locations)
        matches = self.project_context.matching_facts(terms, limit=5)
        result = []
        for fact in matches:
            result.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, "project-context", fact.fact_id),
                    kind=EvidenceKind.PROJECT_CONTEXT,
                    strength=EvidenceStrength.MEDIUM,
                    summary=f"命中项目上下文：{fact.title}",
                    source=fact.source,
                    data={"fact_id": fact.fact_id, "tags": fact.tags, "excerpt": fact.content[:1200]},
                )
            )
        return result

    def _affirmative_evidence_hunting_evidence(
        self, finding: Finding, evidence: Sequence[CodeEvidence]
    ) -> List[CodeEvidence]:
        missing: List[str] = []
        actions: List[str] = []
        has_valid_location = _has_valid_source_location(evidence)
        has_meaningful_flow = _has_meaningful_flow(evidence)
        if not has_valid_location:
            missing.append("source_location")
            actions.append(
                "源码真实性不足：优先用报告路径后缀、文件名和符号名重新匹配源码；检查 Atlas project/files；必要时全文搜索报告中的文件名、函数名和规则关键词。"
            )
        if not has_meaningful_flow and not _has_strong_data_flow(evidence):
            missing.append("data_flow")
            actions.append(
                "数据流不足：优先调用 Atlas trace point/variable 向上游追溯到外部输入源头；若 trace 为 partial、empty 或 No data node，应合理怀疑 Atlas 未正确处理调用链关系，转用报告路径附近源码片段和 agentic-rg 候选源点/汇点逐跳手动重构；一旦找到新的上游节点，再回到 Atlas trace/calls 继续追溯。"
            )
        if not has_meaningful_flow and not _has_call_chain(evidence):
            missing.append("call_chain")
            actions.append(
                "调用链不足：使用报告符号、附近函数、文件 stem 和危险汇点作为 Atlas search 查询词，再对候选 qualified_name 调用 calls both 向上游追到外部输入源头；若 Atlas 缺边或无法解析间接调用，转用源码阅读和 grep/ripgrep 搜索入口函数、调用邻域、参数名、源点词和汇点词；定位到新调用者后再回到 Atlas 继续追溯。"
            )
        if (
            self.analyzer_settings.enabled
            and (not has_valid_location or not has_meaningful_flow)
            and not _has_atlas_semantic_evidence(evidence)
        ):
            missing.append("atlas_semantic")
            if _atlas_database_exists(evidence):
                actions.append(
                    "Atlas 语义证据不足：读取 project/status 确认索引规模和语言能力，读取 project/files 确认报告文件已入库，再用 search/trace/calls 补齐缺口。"
                )
            else:
                actions.append(
                    "Atlas 语义证据不足：Atlas v1.5+ 可无需预建 .atlas/atlas.db 直接通过 MCP Focus 查询；优先确认 Atlas MCP 可用并调用 project/open、project/status、search、trace/calls，必要时启用 auto_index_tools 预热持久缓存。"
                )
        if _has_protection_evidence(evidence):
            missing.append("protection_bypass")
            actions.append(
                "存在防护迹象：继续阅读防护附近源码，证明校验、鉴权、消毒或限流是否覆盖当前输入；若不能完全覆盖，应说明绕过条件和残余风险。"
            )
        if not missing:
            return []
        summary = "正方证据不足补强策略：缺口 " + ", ".join(missing) + "；应继续主动补证而非直接接受证据不足"
        return [
            CodeEvidence(
                evidence_id=evidence_id(finding.finding_id, "affirmative-evidence-plan", *missing),
                kind=EvidenceKind.TOOL_DIAGNOSTIC,
                strength=EvidenceStrength.MEDIUM,
                summary=summary,
                source="affirmative-evidence-planner",
                data={
                    "missing_evidence": missing,
                    "suggested_actions": actions,
                    "atlas_mode": "agentic_only",
                    "auto_index_tools": self.analyzer_settings.auto_index,
                    "atlas_database_exists": _atlas_database_exists(evidence),
                },
            )
        ]


def _dedupe_evidence(evidence: List[CodeEvidence]) -> List[CodeEvidence]:
    seen = set()
    result = []
    for item in evidence:
        if item.evidence_id in seen:
            continue
        seen.add(item.evidence_id)
        result.append(item)
    return result


def _has_valid_source_location(evidence: Sequence[CodeEvidence]) -> bool:
    return any(
        item.kind == EvidenceKind.SOURCE_LOCATION
        and (item.data.get("line_exists") or item.data.get("mcp_success") or item.data.get("matched_files"))
        for item in evidence
    )


def _has_strong_data_flow(evidence: Sequence[CodeEvidence]) -> bool:
    for item in evidence:
        if item.kind == EvidenceKind.SARIF_CODE_FLOW and item.strength in {EvidenceStrength.STRONG, EvidenceStrength.MEDIUM}:
            return True
        if item.kind == EvidenceKind.DATA_FLOW and item.source != "code-search" and item.strength in {
            EvidenceStrength.STRONG,
            EvidenceStrength.MEDIUM,
        }:
            return True
    return False


def _has_call_chain(evidence: Sequence[CodeEvidence]) -> bool:
    return any(
        item.kind == EvidenceKind.CALL_CHAIN
        and item.strength in {EvidenceStrength.STRONG, EvidenceStrength.MEDIUM}
        for item in evidence
    )


def _has_meaningful_flow(evidence: Sequence[CodeEvidence]) -> bool:
    return _has_strong_data_flow(evidence) or _has_call_chain(evidence)


def _has_atlas_semantic_evidence(evidence: Sequence[CodeEvidence]) -> bool:
    return any(
        item.source.startswith("atlas")
        and item.data.get("mcp_success")
        and item.kind in {EvidenceKind.SOURCE_LOCATION, EvidenceKind.DATA_FLOW, EvidenceKind.CALL_CHAIN}
        for item in evidence
    )


def _atlas_database_exists(evidence: Sequence[CodeEvidence]) -> bool:
    return any(
        (item.kind == EvidenceKind.SOURCE_ROOT and item.data.get("atlas_database_exists"))
        or (item.source.startswith("atlas") and item.data.get("database"))
        for item in evidence
    )


def _has_protection_evidence(evidence: Sequence[CodeEvidence]) -> bool:
    return any(item.kind == EvidenceKind.PROTECTION for item in evidence)
