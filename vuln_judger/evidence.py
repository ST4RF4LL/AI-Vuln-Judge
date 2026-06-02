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
        for location in finding.locations:
            evidence.append(self.indexer.evidence_for_location(finding, location))
        evidence.extend(self.indexer.evidence_for_code_flows(finding))
        evidence.extend(self.indexer.source_sink_evidence(finding))
        evidence.extend(self.indexer.protection_evidence(finding))
        compile_db = self.indexer.compile_database_evidence(finding)
        if compile_db is not None:
            evidence.append(compile_db)
        evidence.extend(self._impact_evidence(finding))
        evidence.extend(self._project_context_evidence(finding))
        evidence.extend(self.analyzers.analyze(finding, self.indexer, self.analyzer_settings))
        return EvidenceBundle(finding=finding, evidence=_dedupe_evidence(evidence), diagnostics=diagnostics)

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


def _dedupe_evidence(evidence: List[CodeEvidence]) -> List[CodeEvidence]:
    seen = set()
    result = []
    for item in evidence:
        if item.evidence_id in seen:
            continue
        seen.add(item.evidence_id)
        result.append(item)
    return result
