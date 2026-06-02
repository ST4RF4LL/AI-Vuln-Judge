from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from .analyzers import AnalyzerSettings, AnalyzerSuite
from .models import CodeEvidence, EvidenceKind, EvidenceStrength, Finding, ProjectContext
from .source import SourceIndexer, detect_language, evidence_id, supported_language_for_finding


IMPACT_TERMS = {
    "sql": "data exfiltration or unauthorized data modification through SQL injection",
    "injection": "command execution, query manipulation, or policy bypass depending on sink type",
    "command": "remote command execution or local privilege abuse",
    "exec": "remote command execution or local privilege abuse",
    "path": "unauthorized file read/write through path traversal",
    "traversal": "unauthorized file read/write through path traversal",
    "xxe": "file disclosure or server-side request forgery through XML entity expansion",
    "ssrf": "server-side request forgery against internal services",
    "deserialize": "arbitrary object construction or remote code execution",
    "deserialization": "arbitrary object construction or remote code execution",
    "xss": "client-side script execution and session compromise",
    "auth": "authorization bypass or privilege escalation",
    "permission": "authorization bypass or privilege escalation",
    "buffer": "memory corruption, denial of service, or native code execution",
    "overflow": "memory corruption, denial of service, or native code execution",
    "dos": "denial of service",
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
            diagnostics.append(f"Finding language {language} is outside configured languages {self.languages}")
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
            impacts.append("security impact depends on exploitability, data sensitivity, and reachable sink behavior")
        return [
            CodeEvidence(
                evidence_id=evidence_id(finding.finding_id, "impact"),
                kind=EvidenceKind.IMPACT,
                strength=EvidenceStrength.MEDIUM if len(impacts) > 1 or "depends" not in impacts[0] else EvidenceStrength.WEAK,
                summary="Potential impact: " + "; ".join(impacts[:3]),
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
                    summary=f"Project context match: {fact.title}",
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
