from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

from .models import CodeEvidence, EvidenceKind, EvidenceStrength, Finding, SourceLocation
from .source import SourceIndexer, detect_language, evidence_id


@dataclass
class AnalyzerSettings:
    enabled: bool = True
    auto_index: bool = False
    timeout_seconds: int = 30


class Analyzer:
    name = "analyzer"

    def analyze(self, finding: Finding, indexer: SourceIndexer, settings: AnalyzerSettings) -> List[CodeEvidence]:
        raise NotImplementedError


class AnalyzerSuite:
    def __init__(self, analyzers: Optional[Sequence[Analyzer]] = None):
        self.analyzers = list(analyzers or [AtlasAnalyzer(), CodeGraphAnalyzer(), CodeQLAnalyzer()])

    def analyze(self, finding: Finding, indexer: SourceIndexer, settings: AnalyzerSettings) -> List[CodeEvidence]:
        evidence: List[CodeEvidence] = []
        if not settings.enabled:
            return evidence
        for analyzer in self.analyzers:
            try:
                evidence.extend(analyzer.analyze(finding, indexer, settings))
            except Exception as exc:  # pragma: no cover - defensive diagnostics
                evidence.append(
                    CodeEvidence(
                        evidence_id=evidence_id(finding.finding_id, analyzer.name, "exception"),
                        kind=EvidenceKind.TOOL_DIAGNOSTIC,
                        strength=EvidenceStrength.WEAK,
                        summary=f"{analyzer.name} adapter failed: {exc}",
                        source=analyzer.name,
                    )
                )
        return evidence


class AtlasAnalyzer(Analyzer):
    name = "atlas"

    def __init__(self, binary: Optional[str] = None):
        self.binary = binary or shutil.which("atlas")

    def analyze(self, finding: Finding, indexer: SourceIndexer, settings: AnalyzerSettings) -> List[CodeEvidence]:
        primary = finding.primary_location
        if primary is None:
            return []
        if not self.binary:
            return [_tool_unavailable(finding, self.name, "atlas command was not found")]
        resolved = indexer.resolve_location(primary)
        if not resolved.exists or resolved.absolute_path is None:
            return []
        atlas_db = indexer.source_root / ".atlas" / "atlas.db"
        diagnostics: List[CodeEvidence] = []
        if not atlas_db.exists():
            if not settings.auto_index:
                return [
                    CodeEvidence(
                        evidence_id=evidence_id(finding.finding_id, self.name, "not-indexed"),
                        kind=EvidenceKind.TOOL_DIAGNOSTIC,
                        strength=EvidenceStrength.PARTIAL,
                        summary="Atlas is installed but .atlas/atlas.db is absent; rerun with --auto-index-tools for Atlas traces",
                        source=self.name,
                    )
                ]
            diagnostics.extend(self._index_project(finding, indexer, settings))
        if not atlas_db.exists():
            return diagnostics
        relative = resolved.relative_path
        line = primary.line or 1
        column = primary.column or 1
        traces = [
            ("trace-point", ["trace", "point", "--file", relative, "--line", str(line), "--column", str(column), "--json"]),
            (
                "trace-variable",
                ["trace", "variable", "--file", relative, "--line", str(line), "--column", str(column), "--max-depth", "30", "--json"],
            ),
        ]
        for trace_name, args in traces:
            completed = _run_tool(self.binary, args, cwd=indexer.source_root, timeout=settings.timeout_seconds)
            diagnostics.append(_evidence_from_tool_output(finding, self.name, trace_name, completed, [primary]))
        return diagnostics

    def _index_project(
        self, finding: Finding, indexer: SourceIndexer, settings: AnalyzerSettings
    ) -> List[CodeEvidence]:
        outputs = []
        for step in (["init"], ["index"]):
            completed = _run_tool(self.binary, step, cwd=indexer.source_root, timeout=max(settings.timeout_seconds, 120))
            outputs.append(f"{' '.join(step)}: exit={completed.returncode}")
            if completed.returncode != 0:
                outputs.append((completed.stderr or completed.stdout or "").strip()[:800])
                break
        strength = EvidenceStrength.MEDIUM if (indexer.source_root / ".atlas" / "atlas.db").exists() else EvidenceStrength.PARTIAL
        return [
            CodeEvidence(
                evidence_id=evidence_id(finding.finding_id, self.name, "index"),
                kind=EvidenceKind.TOOL_DIAGNOSTIC,
                strength=strength,
                summary="Atlas indexing attempted: " + "; ".join(item for item in outputs if item),
                source=self.name,
            )
        ]


class CodeGraphAnalyzer(Analyzer):
    name = "codegraph"

    def __init__(self, binary: Optional[str] = None):
        self.binary = binary or shutil.which("codegraph")

    def analyze(self, finding: Finding, indexer: SourceIndexer, settings: AnalyzerSettings) -> List[CodeEvidence]:
        if not self.binary:
            return [_tool_unavailable(finding, self.name, "codegraph command was not found")]
        # CodeGraph command names changed across releases; keep this adapter conservative.
        completed = _run_tool(self.binary, ["status"], cwd=indexer.source_root, timeout=settings.timeout_seconds)
        return [_evidence_from_tool_output(finding, self.name, "status", completed, finding.locations[:1])]


class CodeQLAnalyzer(Analyzer):
    name = "codeql"

    def __init__(self, binary: Optional[str] = None):
        self.binary = binary or shutil.which("codeql")

    def analyze(self, finding: Finding, indexer: SourceIndexer, settings: AnalyzerSettings) -> List[CodeEvidence]:
        primary = finding.primary_location
        if primary is None:
            return []
        language = detect_language(primary.file)
        if language not in {"java", "cpp", "python"}:
            return []
        if not self.binary:
            return [_tool_unavailable(finding, self.name, "codeql command was not found")]
        db_candidates = list((indexer.source_root / ".codeql-db").glob(f"*{language}*")) if (indexer.source_root / ".codeql-db").exists() else []
        if db_candidates:
            return [
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, self.name, "database-found"),
                    kind=EvidenceKind.TOOL_DIAGNOSTIC,
                    strength=EvidenceStrength.STRONG,
                    summary=f"CodeQL is installed and an existing {language} database was found",
                    source=self.name,
                    data={"database": str(db_candidates[0])},
                )
            ]
        return [
            CodeEvidence(
                evidence_id=evidence_id(finding.finding_id, self.name, "database-missing"),
                kind=EvidenceKind.TOOL_DIAGNOSTIC,
                strength=EvidenceStrength.PARTIAL,
                summary=f"CodeQL is installed but no .codeql-db database was found for {language}; semantic data-flow evidence is unavailable",
                source=self.name,
            )
        ]


@dataclass
class ToolCompleted:
    returncode: int
    stdout: str
    stderr: str


def _run_tool(binary: str, args: Sequence[str], cwd: Path, timeout: int) -> ToolCompleted:
    try:
        completed = subprocess.run(
            [binary, *args],
            cwd=str(cwd),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return ToolCompleted(completed.returncode, completed.stdout, completed.stderr)
    except subprocess.TimeoutExpired as exc:
        return ToolCompleted(124, exc.stdout or "", exc.stderr or f"timed out after {timeout}s")


def _evidence_from_tool_output(
    finding: Finding,
    tool_name: str,
    operation: str,
    completed: ToolCompleted,
    locations: Sequence[SourceLocation],
) -> CodeEvidence:
    output = (completed.stdout or completed.stderr or "").strip()
    parsed = _try_json(output)
    ok = completed.returncode == 0
    partial = isinstance(parsed, dict) and bool(parsed.get("partial_result"))
    strength = EvidenceStrength.MEDIUM if ok and not partial else EvidenceStrength.PARTIAL if ok else EvidenceStrength.WEAK
    kind = EvidenceKind.DATA_FLOW if operation.startswith("trace") and ok else EvidenceKind.TOOL_DIAGNOSTIC
    summary = f"{tool_name} {operation} exited with {completed.returncode}"
    if isinstance(parsed, dict):
        diagnostics = parsed.get("diagnostics")
        if diagnostics:
            summary += f"; diagnostics: {str(diagnostics)[:240]}"
        elif parsed.get("ok") is not None:
            summary += f"; ok={parsed.get('ok')}"
    elif output:
        summary += f"; output: {output[:240]}"
    return CodeEvidence(
        evidence_id=evidence_id(finding.finding_id, tool_name, operation),
        kind=kind,
        strength=strength,
        summary=summary,
        source=tool_name,
        locations=list(locations),
        data={"returncode": completed.returncode, "parsed": parsed, "stderr": completed.stderr[:1000]},
    )


def _try_json(text: str):
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _tool_unavailable(finding: Finding, tool_name: str, reason: str) -> CodeEvidence:
    return CodeEvidence(
        evidence_id=evidence_id(finding.finding_id, tool_name, "unavailable"),
        kind=EvidenceKind.TOOL_DIAGNOSTIC,
        strength=EvidenceStrength.WEAK,
        summary=reason,
        source=tool_name,
    )
