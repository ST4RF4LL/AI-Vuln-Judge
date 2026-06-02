from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .models import CodeEvidence, EvidenceKind, EvidenceStrength, Finding, SourceLocation


LANGUAGE_EXTENSIONS = {
    "java": {".java"},
    "cpp": {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
    "python": {".py", ".pyi", ".pyx"},
}

PROTECTION_TERMS = {
    "sanitize",
    "sanitise",
    "escape",
    "validate",
    "validator",
    "allowlist",
    "whitelist",
    "checkpermission",
    "haspermission",
    "isauthorized",
    "authorise",
    "authorize",
    "authz",
    "csrf",
    "rate_limit",
    "ratelimit",
    "permission",
    "policy",
    "guard",
}

SOURCE_TERMS = {
    "request",
    "param",
    "input",
    "body",
    "query",
    "header",
    "cookie",
    "argv",
    "stdin",
    "getParameter",
    "getHeader",
}

SINK_TERMS = {
    "execute",
    "exec",
    "system",
    "popen",
    "eval",
    "deserialize",
    "loads",
    "query",
    "createStatement",
    "open",
    "send_file",
    "redirect",
}


@dataclass
class ResolvedLocation:
    requested: SourceLocation
    absolute_path: Optional[Path]
    relative_path: str
    exists: bool
    line_exists: bool
    language: Optional[str]
    snippet: Optional[str]
    symbol: Optional[str]


class SourceIndexer:
    def __init__(self, source_root: Path, languages: Sequence[str]):
        self.source_root = source_root.expanduser().resolve()
        self.languages = [language.lower() for language in languages]
        self._file_cache: Dict[Path, List[str]] = {}

    def resolve_location(self, location: SourceLocation) -> ResolvedLocation:
        absolute = self._resolve_path(location.file)
        exists = absolute is not None and absolute.exists() and absolute.is_file()
        line_exists = False
        snippet = None
        symbol = None
        language = detect_language(location.file)
        relative = self._relative_display(absolute, location.file)
        if exists and absolute is not None:
            lines = self._read_lines(absolute)
            if location.line is None:
                line_exists = True
                snippet = "\n".join(lines[: min(5, len(lines))])
            elif 1 <= location.line <= len(lines):
                line_exists = True
                snippet = self.snippet(absolute, location.line)
                symbol = self.symbol_at(absolute, location.line, language)
        return ResolvedLocation(
            requested=location,
            absolute_path=absolute,
            relative_path=relative,
            exists=exists,
            line_exists=line_exists,
            language=language,
            snippet=snippet,
            symbol=symbol,
        )

    def evidence_for_location(self, finding: Finding, location: SourceLocation) -> CodeEvidence:
        resolved = self.resolve_location(location)
        strength = EvidenceStrength.STRONG if resolved.exists and resolved.line_exists else EvidenceStrength.WEAK
        if resolved.exists and resolved.line_exists:
            summary = f"SARIF 位置在源码中存在：{resolved.relative_path}"
            if resolved.symbol:
                summary += f"，邻近符号 `{resolved.symbol}`"
        elif resolved.exists:
            summary = f"SARIF 文件存在，但报告行号超出文件范围：{location.display()}"
        else:
            summary = f"SARIF 位置无法在源码根目录下解析：{location.display()}"
        return CodeEvidence(
            evidence_id=evidence_id(finding.finding_id, "loc", location.display()),
            kind=EvidenceKind.SOURCE_LOCATION,
            strength=strength,
            summary=summary,
            source="source-indexer",
            locations=[_display_location(resolved)],
            snippet=resolved.snippet,
            data={
                "exists": resolved.exists,
                "line_exists": resolved.line_exists,
                "language": resolved.language,
                "symbol": resolved.symbol,
            },
        )

    def evidence_for_code_flows(self, finding: Finding) -> List[CodeEvidence]:
        evidence: List[CodeEvidence] = []
        for flow_index, flow in enumerate(finding.code_flows):
            resolved = [self.resolve_location(location) for location in flow]
            verified = [item for item in resolved if item.exists and item.line_exists]
            locations = [_display_location(item) for item in resolved]
            strength = (
                EvidenceStrength.STRONG
                if len(flow) >= 2 and len(verified) == len(flow)
                else EvidenceStrength.MEDIUM
                if len(verified) == len(flow)
                else EvidenceStrength.PARTIAL
            )
            summary = f"SARIF 代码流中有 {len(verified)}/{len(flow)} 个步骤可解析"
            if verified:
                summary += f"，路径从 {verified[0].relative_path} 到 {verified[-1].relative_path}"
            evidence.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, "flow", str(flow_index)),
                    kind=EvidenceKind.SARIF_CODE_FLOW,
                    strength=strength,
                    summary=summary,
                    source="sarif-code-flow",
                    locations=locations,
                    data={
                        "step_count": len(flow),
                        "verified_step_count": len(verified),
                        "symbols": [item.symbol for item in resolved if item.symbol],
                    },
                )
            )
        return evidence

    def protection_evidence(self, finding: Finding) -> List[CodeEvidence]:
        locations = finding.locations + [location for flow in finding.code_flows for location in flow]
        seen = set()
        evidence = []
        for location in locations:
            key = location.display()
            if key in seen:
                continue
            seen.add(key)
            resolved = self.resolve_location(location)
            if not resolved.exists or resolved.absolute_path is None or location.line is None:
                continue
            context = self.snippet(resolved.absolute_path, location.line, before=8, after=8)
            hits = sorted(_term_hits(context, PROTECTION_TERMS))
            if not hits:
                continue
            evidence.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, "protection", key),
                    kind=EvidenceKind.PROTECTION,
                    strength=EvidenceStrength.MEDIUM,
                    summary=f"附近代码包含可能的防护词项：{', '.join(hits)}",
                    source="source-indexer",
                    locations=[_display_location(resolved)],
                    snippet=context,
                    data={"terms": hits},
                )
            )
        return evidence

    def source_sink_evidence(self, finding: Finding) -> List[CodeEvidence]:
        locations = finding.locations + [location for flow in finding.code_flows for location in flow]
        evidence = []
        for location in locations:
            resolved = self.resolve_location(location)
            if not resolved.exists or resolved.absolute_path is None or location.line is None:
                continue
            context = self.snippet(resolved.absolute_path, location.line, before=3, after=3)
            source_hits = sorted(_term_hits(context, SOURCE_TERMS))
            sink_hits = sorted(_term_hits(context, SINK_TERMS))
            if not source_hits and not sink_hits:
                continue
            terms = {"source_terms": source_hits, "sink_terms": sink_hits}
            summary_bits = []
            if source_hits:
                summary_bits.append(f"类似源点的词项：{', '.join(source_hits)}")
            if sink_hits:
                summary_bits.append(f"类似汇点的词项：{', '.join(sink_hits)}")
            evidence.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, "source-sink", location.display()),
                    kind=EvidenceKind.DATA_FLOW,
                    strength=EvidenceStrength.WEAK,
                    summary="局部代码上下文包含：" + "; ".join(summary_bits),
                    source="source-indexer",
                    locations=[_display_location(resolved)],
                    snippet=context,
                    data=terms,
                )
            )
        return evidence

    def compile_database_evidence(self, finding: Finding) -> Optional[CodeEvidence]:
        primary = finding.primary_location
        if primary is None or detect_language(primary.file) != "cpp":
            return None
        candidates = [
            self.source_root / "compile_commands.json",
            self.source_root / "build" / "compile_commands.json",
        ]
        existing = [path for path in candidates if path.exists()]
        if existing:
            summary = f"发现 C++ 编译数据库：{existing[0].relative_to(self.source_root)}"
            strength = EvidenceStrength.STRONG
        else:
            summary = "未找到 compile_commands.json；C++ 分析仅限解析级证据"
            strength = EvidenceStrength.PARTIAL
        return CodeEvidence(
            evidence_id=evidence_id(finding.finding_id, "cpp-compile-db", primary.file),
            kind=EvidenceKind.TOOL_DIAGNOSTIC,
            strength=strength,
            summary=summary,
            source="source-indexer",
            locations=[],
            data={"compile_database": str(existing[0]) if existing else None},
        )

    def snippet(self, file: Path, line: int, before: int = 2, after: int = 2) -> str:
        lines = self._read_lines(file)
        start = max(1, line - before)
        end = min(len(lines), line + after)
        return "\n".join(f"{idx}: {lines[idx - 1]}" for idx in range(start, end + 1))

    def symbol_at(self, file: Path, line: int, language: Optional[str]) -> Optional[str]:
        lines = self._read_lines(file)
        patterns = _symbol_patterns(language)
        for idx in range(min(line, len(lines)), 0, -1):
            text = lines[idx - 1].strip()
            for pattern in patterns:
                match = pattern.search(text)
                if match:
                    return match.group("name")
        return None

    def _read_lines(self, path: Path) -> List[str]:
        if path not in self._file_cache:
            self._file_cache[path] = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return self._file_cache[path]

    def _resolve_path(self, raw: str) -> Optional[Path]:
        candidate = Path(raw)
        candidates: List[Path]
        if candidate.is_absolute():
            candidates = [candidate]
        else:
            candidates = [self.source_root / candidate, self.source_root / raw.lstrip("/")]
        for item in candidates:
            resolved = item.expanduser().resolve()
            try:
                resolved.relative_to(self.source_root)
            except ValueError:
                continue
            return resolved
        return None

    def _relative_display(self, path: Optional[Path], fallback: str) -> str:
        if path is None:
            return fallback
        try:
            return str(path.relative_to(self.source_root)).replace("\\", "/")
        except ValueError:
            return fallback


def detect_language(file: str) -> Optional[str]:
    suffix = Path(file).suffix.lower()
    for language, extensions in LANGUAGE_EXTENSIONS.items():
        if suffix in extensions:
            return language
    return None


def evidence_id(*parts: str) -> str:
    digest = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()
    return f"ev-{digest[:12]}"


def supported_language_for_finding(finding: Finding, languages: Sequence[str]) -> bool:
    primary = finding.primary_location
    if primary is None:
        return True
    language = detect_language(primary.file)
    return language is None or language in {item.lower() for item in languages}


def _display_location(resolved: ResolvedLocation) -> SourceLocation:
    return SourceLocation(
        file=resolved.relative_path,
        line=resolved.requested.line,
        column=resolved.requested.column,
        end_line=resolved.requested.end_line,
        end_column=resolved.requested.end_column,
    )


def _term_hits(text: str, terms: Iterable[str]) -> List[str]:
    lowered = text.lower()
    return [term for term in terms if term.lower() in lowered]


def _symbol_patterns(language: Optional[str]) -> List[re.Pattern[str]]:
    if language == "python":
        return [
            re.compile(r"^(?:async\s+)?def\s+(?P<name>[A-Za-z_][\w]*)\s*\("),
            re.compile(r"^class\s+(?P<name>[A-Za-z_][\w]*)\b"),
        ]
    if language == "java":
        return [
            re.compile(
                r"^(?:public|private|protected|static|final|synchronized|\s)+[\w<>\[\], ?]+\s+(?P<name>[A-Za-z_][\w]*)\s*\("
            ),
            re.compile(r"^(?:public|private|protected|\s)*(?:class|interface|enum)\s+(?P<name>[A-Za-z_][\w]*)\b"),
        ]
    if language == "cpp":
        return [
            re.compile(r"^(?:[\w:<>,~*&\s]+)\s+(?P<name>[A-Za-z_~][\w:~]*)\s*\([^;]*\)\s*(?:const)?\s*\{?$"),
            re.compile(r"^(?:class|struct|namespace)\s+(?P<name>[A-Za-z_][\w]*)\b"),
        ]
    return [
        re.compile(r"^(?:def|class)\s+(?P<name>[A-Za-z_][\w]*)\b"),
        re.compile(r"(?P<name>[A-Za-z_][\w]*)\s*\("),
    ]
