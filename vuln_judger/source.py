from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from .code_search import SEARCH_PATTERNS, GrepMatch, search_source
from .models import CodeEvidence, EvidenceKind, EvidenceStrength, Finding, SourceLocation


LANGUAGE_EXTENSIONS = {
    "java": {".java"},
    "cpp": {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
    "python": {".py", ".pyi", ".pyx"},
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
        self._file_globs: Optional[List[str]] = None

    def _extension_globs(self) -> List[str]:
        if self._file_globs is not None:
            return self._file_globs
        exts: set[str] = set()
        for lang in self.languages:
            for ext in LANGUAGE_EXTENSIONS.get(lang, set()):
                exts.add(ext)
        self._file_globs = sorted(f"*{ext}" for ext in exts) if exts else ["*"]
        return self._file_globs

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
            source="code-search",
            locations=[_display_location(resolved)],
            snippet=resolved.snippet,
            data={
                "exists": resolved.exists,
                "line_exists": resolved.line_exists,
                "language": resolved.language,
                "symbol": resolved.symbol,
                "requested_file": location.file,
                "resolved_file": resolved.relative_path,
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
        matches = search_source(
            self.source_root,
            SEARCH_PATTERNS["protection"],
            file_globs=self._extension_globs(),
            context_lines=5,
            max_matches=20,
        )
        if not matches:
            return []
        by_file: Dict[str, List[GrepMatch]] = {}
        for m in matches:
            by_file.setdefault(m.file, []).append(m)
        evidence: List[CodeEvidence] = []
        for file, file_matches in list(by_file.items())[:5]:
            terms = sorted(set(_extract_terms(m.text, SEARCH_PATTERNS["protection"]) for m in file_matches))
            lines = [m.line for m in file_matches[:3]]
            snippet = self.snippet(
                self.source_root / file, lines[0], before=5, after=5
            ) if lines else None
            evidence.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, "protection", file),
                    kind=EvidenceKind.PROTECTION,
                    strength=EvidenceStrength.MEDIUM if len(file_matches) >= 2 else EvidenceStrength.WEAK,
                    summary=f"rg 搜索 {file} 中发现 {len(file_matches)} 处防护词项：{', '.join(terms[:8])}",
                    source="code-search",
                    locations=[SourceLocation(file=file, line=lines[0])],
                    snippet=snippet,
                    data={"terms": terms, "match_count": len(file_matches), "files_searched": len(by_file)},
                )
            )
        return evidence

    def source_sink_evidence(self, finding: Finding) -> List[CodeEvidence]:
        source_matches = search_source(
            self.source_root,
            SEARCH_PATTERNS["source"],
            file_globs=self._extension_globs(),
            context_lines=3,
            max_matches=20,
        )
        sink_matches = search_source(
            self.source_root,
            SEARCH_PATTERNS["sink"],
            file_globs=self._extension_globs(),
            context_lines=3,
            max_matches=20,
        )
        evidence: List[CodeEvidence] = []
        if source_matches:
            source_terms = sorted(set(_extract_terms(m.text, SEARCH_PATTERNS["source"]) for m in source_matches))[:10]
            source_file = source_matches[0]
            evidence.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, "source-sink", "source"),
                    kind=EvidenceKind.DATA_FLOW,
                    strength=EvidenceStrength.WEAK,
                    summary=f"rg 在源码中搜索到 {len(source_matches)} 处源点词项：{', '.join(source_terms)}",
                    source="code-search",
                    locations=[SourceLocation(file=m.file, line=m.line) for m in source_matches[:5]],
                    data={"source_terms": source_terms, "source_match_count": len(source_matches)},
                )
            )
        if sink_matches:
            sink_terms = sorted(set(_extract_terms(m.text, SEARCH_PATTERNS["sink"]) for m in sink_matches))[:10]
            evidence.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, "source-sink", "sink"),
                    kind=EvidenceKind.DATA_FLOW,
                    strength=EvidenceStrength.WEAK,
                    summary=f"rg 在源码中搜索到 {len(sink_matches)} 处汇点词项：{', '.join(sink_terms)}",
                    source="code-search",
                    locations=[SourceLocation(file=m.file, line=m.line) for m in sink_matches[:5]],
                    data={"sink_terms": sink_terms, "sink_match_count": len(sink_matches)},
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
            summary = "未找到 compile_commands.json；C++ 语义分析降级，但 grep/rg 和 Atlas MCP 调用图仍可提供证据"
            strength = EvidenceStrength.PARTIAL
        return CodeEvidence(
            evidence_id=evidence_id(finding.finding_id, "cpp-compile-db", primary.file),
            kind=EvidenceKind.TOOL_DIAGNOSTIC,
            strength=strength,
            summary=summary,
            source="code-search",
            locations=[],
            data={"compile_database": str(existing[0]) if existing else None},
        )

    def snippet(self, file: Path, line: int, before: int = 2, after: int = 2) -> str:
        lines = self._read_lines(file)
        start = max(1, line - before)
        end = min(len(lines), line + after)
        return "\n".join(f"{idx}: {lines[idx - 1]}" for idx in range(start, end + 1))

    def line_text(self, file: Path, line: int) -> str:
        lines = self._read_lines(file)
        if line < 1 or line > len(lines):
            return ""
        return lines[line - 1]

    def symbol_at(self, file: Path, line: int, language: Optional[str]) -> Optional[str]:
        lines = self._read_lines(file)
        if language == "cpp":
            symbol = _cpp_symbol_at(lines, line)
            if symbol:
                return symbol
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
        candidates = self._path_candidates(raw)
        in_root: List[Path] = []
        for item in candidates:
            resolved = item.expanduser().resolve()
            try:
                resolved.relative_to(self.source_root)
            except ValueError:
                continue
            if resolved in in_root:
                continue
            in_root.append(resolved)
            if resolved.exists() and resolved.is_file():
                return resolved
        return in_root[0] if in_root else None

    def _path_candidates(self, raw: str) -> List[Path]:
        normalized = raw.replace("\\", "/").strip()
        candidate = Path(normalized)
        candidates: List[Path] = []
        if candidate.is_absolute():
            candidates.append(candidate)
        else:
            candidates.append(self.source_root / normalized.lstrip("/"))

        parts = [part for part in Path(normalized).parts if part not in {"", "/", "."}]
        if len(parts) > 1:
            for start in range(1, len(parts)):
                candidates.append(self.source_root.joinpath(*parts[start:]))
        return candidates

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


def _extract_terms(text: str, pattern: str) -> str:
    match = re.search(pattern, text, re.IGNORECASE)
    return match.group(0) if match else ""


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


_CPP_CONTROL_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "return",
    "else",
    "do",
    "case",
    "sizeof",
    "static_assert",
}


def _cpp_symbol_at(lines: Sequence[str], line: int) -> Optional[str]:
    class_pattern = re.compile(r"^(?:class|struct|namespace)\s+(?P<name>[A-Za-z_][\w]*)\b")
    signature_pattern = re.compile(
        r"^(?:(?:template\s*<.*>\s*)|(?:[\w:<>,~*&\s]+\s+))*"
        r"(?P<name>[A-Za-z_~][\w:~]*(?:::[A-Za-z_~][\w:~]*)*)\s*\("
    )
    for idx in range(min(line, len(lines)), 0, -1):
        raw = lines[idx - 1]
        stripped = raw.strip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            continue
        class_match = class_pattern.search(stripped)
        if class_match:
            return class_match.group("name")
        if raw[:1].isspace():
            continue
        first = stripped.split("(", 1)[0].split(None, 1)[0]
        if first in _CPP_CONTROL_KEYWORDS:
            continue
        match = signature_pattern.search(stripped)
        if not match:
            continue
        name = match.group("name")
        if name in _CPP_CONTROL_KEYWORDS:
            continue
        return name
    return None
