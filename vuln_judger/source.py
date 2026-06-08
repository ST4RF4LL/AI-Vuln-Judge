from __future__ import annotations

import hashlib
import os
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
SUPPORTED_LANGUAGES = tuple(LANGUAGE_EXTENSIONS.keys())
_SOURCE_SCAN_EXCLUDED_DIRS = {
    ".atlas",
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".venv",
    "__pycache__",
    "build",
    "cmake-build-debug",
    "cmake-build-release",
    "dist",
    "node_modules",
    "out",
    "target",
    "venv",
}


@dataclass
class ProjectLanguageProfile:
    languages: List[str]
    file_counts: Dict[str, int]
    total_supported_files: int
    fallback_used: bool = False


def detect_project_languages(source_root: Path) -> ProjectLanguageProfile:
    root = source_root.expanduser().resolve()
    counts = {language: 0 for language in SUPPORTED_LANGUAGES}
    if root.exists() and root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                name
                for name in dirnames
                if name not in _SOURCE_SCAN_EXCLUDED_DIRS and not (name.startswith(".") and name not in {".github"})
            ]
            for filename in filenames:
                if filename.startswith("."):
                    continue
                language = detect_language(filename)
                if language in counts:
                    counts[language] += 1
    total = sum(counts.values())
    languages = [language for language in SUPPORTED_LANGUAGES if counts[language] > 0]
    languages.sort(key=lambda language: (-counts[language], SUPPORTED_LANGUAGES.index(language)))
    if not languages:
        return ProjectLanguageProfile(
            languages=list(SUPPORTED_LANGUAGES),
            file_counts=counts,
            total_supported_files=0,
            fallback_used=True,
        )
    return ProjectLanguageProfile(
        languages=languages,
        file_counts={language: counts[language] for language in languages},
        total_supported_files=total,
        fallback_used=False,
    )


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
    def __init__(self, source_root: Path, languages: Optional[Sequence[str]] = None):
        self.source_root = source_root.expanduser().resolve()
        self.language_profile = detect_project_languages(self.source_root)
        self.languages = [language.lower() for language in (languages or self.language_profile.languages)]
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
        requested = location
        language = detect_language(location.file)
        relative = self._relative_display(absolute, location.file)
        if exists and absolute is not None:
            lines = self._read_lines(absolute)
            inferred_line = None
            if location.line is None and location.symbol:
                inferred_line = self.find_symbol_line(absolute, location.symbol, language)
            if location.line is None and inferred_line is not None:
                requested = SourceLocation(
                    file=location.file,
                    line=inferred_line,
                    column=location.column,
                    end_line=location.end_line,
                    end_column=location.end_column,
                    symbol=location.symbol,
                )
                line_exists = True
                snippet = self.snippet(absolute, inferred_line)
                symbol = self.symbol_at(absolute, inferred_line, language) or location.symbol
            elif location.line is None:
                line_exists = True
                snippet = "\n".join(lines[: min(5, len(lines))])
                symbol = location.symbol
            elif 1 <= location.line <= len(lines):
                line_exists = True
                snippet = self.snippet(absolute, location.line)
                symbol = self.symbol_at(absolute, location.line, language) or location.symbol
        return ResolvedLocation(
            requested=requested,
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
        scoped_paths = self._report_scope_paths(finding)
        if not scoped_paths:
            return []
        matches = search_source(
            self.source_root,
            SEARCH_PATTERNS["protection"],
            file_globs=self._extension_globs(),
            paths=scoped_paths,
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
                    summary=f"AI 自主 rg 围绕报告路径 {file} 发现 {len(file_matches)} 处候选防护词项：{', '.join(terms[:8])}",
                    source="agentic-rg",
                    locations=[SourceLocation(file=file, line=lines[0])],
                    snippet=snippet,
                    data={
                        "terms": terms,
                        "match_count": len(file_matches),
                        "files_searched": len(by_file),
                        "search_scope": "report",
                        "scoped_paths": scoped_paths,
                    },
                )
            )
        return evidence

    def source_sink_evidence(self, finding: Finding) -> List[CodeEvidence]:
        scoped_paths = self._report_scope_paths(finding)
        if not scoped_paths:
            return []
        query_terms = _finding_query_terms(finding)
        source_matches = search_source(
            self.source_root,
            SEARCH_PATTERNS["source"],
            file_globs=self._extension_globs(),
            paths=scoped_paths,
            context_lines=3,
            max_matches=20,
        )
        sink_matches = search_source(
            self.source_root,
            SEARCH_PATTERNS["sink"],
            file_globs=self._extension_globs(),
            paths=scoped_paths,
            context_lines=3,
            max_matches=20,
        )
        evidence: List[CodeEvidence] = [
            CodeEvidence(
                evidence_id=evidence_id(finding.finding_id, "agentic-rg", "plan", *scoped_paths[:8]),
                kind=EvidenceKind.TOOL_DIAGNOSTIC,
                strength=EvidenceStrength.MEDIUM,
                summary=(
                    "AI 自主 rg 补证启动：围绕报告位置和 codeFlow 文件搜索候选源点、候选汇点和防护词项；"
                    f"范围 {', '.join(scoped_paths[:8])}"
                ),
                source="agentic-rg",
                data={
                    "search_scope": "report",
                    "scoped_paths": scoped_paths,
                    "query_terms": query_terms,
                    "source_pattern": SEARCH_PATTERNS["source"],
                    "sink_pattern": SEARCH_PATTERNS["sink"],
                },
            )
        ]
        if source_matches:
            source_terms = sorted(set(_extract_terms(m.text, SEARCH_PATTERNS["source"]) for m in source_matches))[:10]
            evidence.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, "source-sink", "source"),
                    kind=EvidenceKind.DATA_FLOW,
                    strength=EvidenceStrength.WEAK,
                    summary=f"AI 自主 rg 围绕报告路径搜索到 {len(source_matches)} 处候选源点词项：{', '.join(source_terms)}",
                    source="agentic-rg",
                    locations=[SourceLocation(file=m.file, line=m.line) for m in source_matches[:5]],
                    data={
                        "source_terms": source_terms,
                        "source_match_count": len(source_matches),
                        "search_scope": "report",
                        "scoped_paths": scoped_paths,
                    },
                )
            )
        if sink_matches:
            sink_terms = sorted(set(_extract_terms(m.text, SEARCH_PATTERNS["sink"]) for m in sink_matches))[:10]
            evidence.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, "source-sink", "sink"),
                    kind=EvidenceKind.DATA_FLOW,
                    strength=EvidenceStrength.WEAK,
                    summary=f"AI 自主 rg 围绕报告路径搜索到 {len(sink_matches)} 处候选汇点词项：{', '.join(sink_terms)}",
                    source="agentic-rg",
                    locations=[SourceLocation(file=m.file, line=m.line) for m in sink_matches[:5]],
                    data={
                        "sink_terms": sink_terms,
                        "sink_match_count": len(sink_matches),
                        "search_scope": "report",
                        "scoped_paths": scoped_paths,
                    },
                )
            )
        return evidence

    def _report_scope_paths(self, finding: Finding) -> List[str]:
        paths: List[str] = []
        for location in _finding_locations(finding):
            resolved = self.resolve_location(location)
            if not resolved.exists or not resolved.absolute_path or not resolved.relative_path:
                continue
            if resolved.relative_path not in paths:
                paths.append(resolved.relative_path)
            if len(paths) >= 12:
                break
        return paths

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

    def find_symbol_line(self, file: Path, symbol: str, language: Optional[str]) -> Optional[int]:
        lines = self._read_lines(file)
        candidates = _symbol_lookup_candidates(symbol)
        if not candidates:
            return None
        for definition_only in (True, False):
            for idx, raw in enumerate(lines, start=1):
                if definition_only and language == "cpp" and raw[:1].isspace():
                    continue
                if _line_matches_symbol(raw, candidates, language, definition_only):
                    return idx
        return None

    def _read_lines(self, path: Path) -> List[str]:
        if path not in self._file_cache:
            try:
                self._file_cache[path] = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                return []
        return self._file_cache[path]

    def _resolve_path(self, raw: str) -> Optional[Path]:
        if not _looks_like_source_path(raw):
            return None
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
        if not _looks_like_source_path(normalized):
            return []
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


def _looks_like_source_path(raw: str) -> bool:
    value = str(raw or "").replace("\\", "/").strip()
    if not value:
        return False
    if value.isdigit():
        return False
    return True


def _finding_locations(finding: Finding) -> List[SourceLocation]:
    locations = list(finding.locations)
    for flow in finding.code_flows:
        locations.extend(flow)
    return locations


def _finding_query_terms(finding: Finding, limit: int = 16) -> List[str]:
    values: List[str] = [finding.rule_id, finding.message]
    values.extend(str(value) for value in finding.properties.values())
    for location in _finding_locations(finding):
        values.append(location.file)
        if location.symbol:
            values.append(location.symbol)
    terms: List[str] = []
    for value in values:
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", str(value or "")):
            lowered = token.lower()
            if lowered in {"the", "and", "for", "with", "from", "this", "that", "warning", "error"}:
                continue
            if token not in terms:
                terms.append(token)
            if len(terms) >= limit:
                return terms
    return terms


def _display_location(resolved: ResolvedLocation) -> SourceLocation:
    return SourceLocation(
        file=resolved.relative_path,
        line=resolved.requested.line,
        column=resolved.requested.column,
        end_line=resolved.requested.end_line,
        end_column=resolved.requested.end_column,
        symbol=resolved.symbol or resolved.requested.symbol,
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


def _symbol_lookup_candidates(symbol: str) -> List[str]:
    cleaned = symbol.strip()
    if not cleaned:
        return []
    candidates = [cleaned]
    if "::" in cleaned:
        candidates.append(cleaned.split("::")[-1])
    return list(dict.fromkeys(candidates))


def _line_matches_symbol(raw: str, candidates: Sequence[str], language: Optional[str], definition_only: bool) -> bool:
    stripped = raw.strip()
    if not stripped or stripped.startswith(("//", "/*", "*")):
        return False
    for candidate in candidates:
        pattern = re.compile(r"(?<![\w:~])" + re.escape(candidate) + r"\s*\(")
        match = pattern.search(stripped)
        if not match:
            continue
        prefix = stripped[: match.start()]
        first = stripped.split("(", 1)[0].split(None, 1)[0]
        if first in _CPP_CONTROL_KEYWORDS:
            continue
        if definition_only and language == "cpp":
            if "=" in prefix or "." in prefix.rstrip()[-1:]:
                continue
            if stripped.endswith(";") and "{" not in stripped:
                continue
        return True
    return False


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
