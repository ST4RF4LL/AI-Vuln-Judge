from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .mcp import MCPError, MCPStdioClient
from .mcp_config import MCPServerStore
from .models import CodeEvidence, EvidenceKind, EvidenceStrength, Finding, SourceLocation
from .source import ResolvedLocation, SourceIndexer, detect_language, evidence_id


@dataclass
class AnalyzerSettings:
    enabled: bool = True
    auto_index: bool = False
    timeout_seconds: int = 120
    mcp_servers_file: Optional[Path] = None

    def __post_init__(self) -> None:
        raw = os.environ.get("VULN_JUDGER_ATLAS_MCP_TIMEOUT") or os.environ.get("VULN_JUDGER_MCP_TIMEOUT")
        if raw:
            try:
                self.timeout_seconds = max(1, int(raw))
            except ValueError:
                pass


class Analyzer:
    name = "analyzer"

    def analyze(self, finding: Finding, indexer: SourceIndexer, settings: AnalyzerSettings) -> List[CodeEvidence]:
        raise NotImplementedError


class AnalyzerSuite:
    def __init__(self, analyzers: Optional[Sequence[Analyzer]] = None):
        self.analyzers = list(analyzers or [AtlasAnalyzer()])

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
                        summary=f"{analyzer.name} 适配器执行失败：{exc}",
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
        if not self.binary and not self._configured_mcp_server(settings):
            diagnostics = [_tool_unavailable(finding, self.name, "未找到 atlas 命令")]
            return diagnostics + self._agentic_source_reading_evidence(finding, indexer)
        resolved_locations = self._resolved_locations(finding, indexer)
        atlas_db = indexer.source_root / ".atlas" / "atlas.db"
        diagnostics: List[CodeEvidence] = []
        if not atlas_db.exists():
            if not settings.auto_index:
                diagnostics = [
                    CodeEvidence(
                        evidence_id=evidence_id(finding.finding_id, self.name, "not-indexed"),
                        kind=EvidenceKind.TOOL_DIAGNOSTIC,
                        strength=EvidenceStrength.PARTIAL,
                        summary="Atlas 已安装，但缺少 .atlas/atlas.db；请先在源码目录执行 atlas index --analysis full，或使用 --auto-index-tools 自动 Atlas 构建索引",
                        source=self.name,
                    )
                ]
                return diagnostics + self._agentic_source_reading_evidence(finding, indexer)
            diagnostics.extend(self._index_project(finding, indexer, settings))
        if not atlas_db.exists():
            return diagnostics + self._agentic_source_reading_evidence(finding, indexer)
        diagnostics.append(
            CodeEvidence(
                evidence_id=evidence_id(finding.finding_id, self.name, "database-present"),
                kind=EvidenceKind.TOOL_DIAGNOSTIC,
                strength=EvidenceStrength.MEDIUM,
                summary="检测到 Atlas 数据库 .atlas/atlas.db，将通过 AI 自主 Atlas MCP 输出数据流、调用图和源码上下文",
                source=self.name,
                data={"database": str(atlas_db), "mcp_preferred": True},
            )
        )
        if not self._supports_mcp(settings):
            diagnostics.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, self.name, "mcp-unavailable"),
                    kind=EvidenceKind.TOOL_DIAGNOSTIC,
                    strength=EvidenceStrength.WEAK,
                    summary="Atlas 数据库已存在，但当前 Atlas 未提供 MCP 子命令；无法提取数据流 trace 和调用图。请确认 Atlas 版本支持 mcp 子命令",
                    source=self.name,
                    data={"database": str(atlas_db), "mcp_supported": False},
                )
            )
            return diagnostics + self._agentic_source_reading_evidence(finding, indexer)
        agentic_evidence = self._agentic_mcp_evidence(finding, indexer, settings, resolved_locations)
        return diagnostics + agentic_evidence + self._agentic_source_reading_evidence(finding, indexer)

    def _resolved_locations(self, finding: Finding, indexer: SourceIndexer) -> List[ResolvedLocation]:
        resolved: List[ResolvedLocation] = []
        seen: set[tuple[str, Optional[int], Optional[int]]] = set()
        for location in finding.locations:
            item = indexer.resolve_location(location)
            if not item.exists or item.absolute_path is None or not item.relative_path:
                continue
            marker = (item.relative_path, location.line, location.column)
            if marker in seen:
                continue
            seen.add(marker)
            resolved.append(item)
        return resolved

    def _supports_mcp(self, settings: AnalyzerSettings) -> bool:
        if self._configured_mcp_server(settings) is not None:
            return True
        if not self.binary:
            return False
        completed = _run_tool(self.binary, ["--help"], cwd=Path.cwd(), timeout=settings.timeout_seconds)
        if completed.returncode != 0:
            return False
        return bool(re.search(r"^\s+mcp\s", completed.stdout, flags=re.MULTILINE))

    def _direct_source_evidence(self, finding: Finding, indexer: SourceIndexer) -> List[CodeEvidence]:
        evidence: List[CodeEvidence] = []
        seen_files: set[str] = set()
        all_locations = finding.locations[:]
        for flow in finding.code_flows:
            all_locations.extend(flow)
        for location in all_locations:
            resolved = indexer.resolve_location(location)
            if not resolved.exists or resolved.absolute_path is None or not resolved.relative_path:
                continue
            if resolved.relative_path in seen_files:
                continue
            seen_files.add(resolved.relative_path)
            effective = resolved.requested
            effective_line = effective.line or 1
            snippet = indexer.snippet(resolved.absolute_path, effective_line, before=15, after=15)
            symbol = resolved.symbol or indexer.symbol_at(resolved.absolute_path, effective_line, resolved.language)
            language = resolved.language or "unknown"
            if symbol:
                summary = f"直接阅读源码 {resolved.relative_path}:{effective.line}，邻近符号 `{symbol}`"
            else:
                summary = f"直接阅读源码 {resolved.relative_path}:{effective.line}，已提取代码上下文"
            evidence.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, self.name, "direct-source", resolved.relative_path, str(effective.line)),
                    kind=EvidenceKind.SOURCE_LOCATION,
                    strength=EvidenceStrength.MEDIUM,
                    summary=summary,
                    source=self.name,
                    locations=[
                        SourceLocation(
                            file=resolved.relative_path,
                            line=effective.line,
                            column=effective.column,
                            symbol=symbol,
                        )
                    ],
                    snippet=snippet,
                    data={
                        "file": resolved.relative_path,
                        "line": effective.line,
                        "language": language,
                        "symbol": symbol,
                        "direct_read": True,
                        "line_exists": resolved.line_exists,
                        "requested_file": location.file,
                        "resolved_file": resolved.relative_path,
                    },
                )
            )
        return evidence

    def _mcp_evidence(
        self,
        finding: Finding,
        indexer: SourceIndexer,
        settings: AnalyzerSettings,
        resolved_locations: Sequence[ResolvedLocation],
    ) -> List[CodeEvidence]:
        try:
            command, cwd, env = self._mcp_command(indexer, settings)
            with MCPStdioClient(
                command,
                cwd=cwd,
                timeout=settings.timeout_seconds,
                env=env,
            ) as client:
                tools = {tool.get("name") for tool in client.list_tools()}
                evidence: List[CodeEvidence] = []
                if "project" not in tools:
                    return [
                        CodeEvidence(
                            evidence_id=evidence_id(finding.finding_id, self.name, "mcp-project-missing"),
                            kind=EvidenceKind.TOOL_DIAGNOSTIC,
                            strength=EvidenceStrength.WEAK,
                            summary="Atlas MCP 已启动，但未暴露 project 工具；无法读取索引状态和文件清单",
                            source="atlas-mcp",
                            data={"transport": "mcp", "tools": sorted(str(tool) for tool in tools), "mcp_success": False},
                        )
                    ]
                status_payload, status_text, status_error = _safe_mcp_tool_payload(client, "project", {"action": "status", "verbose": True})
                evidence.append(self._mcp_status_evidence(finding, status_payload, status_text, status_error, "trace" in tools))
                evidence.extend(self._mcp_indexed_file_evidence(client, finding, indexer))
                if "trace" in tools:
                    evidence.extend(self._mcp_trace_evidence(client, finding, indexer, resolved_locations))
                if "search" in tools and "calls" in tools:
                    evidence.extend(self._mcp_call_evidence(client, finding, indexer, resolved_locations))
                return evidence
        except (MCPError, OSError, ValueError) as exc:
            return [
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, self.name, "mcp-failed"),
                    kind=EvidenceKind.TOOL_DIAGNOSTIC,
                    strength=EvidenceStrength.WEAK,
                    summary=f"Atlas MCP 执行失败：{exc}",
                    source="atlas-mcp",
                    data={"transport": "mcp", "mcp_success": False},
                )
            ]

    def _agentic_mcp_evidence(
        self,
        finding: Finding,
        indexer: SourceIndexer,
        settings: AnalyzerSettings,
        resolved_locations: Sequence[ResolvedLocation],
    ) -> List[CodeEvidence]:
        terms = _agentic_query_terms(finding)
        path_prefixes = _agentic_path_prefixes(finding)
        try:
            command, cwd, env = self._mcp_command(indexer, settings)
            with MCPStdioClient(command, cwd=cwd, timeout=settings.timeout_seconds, env=env) as client:
                tools = {tool.get("name") for tool in client.list_tools()}
                evidence: List[CodeEvidence] = [
                    CodeEvidence(
                        evidence_id=evidence_id(finding.finding_id, self.name, "agentic-start", ",".join(sorted(terms[:8]))),
                        kind=EvidenceKind.TOOL_DIAGNOSTIC,
                        strength=EvidenceStrength.MEDIUM,
                        summary=(
                            "AI 自主 Atlas MCP 补证启动：基于报告文本、路径片段和符号生成查询计划；"
                            f"候选词 {', '.join(terms[:8]) or '无'}；候选路径 {', '.join(path_prefixes[:5]) or '无'}"
                        ),
                        source="atlas-agent-mcp",
                        data={
                            "transport": "mcp",
                            "agentic_atlas": True,
                            "mcp_success": True,
                            "tools": sorted(str(tool) for tool in tools),
                            "query_terms": terms,
                            "path_prefixes": path_prefixes,
                        },
                    )
                ]
                if "project" in tools:
                    status_payload, status_text, status_error = _safe_mcp_tool_payload(client, "project", {"action": "status", "verbose": True})
                    evidence.append(self._agentic_status_evidence(finding, status_payload, status_text, status_error))
                    evidence.extend(self._agentic_file_evidence(client, finding, indexer, path_prefixes))
                if "search" in tools:
                    search_results = self._agentic_search_results(client, terms)
                    if search_results:
                        evidence.append(_agentic_search_evidence(finding, search_results))
                        trace_locations = _agentic_locations_from_search(search_results, limit=6)
                        if "trace" in tools:
                            evidence.extend(self._agentic_trace_evidence(client, finding, trace_locations))
                        if "calls" in tools:
                            evidence.extend(self._agentic_call_evidence(client, finding, search_results))
                    else:
                        evidence.append(
                            CodeEvidence(
                                evidence_id=evidence_id(finding.finding_id, self.name, "agentic-search-empty", ",".join(terms[:8])),
                                kind=EvidenceKind.TOOL_DIAGNOSTIC,
                                strength=EvidenceStrength.WEAK,
                                summary="AI 自主 Atlas MCP search 未找到报告相关符号或路径候选",
                                source="atlas-agent-mcp",
                                data={"transport": "mcp", "mcp_tool": "search", "mcp_success": False, "query_terms": terms},
                            )
                        )
                if resolved_locations and "trace" in tools:
                    evidence.extend(self._agentic_trace_evidence(client, finding, [_display_resolved_location(item) for item in resolved_locations[:4]]))
                return evidence
        except (MCPError, OSError, ValueError) as exc:
            return [
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, self.name, "agentic-mcp-failed"),
                    kind=EvidenceKind.TOOL_DIAGNOSTIC,
                    strength=EvidenceStrength.WEAK,
                    summary=f"AI 自主 Atlas MCP 补证失败：{exc}",
                    source="atlas-agent-mcp",
                    data={"transport": "mcp", "agentic_atlas": True, "mcp_success": False},
                )
            ]

    def _agentic_status_evidence(self, finding: Finding, payload: Any, raw_text: str, is_error: bool) -> CodeEvidence:
        if is_error or not isinstance(payload, dict):
            return CodeEvidence(
                evidence_id=evidence_id(finding.finding_id, self.name, "agentic-status"),
                kind=EvidenceKind.TOOL_DIAGNOSTIC,
                strength=EvidenceStrength.WEAK,
                summary="AI 自主 Atlas MCP project/status 未返回可解析状态" + (f"：{raw_text[:240]}" if raw_text else ""),
                source="atlas-agent-mcp",
                data={"transport": "mcp", "mcp_tool": "project/status", "mcp_success": False, "raw": raw_text[:1000]},
            )
        summary = payload.get("summary") or {}
        bits = []
        for key, label in (("files", "文件"), ("symbols", "符号"), ("edges", "边")):
            if summary.get(key) is not None:
                bits.append(f"{label} {summary.get(key)}")
        return CodeEvidence(
            evidence_id=evidence_id(finding.finding_id, self.name, "agentic-status"),
            kind=EvidenceKind.TOOL_DIAGNOSTIC,
            strength=EvidenceStrength.MEDIUM,
            summary="AI 自主 Atlas MCP project/status 确认索引状态" + ("：" + "，".join(bits) if bits else ""),
            source="atlas-agent-mcp",
            data={
                "transport": "mcp",
                "mcp_tool": "project/status",
                "mcp_success": True,
                "agentic_atlas": True,
                "summary": summary,
                "project": payload.get("project") or {},
                "server": payload.get("server") or {},
            },
        )

    def _agentic_file_evidence(
        self, client: MCPStdioClient, finding: Finding, indexer: SourceIndexer, path_prefixes: Sequence[str]
    ) -> List[CodeEvidence]:
        matched: Dict[str, Dict[str, Any]] = {}
        for prefix in path_prefixes[:12]:
            payload, _, is_error = _safe_mcp_tool_payload(client, "project", {"action": "files", "path_prefix": prefix, "limit": 50})
            if is_error or not isinstance(payload, dict):
                continue
            for item in payload.get("files") or []:
                path = str(item.get("path") or "")
                if not path:
                    continue
                if not (indexer.source_root / path).exists():
                    continue
                if _path_candidate_matches(path, prefix):
                    matched[path] = item
        if not matched:
            return []
        locations = [SourceLocation(file=path) for path in sorted(matched)[:12]]
        status_text = ", ".join(f"{path}={matched[path].get('status')}" for path in sorted(matched)[:5])
        return [
            CodeEvidence(
                evidence_id=evidence_id(finding.finding_id, self.name, "agentic-files", *sorted(matched)[:12]),
                kind=EvidenceKind.SOURCE_LOCATION,
                strength=EvidenceStrength.MEDIUM,
                summary="AI 自主 Atlas MCP project/files 找到报告路径候选：" + status_text,
                source="atlas-agent-mcp",
                locations=locations,
                data={
                    "transport": "mcp",
                    "mcp_tool": "project/files",
                    "mcp_success": True,
                    "agentic_atlas": True,
                    "matched_files": sorted(matched),
                    "path_prefixes": list(path_prefixes),
                },
            )
        ]

    def _agentic_search_results(self, client: MCPStdioClient, terms: Sequence[str]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        seen: set[tuple[str, str, int]] = set()
        for term in terms[:12]:
            payload, _, is_error = _safe_mcp_tool_payload(client, "search", {"query": term, "limit": 10})
            if is_error or not isinstance(payload, dict):
                continue
            for item in payload.get("results") or []:
                if not isinstance(item, dict):
                    continue
                marker = (str(item.get("qualified_name") or item.get("name") or ""), str(item.get("file") or ""), _optional_int(item.get("line")) or 0)
                if marker in seen:
                    continue
                seen.add(marker)
                copied = dict(item)
                copied["query"] = term
                results.append(copied)
                if len(results) >= 30:
                    return results
        return results

    def _agentic_trace_evidence(
        self, client: MCPStdioClient, finding: Finding, locations: Sequence[SourceLocation]
    ) -> List[CodeEvidence]:
        evidence: List[CodeEvidence] = []
        for location in locations[:6]:
            if not location.file or not location.line:
                continue
            column = location.column or 1
            for trace_kind in ("point", "variable"):
                arguments: Dict[str, Any] = {
                    "kind": trace_kind,
                    "file_path": location.file,
                    "line": location.line,
                    "column": column,
                }
                if trace_kind == "variable":
                    arguments["max_depth"] = 30
                payload, raw_text, is_error = _safe_mcp_tool_payload(client, "trace", arguments)
                item = _mcp_trace_item(
                    finding,
                    trace_kind,
                    payload,
                    raw_text,
                    is_error,
                    SourceLocation(file=location.file, line=location.line, column=column, symbol=location.symbol),
                )
                item.source = "atlas-agent-mcp"
                item.evidence_id = evidence_id(
                    finding.finding_id,
                    self.name,
                    "agentic-trace",
                    trace_kind,
                    location.file,
                    str(location.line),
                    str(column),
                )
                item.summary = "AI 自主 " + item.summary
                item.data["agentic_atlas"] = True
                evidence.append(item)
        return evidence

    def _agentic_call_evidence(
        self, client: MCPStdioClient, finding: Finding, search_results: Sequence[Dict[str, Any]]
    ) -> List[CodeEvidence]:
        evidence: List[CodeEvidence] = []
        seen: set[str] = set()
        for result in search_results[:12]:
            qname = str(result.get("qualified_name") or result.get("name") or "").strip()
            if not qname or qname in seen:
                continue
            seen.add(qname)
            payload, raw_text, is_error = _safe_mcp_tool_payload(client, "calls", {"symbol": qname, "direction": "both", "depth": 2, "limit": 30})
            location = SourceLocation(
                file=str(result.get("file") or ""),
                line=_optional_int(result.get("line")),
                symbol=qname,
            )
            if is_error or not isinstance(payload, dict):
                evidence.append(
                    CodeEvidence(
                        evidence_id=evidence_id(finding.finding_id, self.name, "agentic-calls", qname),
                        kind=EvidenceKind.TOOL_DIAGNOSTIC,
                        strength=EvidenceStrength.WEAK,
                        summary=f"AI 自主 Atlas MCP calls 未能解析 `{qname}` 的调用图：{raw_text[:240]}",
                        source="atlas-agent-mcp",
                        locations=[location] if location.file else [],
                        data={"transport": "mcp", "mcp_tool": "calls", "mcp_success": False, "agentic_atlas": True, "symbols": [qname]},
                    )
                )
                continue
            callers = _mcp_call_entries(payload, "callers")
            callees = _mcp_call_entries(payload, "callees")
            if not callers and not callees:
                continue
            locations = [location] if location.file else []
            locations.extend(_locations_from_mcp_entries(callers + callees, limit=12))
            evidence.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, self.name, "agentic-calls", qname),
                    kind=EvidenceKind.CALL_CHAIN,
                    strength=EvidenceStrength.MEDIUM,
                    summary=f"AI 自主 Atlas MCP calls 提取 `{qname}` 调用图：调用方 {len(callers)} 个，被调用方 {len(callees)} 个",
                    source="atlas-agent-mcp",
                    locations=locations,
                    data={
                        "transport": "mcp",
                        "mcp_tool": "calls",
                        "mcp_success": True,
                        "agentic_atlas": True,
                        "symbols": [qname],
                        "callers": callers[:10],
                        "callees": callees[:10],
                    },
                )
            )
        return evidence

    def _agentic_source_reading_evidence(self, finding: Finding, indexer: SourceIndexer) -> List[CodeEvidence]:
        terms = _agentic_query_terms(finding)
        path_names = {Path(location.file.replace("\\", "/")).name for location in finding.locations if location.file}
        evidence: List[CodeEvidence] = []
        for file in _source_files(indexer.source_root):
            try:
                text = file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            relative = str(file.relative_to(indexer.source_root)).replace("\\", "/")
            lower = text.lower()
            matched_terms = [term for term in terms if len(term) >= 3 and term.lower() in lower][:8]
            if Path(relative).name in path_names and Path(relative).name:
                matched_terms.append(Path(relative).name)
            if not matched_terms:
                continue
            line = _first_matching_line(text, matched_terms) or 1
            evidence.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, self.name, "agentic-source", relative),
                    kind=EvidenceKind.SOURCE_LOCATION,
                    strength=EvidenceStrength.WEAK,
                    summary=f"AI 自主源码阅读找到候选文件 {relative}，匹配：{', '.join(list(dict.fromkeys(matched_terms))[:6])}",
                    source="agentic-source-reader",
                    locations=[SourceLocation(file=relative, line=line)],
                    snippet=indexer.snippet(file, line, before=5, after=8),
                    data={
                        "agentic_source_reading": True,
                        "matched_terms": list(dict.fromkeys(matched_terms)),
                        "line_exists": True,
                        "resolved_file": relative,
                    },
                )
            )
            if len(evidence) >= 8:
                break
        if not evidence:
            evidence.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, self.name, "agentic-source-empty"),
                    kind=EvidenceKind.TOOL_DIAGNOSTIC,
                    strength=EvidenceStrength.WEAK,
                    summary="AI 自主源码阅读未找到与报告路径、符号或关键词匹配的候选代码",
                    source="agentic-source-reader",
                    data={"agentic_source_reading": True, "query_terms": terms},
                )
            )
        return evidence

    def _mcp_command(self, indexer: SourceIndexer, settings: AnalyzerSettings) -> tuple[List[str], Path, Dict[str, str]]:
        server = self._configured_mcp_server(settings)
        if server is not None:
            return server.command_for_project(indexer.source_root)
        if self.binary is None:
            raise ValueError("Atlas binary 未配置")
        command = [self.binary, "mcp", "--project", str(indexer.source_root), "--log-format", "json"]
        return command, indexer.source_root, {}

    def _configured_mcp_server(self, settings: AnalyzerSettings):
        if settings.mcp_servers_file is None:
            return None
        return MCPServerStore(settings.mcp_servers_file).default_for_kind("atlas")

    def _mcp_status_evidence(
        self, finding: Finding, payload: Any, raw_text: str, is_error: bool, trace_available: bool
    ) -> CodeEvidence:
        if is_error or not isinstance(payload, dict):
            summary = "Atlas MCP project/status 未返回可解析状态"
            if raw_text:
                summary += f"：{raw_text[:240]}"
            return CodeEvidence(
                evidence_id=evidence_id(finding.finding_id, self.name, "mcp-status"),
                kind=EvidenceKind.TOOL_DIAGNOSTIC,
                strength=EvidenceStrength.WEAK,
                summary=summary,
                source="atlas-mcp",
                data={"transport": "mcp", "mcp_success": False, "raw": raw_text[:1000]},
            )
        summary_data = payload.get("summary") or {}
        project_data = payload.get("project") or {}
        server_data = payload.get("server") or {}
        language = detect_language(finding.primary_location.file) if finding.primary_location else None
        language_capability = _mcp_language_capability(payload, language)
        files_indexed = summary_data.get("files")
        symbols = summary_data.get("symbols")
        edges = summary_data.get("edges")
        bits = []
        if files_indexed is not None:
            bits.append(f"文件 {files_indexed}")
        if symbols is not None:
            bits.append(f"符号 {symbols}")
        if edges is not None:
            bits.append(f"边 {edges}")
        if language and language_capability:
            bits.append(f"{language} 能力 {language_capability.get('capability_level')}")
        summary = "Atlas MCP project/status 确认索引可用"
        if bits:
            summary += "：" + "，".join(bits)
        return CodeEvidence(
            evidence_id=evidence_id(finding.finding_id, self.name, "mcp-status"),
            kind=EvidenceKind.TOOL_DIAGNOSTIC,
            strength=EvidenceStrength.MEDIUM,
            summary=summary,
            source="atlas-mcp",
            data={
                "transport": "mcp",
                "mcp_tool": "project/status",
                "mcp_success": True,
                "files_indexed": files_indexed,
                "symbols": symbols,
                "edges": edges,
                "database": project_data.get("db_path"),
                "atlas_version": server_data.get("atlas_version"),
                "tool_contract_version": server_data.get("tool_contract_version"),
                "language": language,
                "language_level": language_capability.get("capability_level") if language_capability else None,
                "trace_supported": trace_available,
            },
        )

    def _mcp_indexed_file_evidence(
        self, client: MCPStdioClient, finding: Finding, indexer: SourceIndexer
    ) -> List[CodeEvidence]:
        matched_locations: List[SourceLocation] = []
        matched_files: List[str] = []
        statuses: Dict[str, str] = {}
        for location in finding.locations:
            resolved = indexer.resolve_location(location)
            if not resolved.exists:
                continue
            payload, _, is_error = _safe_mcp_tool_payload(client, "project", {"action": "files", "path_prefix": resolved.relative_path, "limit": 20})
            if is_error or not isinstance(payload, dict):
                continue
            for item in payload.get("files") or []:
                if item.get("path") != resolved.relative_path:
                    continue
                matched_files.append(resolved.relative_path)
                statuses[resolved.relative_path] = str(item.get("status") or "unknown")
                effective = resolved.requested
                matched_locations.append(
                    SourceLocation(
                        file=resolved.relative_path,
                        line=effective.line,
                        column=effective.column,
                        symbol=resolved.symbol or effective.symbol,
                    )
                )
                break
        matched_files = list(dict.fromkeys(matched_files))
        if not matched_files:
            return []
        status_text = ", ".join(f"{path}={statuses.get(path)}" for path in matched_files[:5])
        return [
            CodeEvidence(
                evidence_id=evidence_id(finding.finding_id, self.name, "mcp-indexed-files", *matched_files),
                kind=EvidenceKind.SOURCE_LOCATION,
                strength=EvidenceStrength.MEDIUM,
                summary="Atlas MCP project/files 确认索引中包含报告源码文件：" + status_text,
                source="atlas-mcp",
                locations=matched_locations,
                data={
                    "transport": "mcp",
                    "mcp_tool": "project/files",
                    "mcp_success": True,
                    "indexed_files": matched_files,
                    "indexed_file_status": statuses,
                },
            )
        ]

    def _mcp_trace_evidence(
        self,
        client: MCPStdioClient,
        finding: Finding,
        indexer: SourceIndexer,
        resolved_locations: Sequence[ResolvedLocation],
    ) -> List[CodeEvidence]:
        evidence = []
        for resolved in resolved_locations[:6]:
            line = resolved.requested.line or 1
            column = _trace_column(indexer, resolved, line)
            for trace_kind in ("point", "variable"):
                arguments: Dict[str, Any] = {
                    "kind": trace_kind,
                    "file_path": resolved.relative_path,
                    "line": line,
                    "column": column,
                }
                if trace_kind == "variable":
                    arguments["max_depth"] = 30
                payload, raw_text, is_error = _safe_mcp_tool_payload(client, "trace", arguments)
                evidence.append(
                    _mcp_trace_item(
                        finding,
                        trace_kind,
                        payload,
                        raw_text,
                        is_error,
                        SourceLocation(file=resolved.relative_path, line=line, column=column),
                    )
                )
        return evidence

    def _mcp_call_evidence(
        self,
        client: MCPStdioClient,
        finding: Finding,
        indexer: SourceIndexer,
        resolved_locations: Sequence[ResolvedLocation],
    ) -> List[CodeEvidence]:
        search_terms: List[str] = []
        term_locations: Dict[str, SourceLocation] = {}
        for resolved in resolved_locations:
            if resolved.symbol and resolved.symbol not in search_terms:
                search_terms.append(resolved.symbol)
                term_locations[resolved.symbol] = SourceLocation(
                    file=resolved.relative_path,
                    line=resolved.requested.line,
                    column=resolved.requested.column,
                )
        for flow in finding.code_flows:
            for loc in flow:
                r = indexer.resolve_location(loc)
                if r.symbol and r.symbol not in search_terms:
                    search_terms.append(r.symbol)
                    term_locations[r.symbol] = SourceLocation(file=r.relative_path, line=loc.line, column=loc.column)
        evidence: List[CodeEvidence] = []
        seen_symbols: set[str] = set()
        for term in search_terms:
            payload, _, is_error = _safe_mcp_tool_payload(client, "search", {"query": term, "limit": 10})
            if is_error or not isinstance(payload, dict):
                continue
            candidates = payload.get("results") or []
            location = term_locations.get(term) or (SourceLocation(file=resolved_locations[0].relative_path) if resolved_locations else None)
            chosen = _choose_mcp_symbol(candidates, location.file if location else "", term)
            if not chosen:
                continue
            qname = str(chosen.get("qualified_name") or chosen.get("name") or term)
            if qname in seen_symbols:
                continue
            seen_symbols.add(qname)
            calls_payload, raw_text, calls_error = _safe_mcp_tool_payload(client, "calls", {"symbol": qname, "direction": "both", "depth": 2, "limit": 30})
            if calls_error or not isinstance(calls_payload, dict):
                evidence.append(
                    CodeEvidence(
                        evidence_id=evidence_id(finding.finding_id, self.name, "mcp-calls", qname),
                        kind=EvidenceKind.TOOL_DIAGNOSTIC,
                        strength=EvidenceStrength.WEAK,
                        summary=f"Atlas MCP calls 未能解析 `{qname}` 的调用图：{raw_text[:240]}",
                        source="atlas-mcp",
                        locations=[location] if location else [],
                        data={"transport": "mcp", "mcp_tool": "calls", "mcp_success": False, "symbols": [qname]},
                    )
                )
                continue
            callers = _mcp_call_entries(calls_payload, "callers")
            callees = _mcp_call_entries(calls_payload, "callees")
            locations = [location] if location else []
            locations.extend(_locations_from_mcp_entries(callers + callees, limit=12))
            strength = EvidenceStrength.MEDIUM if callers or callees else EvidenceStrength.PARTIAL
            summary = f"Atlas MCP calls 提取 `{qname}` 调用图：调用方 {len(callers)} 个，被调用方 {len(callees)} 个"
            evidence.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, self.name, "mcp-calls", qname),
                    kind=EvidenceKind.CALL_CHAIN,
                    strength=strength,
                    summary=summary,
                    source="atlas-mcp",
                    locations=locations,
                    data={
                        "transport": "mcp",
                        "mcp_tool": "calls",
                        "mcp_success": True,
                        "symbols": [qname],
                        "callers": _compact_mcp_entries(callers),
                        "callees": _compact_mcp_entries(callees),
                    },
                )
            )
        return evidence

    def _index_project(
        self, finding: Finding, indexer: SourceIndexer, settings: AnalyzerSettings
    ) -> List[CodeEvidence]:
        outputs = []
        for step in (["index", "--analysis", "full"], ["init"], ["index", "--analysis", "full"]):
            completed = _run_tool(self.binary, step, cwd=indexer.source_root, timeout=max(settings.timeout_seconds, 120))
            outputs.append(f"{' '.join(step)}: exit={completed.returncode}")
            if step == ["index", "--analysis", "full"] and completed.returncode == 0:
                break
            if completed.returncode != 0:
                outputs.append((completed.stderr or completed.stdout or "").strip()[:800])
                if step != ["index", "--analysis", "full"]:
                    break
        strength = EvidenceStrength.MEDIUM if (indexer.source_root / ".atlas" / "atlas.db").exists() else EvidenceStrength.PARTIAL
        return [
            CodeEvidence(
                evidence_id=evidence_id(finding.finding_id, self.name, "index"),
                kind=EvidenceKind.TOOL_DIAGNOSTIC,
                strength=strength,
                summary="已尝试 Atlas full analysis 索引：" + "; ".join(item for item in outputs if item),
                source=self.name,
            )
        ]


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
            return [_tool_unavailable(finding, self.name, "未找到 codeql 命令")]
        db_candidates = list((indexer.source_root / ".codeql-db").glob(f"*{language}*")) if (indexer.source_root / ".codeql-db").exists() else []
        if db_candidates:
            return [
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, self.name, "database-found"),
                    kind=EvidenceKind.TOOL_DIAGNOSTIC,
                    strength=EvidenceStrength.STRONG,
                    summary=f"CodeQL 已安装，并发现现有 {language} 数据库",
                    source=self.name,
                    data={"database": str(db_candidates[0])},
                )
            ]
        return [
            CodeEvidence(
                evidence_id=evidence_id(finding.finding_id, self.name, "database-missing"),
                kind=EvidenceKind.TOOL_DIAGNOSTIC,
                strength=EvidenceStrength.PARTIAL,
                summary=f"CodeQL 已安装，但未发现 {language} 对应的 .codeql-db 数据库；语义数据流证据不可用",
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
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return ToolCompleted(completed.returncode, _text(completed.stdout), _text(completed.stderr))
    except subprocess.TimeoutExpired as exc:
        return ToolCompleted(124, _text(exc.stdout), _text(exc.stderr) or f"{timeout}s 后超时")


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
    summary = f"{tool_name} {operation} 退出码 {completed.returncode}"
    if isinstance(parsed, dict):
        diagnostics = parsed.get("diagnostics")
        if diagnostics:
            summary += f"；诊断：{str(diagnostics)[:240]}"
        elif parsed.get("ok") is not None:
            summary += f"; ok={parsed.get('ok')}"
    elif output:
        summary += f"；输出：{output[:240]}"
    return CodeEvidence(
        evidence_id=evidence_id(finding.finding_id, tool_name, operation),
        kind=kind,
        strength=strength,
        summary=summary,
        source=tool_name,
        locations=list(locations),
        data={"returncode": completed.returncode, "parsed": parsed, "stderr": completed.stderr[:1000]},
    )


def _safe_mcp_tool_payload(client: MCPStdioClient, name: str, arguments: Dict[str, Any]) -> tuple[Any, str, bool]:
    try:
        return _mcp_tool_payload(client.call_tool(name, arguments))
    except MCPError as exc:
        text = str(exc)
        return {"error": text, "tool": name, "arguments": arguments}, text, True


def _mcp_tool_payload(response: Dict[str, Any]) -> tuple[Any, str, bool]:
    if response.get("error"):
        return response.get("error"), str(response.get("error")), True
    result = response.get("result") or {}
    is_error = bool(result.get("isError"))
    content = result.get("content") or []
    texts = [str(item.get("text") or "") for item in content if item.get("type") == "text"]
    text = "\n".join(item for item in texts if item)
    parsed = _try_json(text)
    if parsed is None:
        parsed = _mcp_partial_json(text)
    return parsed if parsed is not None else text, text, is_error


_TRACE_IDENTIFIER_RE = re.compile(r"[A-Za-z_][\w:]*")
_TRACE_SKIP_IDENTIFIERS = {
    "auto",
    "bool",
    "char",
    "const",
    "double",
    "float",
    "int",
    "idx_t",
    "long",
    "size_t",
    "std",
    "uint8_t",
    "void",
    "if",
    "else",
    "for",
    "while",
    "return",
}


def _trace_column(indexer: SourceIndexer, resolved: ResolvedLocation, line: int) -> int:
    if resolved.requested.column:
        return resolved.requested.column
    if resolved.absolute_path is None:
        return 1
    text = indexer.line_text(resolved.absolute_path, line)
    for match in _TRACE_IDENTIFIER_RE.finditer(text):
        token = match.group(0)
        if token in _TRACE_SKIP_IDENTIFIERS:
            continue
        if "::" in token:
            return match.start() + token.rfind("::") + 3
        return match.start() + 1
    stripped = len(text) - len(text.lstrip())
    return stripped + 1 if text else 1


def _mcp_language_capability(payload: Dict[str, Any], language: Optional[str]) -> Optional[Dict[str, Any]]:
    if not language:
        return None
    for item in payload.get("language_capabilities") or []:
        if item.get("language") == language:
            return item
    return None


def _mcp_partial_json(text: str) -> Optional[Dict[str, Any]]:
    if not text.lstrip().startswith("{"):
        return None
    result: Dict[str, Any] = {"truncated_json": True}
    for key in ("ok", "partial_result"):
        match = re.search(rf'"{key}"\s*:\s*(true|false)', text)
        if match:
            result[key] = match.group(1) == "true"
    for key in ("kind", "query_id"):
        match = re.search(rf'"{key}"\s*:\s*"([^"]+)"', text)
        if match:
            result[key] = match.group(1)
    language = _first_match(r'"language"\s*:\s*"([^"]+)"', text)
    capability_level = _first_match(r'"capability_level"\s*:\s*"([^"]+)"', text)
    if language or capability_level:
        result["capability"] = {"language": language, "capability_level": capability_level}
    return result if len(result) > 1 else None


def _mcp_trace_item(
    finding: Finding,
    trace_kind: str,
    payload: Any,
    raw_text: str,
    is_error: bool,
    location: SourceLocation,
) -> CodeEvidence:
    operation = f"mcp-trace-{trace_kind}"
    locations = [location]
    if is_error or not isinstance(payload, dict):
        summary = f"Atlas MCP trace {trace_kind} 未返回可解析结果"
        if raw_text:
            summary += f"：{raw_text[:240]}"
        return CodeEvidence(
            evidence_id=evidence_id(
                finding.finding_id,
                "atlas",
                operation,
                location.file,
                str(location.line),
                str(location.column),
            ),
            kind=EvidenceKind.TOOL_DIAGNOSTIC,
            strength=EvidenceStrength.WEAK,
            summary=summary,
            source="atlas-mcp",
            locations=locations,
            data={
                "transport": "mcp",
                "mcp_tool": "trace",
                "trace_kind": trace_kind,
                "trace_supported": True,
                "mcp_success": False,
                "raw": raw_text[:1000],
                "trace_file": location.file,
                "trace_line": location.line,
                "trace_column": location.column,
            },
        )
    ok = bool(payload.get("ok"))
    partial = bool(payload.get("partial_result"))
    diagnostics = _mcp_diagnostic_messages(payload.get("diagnostics"))
    kind = EvidenceKind.DATA_FLOW if trace_kind == "variable" and ok else EvidenceKind.TOOL_DIAGNOSTIC
    if ok and not partial and not diagnostics:
        strength = EvidenceStrength.MEDIUM
    elif ok:
        strength = EvidenceStrength.PARTIAL
    else:
        strength = EvidenceStrength.WEAK
    summary = f"Atlas MCP trace {trace_kind} 返回 ok={ok}（位置 {location.display()}）"
    if payload.get("truncated_json"):
        summary += "，返回 JSON 被截断但已提取关键字段"
    if partial:
        summary += "，结果为 partial"
    if diagnostics:
        summary += "，诊断：" + "; ".join(diagnostics[:3])
    capability = payload.get("capability") or {}
    if isinstance(capability, dict) and capability.get("capability_level"):
        summary += f"，能力 {capability.get('language')}:{capability.get('capability_level')}"
    return CodeEvidence(
        evidence_id=evidence_id(
            finding.finding_id,
            "atlas",
            operation,
            location.file,
            str(location.line),
            str(location.column),
        ),
        kind=kind,
        strength=strength,
        summary=summary,
        source="atlas-mcp",
        locations=locations,
        data={
            "transport": "mcp",
            "mcp_tool": "trace",
            "trace_kind": trace_kind,
            "trace_supported": True,
            "mcp_success": True,
            "ok": ok,
            "partial_result": partial,
            "diagnostics": diagnostics,
            "query_id": payload.get("query_id"),
            "truncated_json": bool(payload.get("truncated_json")),
            "language_level": capability.get("capability_level") if isinstance(capability, dict) else None,
            "trace_file": location.file,
            "trace_line": location.line,
            "trace_column": location.column,
            "result": _compact_mcp_trace_result(payload.get("result")),
        },
    )


def _mcp_diagnostic_messages(value: Any) -> List[str]:
    if not value:
        return []
    messages = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                message = item.get("message") or item.get("code") or item
            else:
                message = item
            messages.append(str(message))
    else:
        messages.append(str(value))
    return messages


def _choose_mcp_symbol(candidates: Sequence[Dict[str, Any]], relative_path: str, symbol: str) -> Optional[Dict[str, Any]]:
    if not candidates:
        return None
    for item in candidates:
        if item.get("file") == relative_path and item.get("name") == symbol:
            return item
    for item in candidates:
        if item.get("file") == relative_path:
            return item
    return candidates[0]


def _mcp_call_entries(payload: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    seen = set()
    for hop in payload.get("hops") or []:
        for item in hop.get(key) or []:
            if not isinstance(item, dict):
                continue
            marker = (item.get("qualified_name"), item.get("file"), item.get("line"))
            if marker in seen:
                continue
            seen.add(marker)
            entries.append(item)
    return entries


def _locations_from_mcp_entries(entries: Sequence[Dict[str, Any]], limit: int) -> List[SourceLocation]:
    locations = []
    for item in entries[:limit]:
        file = item.get("file")
        if not file:
            continue
        locations.append(SourceLocation(file=str(file), line=_optional_int(item.get("line"))))
    return locations


def _agentic_query_terms(finding: Finding, limit: int = 24) -> List[str]:
    raw_text = " ".join(
        [
            finding.rule_id,
            finding.message,
            " ".join(str(value) for value in finding.properties.values()),
            json.dumps(finding.raw, ensure_ascii=False)[:4000],
            " ".join(location.file for location in finding.locations),
            " ".join(location.symbol or "" for location in finding.locations),
        ]
    )
    terms: List[str] = []
    for location in finding.locations:
        if location.symbol:
            terms.append(location.symbol)
            terms.extend(_symbol_parts(location.symbol))
        path = location.file.replace("\\", "/")
        if path:
            terms.append(Path(path).name)
            terms.append(Path(path).stem)
    for match in re.finditer(r"`([^`]{2,120})`", raw_text):
        token = match.group(1).strip()
        if "/" in token or "\\" in token:
            terms.extend([Path(token.replace("\\", "/")).name, Path(token.replace("\\", "/")).stem])
        elif _looks_like_symbol(token):
            terms.append(token.rstrip("()"))
            terms.extend(_symbol_parts(token.rstrip("()")))
    for match in re.finditer(r"\b([A-Za-z_~][\w:~]*(?:::[A-Za-z_~][\w:~]*)*)\s*\(", raw_text):
        token = match.group(1)
        if token not in {"if", "for", "while", "switch", "return", "sizeof"}:
            terms.append(token)
            terms.extend(_symbol_parts(token))
    for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{3,}\b", raw_text):
        if token.lower() in _AGENTIC_STOP_TERMS:
            continue
        terms.append(token)
    return _dedupe_text(terms, limit=limit)


def _agentic_path_prefixes(finding: Finding, limit: int = 16) -> List[str]:
    prefixes: List[str] = []
    for location in finding.locations:
        normalized = location.file.replace("\\", "/").strip("/")
        if not normalized:
            continue
        parts = [part for part in normalized.split("/") if part and part not in {".", ".."}]
        if not parts:
            continue
        prefixes.append(normalized)
        for size in range(min(4, len(parts)), 0, -1):
            prefixes.append("/".join(parts[-size:]))
        prefixes.append(parts[-1])
    return _dedupe_text(prefixes, limit=limit)


def _agentic_search_evidence(finding: Finding, results: Sequence[Dict[str, Any]]) -> CodeEvidence:
    locations = _agentic_locations_from_search(results, limit=12)
    names = _dedupe_text([str(item.get("qualified_name") or item.get("name") or "") for item in results], limit=8)
    compact_results = _compact_mcp_entries(results, limit=12)
    return CodeEvidence(
        evidence_id=evidence_id(finding.finding_id, "atlas", "agentic-search", *names[:8]),
        kind=EvidenceKind.SOURCE_LOCATION,
        strength=EvidenceStrength.MEDIUM if locations else EvidenceStrength.WEAK,
        summary=f"AI 自主 Atlas MCP search 找到 {len(results)} 个报告相关候选符号：" + ", ".join(names[:8]),
        source="atlas-agent-mcp",
        locations=locations,
        data={
            "transport": "mcp",
            "mcp_tool": "search",
            "mcp_success": True,
            "agentic_atlas": True,
            "symbols": names,
            "results": compact_results,
        },
    )


def _agentic_locations_from_search(results: Sequence[Dict[str, Any]], limit: int) -> List[SourceLocation]:
    locations: List[SourceLocation] = []
    seen = set()
    for item in results:
        file = str(item.get("file") or "")
        if not file:
            continue
        line = _optional_int(item.get("line") or item.get("start_line"))
        symbol = str(item.get("qualified_name") or item.get("name") or "") or None
        marker = (file, line, symbol)
        if marker in seen:
            continue
        seen.add(marker)
        locations.append(SourceLocation(file=file, line=line, symbol=symbol))
        if len(locations) >= limit:
            break
    return locations


def _display_resolved_location(resolved: ResolvedLocation) -> SourceLocation:
    return SourceLocation(
        file=resolved.relative_path,
        line=resolved.requested.line,
        column=resolved.requested.column,
        symbol=resolved.symbol or resolved.requested.symbol,
    )


def _path_candidate_matches(path: str, prefix: str) -> bool:
    normalized_path = path.replace("\\", "/").strip("/")
    normalized_prefix = prefix.replace("\\", "/").strip("/")
    if not normalized_prefix:
        return False
    return (
        normalized_path.startswith(normalized_prefix)
        or normalized_path.endswith("/" + normalized_prefix)
        or Path(normalized_path).name == normalized_prefix
    )


def _source_files(root: Path) -> List[Path]:
    result: List[Path] = []
    excluded = {".git", ".atlas", ".venv", "__pycache__", "node_modules", "build", "dist", "target"}
    for path in root.rglob("*"):
        if any(part in excluded for part in path.parts):
            continue
        if path.is_file() and detect_language(str(path)):
            result.append(path)
            if len(result) >= 2000:
                break
    return result


def _first_matching_line(text: str, terms: Sequence[str]) -> Optional[int]:
    lowered_terms = [term.lower() for term in terms if term]
    for idx, line in enumerate(text.splitlines(), start=1):
        lower = line.lower()
        if any(term in lower for term in lowered_terms):
            return idx
    return None


def _looks_like_symbol(token: str) -> bool:
    return bool(re.match(r"^[A-Za-z_~][\w:~]*(?:\([^)]*\))?$", token.strip()))


def _symbol_parts(symbol: str) -> List[str]:
    parts = re.split(r"::|\.|->", symbol)
    return [part for part in parts if len(part) >= 3]


def _dedupe_text(values: Sequence[str], limit: int) -> List[str]:
    result: List[str] = []
    seen = set()
    for value in values:
        text = str(value or "").strip().strip("`'\"")
        if not text:
            continue
        marker = text.lower()
        if marker in seen:
            continue
        seen.add(marker)
        result.append(text)
        if len(result) >= limit:
            break
    return result


_AGENTIC_STOP_TERMS = {
    "true",
    "false",
    "null",
    "none",
    "warning",
    "error",
    "high",
    "medium",
    "low",
    "critical",
    "message",
    "locations",
    "format",
    "markdown",
    "summary",
    "source",
    "path",
    "file",
    "line",
    "column",
}


def _compact_mcp_entries(entries: Sequence[Dict[str, Any]], limit: int = 12) -> List[Dict[str, Any]]:
    result = []
    for item in entries[:limit]:
        result.append(
            {
                "qualified_name": item.get("qualified_name"),
                "name": item.get("name"),
                "file": item.get("file"),
                "line": item.get("line"),
                "edge": item.get("edge"),
                "kind": item.get("kind"),
            }
        )
    return result


def _compact_mcp_trace_result(result: Any) -> Any:
    if not isinstance(result, dict):
        return result
    compact: Dict[str, Any] = {}
    for key in ("data_node", "binding", "binding_use", "reference", "resolved_symbol", "callsite"):
        value = result.get(key)
        if value:
            compact[key] = _compact_trace_value(value)
    scope = result.get("scope")
    if isinstance(scope, dict):
        compact["scope"] = {
            "kind": scope.get("kind"),
            "name": str(scope.get("name") or "")[:240],
            "range": scope.get("range"),
        }
    for key in ("incoming", "outgoing", "path", "steps"):
        value = result.get(key)
        if isinstance(value, list) and value:
            compact[key] = [_compact_trace_value(item) for item in value[:12]]
    return compact


def _compact_trace_value(value: Any) -> Any:
    if isinstance(value, dict):
        keep = {}
        for key in ("kind", "name", "qualified_name", "file", "line", "column", "range", "edge", "confidence"):
            if key in value:
                keep[key] = value.get(key)
        return keep or {key: str(item)[:120] for key, item in list(value.items())[:6]}
    return str(value)[:240]


def _try_json(text: str):
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _first_match(pattern: str, text: str) -> Optional[str]:
    match = re.search(pattern, text)
    return match.group(1) if match else None


def _optional_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

def _tool_unavailable(finding: Finding, tool_name: str, reason: str) -> CodeEvidence:
    return CodeEvidence(
        evidence_id=evidence_id(finding.finding_id, tool_name, "unavailable"),
        kind=EvidenceKind.TOOL_DIAGNOSTIC,
        strength=EvidenceStrength.WEAK,
        summary=reason,
        source=tool_name,
    )
