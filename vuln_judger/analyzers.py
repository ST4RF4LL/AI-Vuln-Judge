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
    agent_managed_atlas: bool = False

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
        if settings.agent_managed_atlas:
            diagnostics.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, self.name, "agent-managed"),
                    kind=EvidenceKind.TOOL_DIAGNOSTIC,
                    strength=EvidenceStrength.MEDIUM,
                    summary="启用 LLM Agent 自主 Atlas MCP 调用；预分析器不执行固定 Atlas MCP trace/calls 流程",
                    source=self.name,
                    data={
                        "agent_managed_atlas": True,
                        "database": str(atlas_db) if atlas_db.exists() else None,
                        "focus_runtime": True,
                    },
                )
            )
            return diagnostics + self._agentic_source_reading_evidence(finding, indexer)
        mcp_supported = self._supports_mcp(settings)
        if not mcp_supported:
            if settings.auto_index and self.binary:
                diagnostics.extend(self._index_project(finding, indexer, settings))
            diagnostics.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, self.name, "mcp-unavailable"),
                    kind=EvidenceKind.TOOL_DIAGNOSTIC,
                    strength=EvidenceStrength.WEAK,
                    summary="当前 Atlas 未提供 MCP 子命令；无法使用 Atlas Focus 查询提取数据流 trace 和调用图。请确认 Atlas 版本支持 mcp 子命令",
                    source=self.name,
                    data={"database": str(atlas_db) if atlas_db.exists() else None, "mcp_supported": False},
                )
            )
            return diagnostics + self._agentic_source_reading_evidence(finding, indexer)
        if atlas_db.exists():
            diagnostics.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, self.name, "database-present"),
                    kind=EvidenceKind.TOOL_DIAGNOSTIC,
                    strength=EvidenceStrength.MEDIUM,
                    summary="检测到 Atlas 持久缓存 .atlas/atlas.db，将通过 Atlas MCP 预分析输出数据流、调用图和源码上下文",
                    source=self.name,
                    data={"database": str(atlas_db), "mcp_preferred": True, "focus_runtime": True},
                )
            )
        else:
            if settings.auto_index:
                if self.binary:
                    diagnostics.extend(self._index_project(finding, indexer, settings))
                else:
                    diagnostics.append(
                        CodeEvidence(
                            evidence_id=evidence_id(finding.finding_id, self.name, "prewarm-unavailable"),
                            kind=EvidenceKind.TOOL_DIAGNOSTIC,
                            strength=EvidenceStrength.WEAK,
                            summary="已请求预热 Atlas 持久缓存，但本机未找到 atlas CLI；继续使用已配置的 Atlas MCP Focus 查询",
                            source=self.name,
                            data={"database": None, "mcp_preferred": True, "focus_runtime": True, "auto_index_tools": settings.auto_index},
                        )
                    )
            diagnostics.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, self.name, "focus-runtime"),
                    kind=EvidenceKind.TOOL_DIAGNOSTIC,
                    strength=EvidenceStrength.MEDIUM,
                    summary="未检测到 Atlas 持久缓存 .atlas/atlas.db；将直接使用 Atlas v1.5+ MCP Focus 查询按需分析，无需预先执行 atlas index",
                    source=self.name,
                    data={"database": None, "mcp_preferred": True, "focus_runtime": True, "auto_index_tools": settings.auto_index},
                )
            )
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
                            "Atlas MCP 预分析补证启动：基于报告文本、路径片段和符号生成查询计划；"
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
                    evidence.append(self._agentic_project_open_evidence(client, finding, indexer, settings))
                    status_payload, status_text, status_error = _safe_mcp_tool_payload(client, "project", {"action": "status", "verbose": True})
                    evidence.append(self._agentic_status_evidence(finding, status_payload, status_text, status_error))
                    evidence.extend(self._agentic_file_evidence(client, finding, indexer, path_prefixes))
                focus_scan_state: Dict[str, Any] = {"attempted": False, "succeeded": False, "project_path": str(indexer.source_root)}
                if "search" in tools:
                    search_scopes = _agentic_focus_scopes(
                        [item.relative_path for item in resolved_locations] + list(path_prefixes)
                    )
                    search_results = self._agentic_search_results(client, terms, search_scopes)
                    if search_results:
                        evidence.append(_agentic_search_evidence(finding, search_results))
                        trace_locations = _agentic_locations_from_search(search_results, limit=6)
                        if "trace" in tools:
                            evidence.extend(
                                self._agentic_trace_evidence(
                                    client,
                                    finding,
                                    trace_locations,
                                    tools,
                                    settings,
                                    focus_scan_state,
                                )
                            )
                        if "calls" in tools:
                            evidence.extend(
                                self._agentic_call_evidence(
                                    client,
                                    finding,
                                    search_results,
                                    tools,
                                    settings,
                                    focus_scan_state,
                                )
                            )
                    else:
                        evidence.append(
                            CodeEvidence(
                                evidence_id=evidence_id(finding.finding_id, self.name, "agentic-search-empty", ",".join(terms[:8])),
                                kind=EvidenceKind.TOOL_DIAGNOSTIC,
                                strength=EvidenceStrength.WEAK,
                                summary="Atlas MCP 预分析 search 未找到报告相关符号或路径候选",
                                source="atlas-agent-mcp",
                                data={"transport": "mcp", "mcp_tool": "search", "mcp_success": False, "query_terms": terms},
                            )
                        )
                if resolved_locations and "trace" in tools:
                    evidence.extend(
                        self._agentic_trace_evidence(
                            client,
                            finding,
                            [_display_resolved_location(item) for item in resolved_locations[:4]],
                            tools,
                            settings,
                            focus_scan_state,
                        )
                    )
                return evidence
        except (MCPError, OSError, ValueError) as exc:
            return [
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, self.name, "agentic-mcp-failed"),
                    kind=EvidenceKind.TOOL_DIAGNOSTIC,
                    strength=EvidenceStrength.WEAK,
                    summary=f"Atlas MCP 预分析补证失败：{exc}",
                    source="atlas-agent-mcp",
                    data={"transport": "mcp", "agentic_atlas": True, "mcp_success": False},
                )
            ]

    def _agentic_project_open_evidence(
        self, client: MCPStdioClient, finding: Finding, indexer: SourceIndexer, _settings: AnalyzerSettings
    ) -> CodeEvidence:
        arguments = {
            "action": "open",
            "project_path": str(indexer.source_root),
        }
        payload, raw_text, is_error = _safe_mcp_tool_payload(client, "project", arguments)
        if is_error or not isinstance(payload, dict):
            return CodeEvidence(
                evidence_id=evidence_id(finding.finding_id, self.name, "agentic-open"),
                kind=EvidenceKind.TOOL_DIAGNOSTIC,
                strength=EvidenceStrength.WEAK,
                summary="Atlas MCP 预分析 project/open 未确认项目激活；将继续使用 MCP 启动目录尝试查询"
                + (f"：{raw_text[:240]}" if raw_text else ""),
                source="atlas-agent-mcp",
                data={
                    "transport": "mcp",
                    "mcp_tool": "project/open",
                    "mcp_success": False,
                    "agentic_atlas": True,
                    "focus_runtime": True,
                    "project_path": str(indexer.source_root),
                    "raw": raw_text[:1000],
                },
            )
        return CodeEvidence(
            evidence_id=evidence_id(finding.finding_id, self.name, "agentic-open"),
            kind=EvidenceKind.TOOL_DIAGNOSTIC,
            strength=EvidenceStrength.MEDIUM,
            summary="Atlas MCP 预分析 project/open 已激活项目",
            source="atlas-agent-mcp",
            data={
                "transport": "mcp",
                "mcp_tool": "project/open",
                "mcp_success": True,
                "agentic_atlas": True,
                "focus_runtime": True,
                "project_path": str(indexer.source_root),
                "project": payload.get("project") or payload.get("result") or {},
                "analysis": payload.get("analysis") or {},
                "precision": payload.get("precision") or {},
                "work": payload.get("work") or {},
            },
        )

    def _agentic_status_evidence(self, finding: Finding, payload: Any, raw_text: str, is_error: bool) -> CodeEvidence:
        if is_error or not isinstance(payload, dict):
            return CodeEvidence(
                evidence_id=evidence_id(finding.finding_id, self.name, "agentic-status"),
                kind=EvidenceKind.TOOL_DIAGNOSTIC,
                strength=EvidenceStrength.WEAK,
                summary="Atlas MCP 预分析 project/status 未返回可解析状态" + (f"：{raw_text[:240]}" if raw_text else ""),
                source="atlas-agent-mcp",
                data={"transport": "mcp", "mcp_tool": "project/status", "mcp_success": False, "raw": raw_text[:1000]},
            )
        summary = _mcp_result_dict(payload).get("summary") or payload.get("summary") or {}
        bits = []
        for key, label in (("files", "文件"), ("symbols", "符号"), ("edges", "边")):
            if summary.get(key) is not None:
                bits.append(f"{label} {summary.get(key)}")
        precision_text = _mcp_precision_text(payload)
        if precision_text:
            bits.append(precision_text)
        return CodeEvidence(
            evidence_id=evidence_id(finding.finding_id, self.name, "agentic-status"),
            kind=EvidenceKind.TOOL_DIAGNOSTIC,
            strength=EvidenceStrength.MEDIUM,
            summary="Atlas MCP 预分析 project/status 确认项目状态" + ("：" + "，".join(bits) if bits else ""),
            source="atlas-agent-mcp",
            data={
                "transport": "mcp",
                "mcp_tool": "project/status",
                "mcp_success": True,
                "agentic_atlas": True,
                "focus_runtime": True,
                "summary": summary,
                "project": payload.get("project") or _mcp_result_dict(payload).get("project") or {},
                "server": payload.get("server") or _mcp_result_dict(payload).get("server") or {},
                "analysis": payload.get("analysis") or {},
                "precision": payload.get("precision") or {},
                "work": payload.get("work") or {},
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
            for item in _mcp_files(payload):
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
                summary="Atlas MCP 预分析 project/files 找到报告路径候选：" + status_text,
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

    def _agentic_search_results(
        self, client: MCPStdioClient, terms: Sequence[str], scopes: Sequence[str] = ()
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        seen: set[tuple[str, str, int]] = set()
        search_specs: List[Dict[str, Any]] = []
        focus_scopes = _agentic_focus_scopes(scopes, limit=8)
        if focus_scopes:
            for scope in focus_scopes[:6]:
                for term in terms[:4]:
                    search_specs.append({"query": term, "scope": scope, "limit": 10})
        else:
            for term in terms[:8]:
                search_specs.append({"query": term, "limit": 10})
        for arguments in search_specs[:32]:
            payload, _, is_error = _safe_mcp_tool_payload(client, "search", arguments)
            if is_error or not isinstance(payload, dict):
                continue
            for item in _mcp_results(payload):
                if not isinstance(item, dict):
                    continue
                marker = (str(item.get("qualified_name") or item.get("name") or ""), str(item.get("file") or ""), _optional_int(item.get("line")) or 0)
                if marker in seen:
                    continue
                seen.add(marker)
                copied = dict(item)
                copied["query"] = arguments.get("query")
                if arguments.get("scope"):
                    copied["scope"] = arguments.get("scope")
                results.append(copied)
                if len(results) >= 30:
                    return results
            if focus_scopes and results:
                return results
        return results

    def _agentic_trace_evidence(
        self,
        client: MCPStdioClient,
        finding: Finding,
        locations: Sequence[SourceLocation],
        tools: set[Any],
        settings: AnalyzerSettings,
        focus_scan_state: Dict[str, Any],
    ) -> List[CodeEvidence]:
        evidence: List[CodeEvidence] = []
        for location in locations[:6]:
            if not location.file or not location.line:
                continue
            column = location.column or 1
            trace_kinds = ["point", "variable"]
            if location.symbol:
                trace_kinds.append("callers")
            for trace_kind in trace_kinds:
                if trace_kind == "callers":
                    arguments = {"kind": trace_kind, "symbol": location.symbol, "max_depth": 12}
                else:
                    arguments = {
                        "kind": trace_kind,
                        "file_path": location.file,
                        "line": location.line,
                        "column": column,
                    }
                    if trace_kind == "variable":
                        arguments["max_depth"] = 30
                payload, raw_text, is_error = _safe_mcp_tool_payload(client, "trace", arguments)
                retried_after_focus_scan = False
                if _mcp_needs_materialized_facts(payload, raw_text):
                    focus_scan_evidence = self._agentic_focus_rescan_evidence(
                        client,
                        finding,
                        tools,
                        settings,
                        focus_scan_state,
                        "trace",
                        [location.file],
                    )
                    evidence.extend(focus_scan_evidence)
                    if focus_scan_state.get("succeeded"):
                        payload, raw_text, is_error = _safe_mcp_tool_payload(client, "trace", arguments)
                        retried_after_focus_scan = True
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
                if item.summary.startswith("Atlas MCP "):
                    item.summary = "Atlas MCP 预分析 " + item.summary[len("Atlas MCP ") :]
                else:
                    item.summary = "预分析 " + item.summary
                item.data["agentic_atlas"] = True
                if retried_after_focus_scan:
                    item.summary += "；已在 MCP Focus scoped search 触发项目事实后重试"
                    item.data["focus_scan_retry"] = True
                evidence.append(item)
        return evidence

    def _agentic_call_evidence(
        self,
        client: MCPStdioClient,
        finding: Finding,
        search_results: Sequence[Dict[str, Any]],
        tools: set[Any],
        settings: AnalyzerSettings,
        focus_scan_state: Dict[str, Any],
    ) -> List[CodeEvidence]:
        evidence: List[CodeEvidence] = []
        seen: set[str] = set()
        for result in search_results[:12]:
            qname = str(result.get("qualified_name") or result.get("name") or "").strip()
            if not qname or qname in seen:
                continue
            seen.add(qname)
            payload, raw_text, is_error = _safe_mcp_tool_payload(client, "calls", {"symbol": qname, "direction": "both", "depth": 2, "limit": 30})
            retried_after_focus_scan = False
            if _mcp_needs_materialized_facts(payload, raw_text):
                focus_scan_evidence = self._agentic_focus_rescan_evidence(
                    client,
                    finding,
                    tools,
                    settings,
                    focus_scan_state,
                    "calls",
                    [str(result.get("file") or "")],
                )
                evidence.extend(focus_scan_evidence)
                if focus_scan_state.get("succeeded"):
                    payload, raw_text, is_error = _safe_mcp_tool_payload(
                        client,
                        "calls",
                        {"symbol": qname, "direction": "both", "depth": 2, "limit": 30},
                    )
                    retried_after_focus_scan = True
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
                        summary=f"Atlas MCP 预分析 calls 未能解析 `{qname}` 的调用图：{raw_text[:240]}",
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
                    summary=(
                        f"Atlas MCP 预分析 calls 提取 `{qname}` 调用图：调用方 {len(callers)} 个，被调用方 {len(callees)} 个"
                        + ("；已在 MCP Focus scoped search 触发项目事实后重试" if retried_after_focus_scan else "")
                    ),
                    source="atlas-agent-mcp",
                    locations=locations,
                    data={
                        "transport": "mcp",
                        "mcp_tool": "calls",
                        "mcp_success": True,
                        "agentic_atlas": True,
                        "focus_scan_retry": retried_after_focus_scan,
                        "symbols": [qname],
                        "callers": callers[:10],
                        "callees": callees[:10],
                    },
                )
            )
        return evidence

    def _agentic_focus_rescan_evidence(
        self,
        client: MCPStdioClient,
        finding: Finding,
        tools: set[Any],
        settings: AnalyzerSettings,
        focus_scan_state: Dict[str, Any],
        reason: str,
        focus_paths: Sequence[str],
    ) -> List[CodeEvidence]:
        if focus_scan_state.get("attempted"):
            return []
        focus_scan_state["attempted"] = True
        if "search" not in tools:
            return [
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, self.name, "agentic-focus-rescan", "project-missing"),
                    kind=EvidenceKind.TOOL_DIAGNOSTIC,
                    strength=EvidenceStrength.WEAK,
                    summary=(
                        "Atlas MCP 返回 No project facts have been materialized yet，"
                        "但当前 MCP Server 未暴露 search 工具，无法通过 scoped search 触发 Focus 分析"
                    ),
                    source="atlas-agent-mcp",
                    data={
                        "transport": "mcp",
                        "mcp_tool": "search",
                        "mcp_success": False,
                        "agentic_atlas": True,
                        "focus_scan_reason": reason,
                        "tools": sorted(str(tool) for tool in tools),
                    },
                )
            ]

        terms = _agentic_query_terms(finding, limit=8)
        scopes = _agentic_focus_scopes(list(focus_paths) + _agentic_path_prefixes(finding), limit=8)
        search_attempts: List[Dict[str, Any]] = []
        search_ok = False
        for arguments in _focus_search_specs(terms, scopes, limit=24):
            payload, raw_text, is_error = _safe_mcp_tool_payload(client, "search", arguments)
            results = _mcp_results(payload) if isinstance(payload, dict) else []
            search_attempts.append(
                {
                    "arguments": arguments,
                    "ok": not is_error,
                    "result_count": len(results),
                    "raw": raw_text[:500],
                }
            )
            if not is_error:
                search_ok = True
            if search_ok and results:
                break

        files_results: List[Dict[str, Any]] = []
        if "project" in tools:
            for focus_path in scopes[:6]:
                files_payload, files_raw, files_error = _safe_mcp_tool_payload(
                    client,
                    "project",
                    {"action": "files", "path_prefix": focus_path, "limit": 20},
                )
                files_results.append(
                    {
                        "path_prefix": focus_path,
                        "ok": not files_error,
                        "raw": files_raw[:500],
                        "files": _mcp_files(files_payload) if isinstance(files_payload, dict) else [],
                    }
                )

        status_payload: Any = None
        status_raw = ""
        status_error = False
        if "project" in tools:
            status_payload, status_raw, status_error = _safe_mcp_tool_payload(
                client,
                "project",
                {"action": "status", "verbose": True},
            )

        success = search_ok and not _mcp_needs_materialized_facts(status_payload, status_raw)
        focus_scan_state["succeeded"] = success
        summary = "Atlas MCP 预分析 Focus scoped search "
        if success:
            summary += f"已触发项目事实；触发原因：{reason} 返回 No project facts have been materialized yet"
        else:
            details = next((item.get("raw") for item in search_attempts if item.get("raw")), "") or status_raw
            summary += "触发项目事实失败"
            if details:
                summary += f"：{details[:240]}"
        return [
            CodeEvidence(
                evidence_id=evidence_id(finding.finding_id, self.name, "agentic-focus-rescan", reason),
                kind=EvidenceKind.TOOL_DIAGNOSTIC,
                strength=EvidenceStrength.MEDIUM if success else EvidenceStrength.WEAK,
                summary=summary,
                source="atlas-agent-mcp",
                data={
                    "transport": "mcp",
                    "mcp_tool": "search",
                    "mcp_success": success,
                    "agentic_atlas": True,
                    "focus_scan_reason": reason,
                    "search_attempts": search_attempts,
                    "focus_paths": list(focus_paths),
                    "files_results": files_results,
                    "status": status_payload if isinstance(status_payload, dict) and not status_error else None,
                    "status_raw": status_raw[:1000],
                },
            )
        ]

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
        command = [self.binary, "mcp", "--log-format", "json"]
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
        result_data = _mcp_result_dict(payload)
        summary_data = result_data.get("summary") or payload.get("summary") or {}
        project_data = payload.get("project") or result_data.get("project") or {}
        server_data = payload.get("server") or result_data.get("server") or {}
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
        precision_text = _mcp_precision_text(payload)
        if precision_text:
            bits.append(precision_text)
        summary = "Atlas MCP project/status 确认项目状态可用"
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
                "analysis": payload.get("analysis") or {},
                "precision": payload.get("precision") or {},
                "work": payload.get("work") or {},
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
            for item in _mcp_files(payload):
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
            trace_kinds = ["point", "variable"]
            if resolved.symbol:
                trace_kinds.append("callers")
            for trace_kind in trace_kinds:
                if trace_kind == "callers":
                    arguments = {"kind": trace_kind, "symbol": resolved.symbol, "max_depth": 12}
                else:
                    arguments = {
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
            candidates = _mcp_results(payload)
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


def _mcp_needs_materialized_facts(payload: Any, raw_text: str = "") -> bool:
    text = " ".join([raw_text or "", _mcp_error_text(payload)]).lower()
    return "no project facts have been materialized yet" in text


def _mcp_error_text(value: Any) -> str:
    if value in (None, "", [], {}):
        return ""
    if isinstance(value, str):
        return value[:2000]
    if isinstance(value, dict):
        chunks = []
        for key in ("error", "message", "diagnostic", "diagnostics", "raw"):
            if key in value:
                chunks.append(_mcp_error_text(value.get(key)))
        result = value.get("result")
        if isinstance(result, dict):
            chunks.append(_mcp_error_text(result))
        return " ".join(chunk for chunk in chunks if chunk)[:4000]
    if isinstance(value, list):
        return " ".join(_mcp_error_text(item) for item in value[:20])[:4000]
    return str(value)[:1000]


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
    result = _mcp_result_dict(payload)
    for item in payload.get("language_capabilities") or result.get("language_capabilities") or []:
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


def _mcp_result_dict(payload: Dict[str, Any]) -> Dict[str, Any]:
    result = payload.get("result")
    return result if isinstance(result, dict) else {}


def _mcp_files(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    result = _mcp_result_dict(payload)
    files = payload.get("files") or result.get("files") or []
    return [item for item in files if isinstance(item, dict)]


def _mcp_results(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    result = _mcp_result_dict(payload)
    results = payload.get("results") or result.get("results") or []
    return [item for item in results if isinstance(item, dict)]


def _mcp_precision_text(payload: Dict[str, Any]) -> str:
    precision = payload.get("precision")
    if not isinstance(precision, dict):
        return ""
    coverage = precision.get("coverage_tier") or precision.get("coverage")
    confidence = precision.get("semantic_confidence") or precision.get("confidence")
    parts = []
    if coverage:
        parts.append(f"覆盖 {coverage}")
    if confidence:
        parts.append(f"语义置信 {confidence}")
    return "Precision " + "/".join(parts) if parts else ""


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
    focus_locations = _locations_from_mcp_trace_payload(payload)
    locations = _dedupe_locations([location] + focus_locations)
    has_focus_path = _mcp_trace_payload_has_path_facts(payload)
    if ok and trace_kind == "callers" and (has_focus_path or focus_locations):
        kind = EvidenceKind.CALL_CHAIN
    elif ok and (trace_kind in {"variable", "forward"} or has_focus_path):
        kind = EvidenceKind.DATA_FLOW
    else:
        kind = EvidenceKind.TOOL_DIAGNOSTIC
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
    precision_text = _mcp_precision_text(payload)
    if precision_text:
        summary += f"，{precision_text}"
    work = payload.get("work")
    if isinstance(work, dict) and work:
        summary += "，包含 Focus 后台工作信息"
    if focus_locations:
        summary += f"，已提取 Focus 路径位置 {len(focus_locations)} 个"
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
            "analysis": payload.get("analysis") or {},
            "precision": payload.get("precision") or {},
            "work": payload.get("work") or {},
            "lazy_diagnostics": payload.get("lazy_diagnostics") or [],
            "analysis_contract": payload.get("analysis_contract") or {},
            "trace_file": location.file,
            "trace_line": location.line,
            "trace_column": location.column,
            "focus_path": [item.display() for item in focus_locations],
            "focus_path_facts": has_focus_path,
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
    roots = _mcp_payload_roots(payload)
    aliases = [key]
    if key == "callers":
        aliases.extend(["incoming", "sources", "predecessors"])
    elif key == "callees":
        aliases.extend(["outgoing", "targets", "successors"])
    for root in roots:
        for alias in aliases:
            for item in _coerce_list(root.get(alias)):
                entry = _mcp_entry_from_value(item)
                if entry:
                    marker = (entry.get("qualified_name"), entry.get("file"), entry.get("line"), entry.get("edge"))
                    if marker not in seen:
                        seen.add(marker)
                        entries.append(entry)
        for hop in _coerce_list(root.get("hops")):
            if not isinstance(hop, dict):
                continue
            for item in _coerce_list(hop.get(key)):
                entry = _mcp_entry_from_value(item)
                if entry:
                    marker = (entry.get("qualified_name"), entry.get("file"), entry.get("line"), entry.get("edge"))
                    if marker not in seen:
                        seen.add(marker)
                        entries.append(entry)
        node_lookup = _mcp_node_lookup(root)
        for edge in _coerce_list(root.get("edges")) + _coerce_list(root.get("relationships")):
            entry = _mcp_entry_from_edge(edge, key, node_lookup)
            if entry:
                marker = (entry.get("qualified_name"), entry.get("file"), entry.get("line"), entry.get("edge"))
                if marker not in seen:
                    seen.add(marker)
                    entries.append(entry)
        for item in _mcp_path_entries(root, key):
            marker = (item.get("qualified_name"), item.get("file"), item.get("line"), item.get("edge"))
            if marker not in seen:
                seen.add(marker)
                entries.append(item)
    return entries


def _mcp_payload_roots(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    roots = [payload]
    result = _mcp_result_dict(payload)
    if result and result is not payload:
        roots.append(result)
    return roots


def _coerce_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if value in (None, "", {}):
        return []
    return [value]


def _mcp_entry_from_value(value: Any, edge: Optional[str] = None) -> Optional[Dict[str, Any]]:
    if isinstance(value, dict):
        entry = dict(value)
    elif isinstance(value, str) and value.strip():
        entry = {"qualified_name": value.strip(), "name": value.strip()}
    else:
        return None
    if edge and not entry.get("edge"):
        entry["edge"] = edge
    if not entry.get("qualified_name"):
        for key in ("symbol", "name", "id"):
            if entry.get(key):
                entry["qualified_name"] = str(entry.get(key))
                break
    if not entry.get("name") and entry.get("qualified_name"):
        entry["name"] = str(entry.get("qualified_name")).split(".")[-1].split("::")[-1]
    return entry if entry.get("qualified_name") or entry.get("file") else None


def _mcp_node_lookup(root: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    lookup: Dict[str, Dict[str, Any]] = {}
    for node in _coerce_list(root.get("nodes")):
        if not isinstance(node, dict):
            continue
        for key in ("id", "symbol", "qualified_name", "name"):
            value = node.get(key)
            if value not in (None, ""):
                lookup[str(value)] = node
    return lookup


def _mcp_entry_from_edge(edge: Any, key: str, nodes: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(edge, dict):
        return None
    if key == "callers":
        raw = edge.get("from") or edge.get("source") or edge.get("caller") or edge.get("caller_symbol")
    else:
        raw = edge.get("to") or edge.get("target") or edge.get("callee") or edge.get("callee_symbol")
    if isinstance(raw, dict):
        entry = _mcp_entry_from_value(raw, edge=str(edge.get("kind") or edge.get("edge") or "calls"))
    elif raw not in (None, ""):
        entry = _mcp_entry_from_value(nodes.get(str(raw)) or str(raw), edge=str(edge.get("kind") or edge.get("edge") or "calls"))
    else:
        prefix = "from" if key == "callers" else "to"
        entry = _mcp_entry_from_value(
            {
                "qualified_name": edge.get(f"{prefix}_symbol") or edge.get(f"{prefix}_name"),
                "name": edge.get(f"{prefix}_name"),
                "file": edge.get(f"{prefix}_file"),
                "line": edge.get(f"{prefix}_line"),
                "edge": edge.get("kind") or edge.get("edge") or "calls",
            }
        )
    return entry


def _mcp_path_entries(root: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    raw_paths = []
    for path_key in ("paths", "path", "chains", "chain"):
        value = root.get(path_key)
        if value:
            if path_key in {"path", "chain"} and isinstance(value, list):
                raw_paths.append(value)
            else:
                raw_paths.extend(_coerce_list(value))
    for raw_path in raw_paths:
        if isinstance(raw_path, dict):
            steps = raw_path.get("steps") or raw_path.get("nodes") or raw_path.get("path") or []
        else:
            steps = raw_path
        step_values = _coerce_list(steps)
        if not step_values:
            continue
        relevant = step_values[:-1] if key == "callers" else step_values[1:]
        if not relevant and step_values:
            relevant = step_values
        for step in relevant:
            entry = _mcp_entry_from_value(step, edge="path")
            if entry:
                entries.append(entry)
    return entries


def _locations_from_mcp_entries(entries: Sequence[Dict[str, Any]], limit: int) -> List[SourceLocation]:
    locations = []
    for item in entries[:limit]:
        file = item.get("file")
        if not file:
            continue
        locations.append(SourceLocation(file=str(file), line=_optional_int(item.get("line"))))
    return locations


def _locations_from_mcp_trace_payload(payload: Dict[str, Any]) -> List[SourceLocation]:
    result = payload.get("result")
    if result in (None, "", [], {}):
        return []
    locations: List[SourceLocation] = []
    seen: set[tuple[str, Optional[int], Optional[int], Optional[str]]] = set()
    for value in _walk_mcp_values(result):
        if not isinstance(value, dict):
            continue
        location = _source_location_from_mcp_mapping(value)
        if location is None:
            continue
        marker = (location.file, location.line, location.column, location.symbol)
        if marker in seen:
            continue
        seen.add(marker)
        locations.append(location)
        if len(locations) >= 24:
            break
    return locations


def _walk_mcp_values(value: Any) -> List[Any]:
    values: List[Any] = []
    stack = [value]
    while stack and len(values) < 500:
        current = stack.pop()
        values.append(current)
        if isinstance(current, dict):
            for child in reversed(list(current.values())):
                if isinstance(child, (dict, list)):
                    stack.append(child)
        elif isinstance(current, list):
            for child in reversed(current):
                if isinstance(child, (dict, list)):
                    stack.append(child)
    return values


def _source_location_from_mcp_mapping(value: Dict[str, Any]) -> Optional[SourceLocation]:
    file_value = value.get("file") or value.get("file_path") or value.get("relative_path") or value.get("path")
    if not file_value or not isinstance(file_value, str):
        return None
    line = _optional_int(value.get("line") or value.get("start_line") or value.get("startLine"))
    column = _optional_int(value.get("column") or value.get("start_column") or value.get("startColumn"))
    range_value = value.get("range")
    if isinstance(range_value, dict):
        start = range_value.get("start") or {}
        if isinstance(start, dict):
            line = line or _optional_int(start.get("line") or start.get("row"))
            column = column or _optional_int(start.get("column") or start.get("col"))
        line = line or _optional_int(range_value.get("start_line") or range_value.get("startLine"))
        column = column or _optional_int(range_value.get("start_column") or range_value.get("startColumn"))
    symbol = value.get("qualified_name") or value.get("symbol") or value.get("name")
    return SourceLocation(
        file=file_value,
        line=line,
        column=column,
        symbol=str(symbol) if symbol not in (None, "") else None,
    )


def _mcp_trace_payload_has_path_facts(payload: Dict[str, Any]) -> bool:
    result = payload.get("result")
    if result in (None, "", [], {}):
        return False
    return _mcp_trace_result_has_path_facts(result)


def _mcp_trace_result_has_path_facts(value: Any) -> bool:
    path_keys = {
        "path",
        "paths",
        "steps",
        "incoming",
        "outgoing",
        "edges",
        "nodes",
        "sources",
        "sinks",
        "flows",
        "flow",
        "chain",
        "chains",
        "callers",
        "callees",
    }
    if isinstance(value, dict):
        for key, child in value.items():
            if key in path_keys and isinstance(child, (dict, list)) and child:
                return True
            if isinstance(child, (dict, list)) and _mcp_trace_result_has_path_facts(child):
                return True
    elif isinstance(value, list):
        if len(value) >= 2 and any(isinstance(item, dict) and _source_location_from_mcp_mapping(item) for item in value):
            return True
        return any(_mcp_trace_result_has_path_facts(item) for item in value if isinstance(item, (dict, list)))
    return False


def _dedupe_locations(locations: Sequence[SourceLocation]) -> List[SourceLocation]:
    result: List[SourceLocation] = []
    seen: set[tuple[str, Optional[int], Optional[int], Optional[str]]] = set()
    for location in locations:
        if not location or not location.file:
            continue
        marker = (location.file, location.line, location.column, location.symbol)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(location)
    return result


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


def _agentic_focus_scopes(paths: Sequence[str], limit: int = 12) -> List[str]:
    scopes: List[str] = []
    for raw in paths:
        normalized = str(raw or "").replace("\\", "/").strip()
        normalized = re.sub(r"^\./", "", normalized).strip("/")
        if not normalized or normalized in {".", ".."}:
            continue
        parts = [part for part in normalized.split("/") if part and part not in {".", ".."}]
        if not parts:
            continue
        scopes.append("/".join(parts))
        if "." in parts[-1]:
            for size in range(min(4, len(parts)), 0, -1):
                scopes.append("/".join(parts[-size:]))
    return _dedupe_text(scopes, limit=limit)


def _focus_search_specs(terms: Sequence[str], scopes: Sequence[str], limit: int) -> List[Dict[str, Any]]:
    specs: List[Dict[str, Any]] = []
    focus_scopes = _agentic_focus_scopes(scopes, limit=8)
    if focus_scopes:
        for scope in focus_scopes[:6]:
            for term in terms[:4]:
                specs.append({"query": term, "scope": scope, "limit": 10})
    else:
        for term in terms[:8]:
            specs.append({"query": term, "limit": 10})
    return specs[:limit]


def _agentic_search_evidence(finding: Finding, results: Sequence[Dict[str, Any]]) -> CodeEvidence:
    locations = _agentic_locations_from_search(results, limit=12)
    names = _dedupe_text([str(item.get("qualified_name") or item.get("name") or "") for item in results], limit=8)
    compact_results = _compact_mcp_entries(results, limit=12)
    return CodeEvidence(
        evidence_id=evidence_id(finding.finding_id, "atlas", "agentic-search", *names[:8]),
        kind=EvidenceKind.SOURCE_LOCATION,
        strength=EvidenceStrength.MEDIUM if locations else EvidenceStrength.WEAK,
        summary=f"Atlas MCP 预分析 search 找到 {len(results)} 个报告相关候选符号：" + ", ".join(names[:8]),
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
        parsed: Any = json.loads(text)
    except json.JSONDecodeError:
        return None
    for _ in range(2):
        if not isinstance(parsed, str):
            return parsed
        stripped = parsed.strip()
        if not stripped or stripped[0] not in "{[":
            return parsed
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            return parsed
    return parsed


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
