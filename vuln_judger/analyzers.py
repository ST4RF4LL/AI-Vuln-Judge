from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .mcp import MCPError, MCPStdioClient
from .mcp_config import MCPServerStore
from .models import CodeEvidence, EvidenceKind, EvidenceStrength, Finding, SourceLocation
from .source import SourceIndexer, detect_language, evidence_id


@dataclass
class AnalyzerSettings:
    enabled: bool = True
    auto_index: bool = False
    timeout_seconds: int = 30
    mcp_servers_file: Optional[Path] = None


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
            return [_tool_unavailable(finding, self.name, "未找到 atlas 命令")]
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
                        summary="Atlas 已安装，但缺少 .atlas/atlas.db；请先在源码目录执行 atlas index --analysis full，或使用 --auto-index-tools 自动尝试 full analysis 索引",
                        source=self.name,
                    )
                ]
            diagnostics.extend(self._index_project(finding, indexer, settings))
        if not atlas_db.exists():
            return diagnostics + self._direct_source_evidence(finding, indexer)
        diagnostics.append(
            CodeEvidence(
                evidence_id=evidence_id(finding.finding_id, self.name, "database-present"),
                kind=EvidenceKind.TOOL_DIAGNOSTIC,
                strength=EvidenceStrength.MEDIUM,
                summary="检测到 Atlas 数据库 .atlas/atlas.db，将通过 Atlas MCP 输出数据流、调用图和源码上下文",
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
            return diagnostics + self._direct_source_evidence(finding, indexer)
        mcp_evidence = self._mcp_evidence(finding, indexer, settings, resolved.relative_path)
        if not any(item.data.get("mcp_success") for item in mcp_evidence):
            diagnostics.extend(mcp_evidence)
            diagnostics.extend(self._direct_source_evidence(finding, indexer))
            return diagnostics
        return diagnostics + mcp_evidence + self._direct_source_evidence(finding, indexer)

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
            snippet = indexer.snippet(resolved.absolute_path, location.line or 1, before=15, after=15)
            symbol = resolved.symbol or indexer.symbol_at(resolved.absolute_path, location.line or 1, resolved.language)
            language = resolved.language or "unknown"
            if symbol:
                summary = f"直接阅读源码 {resolved.relative_path}:{location.line}，邻近符号 `{symbol}`"
            else:
                summary = f"直接阅读源码 {resolved.relative_path}:{location.line}，已提取代码上下文"
            evidence.append(
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, self.name, "direct-source", resolved.relative_path, str(location.line)),
                    kind=EvidenceKind.SOURCE_LOCATION,
                    strength=EvidenceStrength.MEDIUM,
                    summary=summary,
                    source=self.name,
                    locations=[SourceLocation(file=resolved.relative_path, line=location.line, column=location.column)],
                    snippet=snippet,
                    data={
                        "file": resolved.relative_path,
                        "line": location.line,
                        "language": language,
                        "symbol": symbol,
                        "direct_read": True,
                    },
                )
            )
        return evidence

    def _mcp_evidence(
        self, finding: Finding, indexer: SourceIndexer, settings: AnalyzerSettings, relative_path: str
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
                status_payload, status_text, status_error = _mcp_tool_payload(
                    client.call_tool("project", {"action": "status", "verbose": True})
                )
                evidence.append(self._mcp_status_evidence(finding, status_payload, status_text, status_error, "trace" in tools))
                evidence.extend(self._mcp_indexed_file_evidence(client, finding, indexer))
                if "trace" in tools:
                    evidence.extend(self._mcp_trace_evidence(client, finding, relative_path))
                if "search" in tools and "calls" in tools:
                    evidence.extend(self._mcp_call_evidence(client, finding, indexer, relative_path))
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
            payload, _, is_error = _mcp_tool_payload(
                client.call_tool("project", {"action": "files", "path_prefix": resolved.relative_path, "limit": 20})
            )
            if is_error or not isinstance(payload, dict):
                continue
            for item in payload.get("files") or []:
                if item.get("path") != resolved.relative_path:
                    continue
                matched_files.append(resolved.relative_path)
                statuses[resolved.relative_path] = str(item.get("status") or "unknown")
                matched_locations.append(
                    SourceLocation(file=resolved.relative_path, line=location.line, column=location.column)
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
        self, client: MCPStdioClient, finding: Finding, relative_path: str
    ) -> List[CodeEvidence]:
        primary = finding.primary_location
        if primary is None:
            return []
        line = primary.line or 1
        column = primary.column or 1
        evidence = []
        for trace_kind in ("point", "variable"):
            arguments: Dict[str, Any] = {
                "kind": trace_kind,
                "file_path": relative_path,
                "line": line,
                "column": column,
            }
            if trace_kind == "variable":
                arguments["max_depth"] = 30
            payload, raw_text, is_error = _mcp_tool_payload(client.call_tool("trace", arguments))
            evidence.append(_mcp_trace_item(finding, trace_kind, payload, raw_text, is_error, primary))
        return evidence

    def _mcp_call_evidence(
        self, client: MCPStdioClient, finding: Finding, indexer: SourceIndexer, relative_path: str
    ) -> List[CodeEvidence]:
        primary = finding.primary_location
        if primary is None:
            return []
        resolved = indexer.resolve_location(primary)
        search_terms: List[str] = []
        if resolved.symbol:
            search_terms.append(resolved.symbol)
        for flow in finding.code_flows:
            for loc in flow:
                r = indexer.resolve_location(loc)
                if r.symbol and r.symbol not in search_terms:
                    search_terms.append(r.symbol)
        chosen: Optional[Dict[str, Any]] = None
        for term in search_terms:
            payload, _, is_error = _mcp_tool_payload(
                client.call_tool("search", {"query": term, "limit": 10})
            )
            if is_error or not isinstance(payload, dict):
                continue
            candidates = payload.get("results") or []
            chosen = _choose_mcp_symbol(candidates, relative_path, term)
            if chosen:
                break
        if not chosen:
            return []
        qname = str(chosen.get("qualified_name") or chosen.get("name") or resolved.symbol or search_terms[0])
        calls_payload, raw_text, calls_error = _mcp_tool_payload(
            client.call_tool("calls", {"symbol": qname, "direction": "both", "depth": 2, "limit": 30})
        )
        if calls_error or not isinstance(calls_payload, dict):
            return [
                CodeEvidence(
                    evidence_id=evidence_id(finding.finding_id, self.name, "mcp-calls", qname),
                    kind=EvidenceKind.TOOL_DIAGNOSTIC,
                    strength=EvidenceStrength.WEAK,
                    summary=f"Atlas MCP calls 未能解析 `{qname}` 的调用图：{raw_text[:240]}",
                    source="atlas-mcp",
                    locations=[SourceLocation(file=relative_path, line=primary.line, column=primary.column)],
                    data={"transport": "mcp", "mcp_tool": "calls", "mcp_success": False, "symbols": [qname]},
                )
            ]
        callers = _mcp_call_entries(calls_payload, "callers")
        callees = _mcp_call_entries(calls_payload, "callees")
        locations = [SourceLocation(file=relative_path, line=primary.line, column=primary.column)]
        locations.extend(_locations_from_mcp_entries(callers + callees, limit=12))
        strength = EvidenceStrength.MEDIUM if callers or callees else EvidenceStrength.PARTIAL
        summary = f"Atlas MCP calls 提取 `{qname}` 调用图：调用方 {len(callers)} 个，被调用方 {len(callees)} 个"
        return [
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
        ]

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
    primary: SourceLocation,
) -> CodeEvidence:
    operation = f"mcp-trace-{trace_kind}"
    locations = [primary]
    if is_error or not isinstance(payload, dict):
        summary = f"Atlas MCP trace {trace_kind} 未返回可解析结果"
        if raw_text:
            summary += f"：{raw_text[:240]}"
        return CodeEvidence(
            evidence_id=evidence_id(finding.finding_id, "atlas", operation),
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
    summary = f"Atlas MCP trace {trace_kind} 返回 ok={ok}"
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
        evidence_id=evidence_id(finding.finding_id, "atlas", operation),
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
