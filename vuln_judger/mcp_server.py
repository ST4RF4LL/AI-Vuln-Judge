from __future__ import annotations

import json
import sys
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, TextIO, Tuple
from uuid import uuid4

from .agents import DEFAULT_AGENTS_DIR, AgentDirectoryStore
from .analyzers import AnalyzerSettings, AnalyzerSuite
from .api import DEFAULT_RECORDS_DIR, _export_run_markdown
from .debate import DebateOrchestrator
from .evidence import EvidenceCollector
from .mcp_config import DEFAULT_MCP_SERVERS_FILE
from .models import RunConfig, SourceLocation, to_jsonable
from .pipeline import run_judgement
from .providers import DEFAULT_PROVIDERS_FILE
from .records import RunRecordStore
from .sarif import load_report
from .skills import DEFAULT_SKILLS_FILE, load_project_context
from .source import SourceIndexer


MCP_PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "vuln-judger-mcp"
SERVER_VERSION = "0.1.0"


@dataclass
class JudgerMCPSettings:
    records_dir: Path = DEFAULT_RECORDS_DIR
    providers_file: Path = DEFAULT_PROVIDERS_FILE
    mcp_servers_file: Path = DEFAULT_MCP_SERVERS_FILE
    skills_file: Path = DEFAULT_SKILLS_FILE
    agents_dir: Path = DEFAULT_AGENTS_DIR


class JudgerMCPServer:
    def __init__(
        self,
        settings: Optional[JudgerMCPSettings] = None,
        stdin: Optional[TextIO] = None,
        stdout: Optional[TextIO] = None,
    ):
        self.settings = settings or JudgerMCPSettings()
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout
        self.records = RunRecordStore(self.settings.records_dir)
        self.agent_store = AgentDirectoryStore(self.settings.agents_dir)
        self.tools = _tool_specs()

    def serve_forever(self) -> None:
        while True:
            incoming = _read_message(self.stdin)
            if incoming is None:
                return
            message, framing = incoming
            response = self._handle_message(message)
            if response is not None:
                _write_message(self.stdout, response, framing)

    def _handle_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        request_id = message.get("id")
        method = str(message.get("method") or "")
        if request_id is None and method.startswith("notifications/"):
            return None
        try:
            if method == "initialize":
                return _result(
                    request_id,
                    {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                    },
                )
            if method == "ping":
                return _result(request_id, {})
            if method == "tools/list":
                return _result(request_id, {"tools": self.tools})
            if method == "tools/call":
                params = message.get("params") or {}
                name = str(params.get("name") or "")
                arguments = params.get("arguments") or {}
                return self._tool_response(request_id, name, arguments if isinstance(arguments, dict) else {})
            if method in {"resources/list", "prompts/list"}:
                key = "resources" if method == "resources/list" else "prompts"
                return _result(request_id, {key: []})
            return _error(request_id, -32601, f"Method not found: {method}")
        except Exception as exc:
            return _error(request_id, -32603, str(exc), {"traceback": traceback.format_exc(limit=8)})

    def _tool_response(self, request_id: Any, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        try:
            payload = self._call_tool(name, arguments)
            return _tool_result(request_id, payload)
        except Exception as exc:
            return _tool_result(
                request_id,
                {"error": str(exc), "tool": name, "traceback": traceback.format_exc(limit=8)},
                is_error=True,
            )

    def _call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        if name == "judge_report":
            return self._judge_report(arguments)
        if name == "one_round_judge":
            return self._one_round_judge(arguments)
        if name == "collect_evidence":
            return self._collect_evidence(arguments)
        if name == "resolve_report_locations":
            return self._resolve_report_locations(arguments)
        if name == "list_runs":
            return self._list_runs(arguments)
        if name == "get_run":
            return self._get_run(arguments)
        if name == "get_finding":
            return self._get_finding(arguments)
        if name == "export_run_markdown":
            return self._export_run_markdown(arguments)
        raise ValueError(f"Unknown tool: {name}")

    def _judge_report(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        report_path = _required_path(arguments, "report_path")
        source_path = _required_path(arguments, "source_path")
        skills_path = _optional_path(arguments.get("skills_path"))
        run_id = _optional_text(arguments.get("run_id"))
        enable_llm = bool(arguments.get("enable_llm", False))
        config = RunConfig(
            sarif_path=report_path,
            source_path=source_path,
            skills_path=skills_path,
            providers_file=_optional_path(arguments.get("providers_file")) or self.settings.providers_file,
            mcp_servers_file=_optional_path(arguments.get("mcp_servers_file")) or self.settings.mcp_servers_file,
            run_id=run_id,
            max_rounds=int(arguments.get("max_rounds") or 4),
            auto_index_tools=bool(arguments.get("auto_index_tools", False)),
            enable_external_tools=bool(arguments.get("enable_external_tools", True)),
            enable_llm=enable_llm,
            affirmative_provider_id=_optional_text(arguments.get("affirmative_provider_id")),
            negative_provider_id=_optional_text(arguments.get("negative_provider_id")),
            moderator_provider_id=_optional_text(arguments.get("moderator_provider_id")),
            affirmative_agent=self.agent_store.agent("affirmative", _optional_text(arguments.get("affirmative_agent_profile"))),
            negative_agent=self.agent_store.agent("negative", _optional_text(arguments.get("negative_agent_profile"))),
            moderator_agent=self.agent_store.agent("moderator", _optional_text(arguments.get("moderator_agent_profile"))),
        )
        report = run_judgement(config)
        saved = bool(arguments.get("save", True))
        payload = to_jsonable(report)
        if saved:
            self.records.save_payload(payload)
        result = _run_summary(payload)
        result["saved"] = saved
        result["record_path"] = str(self.records._path(report.run_id)) if saved else None
        if bool(arguments.get("include_report", False)):
            result["report"] = payload
        return result

    def _one_round_judge(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        finding, findings, indexer, collector = self._collector_context(arguments)
        bundle = collector.collect(finding)
        report = DebateOrchestrator(
            max_rounds=1,
            affirmative_agent=self.agent_store.agent("affirmative", _optional_text(arguments.get("affirmative_agent_profile"))),
            negative_agent=self.agent_store.agent("negative", _optional_text(arguments.get("negative_agent_profile"))),
            moderator_agent=self.agent_store.agent("moderator", _optional_text(arguments.get("moderator_agent_profile"))),
        ).adjudicate(bundle)
        report_payload = to_jsonable(report)
        run_id = _optional_text(arguments.get("run_id")) or f"run-{uuid4().hex[:12]}"
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        run_payload = {
            "run_id": run_id,
            "status": "completed",
            "created_at": created_at,
            "source_path": str(_required_path(arguments, "source_path")),
            "sarif_path": str(_required_path(arguments, "report_path")),
            "languages": list(indexer.languages),
            "finding_count": 1,
            "source_finding_count": len(findings),
            "project_context_facts": len(collector.project_context.facts),
            "reports": [report_payload],
            "diagnostics": [f"{finding.finding_id}: {item}" for item in bundle.diagnostics],
            "llm_providers": {"enabled": False, "affirmative": {}, "negative": {}, "moderator": {}},
            "agent_configs": {
                "affirmative": to_jsonable(self.agent_store.agent("affirmative", _optional_text(arguments.get("affirmative_agent_profile")))),
                "negative": to_jsonable(self.agent_store.agent("negative", _optional_text(arguments.get("negative_agent_profile")))),
                "moderator": to_jsonable(self.agent_store.agent("moderator", _optional_text(arguments.get("moderator_agent_profile")))),
            },
        }
        saved = bool(arguments.get("save", False))
        if saved:
            self.records.save_payload(run_payload)
        evidence = report_payload.get("evidence_chain") or []
        evidence_limit = int(arguments.get("evidence_limit") or 40)
        result = {
            "mode": "one_round_judge",
            "run_id": run_id,
            "saved": saved,
            "record_path": str(self.records._path(run_id)) if saved else None,
            "configuration": {
                "max_rounds": 1,
                "enable_external_tools": bool(arguments.get("enable_external_tools", True)),
                "auto_index_tools": bool(arguments.get("auto_index_tools", False)),
                "atlas_mode": "agentic_only",
                "enable_llm": False,
                "languages": list(indexer.languages),
            },
            "finding_count": len(findings),
            "judged_finding_count": 1,
            "selected_finding": _finding_brief(finding),
            "verdict": _verdict_detail(report_payload),
            "missing_evidence": _missing_evidence(
                report_payload,
                bundle.diagnostics,
                external_tools_enabled=bool(arguments.get("enable_external_tools", True)),
            ),
            "evidence_summary": _evidence_summary(evidence),
            "source_locations": report_payload.get("source_locations", []),
            "recommended_next_steps": report_payload.get("recommended_next_steps", []),
            "disputed_points": report_payload.get("disputed_points", []),
            "agent_configs": run_payload["agent_configs"],
            "debate": report_payload.get("debate", []),
            "diagnostics": run_payload["diagnostics"],
        }
        if bool(arguments.get("include_evidence", True)):
            result["evidence"] = evidence[: max(0, evidence_limit)]
            result["evidence_truncated"] = len(evidence) > max(0, evidence_limit)
            result["evidence_total"] = len(evidence)
        if bool(arguments.get("include_report", False)):
            result["report"] = report_payload
            result["run"] = run_payload
        return result

    def _collect_evidence(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        finding, findings, indexer, collector = self._collector_context(arguments)
        bundle = collector.collect(finding)
        return {
            "finding_count": len(findings),
            "selected_finding": _finding_brief(finding),
            "diagnostics": bundle.diagnostics,
            "evidence": to_jsonable(bundle.evidence),
        }

    def _resolve_report_locations(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        report_path = _required_path(arguments, "report_path")
        source_path = _required_path(arguments, "source_path")
        findings = load_report(report_path)
        indexer = SourceIndexer(source_path)
        max_snippets = int(arguments.get("max_snippets") or 12)
        snippet_count = 0
        result = []
        for finding in findings:
            locations = []
            for location in finding.locations:
                resolved = indexer.resolve_location(location)
                item = {
                    "requested": location.display(),
                    "requested_file": location.file,
                    "resolved_file": resolved.relative_path,
                    "exists": resolved.exists,
                    "line_exists": resolved.line_exists,
                    "language": resolved.language,
                    "symbol": resolved.symbol,
                    "location": to_jsonable(
                        SourceLocation(
                            file=resolved.relative_path,
                            line=resolved.requested.line,
                            column=resolved.requested.column,
                            end_line=resolved.requested.end_line,
                            end_column=resolved.requested.end_column,
                            symbol=resolved.symbol or resolved.requested.symbol,
                        )
                    ),
                }
                if resolved.snippet and snippet_count < max_snippets:
                    item["snippet"] = resolved.snippet
                    snippet_count += 1
                locations.append(item)
            result.append({**_finding_brief(finding), "locations": locations, "code_flow_count": len(finding.code_flows)})
        return {"finding_count": len(findings), "findings": result}

    def _list_runs(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        limit = int(arguments.get("limit") or 50)
        return {"runs": self.records.list()[:limit]}

    def _get_run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        run = self._load_run(arguments)
        if bool(arguments.get("include_reports", False)):
            return run
        return _run_summary(run)

    def _get_finding(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        run = self._load_run(arguments)
        finding_id = _required_text(arguments, "finding_id")
        for report in run.get("reports") or []:
            if report.get("finding_id") == finding_id:
                return report
        raise ValueError(f"Finding not found: {finding_id}")

    def _export_run_markdown(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        run = self._load_run(arguments)
        return {"run_id": run.get("run_id"), "markdown": _export_run_markdown(run)}

    def _load_run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        run_id = _required_text(arguments, "run_id")
        run = self.records.get(run_id)
        if run is None:
            raise ValueError(f"Run not found: {run_id}")
        return run

    def _collector_context(
        self, arguments: Dict[str, Any]
    ) -> Tuple[Any, Sequence[Any], SourceIndexer, EvidenceCollector]:
        report_path = _required_path(arguments, "report_path")
        source_path = _required_path(arguments, "source_path")
        findings = load_report(report_path)
        finding = _select_finding(findings, arguments)
        indexer = SourceIndexer(source_path)
        languages = list(indexer.languages)
        project_context = load_project_context(_optional_path(arguments.get("skills_path")))
        collector = EvidenceCollector(
            indexer=indexer,
            project_context=project_context,
            analyzers=AnalyzerSuite(),
            analyzer_settings=AnalyzerSettings(
                enabled=bool(arguments.get("enable_external_tools", True)),
                auto_index=bool(arguments.get("auto_index_tools", False)),
                mcp_servers_file=_optional_path(arguments.get("mcp_servers_file")) or self.settings.mcp_servers_file,
            ),
            languages=languages,
        )
        return finding, findings, indexer, collector


def serve_mcp(settings: Optional[JudgerMCPSettings] = None) -> None:
    JudgerMCPServer(settings=settings).serve_forever()


def _tool_specs() -> List[Dict[str, Any]]:
    return [
        _tool(
            "judge_report",
            "Run vuln-judger on a SARIF or Markdown report and optionally save the run record.",
            {
                "report_path": {"type": "string", "description": "SARIF/JSON/Markdown report path."},
                "source_path": {"type": "string", "description": "Source tree root path."},
                "skills_path": {"type": "string", "description": "Optional project skills directory."},
                "mcp_servers_file": {"type": "string"},
                "max_rounds": {"type": "integer", "minimum": 1, "default": 4},
                "enable_external_tools": {"type": "boolean", "default": True},
                "auto_index_tools": {
                    "type": "boolean",
                    "default": False,
                    "description": "Automatically build an Atlas index when .atlas/atlas.db is missing.",
                },
                "enable_llm": {"type": "boolean", "default": False},
                "providers_file": {"type": "string"},
                "affirmative_provider_id": {"type": "string"},
                "negative_provider_id": {"type": "string"},
                "moderator_provider_id": {"type": "string"},
                "affirmative_agent_profile": {"type": "string"},
                "negative_agent_profile": {"type": "string"},
                "moderator_agent_profile": {"type": "string"},
                "save": {"type": "boolean", "default": True},
                "include_report": {"type": "boolean", "default": False},
                "run_id": {"type": "string"},
            },
            ["report_path", "source_path"],
        ),
        _tool(
            "one_round_judge",
            "Quickly validate one finding with default settings, one debate round, evidence collection, and missing-evidence guidance.",
            {
                "report_path": {"type": "string", "description": "SARIF/JSON/Markdown report path."},
                "source_path": {"type": "string", "description": "Source tree root path."},
                "skills_path": {"type": "string", "description": "Optional project skills directory."},
                "finding_index": {"type": "integer", "minimum": 0, "default": 0},
                "finding_id": {"type": "string"},
                "rule_id": {"type": "string"},
                "enable_external_tools": {"type": "boolean", "default": True},
                "auto_index_tools": {
                    "type": "boolean",
                    "default": False,
                    "description": "Automatically build an Atlas index when .atlas/atlas.db is missing.",
                },
                "mcp_servers_file": {"type": "string"},
                "affirmative_agent_profile": {"type": "string"},
                "negative_agent_profile": {"type": "string"},
                "moderator_agent_profile": {"type": "string"},
                "include_evidence": {"type": "boolean", "default": True},
                "evidence_limit": {"type": "integer", "minimum": 0, "default": 40},
                "include_report": {"type": "boolean", "default": False},
                "save": {"type": "boolean", "default": False},
                "run_id": {"type": "string"},
            },
            ["report_path", "source_path"],
        ),
        _tool(
            "collect_evidence",
            "Collect source, SARIF, Atlas, search and impact evidence for one finding without running debate.",
            _analysis_properties(),
            ["report_path", "source_path"],
        ),
        _tool(
            "resolve_report_locations",
            "Resolve report locations against a source tree and return snippets for validation.",
            {
                "report_path": {"type": "string"},
                "source_path": {"type": "string"},
                "max_snippets": {"type": "integer", "minimum": 0, "default": 12},
            },
            ["report_path", "source_path"],
        ),
        _tool(
            "list_runs",
            "List saved vuln-judger run records.",
            {"limit": {"type": "integer", "minimum": 1, "default": 50}},
            [],
        ),
        _tool(
            "get_run",
            "Get a saved run summary or full run report.",
            {"run_id": {"type": "string"}, "include_reports": {"type": "boolean", "default": False}},
            ["run_id"],
        ),
        _tool(
            "get_finding",
            "Get one finding report from a saved run.",
            {"run_id": {"type": "string"}, "finding_id": {"type": "string"}},
            ["run_id", "finding_id"],
        ),
        _tool(
            "export_run_markdown",
            "Export a saved run as Markdown.",
            {"run_id": {"type": "string"}},
            ["run_id"],
        ),
    ]


def _analysis_properties() -> Dict[str, Any]:
    return {
        "report_path": {"type": "string"},
        "source_path": {"type": "string"},
        "skills_path": {"type": "string"},
        "finding_index": {"type": "integer", "minimum": 0},
        "finding_id": {"type": "string"},
        "rule_id": {"type": "string"},
        "enable_external_tools": {"type": "boolean", "default": True},
        "auto_index_tools": {
            "type": "boolean",
            "default": False,
            "description": "Automatically build an Atlas index when .atlas/atlas.db is missing.",
        },
        "mcp_servers_file": {"type": "string"},
    }


def _tool(name: str, description: str, properties: Dict[str, Any], required: Sequence[str]) -> Dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": list(required),
            "additionalProperties": False,
        },
    }

def _read_message(stdin: TextIO) -> Optional[Tuple[Dict[str, Any], str]]:
    raw_line = stdin.buffer.readline() if hasattr(stdin, "buffer") else stdin.readline().encode("utf-8")
    while raw_line in {b"\n", b"\r\n"}:
        raw_line = stdin.buffer.readline() if hasattr(stdin, "buffer") else stdin.readline().encode("utf-8")
    if not raw_line:
        return None
    if raw_line.lower().startswith(b"content-length:"):
        headers = [raw_line]
        while True:
            line = stdin.buffer.readline() if hasattr(stdin, "buffer") else stdin.readline().encode("utf-8")
            if not line:
                return None
            if line in {b"\n", b"\r\n"}:
                break
            headers.append(line)
        length = _content_length(headers)
        body = stdin.buffer.read(length) if hasattr(stdin, "buffer") else stdin.read(length).encode("utf-8")
        return json.loads(body.decode("utf-8")), "header"
    return json.loads(raw_line.decode("utf-8")), "line"


def _write_message(stdout: TextIO, message: Dict[str, Any], framing: str) -> None:
    raw = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if framing == "header":
        stdout.buffer.write(f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii") + raw)
        stdout.buffer.flush()
    else:
        stdout.write(raw.decode("utf-8") + "\n")
        stdout.flush()


def _content_length(headers: Iterable[bytes]) -> int:
    for header in headers:
        name, _, value = header.partition(b":")
        if name.strip().lower() == b"content-length":
            return int(value.strip())
    raise ValueError("Missing Content-Length header")


def _result(request_id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    error = {"code": code, "message": message}
    if data:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _tool_result(request_id: Any, payload: Any, is_error: bool = False) -> Dict[str, Any]:
    return _result(
        request_id,
        {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(to_jsonable(payload), ensure_ascii=False, indent=2, sort_keys=True),
                }
            ],
            "isError": is_error,
        },
    )


def _required_path(arguments: Dict[str, Any], key: str) -> Path:
    value = _required_text(arguments, key)
    return Path(value).expanduser().resolve()


def _optional_path(value: Any) -> Optional[Path]:
    text = _optional_text(value)
    return Path(text).expanduser().resolve() if text else None


def _required_text(arguments: Dict[str, Any], key: str) -> str:
    value = _optional_text(arguments.get(key))
    if not value:
        raise ValueError(f"{key} is required")
    return value


def _optional_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None

def _select_finding(findings: Sequence[Any], arguments: Dict[str, Any]) -> Any:
    if not findings:
        raise ValueError("Report contains no findings")
    finding_id = _optional_text(arguments.get("finding_id"))
    if finding_id:
        for finding in findings:
            if finding.finding_id == finding_id:
                return finding
        raise ValueError(f"finding_id not found: {finding_id}")
    rule_id = _optional_text(arguments.get("rule_id"))
    if rule_id:
        for finding in findings:
            if finding.rule_id == rule_id:
                return finding
        raise ValueError(f"rule_id not found: {rule_id}")
    index = int(arguments.get("finding_index") or 0)
    if index < 0 or index >= len(findings):
        raise ValueError(f"finding_index out of range: {index}")
    return findings[index]


def _finding_brief(finding: Any) -> Dict[str, Any]:
    return {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "level": finding.level,
        "message": finding.message,
        "locations": [location.display() for location in finding.locations],
    }


def _verdict_detail(report: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "finding_id": report.get("finding_id"),
        "rule_id": report.get("rule_id"),
        "verdict": report.get("verdict"),
        "confidence": report.get("confidence"),
        "reasoning_summary": report.get("reasoning_summary"),
        "final_conclusion": report.get("final_conclusion"),
        "protection_assessment": report.get("protection_assessment"),
        "impact_assessment": report.get("impact_assessment"),
    }


def _evidence_summary(evidence: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    by_kind: Dict[str, int] = {}
    by_source: Dict[str, int] = {}
    by_strength: Dict[str, int] = {}
    key_evidence = []
    for item in evidence:
        kind = str(item.get("kind") or "UNKNOWN")
        source = str(item.get("source") or "unknown")
        strength = str(item.get("strength") or "UNKNOWN")
        by_kind[kind] = by_kind.get(kind, 0) + 1
        by_source[source] = by_source.get(source, 0) + 1
        by_strength[strength] = by_strength.get(strength, 0) + 1
        if len(key_evidence) < 12 and (
            kind
            in {
                "REPORT",
                "SOURCE_LOCATION",
                "SARIF_CODE_FLOW",
                "DATA_FLOW",
                "CALL_CHAIN",
                "TOOL_DIAGNOSTIC",
            }
            or source.startswith("atlas")
        ):
            key_evidence.append(
                {
                    "evidence_id": item.get("evidence_id"),
                    "kind": kind,
                    "source": source,
                    "strength": strength,
                    "summary": item.get("summary"),
                    "locations": item.get("locations", []),
                }
            )
    return {
        "total": len(evidence),
        "by_kind": by_kind,
        "by_source": by_source,
        "by_strength": by_strength,
        "key_evidence": key_evidence,
    }


def _missing_evidence(
    report: Dict[str, Any],
    diagnostics: Sequence[str],
    external_tools_enabled: bool = True,
) -> List[Dict[str, Any]]:
    evidence = report.get("evidence_chain") or []
    missing: List[Dict[str, Any]] = []
    if not _has_evidence_kind(evidence, "SOURCE_LOCATION", require_line=True):
        missing.append(
            {
                "type": "source_location",
                "summary": "缺少可解析到源码树的具体文件/行号证据。",
                "suggestion": "先调用 resolve_report_locations 校验报告路径，必要时补充正确 source_path 或报告行号。",
            }
        )
    if not _has_meaningful_evidence(evidence, {"SARIF_CODE_FLOW", "DATA_FLOW", "CALL_CHAIN"}):
        missing.append(
            {
                "type": "flow_or_call_chain",
                "summary": "缺少中等以上强度的数据流或调用链闭环证据。",
                "suggestion": "优先补充 SARIF codeFlows；或构建 Atlas 索引后通过 collect_evidence 获取 trace/calls。",
            }
        )
    if _has_cpp_compile_gap(evidence):
        missing.append(
            {
                "type": "cpp_compile_database",
                "summary": "C++ 项目缺少 compile_commands.json，语义证据质量会降级。",
                "suggestion": "生成 compile_commands.json，或使用 Atlas calls/search 与源码片段手动补齐路径。",
            }
        )
    if external_tools_enabled and not _has_atlas_success(evidence):
        missing.append(
            {
                "type": "atlas_evidence",
                "summary": "未获得成功的 Atlas MCP 语义证据。",
                "suggestion": "确认 Atlas MCP 配置可用；必要时开启 auto_index_tools 自动 Atlas 构建索引。",
            }
        )
    if _has_evidence_kind(evidence, "PROTECTION"):
        missing.append(
            {
                "type": "protection_validation",
                "summary": "存在校验、鉴权、消毒或过滤相关防护证据，尚需验证是否覆盖攻击路径。",
                "suggestion": "检查防护代码与报告位置的数据关系，补充可绕过或不可绕过的源码证据。",
            }
        )
    if not _has_evidence_kind(evidence, "IMPACT") and not _has_evidence_kind(evidence, "PROJECT_CONTEXT"):
        missing.append(
            {
                "type": "impact_context",
                "summary": "缺少资产、权限边界或业务影响上下文。",
                "suggestion": "补充项目 Skill/上下文，说明可达汇点对应的数据资产或权限影响。",
            }
        )
    for point in report.get("disputed_points") or []:
        if point and not any(point == item.get("summary") for item in missing):
            missing.append({"type": "disputed_point", "summary": point, "suggestion": "按该争议点补充证据后重新运行 one_round_judge。"})
    for diagnostic in diagnostics:
        missing.append({"type": "diagnostic", "summary": diagnostic, "suggestion": "先处理该工具或配置诊断，再重新快速验证。"})
    for step in report.get("recommended_next_steps") or []:
        missing.append({"type": "next_step", "summary": step, "suggestion": step})
    return _dedupe_missing(missing)


def _has_evidence_kind(evidence: Sequence[Dict[str, Any]], kind: str, require_line: bool = False) -> bool:
    for item in evidence:
        if item.get("kind") != kind:
            continue
        if not require_line:
            return True
        if item.get("data", {}).get("line_exists") or item.get("data", {}).get("indexed_files"):
            return True
    return False


def _has_meaningful_evidence(evidence: Sequence[Dict[str, Any]], kinds: set[str]) -> bool:
    for item in evidence:
        if item.get("kind") not in kinds:
            continue
        if item.get("source") == "code-search":
            continue
        if item.get("strength") in {"STRONG", "MEDIUM"}:
            return True
    return False


def _has_cpp_compile_gap(evidence: Sequence[Dict[str, Any]]) -> bool:
    for item in evidence:
        if item.get("kind") != "TOOL_DIAGNOSTIC" or item.get("source") != "code-search":
            continue
        if item.get("data", {}).get("compile_database") is None and "compile_commands.json" in str(item.get("summary") or ""):
            return True
    return False


def _has_atlas_success(evidence: Sequence[Dict[str, Any]]) -> bool:
    return any(str(item.get("source") or "").startswith("atlas") and item.get("data", {}).get("mcp_success") for item in evidence)


def _dedupe_missing(items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    result = []
    for item in items:
        marker = (item.get("type"), item.get("summary"))
        if marker in seen:
            continue
        seen.add(marker)
        result.append(dict(item))
    return result


def _run_summary(run: Dict[str, Any]) -> Dict[str, Any]:
    reports = run.get("reports") or []
    counts: Dict[str, int] = {}
    finding_summaries = []
    for report in reports:
        verdict = str(report.get("verdict") or "UNKNOWN")
        counts[verdict] = counts.get(verdict, 0) + 1
        finding_summaries.append(
            {
                "finding_id": report.get("finding_id"),
                "rule_id": report.get("rule_id"),
                "verdict": report.get("verdict"),
                "confidence": report.get("confidence"),
                "summary": report.get("reasoning_summary"),
                "source_locations": report.get("source_locations", []),
            }
        )
    return {
        "run_id": run.get("run_id"),
        "status": run.get("status", "completed"),
        "created_at": run.get("created_at"),
        "source_path": run.get("source_path"),
        "sarif_path": run.get("sarif_path"),
        "languages": run.get("languages", []),
        "finding_count": run.get("finding_count", len(reports)),
        "verdict_counts": counts,
        "findings": finding_summaries,
        "diagnostics": run.get("diagnostics", []),
    }
