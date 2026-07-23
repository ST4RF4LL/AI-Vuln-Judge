from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional, Sequence
from uuid import uuid4

from .analyzers import AnalyzerSettings, AnalyzerSuite
from .debate import DebateOrchestrator
from .evidence import EvidenceCollector
from .llm import LLMClient, build_llm_clients
from .logging_config import logger
from .models import (
    REPORT_FINDINGS_SCHEMA,
    CodeEvidence,
    DebateRole,
    DebateTurn,
    EvidenceKind,
    EvidenceStrength,
    RunConfig,
    RunReport,
    SourceLocation,
    Verdict,
    VerdictReport,
    to_jsonable,
)
from .providers import DEFAULT_PROVIDERS_FILE, ProviderConfig, ProviderStore
from .sarif import load_sarif, prepare_report_for_processing
from .skills import load_project_context
from .source import SourceIndexer


LOG = logger("pipeline")


class RunStopped(Exception):
    """Raised when a running judgement task is stopped cooperatively."""


def run_judgement(
    config: RunConfig,
    progress_callback: Optional[Callable[[RunReport], None]] = None,
    should_stop: Optional[Callable[[], bool]] = None,
) -> RunReport:
    source_path = config.source_path.expanduser().resolve()
    sarif_path = config.sarif_path.expanduser().resolve()
    indexer = SourceIndexer(source_path)
    languages = list(indexer.languages)
    run_id = config.run_id or _run_id(sarif_path, source_path, languages)
    created_at = config.created_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    LOG.info(
        "开始漏洞研判 run_id=%s report=%s source=%s languages=%s llm=%s external_tools=%s",
        config.run_id,
        sarif_path,
        source_path,
        ",".join(languages),
        config.enable_llm,
        config.enable_external_tools,
    )
    affirmative_provider, negative_provider, moderator_provider = _resolve_providers(config)
    LOG.info(
        "Provider 解析完成 affirmative=%s negative=%s moderator=%s",
        affirmative_provider.id if affirmative_provider else None,
        negative_provider.id if negative_provider else None,
        moderator_provider.id if moderator_provider else None,
    )
    affirmative_client, negative_client, moderator_client = build_llm_clients(
        enabled=config.enable_llm,
        affirmative_provider=affirmative_provider,
        negative_provider=negative_provider,
        moderator_provider=moderator_provider,
        legacy_model=config.llm_model,
        legacy_endpoint=config.llm_endpoint,
    )
    if config.reused_findings:
        findings = list(config.reused_findings)
        diagnostics = [f"已复用任务 {config.reuse_findings_from_run_id} 的报告拆分结果"]
        effective_report_path = sarif_path
        temporary_report = False
    else:
        prepared_report = prepare_report_for_processing(
            sarif_path,
            moderator_client=moderator_client,
            moderator_agent=config.moderator_agent,
            source_path=source_path,
            source_indexer=indexer,
        )
        diagnostics = list(prepared_report.diagnostics)
        findings = list(prepared_report.findings) if prepared_report.findings is not None else load_sarif(prepared_report.effective_path)
        effective_report_path = prepared_report.effective_path
        temporary_report = prepared_report.temporary
    report_findings = {
        "schema": REPORT_FINDINGS_SCHEMA,
        "origin": "reused" if config.reused_findings else "builtin_prepared",
        "finding_count": len(findings),
        "findings": [to_jsonable(finding) for finding in findings],
    }
    if config.reuse_findings_from_run_id and config.reused_findings:
        report_findings["reused_from_run_id"] = config.reuse_findings_from_run_id
    LOG.info(
        "报告解析完成 findings=%s report=%s effective_report=%s temporary=%s",
        len(findings),
        sarif_path,
        effective_report_path,
        temporary_report,
    )
    project_context = load_project_context(config.skills_path)
    LOG.info("项目知识库加载完成 facts=%s skills=%s", len(project_context.facts), config.skills_path)
    analyzer_settings = AnalyzerSettings(
        enabled=config.enable_external_tools,
        auto_index=config.auto_index_tools,
        mcp_servers_file=config.mcp_servers_file,
        agent_managed_atlas=config.enable_llm,
    )
    collector = EvidenceCollector(
        indexer=indexer,
        project_context=project_context,
        analyzers=AnalyzerSuite(),
        analyzer_settings=analyzer_settings,
        languages=languages,
    )
    orchestrator_template = DebateOrchestrator(
        max_rounds=config.max_rounds,
        affirmative_client=affirmative_client,
        negative_client=negative_client,
        moderator_client=moderator_client,
        affirmative_agent=config.affirmative_agent,
        negative_agent=config.negative_agent,
        moderator_agent=config.moderator_agent,
        source_path=source_path,
        mcp_servers_file=config.mcp_servers_file,
        enable_atlas_tools=config.enable_external_tools,
    )
    llm_providers = _llm_provider_metadata(
        config.enable_llm,
        affirmative_provider,
        negative_provider,
        moderator_provider,
        affirmative_client,
        negative_client,
        moderator_client,
    )
    agent_configs = _agent_config_metadata(orchestrator_template)
    reports = [_coerce_verdict_report(item) for item in config.resume_reports]
    diagnostics = [*config.resume_diagnostics, *diagnostics]
    start_index = _resume_start_index(config.resume_from_finding_index, len(reports), len(findings))

    def check_stop() -> None:
        if should_stop is not None and should_stop():
            LOG.info("漏洞研判收到中断信号 run_id=%s", run_id)
            raise RunStopped(f"任务 {run_id} 已中断")

    def emit_progress(
        partial_reports=None,
        *,
        current_finding=None,
        current_finding_index: Optional[int] = None,
        completed_finding_count: Optional[int] = None,
    ) -> None:
        if progress_callback is None:
            return
        completed_count = len(reports) if completed_finding_count is None else completed_finding_count
        resume_index = current_finding_index if current_finding_index is not None else completed_count
        progress_callback(
            RunReport(
                run_id=run_id,
                created_at=created_at,
                source_path=str(source_path),
                sarif_path=str(sarif_path),
                languages=list(languages),
                finding_count=len(findings),
                project_context_facts=len(project_context.facts),
                reports=list(partial_reports if partial_reports is not None else reports),
                status="running",
                llm_providers=llm_providers,
                agent_configs=agent_configs,
                diagnostics=list(diagnostics),
                report_findings=report_findings if config.reused_findings else {},
                completed_finding_count=completed_count,
                current_finding_id=current_finding.finding_id if current_finding is not None else None,
                current_finding_index=current_finding_index,
                resume_from_finding_id=current_finding.finding_id if current_finding is not None else None,
                resume_from_finding_index=resume_index,
            )
        )

    emit_progress()
    check_stop()
    for finding_index, finding in enumerate(findings):
        if finding_index < start_index:
            continue
        check_stop()
        LOG.info("开始处理 finding=%s rule=%s", finding.finding_id, finding.rule_id)
        emit_progress(
            reports,
            current_finding=finding,
            current_finding_index=finding_index,
            completed_finding_count=len(reports),
        )
        bundle = collector.collect(finding)
        diagnostics.extend(f"{finding.finding_id}: {item}" for item in bundle.diagnostics)
        emit_progress(
            reports,
            current_finding=finding,
            current_finding_index=finding_index,
            completed_finding_count=len(reports),
        )
        check_stop()

        def on_finding_progress(partial_report):
            emit_progress(
                [*reports, partial_report],
                current_finding=finding,
                current_finding_index=finding_index,
                completed_finding_count=len(reports),
            )
            check_stop()

        orchestrator = DebateOrchestrator(
            max_rounds=config.max_rounds,
            affirmative_client=affirmative_client,
            negative_client=negative_client,
            moderator_client=moderator_client,
            affirmative_agent=config.affirmative_agent,
            negative_agent=config.negative_agent,
            moderator_agent=config.moderator_agent,
            progress_callback=on_finding_progress,
            source_path=source_path,
            mcp_servers_file=config.mcp_servers_file,
            enable_atlas_tools=config.enable_external_tools,
        )
        verdict = orchestrator.adjudicate(bundle)
        reports.append(verdict)
        emit_progress(reports, completed_finding_count=len(reports))
        check_stop()
        LOG.info(
            "完成处理 finding=%s verdict=%s confidence=%s evidence=%s diagnostics=%s",
            finding.finding_id,
            verdict.verdict.value,
            verdict.confidence,
            len(verdict.evidence_chain),
            len(bundle.diagnostics),
        )
    report = RunReport(
        run_id=run_id,
        created_at=created_at,
        source_path=str(source_path),
        sarif_path=str(sarif_path),
        languages=list(languages),
        finding_count=len(findings),
        project_context_facts=len(project_context.facts),
        reports=reports,
        status="completed",
        llm_providers=llm_providers,
        agent_configs=agent_configs,
        diagnostics=diagnostics,
        report_findings=report_findings,
        completed_finding_count=len(reports),
        resume_from_finding_index=len(reports),
    )
    LOG.info("漏洞研判完成 run_id=%s findings=%s diagnostics=%s", report.run_id, report.finding_count, len(report.diagnostics))
    return report


def run_to_json(config: RunConfig, output_path: Optional[Path] = None) -> str:
    report = run_judgement(config)
    payload = json.dumps(to_jsonable(report), ensure_ascii=False, indent=2, sort_keys=True)
    if output_path is not None:
        output_path.expanduser().resolve().write_text(payload + "\n", encoding="utf-8")
    return payload


def _resume_start_index(requested_index: int, completed_count: int, finding_count: int) -> int:
    try:
        index = int(requested_index)
    except (TypeError, ValueError):
        index = completed_count
    index = max(index, completed_count)
    return min(index, finding_count)


def _coerce_verdict_report(value) -> VerdictReport:
    if isinstance(value, VerdictReport):
        return value
    if not isinstance(value, dict):
        raise TypeError(f"Unsupported verdict report payload: {type(value)!r}")
    return VerdictReport(
        finding_id=str(value.get("finding_id") or ""),
        rule_id=str(value.get("rule_id") or ""),
        verdict=_coerce_enum(Verdict, value.get("verdict"), Verdict.INCONCLUSIVE),
        confidence=float(value.get("confidence") or 0.0),
        reasoning_summary=str(value.get("reasoning_summary") or ""),
        final_conclusion=str(value.get("final_conclusion") or ""),
        evidence_chain=[_coerce_code_evidence(item) for item in value.get("evidence_chain") or []],
        debate=[_coerce_debate_turn(item) for item in value.get("debate") or []],
        disputed_points=[str(item) for item in value.get("disputed_points") or []],
        protection_assessment=str(value.get("protection_assessment") or ""),
        impact_assessment=str(value.get("impact_assessment") or ""),
        source_locations=[_coerce_source_location(item) for item in value.get("source_locations") or []],
        recommended_next_steps=[str(item) for item in value.get("recommended_next_steps") or []],
        evidence_graph=value.get("evidence_graph") if isinstance(value.get("evidence_graph"), dict) else {},
        verification_case=value.get("verification_case") if isinstance(value.get("verification_case"), dict) else {},
        evidence_ledger=value.get("evidence_ledger") if isinstance(value.get("evidence_ledger"), list) else [],
        scorecard=value.get("scorecard") if isinstance(value.get("scorecard"), dict) else {},
        vulnerability_type=str(value.get("vulnerability_type") or ""),
    )


def _coerce_code_evidence(value) -> CodeEvidence:
    if isinstance(value, CodeEvidence):
        return value
    data = value if isinstance(value, dict) else {}
    return CodeEvidence(
        evidence_id=str(data.get("evidence_id") or ""),
        kind=_coerce_enum(EvidenceKind, data.get("kind"), EvidenceKind.TOOL_DIAGNOSTIC),
        strength=_coerce_enum(EvidenceStrength, data.get("strength"), EvidenceStrength.WEAK),
        summary=str(data.get("summary") or ""),
        source=str(data.get("source") or ""),
        locations=[_coerce_source_location(item) for item in data.get("locations") or []],
        snippet=data.get("snippet"),
        data=data.get("data") if isinstance(data.get("data"), dict) else {},
    )


def _coerce_debate_turn(value) -> DebateTurn:
    if isinstance(value, DebateTurn):
        return value
    data = value if isinstance(value, dict) else {}
    return DebateTurn(
        role=_coerce_enum(DebateRole, data.get("role"), DebateRole.MODERATOR),
        round_index=int(data.get("round_index") or 0),
        claim=str(data.get("claim") or ""),
        evidence_ids=[str(item) for item in data.get("evidence_ids") or []],
        resolved=bool(data.get("resolved", False)),
        structured=data.get("structured") if isinstance(data.get("structured"), dict) else {},
        raw_claim=str(data.get("raw_claim")) if data.get("raw_claim") is not None else None,
    )


def _coerce_source_location(value) -> SourceLocation:
    if isinstance(value, SourceLocation):
        return value
    data = value if isinstance(value, dict) else {}
    return SourceLocation(
        file=str(data.get("file") or ""),
        line=_optional_int(data.get("line")),
        column=_optional_int(data.get("column")),
        end_line=_optional_int(data.get("end_line")),
        end_column=_optional_int(data.get("end_column")),
        symbol=str(data.get("symbol")) if data.get("symbol") is not None else None,
    )


def _coerce_enum(enum_type, value, default):
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        return default


def _optional_int(value) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _run_id(sarif_path: Path, source_path: Path, languages: Sequence[str]) -> str:
    seed = f"{sarif_path}:{source_path}:{','.join(languages)}:{uuid4().hex}"
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return f"run-{digest[:12]}"


def _resolve_providers(config: RunConfig) -> tuple[Optional[ProviderConfig], Optional[ProviderConfig], Optional[ProviderConfig]]:
    providers_file = config.providers_file
    if providers_file is None and (
        config.affirmative_provider_id or config.negative_provider_id or config.moderator_provider_id
    ):
        providers_file = DEFAULT_PROVIDERS_FILE
    if providers_file is None:
        return None, None, None
    store = ProviderStore(providers_file)
    return store.resolve_trio(config.affirmative_provider_id, config.negative_provider_id, config.moderator_provider_id)


def _llm_provider_metadata(
    enabled: bool,
    affirmative_provider: Optional[ProviderConfig],
    negative_provider: Optional[ProviderConfig],
    moderator_provider: Optional[ProviderConfig],
    affirmative_client: Optional[LLMClient],
    negative_client: Optional[LLMClient],
    moderator_client: Optional[LLMClient],
) -> dict:
    return {
        "enabled": enabled,
        "affirmative": _role_provider_metadata(enabled, affirmative_provider, affirmative_client),
        "negative": _role_provider_metadata(enabled, negative_provider, negative_client),
        "moderator": _role_provider_metadata(enabled, moderator_provider, moderator_client),
    }


def _agent_config_metadata(orchestrator: DebateOrchestrator) -> dict:
    return {
        "affirmative": to_jsonable(orchestrator.affirmative_agent),
        "negative": to_jsonable(orchestrator.negative_agent),
        "moderator": to_jsonable(orchestrator.moderator_agent),
    }


def _role_provider_metadata(enabled: bool, provider: Optional[ProviderConfig], client: Optional[LLMClient]) -> dict:
    if provider is not None:
        client_available = client is not None
        api_key_configured = bool(provider.resolved_api_key())
        if not enabled:
            status = "llm_disabled"
        elif client_available:
            status = "ready"
        elif not api_key_configured:
            status = "missing_api_key"
        else:
            status = "client_unavailable"
        return {
            "configured": True,
            "enabled": enabled,
            "provider_id": provider.id,
            "provider_name": provider.name,
            "model": provider.model,
            "endpoint": provider.endpoint,
            "api_key_configured": api_key_configured,
            "client_available": client_available,
            "status": status,
        }
    if client is not None:
        return {
            "configured": True,
            "enabled": enabled,
            "provider_id": client.provider_id,
            "provider_name": client.provider_name,
            "model": client.model,
            "endpoint": getattr(client, "endpoint", None),
            "api_key_configured": True,
            "client_available": True,
            "status": "ready",
        }
    return {
        "configured": False,
        "enabled": enabled,
        "api_key_configured": False,
        "client_available": False,
        "status": "not_configured",
    }
