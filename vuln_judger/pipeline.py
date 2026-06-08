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
from .models import RunConfig, RunReport, to_jsonable
from .providers import DEFAULT_PROVIDERS_FILE, ProviderConfig, ProviderStore
from .sarif import load_report
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
    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    LOG.info(
        "开始漏洞研判 run_id=%s report=%s source=%s languages=%s llm=%s external_tools=%s",
        config.run_id,
        sarif_path,
        source_path,
        ",".join(languages),
        config.enable_llm,
        config.enable_external_tools,
    )
    findings = load_report(sarif_path)
    LOG.info("报告解析完成 findings=%s report=%s", len(findings), sarif_path)
    project_context = load_project_context(config.skills_path)
    LOG.info("项目知识库加载完成 facts=%s skills=%s", len(project_context.facts), config.skills_path)
    analyzer_settings = AnalyzerSettings(
        enabled=config.enable_external_tools,
        auto_index=config.auto_index_tools,
        mcp_servers_file=config.mcp_servers_file,
    )
    collector = EvidenceCollector(
        indexer=indexer,
        project_context=project_context,
        analyzers=AnalyzerSuite(),
        analyzer_settings=analyzer_settings,
        languages=languages,
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
    orchestrator_template = DebateOrchestrator(
        max_rounds=config.max_rounds,
        affirmative_client=affirmative_client,
        negative_client=negative_client,
        moderator_client=moderator_client,
        affirmative_agent=config.affirmative_agent,
        negative_agent=config.negative_agent,
        moderator_agent=config.moderator_agent,
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
    reports = []
    diagnostics = []

    def check_stop() -> None:
        if should_stop is not None and should_stop():
            LOG.info("漏洞研判收到停止信号 run_id=%s", run_id)
            raise RunStopped(f"任务 {run_id} 已停止")

    def emit_progress(partial_reports=None) -> None:
        if progress_callback is None:
            return
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
            )
        )

    emit_progress()
    check_stop()
    for finding in findings:
        check_stop()
        LOG.info("开始处理 finding=%s rule=%s", finding.finding_id, finding.rule_id)
        bundle = collector.collect(finding)
        diagnostics.extend(f"{finding.finding_id}: {item}" for item in bundle.diagnostics)
        emit_progress(reports)
        check_stop()

        def on_finding_progress(partial_report):
            emit_progress([*reports, partial_report])
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
        )
        verdict = orchestrator.adjudicate(bundle)
        reports.append(verdict)
        emit_progress(reports)
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
    )
    LOG.info("漏洞研判完成 run_id=%s findings=%s diagnostics=%s", report.run_id, report.finding_count, len(report.diagnostics))
    return report


def run_to_json(config: RunConfig, output_path: Optional[Path] = None) -> str:
    report = run_judgement(config)
    payload = json.dumps(to_jsonable(report), ensure_ascii=False, indent=2, sort_keys=True)
    if output_path is not None:
        output_path.expanduser().resolve().write_text(payload + "\n", encoding="utf-8")
    return payload


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
