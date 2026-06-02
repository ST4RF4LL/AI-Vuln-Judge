from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence
from uuid import uuid4

from .analyzers import AnalyzerSettings, AnalyzerSuite
from .debate import DebateOrchestrator
from .evidence import EvidenceCollector
from .llm import LLMClient, build_llm_clients
from .models import RunConfig, RunReport, to_jsonable
from .providers import DEFAULT_PROVIDERS_FILE, ProviderConfig, ProviderStore
from .sarif import load_report
from .skills import load_project_context
from .source import SourceIndexer


def run_judgement(config: RunConfig) -> RunReport:
    source_path = config.source_path.expanduser().resolve()
    sarif_path = config.sarif_path.expanduser().resolve()
    findings = load_report(sarif_path)
    project_context = load_project_context(config.skills_path)
    indexer = SourceIndexer(source_path, config.languages)
    analyzer_settings = AnalyzerSettings(
        enabled=config.enable_external_tools,
        auto_index=config.auto_index_tools,
    )
    collector = EvidenceCollector(
        indexer=indexer,
        project_context=project_context,
        analyzers=AnalyzerSuite(),
        analyzer_settings=analyzer_settings,
        languages=config.languages,
    )
    affirmative_provider, negative_provider = _resolve_providers(config)
    affirmative_client, negative_client = build_llm_clients(
        enabled=config.enable_llm,
        affirmative_provider=affirmative_provider,
        negative_provider=negative_provider,
        legacy_model=config.llm_model,
        legacy_endpoint=config.llm_endpoint,
    )
    orchestrator = DebateOrchestrator(
        max_rounds=config.max_rounds,
        affirmative_client=affirmative_client,
        negative_client=negative_client,
    )
    reports = []
    diagnostics = []
    for finding in findings:
        bundle = collector.collect(finding)
        diagnostics.extend(f"{finding.finding_id}: {item}" for item in bundle.diagnostics)
        reports.append(orchestrator.adjudicate(bundle))
    return RunReport(
        run_id=config.run_id or _run_id(sarif_path, source_path, config.languages),
        created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        source_path=str(source_path),
        sarif_path=str(sarif_path),
        languages=list(config.languages),
        finding_count=len(findings),
        project_context_facts=len(project_context.facts),
        reports=reports,
        llm_providers=_llm_provider_metadata(
            config.enable_llm,
            affirmative_provider,
            negative_provider,
            affirmative_client,
            negative_client,
        ),
        diagnostics=diagnostics,
    )


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


def _resolve_providers(config: RunConfig) -> tuple[Optional[ProviderConfig], Optional[ProviderConfig]]:
    providers_file = config.providers_file
    if providers_file is None and (config.affirmative_provider_id or config.negative_provider_id):
        providers_file = DEFAULT_PROVIDERS_FILE
    if providers_file is None:
        return None, None
    store = ProviderStore(providers_file)
    return store.resolve_pair(config.affirmative_provider_id, config.negative_provider_id)


def _llm_provider_metadata(
    enabled: bool,
    affirmative_provider: Optional[ProviderConfig],
    negative_provider: Optional[ProviderConfig],
    affirmative_client: Optional[LLMClient],
    negative_client: Optional[LLMClient],
) -> dict:
    return {
        "enabled": enabled,
        "affirmative": _role_provider_metadata(enabled, affirmative_provider, affirmative_client),
        "negative": _role_provider_metadata(enabled, negative_provider, negative_client),
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
