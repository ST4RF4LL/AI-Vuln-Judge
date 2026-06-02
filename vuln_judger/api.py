from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock, Thread
from typing import Optional
from urllib.parse import unquote, urlparse
from uuid import uuid4

from .agents import DEFAULT_AGENTS_DIR, AgentDirectoryStore
from .llm import test_provider_connection
from .models import AgentConfig, RunConfig, to_jsonable
from .pipeline import run_judgement
from .providers import DEFAULT_PROVIDERS_FILE, ProviderStore
from .records import RunRecordStore


DEFAULT_RECORDS_DIR = Path(".vuln-judger") / "runs"


def serve(
    host: str = "127.0.0.1",
    port: int = 8765,
    records_dir: Path = DEFAULT_RECORDS_DIR,
    providers_file: Path = DEFAULT_PROVIDERS_FILE,
    agents_dir: Path = DEFAULT_AGENTS_DIR,
) -> None:
    store = RunRecordStore(records_dir)
    provider_store = ProviderStore(providers_file)
    agent_store = AgentDirectoryStore(agents_dir)
    server = ThreadingHTTPServer((host, port), make_handler(store, provider_store, agent_store))
    print(f"vuln-judger UI listening on http://{host}:{port}")
    print(f"records directory: {store.root}")
    print(f"providers file: {provider_store.path}")
    print(f"agents directory: {agent_store.root}")
    server.serve_forever()


def make_handler(
    store: RunRecordStore,
    provider_store: Optional[ProviderStore] = None,
    agent_store: Optional[AgentDirectoryStore] = None,
):
    provider_store = provider_store or ProviderStore(store.root.parent / "providers.json")
    agent_store = agent_store or AgentDirectoryStore(DEFAULT_AGENTS_DIR)
    tasks = {}
    tasks_lock = Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "vuln-judger/0.1"

        def do_POST(self) -> None:  # noqa: N802
            parts = _parts(self.path)
            try:
                if parts == ["runs"]:
                    payload = self._read_json()
                    run_id = _new_run_id()
                    config = _config_from_payload(payload, provider_store.path, run_id, agent_store)
                    task = _task_from_config(config, run_id, "running")
                    with tasks_lock:
                        tasks[run_id] = task
                    Thread(target=_run_task, args=(config, store, tasks, tasks_lock), daemon=True).start()
                    self._json(
                        {
                            "run_id": run_id,
                            "status": "running",
                            "finding_count": 0,
                            "created_at": task["created_at"],
                        },
                        HTTPStatus.CREATED,
                    )
                    return
                if parts == ["providers"]:
                    self._json(provider_store.upsert(self._read_json()), HTTPStatus.CREATED)
                    return
                if parts == ["providers", "defaults"]:
                    payload = self._read_json()
                    self._json(provider_store.set_defaults(payload.get("affirmative"), payload.get("negative")))
                    return
                if parts == ["agent-prompts"]:
                    payload = self._read_json()
                    if payload.get("reset"):
                        agent_store.ensure_defaults()
                        self._json(agent_store.summary())
                    elif payload.get("action") == "star":
                        self._json(
                            to_jsonable(
                                agent_store.set_starred(
                                    payload.get("role"),
                                    payload.get("profile_id"),
                                    bool(payload.get("starred")),
                                )
                            )
                        )
                    else:
                        role = payload.get("role")
                        profile_id = payload.get("profile_id")
                        instructions = payload.get("instructions")
                        self._json(to_jsonable(agent_store.save_profile(role, profile_id, instructions)), HTTPStatus.CREATED)
                    return
                if len(parts) == 3 and parts[0] == "providers" and parts[2] == "test":
                    provider = provider_store.get(parts[1])
                    if provider is None:
                        self._json({"error": "provider not found"}, HTTPStatus.NOT_FOUND)
                        return
                    payload = self._read_json()
                    result = test_provider_connection(provider, api_key_override=payload.get("api_key"))
                    result.pop("content", None)
                    self._json(result, HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST)
                    return
                self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            except Exception as exc:
                self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

        def do_DELETE(self) -> None:  # noqa: N802
            parts = _parts(self.path)
            if len(parts) == 3 and parts[0] == "agent-prompts":
                try:
                    self._json(agent_store.delete_profile(parts[1], parts[2]))
                except Exception as exc:
                    self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return
            if len(parts) == 2 and parts[0] == "providers":
                if provider_store.delete(parts[1]):
                    self._json({"deleted": True})
                else:
                    self._json({"error": "provider not found"}, HTTPStatus.NOT_FOUND)
                return
            self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def do_GET(self) -> None:  # noqa: N802
            parts = _parts(self.path)
            if not parts or parts == ["ui"]:
                self._html(app_html())
                return
            if parts == ["healthz"]:
                self._json({"ok": True})
                return
            if parts == ["providers"]:
                self._json(provider_store.list())
                return
            if parts == ["providers", "defaults"]:
                self._json(provider_store.defaults())
                return
            if parts == ["agent-prompts"]:
                self._json(agent_store.summary())
                return
            if parts == ["agent-prompts", "defaults"]:
                self._json(agent_store.defaults())
                return
            if len(parts) == 2 and parts[0] == "providers":
                provider = provider_store.get(parts[1])
                if provider is None:
                    self._json({"error": "provider not found"}, HTTPStatus.NOT_FOUND)
                    return
                self._json(provider.public_dict())
                return
            if parts == ["runs"]:
                self._json(_list_runs(store, tasks, tasks_lock))
                return
            if len(parts) >= 2 and parts[0] == "runs":
                run = store.get(parts[1])
                task = _get_task(tasks, tasks_lock, parts[1])
                if run is None:
                    if task is None:
                        self._json({"error": "run not found"}, HTTPStatus.NOT_FOUND)
                        return
                    if len(parts) == 2:
                        self._json(task)
                        return
                    if len(parts) == 3 and parts[2] == "findings":
                        self._json([])
                        return
                    self._json({"error": "run is not completed"}, HTTPStatus.BAD_REQUEST)
                    return
                if len(parts) == 2:
                    self._json(_run_detail(run))
                    return
                if len(parts) == 3 and parts[2] == "findings":
                    self._json([_finding_summary(report) for report in run.get("reports", [])])
                    return
                if len(parts) == 4 and parts[2] == "findings":
                    for report in run.get("reports", []):
                        if report.get("finding_id") == parts[3]:
                            self._json(report)
                            return
                    self._json({"error": "finding not found"}, HTTPStatus.NOT_FOUND)
                    return
            self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def log_message(self, format: str, *args) -> None:  # noqa: A002
            return

        def _read_json(self):
            length = int(self.headers.get("content-length") or 0)
            body = self.rfile.read(length).decode("utf-8")
            return json.loads(body or "{}")

        def _json(self, payload, status: HTTPStatus = HTTPStatus.OK) -> None:
            raw = json.dumps(to_jsonable(payload), ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "application/json; charset=utf-8")
            self.send_header("cache-control", "no-store")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _html(self, html: str, status: HTTPStatus = HTTPStatus.OK) -> None:
            raw = html.encode("utf-8")
            self.send_response(status)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("cache-control", "no-store")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    return Handler


def _parts(path: str) -> list[str]:
    return [unquote(part) for part in urlparse(path).path.strip("/").split("/") if part]


def _config_from_payload(
    payload,
    providers_file: Path,
    run_id: Optional[str] = None,
    agent_store: Optional[AgentDirectoryStore] = None,
) -> RunConfig:
    languages = payload.get("languages") or ["java", "cpp", "python"]
    if isinstance(languages, str):
        languages = [item.strip().lower() for item in languages.split(",") if item.strip()]
    skills_path: Optional[Path] = Path(payload["skills_path"]) if payload.get("skills_path") else None
    report_path = payload.get("sarif_path") or payload.get("report_path")
    if not report_path:
        raise ValueError("report_path or sarif_path is required")
    affirmative_agent = _agent_config_from_payload(payload, "affirmative")
    negative_agent = _agent_config_from_payload(payload, "negative")
    if agent_store is not None:
        if affirmative_agent is None:
            affirmative_agent = agent_store.agent("affirmative", payload.get("affirmative_agent_profile"))
        if negative_agent is None:
            negative_agent = agent_store.agent("negative", payload.get("negative_agent_profile"))
    return RunConfig(
        sarif_path=Path(report_path),
        source_path=Path(payload["source_path"]),
        skills_path=skills_path,
        providers_file=providers_file,
        run_id=run_id,
        languages=languages,
        max_rounds=int(payload.get("max_rounds") or 4),
        auto_index_tools=bool(payload.get("auto_index_tools") or False),
        enable_external_tools=bool(payload.get("enable_external_tools", True)),
        enable_llm=bool(payload.get("enable_llm", False)),
        llm_model=payload.get("llm_model"),
        llm_endpoint=payload.get("llm_endpoint"),
        affirmative_provider_id=payload.get("affirmative_provider_id"),
        negative_provider_id=payload.get("negative_provider_id"),
        affirmative_agent=affirmative_agent,
        negative_agent=negative_agent,
    )


def _run_detail(run):
    return {
        "run_id": run.get("run_id"),
        "status": "completed",
        "created_at": run.get("created_at"),
        "source_path": run.get("source_path"),
        "sarif_path": run.get("sarif_path"),
        "languages": run.get("languages", []),
        "finding_count": run.get("finding_count", 0),
        "project_context_facts": run.get("project_context_facts", 0),
        "diagnostics": run.get("diagnostics", []),
        "llm_providers": run.get("llm_providers", {}),
        "agent_configs": run.get("agent_configs", {}),
        "verdict_counts": _verdict_counts(run),
    }


def _list_runs(store: RunRecordStore, tasks: dict, tasks_lock: Lock):
    records = store.list()
    completed_ids = {item.get("run_id") for item in records}
    with tasks_lock:
        visible_tasks = [
            dict(task)
            for task in tasks.values()
            if task.get("status") != "completed" and task.get("run_id") not in completed_ids
        ]
    combined = visible_tasks + records
    combined.sort(key=lambda item: item.get("created_at") or "", reverse=True)
    return combined


def _get_task(tasks: dict, tasks_lock: Lock, run_id: str):
    with tasks_lock:
        task = tasks.get(run_id)
        return dict(task) if task else None


def _new_run_id() -> str:
    return f"run-{uuid4().hex[:12]}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _task_from_config(config: RunConfig, run_id: str, status: str, error: Optional[str] = None):
    return {
        "run_id": run_id,
        "status": status,
        "created_at": _now(),
        "source_path": str(config.source_path),
        "sarif_path": str(config.sarif_path),
        "languages": list(config.languages),
        "finding_count": 0,
        "project_context_facts": 0,
        "diagnostic_count": 0,
        "diagnostics": [],
        "llm_providers": {},
        "agent_configs": _agent_task_metadata(config),
        "verdict_counts": {},
        "error": error,
    }


def _run_task(config: RunConfig, store: RunRecordStore, tasks: dict, tasks_lock: Lock) -> None:
    try:
        report = run_judgement(config)
        store.save(report)
        with tasks_lock:
            tasks[report.run_id] = {
                "run_id": report.run_id,
                "status": "completed",
                "created_at": report.created_at,
                "source_path": report.source_path,
                "sarif_path": report.sarif_path,
                "languages": report.languages,
                "finding_count": report.finding_count,
                "project_context_facts": report.project_context_facts,
                "diagnostic_count": len(report.diagnostics),
                "diagnostics": report.diagnostics,
                "llm_providers": report.llm_providers,
                "agent_configs": report.agent_configs,
                "verdict_counts": _verdict_counts(to_jsonable(report)),
            }
    except Exception as exc:
        with tasks_lock:
            existing = tasks.get(config.run_id or "")
            failed = dict(existing or _task_from_config(config, config.run_id or _new_run_id(), "failed"))
            failed["status"] = "failed"
            failed["error"] = str(exc)
            failed["diagnostics"] = [str(exc)]
            tasks[failed["run_id"]] = failed


def _finding_summary(report):
    return {
        "finding_id": report.get("finding_id"),
        "rule_id": report.get("rule_id"),
        "verdict": report.get("verdict"),
        "confidence": report.get("confidence"),
        "summary": report.get("reasoning_summary"),
        "source_locations": report.get("source_locations", []),
        "evidence_count": len(report.get("evidence_chain", [])),
        "debate_turn_count": len(report.get("debate", [])),
    }


def _agent_config_from_payload(payload, role: str) -> Optional[AgentConfig]:
    raw = payload.get(f"{role}_agent") or {}
    name = ""
    instructions = ""
    if isinstance(raw, dict):
        name = str(raw.get("name") or "")
        instructions = str(raw.get("instructions") or "")
    elif raw:
        instructions = str(raw)
    name = str(payload.get(f"{role}_agent_name") or name).strip()
    instructions = str(payload.get(f"{role}_agent_instructions") or instructions).strip()
    if not name and not instructions:
        return None
    return AgentConfig(name=name, instructions=instructions)


def _agent_task_metadata(config: RunConfig) -> dict:
    return {
        "affirmative": to_jsonable(config.affirmative_agent) if config.affirmative_agent else None,
        "negative": to_jsonable(config.negative_agent) if config.negative_agent else None,
    }


def _verdict_counts(run):
    counts = {}
    for report in run.get("reports", []):
        verdict = report.get("verdict", "UNKNOWN")
        counts[verdict] = counts.get(verdict, 0) + 1
    return counts


def app_html() -> str:
    title = "Vulnerability Judger Records"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #17202a;
      --muted: #5f6b7a;
      --line: #d9dee7;
      --accent: #146c94;
      --tp: #1b7f49;
      --fp: #9a4d0a;
      --inc: #7161a5;
      --bad: #b42318;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: var(--bg); color: var(--text); }}
    header {{
      min-height: 72px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 24px;
      padding: 18px 28px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
    }}
    h1 {{ margin: 0; font-size: 22px; line-height: 1.2; font-weight: 700; letter-spacing: 0; }}
    main {{
      display: grid;
      grid-template-columns: minmax(320px, 390px) minmax(0, 1fr);
      gap: 18px;
      padding: 18px;
      height: calc(100vh - 73px);
      min-height: 660px;
    }}
    button, input, select, textarea {{ font: inherit; }}
    button {{
      border: 1px solid var(--line);
      background: #ffffff;
      color: var(--text);
      border-radius: 6px;
      padding: 8px 11px;
      cursor: pointer;
    }}
    button:hover {{ border-color: var(--accent); color: #0d4f6f; }}
    input, select, textarea {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px 10px;
      background: #ffffff;
      color: var(--text);
    }}
    textarea {{ min-height: 88px; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    label {{ display: grid; gap: 5px; font-size: 12px; color: var(--muted); }}
    .toolbar {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
    .muted {{ color: var(--muted); }}
    .pane {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      min-width: 0;
      min-height: 0;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }}
    .pane-title {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 14px 16px;
      border-bottom: 1px solid var(--line);
      min-height: 54px;
    }}
    .pane-title h2 {{ margin: 0; font-size: 15px; line-height: 1.2; }}
    .scroll {{ overflow: auto; min-height: 0; }}
    .run-list {{ display: grid; gap: 0; }}
    .run-item {{
      display: grid;
      gap: 8px;
      width: 100%;
      text-align: left;
      border: 0;
      border-bottom: 1px solid var(--line);
      border-radius: 0;
      padding: 13px 15px;
      background: #ffffff;
    }}
    .run-item.active {{ box-shadow: inset 4px 0 0 var(--accent); background: #edf7fb; }}
    .run-id {{ font-weight: 700; overflow-wrap: anywhere; }}
    .path {{ color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }}
    .chips {{ display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }}
    .chip {{
      display: inline-flex;
      align-items: center;
      min-height: 22px;
      padding: 3px 7px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: #f8fafc;
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
    }}
    .chip.tp {{ color: var(--tp); border-color: #8fd4aa; background: #effaf3; }}
    .chip.fp {{ color: var(--fp); border-color: #edc391; background: #fff7ed; }}
    .chip.inc {{ color: var(--inc); border-color: #c9c1ef; background: #f6f3ff; }}
    .content {{ padding: 16px; display: grid; gap: 16px; }}
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(120px, 1fr));
      gap: 10px;
    }}
    .metric {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fbfcfe;
      min-height: 76px;
    }}
    .metric .label {{ color: var(--muted); font-size: 12px; }}
    .metric .value {{ margin-top: 6px; font-size: 20px; font-weight: 700; overflow-wrap: anywhere; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 10px 9px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }}
    th {{ font-size: 12px; color: var(--muted); background: #fbfcfe; position: sticky; top: 0; }}
    tr.clickable {{ cursor: pointer; }}
    tr.clickable:hover {{ background: #f5fbff; }}
    .detail {{
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
      background: #ffffff;
    }}
    .detail h3 {{
      margin: 0;
      padding: 12px 14px;
      font-size: 14px;
      border-bottom: 1px solid var(--line);
      background: #fbfcfe;
    }}
    .detail-body {{ padding: 14px; display: grid; gap: 12px; }}
    .form-grid {{ display: grid; grid-template-columns: repeat(2, minmax(160px, 1fr)); gap: 12px; }}
    .form-grid .wide {{ grid-column: 1 / -1; }}
    pre {{
      margin: 0;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      background: #111827;
      color: #f8fafc;
      border-radius: 6px;
      padding: 12px;
      font-size: 12px;
      line-height: 1.5;
      max-height: 280px;
      overflow: auto;
    }}
    .empty {{ padding: 42px 18px; color: var(--muted); text-align: center; }}
    .error {{ color: var(--bad); }}
    .success {{ color: var(--tp); }}
    .modal-backdrop {{
      position: fixed;
      inset: 0;
      z-index: 20;
      display: none;
      align-items: stretch;
      justify-content: flex-end;
      background: rgba(15, 23, 42, 0.42);
    }}
    .modal-backdrop.open {{ display: flex; }}
    .settings-panel {{
      width: min(760px, 100%);
      height: 100%;
      background: var(--panel);
      border-left: 1px solid var(--line);
      display: flex;
      flex-direction: column;
      box-shadow: -18px 0 40px rgba(15, 23, 42, 0.18);
    }}
    .settings-head {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 18px 20px;
      border-bottom: 1px solid var(--line);
    }}
    .settings-head h2 {{ margin: 0; font-size: 18px; }}
    .settings-body {{ padding: 16px; overflow: auto; display: grid; gap: 16px; }}
    .profile-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
      gap: 10px;
      align-items: stretch;
    }}
    .profile-card {{
      min-width: 0;
      min-height: 154px;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      background: #fbfcfe;
      display: grid;
      grid-template-rows: auto minmax(52px, 1fr) auto;
      gap: 8px;
      overflow: hidden;
    }}
    .profile-card.starred {{ border-color: #f0c55a; background: #fffbeb; }}
    .profile-card.default {{ box-shadow: inset 3px 0 0 var(--accent); }}
    .profile-head {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; min-width: 0; }}
    .profile-title {{ font-weight: 700; overflow-wrap: anywhere; min-width: 0; }}
    .profile-path {{ color: var(--muted); font-size: 12px; line-height: 1.35; overflow-wrap: anywhere; }}
    .profile-preview {{
      color: var(--muted);
      font-size: 12px;
      line-height: 1.45;
      overflow: hidden;
      display: -webkit-box;
      -webkit-line-clamp: 3;
      -webkit-box-orient: vertical;
    }}
    .profile-actions {{ display: flex; gap: 7px; flex-wrap: wrap; align-items: center; }}
    .profile-actions button {{ padding: 6px 9px; min-height: 30px; }}
    .profile-actions button:disabled {{ cursor: not-allowed; opacity: 0.52; border-color: var(--line); color: var(--muted); }}
    @media (max-width: 900px) {{
      header {{ align-items: flex-start; flex-direction: column; }}
      main {{ grid-template-columns: 1fr; height: auto; min-height: 0; }}
      .pane {{ min-height: 360px; }}
      .summary-grid {{ grid-template-columns: repeat(2, minmax(120px, 1fr)); }}
      .form-grid {{ grid-template-columns: 1fr; }}
      .profile-grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Vulnerability Judger Records</h1>
      <div class="muted" id="subtitle">Static report adjudication run history</div>
    </div>
    <div class="toolbar">
      <button id="open-run-config" type="button" title="Start a new judgement run">Start Run</button>
      <button id="open-providers" type="button" title="Configure LLM providers">LLM Providers</button>
      <button id="open-agent-prompts" type="button" title="Configure Agent prompts">Agent Prompts</button>
      <button id="refresh" type="button" title="Refresh records">Refresh</button>
      <button id="clear-selection" type="button" title="Clear current detail">Clear</button>
    </div>
  </header>
  <main>
    <section class="pane" aria-label="Run records">
      <div class="pane-title">
        <h2>Runs</h2>
        <span class="muted" id="run-count">0 records</span>
      </div>
      <div class="scroll">
        <div class="run-list" id="run-list"></div>
      </div>
    </section>
    <section class="pane" aria-label="Run details and provider settings">
      <div class="pane-title">
        <h2 id="detail-title">Run Detail</h2>
        <span class="muted" id="detail-status">No run selected</span>
      </div>
      <div class="scroll">
        <div class="content" id="detail"></div>
      </div>
    </section>
  </main>
  <div class="modal-backdrop" id="providers-modal" role="dialog" aria-modal="true" aria-labelledby="providers-title">
    <section class="settings-panel" aria-label="LLM Providers settings">
      <div class="settings-head">
        <div>
          <h2 id="providers-title">LLM Providers</h2>
          <div class="muted">Configure OpenAI-compatible APIs for affirmative and negative agents.</div>
        </div>
        <button id="close-providers" type="button" title="Close provider settings">Close</button>
      </div>
      <div class="settings-body">
        <div class="detail" id="provider-panel">
          <h3>Provider Configuration</h3>
          <div class="detail-body">
            <div class="muted">Saved API keys are stored locally; prefer environment-variable keys when possible.</div>
            <div class="form-grid">
              <label>ID<input id="provider-id" placeholder="openai-main"></label>
              <label>Name<input id="provider-name" placeholder="OpenAI Main"></label>
              <label class="wide">Endpoint<input id="provider-endpoint" placeholder="https://api.openai.com/v1/chat/completions"></label>
              <label>Model<input id="provider-model" placeholder="gpt-4.1"></label>
              <label>API key env<input id="provider-key-env" placeholder="OPENAI_API_KEY"></label>
              <label class="wide">API key (optional plaintext)<input id="provider-key" type="password" placeholder="Leave blank to keep current saved key"></label>
              <label class="wide">Extra JSON<textarea id="provider-extra" placeholder='{{"temperature":0.1,"max_tokens":1200}}'></textarea></label>
              <label>Affirmative default<select id="default-affirmative"></select></label>
              <label>Negative default<select id="default-negative"></select></label>
            </div>
            <div class="toolbar">
              <button id="save-provider" type="button">Save Provider</button>
              <button id="test-provider" type="button">Test Selected</button>
              <button id="delete-provider" type="button">Delete Selected</button>
              <button id="save-defaults" type="button">Save Defaults</button>
            </div>
            <div class="chips" id="provider-list"></div>
            <pre id="provider-result">No provider test run yet.</pre>
          </div>
        </div>
      </div>
    </section>
  </div>
  <div class="modal-backdrop" id="agent-prompts-modal" role="dialog" aria-modal="true" aria-labelledby="agent-prompts-title">
    <section class="settings-panel" aria-label="Agent prompt settings">
      <div class="settings-head">
        <div>
          <h2 id="agent-prompts-title">Agent Prompts</h2>
          <div class="muted">Configure role profile directories and AGENT.md prompts.</div>
        </div>
        <button id="close-agent-prompts" type="button" title="Close Agent prompt settings">Close</button>
      </div>
      <div class="settings-body">
        <div class="detail" id="agent-affirmative-profile-panel">
          <h3>Affirmative Profiles</h3>
          <div class="detail-body">
            <div class="profile-grid" id="agent-affirmative-profile-list"></div>
            <div class="form-grid">
              <label>Affirmative profile<select id="agent-affirmative-profile"></select></label>
              <label>Affirmative profile ID<input id="agent-affirmative-profile-id" placeholder="Affirmative_default"></label>
              <label class="wide">Affirmative AGENT.md<textarea id="agent-affirmative-instructions"></textarea></label>
            </div>
            <div class="toolbar">
              <button id="save-affirmative-agent" type="button">Save Affirmative</button>
            </div>
          </div>
        </div>
        <div class="detail" id="agent-negative-profile-panel">
          <h3>Negative Profiles</h3>
          <div class="detail-body">
            <div class="profile-grid" id="agent-negative-profile-list"></div>
            <div class="form-grid">
              <label>Negative profile<select id="agent-negative-profile"></select></label>
              <label>Negative profile ID<input id="agent-negative-profile-id" placeholder="Negative_default"></label>
              <label class="wide">Negative AGENT.md<textarea id="agent-negative-instructions"></textarea></label>
            </div>
            <div class="toolbar">
              <button id="save-negative-agent" type="button">Save Negative</button>
            </div>
          </div>
        </div>
        <div class="detail" id="agent-profile-actions">
          <h3>Profile Actions</h3>
          <div class="detail-body">
            <div class="toolbar">
              <button id="reset-agent-prompts" type="button">Ensure Defaults</button>
            </div>
            <pre id="agent-prompts-result">No Agent prompt changes yet.</pre>
          </div>
        </div>
      </div>
    </section>
  </div>
  <div class="modal-backdrop" id="run-config-modal" role="dialog" aria-modal="true" aria-labelledby="run-config-title">
    <section class="settings-panel" aria-label="Run configuration">
      <div class="settings-head">
        <div>
          <h2 id="run-config-title">Start Run</h2>
          <div class="muted">Create a static report judgement task from local paths.</div>
        </div>
        <button id="close-run-config" type="button" title="Close run configuration">Close</button>
      </div>
      <div class="settings-body">
        <div class="detail" id="run-config-panel">
          <h3>Task Configuration</h3>
          <div class="detail-body">
            <div class="form-grid">
              <label class="wide">Report path<input id="run-sarif" placeholder="fixtures/demo_sarif/report.sarif or report.md"></label>
              <label class="wide">Source path<input id="run-source" placeholder="fixtures/demo_sarif/source"></label>
              <label class="wide">Skills path<input id="run-skills" placeholder="fixtures/demo_sarif/skills"></label>
              <label>Languages<input id="run-languages" value="java,cpp,python"></label>
              <label>Max rounds<input id="run-max-rounds" type="number" min="1" value="4"></label>
              <label>Affirmative provider<select id="run-affirmative-provider"></select></label>
              <label>Negative provider<select id="run-negative-provider"></select></label>
              <label>Affirmative agent profile<select id="run-affirmative-agent-profile"></select></label>
              <label>Negative agent profile<select id="run-negative-agent-profile"></select></label>
            </div>
            <div class="chips">
              <label><input id="run-external-tools" type="checkbox" checked> External tools</label>
              <label><input id="run-auto-index" type="checkbox"> Auto-index tools</label>
              <label><input id="run-llm" type="checkbox"> Use LLM debate</label>
            </div>
            <div class="toolbar">
              <button id="start-run" type="button">Start Run</button>
              <button id="fill-demo-run" type="button">Use Demo Fixture</button>
              <button id="fill-markdown-demo-run" type="button">Use Markdown Demo</button>
            </div>
            <pre id="run-result">No run started yet.</pre>
          </div>
        </div>
      </div>
    </section>
  </div>
  <script>
    const state = {{ runs: [], selectedRun: null, selectedFinding: null, providers: [], defaults: {{}}, agentPrompts: {{}} }};
    const el = {{
      list: document.getElementById('run-list'),
      count: document.getElementById('run-count'),
      detail: document.getElementById('detail'),
      title: document.getElementById('detail-title'),
      status: document.getElementById('detail-status'),
      subtitle: document.getElementById('subtitle'),
      providerList: document.getElementById('provider-list'),
      providersModal: document.getElementById('providers-modal'),
      agentPromptsModal: document.getElementById('agent-prompts-modal'),
      runConfigModal: document.getElementById('run-config-modal'),
      providerResult: document.getElementById('provider-result'),
      agentPromptsResult: document.getElementById('agent-prompts-result'),
      providerId: document.getElementById('provider-id'),
      providerName: document.getElementById('provider-name'),
      providerEndpoint: document.getElementById('provider-endpoint'),
      providerModel: document.getElementById('provider-model'),
      providerKeyEnv: document.getElementById('provider-key-env'),
      providerKey: document.getElementById('provider-key'),
      providerExtra: document.getElementById('provider-extra'),
      defaultAffirmative: document.getElementById('default-affirmative'),
      defaultNegative: document.getElementById('default-negative'),
      agentAffirmativeProfileList: document.getElementById('agent-affirmative-profile-list'),
      agentNegativeProfileList: document.getElementById('agent-negative-profile-list'),
      agentAffirmativeProfile: document.getElementById('agent-affirmative-profile'),
      agentNegativeProfile: document.getElementById('agent-negative-profile'),
      agentAffirmativeProfileId: document.getElementById('agent-affirmative-profile-id'),
      agentNegativeProfileId: document.getElementById('agent-negative-profile-id'),
      agentAffirmativeInstructions: document.getElementById('agent-affirmative-instructions'),
      agentNegativeInstructions: document.getElementById('agent-negative-instructions'),
      runSarif: document.getElementById('run-sarif'),
      runSource: document.getElementById('run-source'),
      runSkills: document.getElementById('run-skills'),
      runLanguages: document.getElementById('run-languages'),
      runMaxRounds: document.getElementById('run-max-rounds'),
      runAffirmativeProvider: document.getElementById('run-affirmative-provider'),
      runNegativeProvider: document.getElementById('run-negative-provider'),
      runAffirmativeAgentProfile: document.getElementById('run-affirmative-agent-profile'),
      runNegativeAgentProfile: document.getElementById('run-negative-agent-profile'),
      runExternalTools: document.getElementById('run-external-tools'),
      runAutoIndex: document.getElementById('run-auto-index'),
      runLlm: document.getElementById('run-llm'),
      runResult: document.getElementById('run-result'),
    }};

    document.getElementById('open-run-config').addEventListener('click', async () => {{
      el.runConfigModal.classList.add('open');
      await Promise.all([loadProviders(), loadAgentPrompts()]);
    }});
    document.getElementById('close-run-config').addEventListener('click', () => {{
      el.runConfigModal.classList.remove('open');
    }});
    el.runConfigModal.addEventListener('click', (event) => {{
      if (event.target === el.runConfigModal) el.runConfigModal.classList.remove('open');
    }});
    document.getElementById('open-providers').addEventListener('click', async () => {{
      el.providersModal.classList.add('open');
      await loadProviders();
    }});
    document.getElementById('close-providers').addEventListener('click', () => {{
      el.providersModal.classList.remove('open');
    }});
    el.providersModal.addEventListener('click', (event) => {{
      if (event.target === el.providersModal) el.providersModal.classList.remove('open');
    }});
    document.getElementById('open-agent-prompts').addEventListener('click', async () => {{
      el.agentPromptsModal.classList.add('open');
      await loadAgentPrompts();
    }});
    document.getElementById('close-agent-prompts').addEventListener('click', () => {{
      el.agentPromptsModal.classList.remove('open');
    }});
    el.agentPromptsModal.addEventListener('click', (event) => {{
      if (event.target === el.agentPromptsModal) el.agentPromptsModal.classList.remove('open');
    }});
    document.getElementById('refresh').addEventListener('click', refreshAll);
    document.getElementById('clear-selection').addEventListener('click', () => {{
      state.selectedRun = null;
      state.selectedFinding = null;
      renderRuns();
      renderEmpty('Select a run to inspect findings, evidence, and debate turns.');
    }});
    document.getElementById('save-provider').addEventListener('click', saveProvider);
    document.getElementById('test-provider').addEventListener('click', testProvider);
    document.getElementById('delete-provider').addEventListener('click', deleteProvider);
    document.getElementById('save-defaults').addEventListener('click', saveDefaults);
    document.getElementById('save-affirmative-agent').addEventListener('click', () => saveAgentProfile('affirmative'));
    document.getElementById('save-negative-agent').addEventListener('click', () => saveAgentProfile('negative'));
    document.getElementById('reset-agent-prompts').addEventListener('click', resetAgentPrompts);
    document.getElementById('start-run').addEventListener('click', startRun);
    document.getElementById('fill-demo-run').addEventListener('click', fillDemoRun);
    document.getElementById('fill-markdown-demo-run').addEventListener('click', fillMarkdownDemoRun);
    el.runAffirmativeProvider.addEventListener('change', enableRunLlmForSelectedProviders);
    el.runNegativeProvider.addEventListener('change', enableRunLlmForSelectedProviders);
    el.agentAffirmativeProfile.addEventListener('change', () => fillAgentProfileEditor('affirmative'));
    el.agentNegativeProfile.addEventListener('change', () => fillAgentProfileEditor('negative'));

    function esc(value) {{
      return String(value ?? '').replace(/[&<>"']/g, ch => ({{
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
      }}[ch]));
    }}
    function fmtDate(value) {{
      if (!value) return 'unknown time';
      const date = new Date(value);
      return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
    }}
    function verdictClass(verdict) {{
      if (verdict === 'TRUE_POSITIVE') return 'tp';
      if (verdict === 'FALSE_POSITIVE') return 'fp';
      if (verdict === 'INCONCLUSIVE') return 'inc';
      return '';
    }}
    async function fetchJson(url, options) {{
      const response = await fetch(url, options);
      if (!response.ok) {{
        const body = await response.text();
        throw new Error(`${{response.status}} ${{response.statusText}}: ${{body}}`);
      }}
      return response.json();
    }}
    function jsonPost(body) {{
      return {{ method: 'POST', headers: {{ 'content-type': 'application/json' }}, body: JSON.stringify(body || {{}}) }};
    }}

    async function refreshAll() {{
      await Promise.all([loadProviders(), loadAgentPrompts(), loadRuns()]);
    }}

    async function loadProviders() {{
      try {{
        const [providers, defaults] = await Promise.all([fetchJson('/providers'), fetchJson('/providers/defaults')]);
        state.providers = providers;
        state.defaults = defaults;
        renderProviders();
      }} catch (error) {{
        el.providerResult.textContent = error.message;
      }}
    }}

    async function loadAgentPrompts() {{
      try {{
        state.agentPrompts = await fetchJson('/agent-prompts');
        renderAgentPrompts();
      }} catch (error) {{
        el.agentPromptsResult.textContent = error.message;
      }}
    }}

    function renderAgentPrompts() {{
      const currentAffirmative = el.agentAffirmativeProfile.value;
      const currentNegative = el.agentNegativeProfile.value;
      const currentRunAffirmative = el.runAffirmativeAgentProfile.value;
      const currentRunNegative = el.runNegativeAgentProfile.value;
      const affirmativeOptions = profileOptions('affirmative');
      const negativeOptions = profileOptions('negative');
      el.agentAffirmativeProfile.innerHTML = affirmativeOptions;
      el.agentNegativeProfile.innerHTML = negativeOptions;
      el.runAffirmativeAgentProfile.innerHTML = affirmativeOptions;
      el.runNegativeAgentProfile.innerHTML = negativeOptions;
      el.agentAffirmativeProfile.value = profileExists('affirmative', currentAffirmative) ? currentAffirmative : defaultProfileId('affirmative');
      el.agentNegativeProfile.value = profileExists('negative', currentNegative) ? currentNegative : defaultProfileId('negative');
      el.runAffirmativeAgentProfile.value = profileExists('affirmative', currentRunAffirmative) ? currentRunAffirmative : defaultProfileId('affirmative');
      el.runNegativeAgentProfile.value = profileExists('negative', currentRunNegative) ? currentRunNegative : defaultProfileId('negative');
      renderAgentProfileCards('affirmative');
      renderAgentProfileCards('negative');
      fillAgentProfileEditor('affirmative');
      fillAgentProfileEditor('negative');
    }}

    function profileOptions(role) {{
      return profilesFor(role).map(profile => (
        `<option value="${{esc(profile.profile_id)}}">${{esc(profile.profile_id)}} / ${{esc(profile.path || 'AGENT.md')}}</option>`
      )).join('');
    }}

    function profilesFor(role) {{
      return ((state.agentPrompts.roles || {{}})[role] || []);
    }}

    function profileExists(role, profileId) {{
      return Boolean(profileId && profilesFor(role).some(profile => profile.profile_id === profileId));
    }}

    function defaultProfileId(role) {{
      const defaults = state.agentPrompts.defaults || {{}};
      const profiles = profilesFor(role);
      return defaults[role] || (profiles[0] && profiles[0].profile_id) || '';
    }}

    function findAgentProfile(role, profileId) {{
      return profilesFor(role).find(profile => profile.profile_id === profileId) || profilesFor(role)[0] || null;
    }}

    function renderAgentProfileCards(role) {{
      const container = role === 'affirmative' ? el.agentAffirmativeProfileList : el.agentNegativeProfileList;
      const profiles = profilesFor(role);
      container.innerHTML = profiles.map(profile => profileCard(role, profile)).join('') || '<div class="muted">No profiles found.</div>';
      for (const button of container.querySelectorAll('button[data-agent-edit]')) {{
        button.addEventListener('click', () => {{
          const select = role === 'affirmative' ? el.agentAffirmativeProfile : el.agentNegativeProfile;
          select.value = button.dataset.profileId;
          fillAgentProfileEditor(role);
        }});
      }}
      for (const button of container.querySelectorAll('button[data-agent-star]')) {{
        button.addEventListener('click', () => toggleAgentStar(role, button.dataset.profileId, button.dataset.starred !== 'true'));
      }}
      for (const button of container.querySelectorAll('button[data-agent-delete]')) {{
        button.addEventListener('click', () => deleteAgentProfile(role, button.dataset.profileId));
      }}
    }}

    function profileCard(role, profile) {{
      const classes = ['profile-card'];
      if (profile.starred) classes.push('starred');
      if (profile.is_default) classes.push('default');
      const deleteDisabled = profile.deletable ? '' : 'disabled';
      const deleteTitle = profile.deletable ? 'Delete Agent profile' : 'Default Agent cannot be deleted';
      return `<div class="${{classes.join(' ')}}">
        <div class="profile-head">
          <div>
            <div class="profile-title">${{profile.starred ? '*' : ''}} ${{esc(profile.profile_id || profile.name || 'Agent')}}</div>
            <div class="profile-path">${{esc(profile.path || 'AGENT.md')}}</div>
          </div>
          <span class="chip">${{profile.is_default ? 'default' : esc(profile.role || role)}}</span>
        </div>
        <div class="profile-preview">${{esc(profile.instructions || '')}}</div>
        <div class="profile-actions">
          <button type="button" data-agent-edit="true" data-profile-id="${{esc(profile.profile_id)}}">Edit</button>
          <button type="button" data-agent-star="true" data-profile-id="${{esc(profile.profile_id)}}" data-starred="${{profile.starred ? 'true' : 'false'}}">${{profile.starred ? 'Unstar' : 'Star'}}</button>
          <button type="button" data-agent-delete="true" data-profile-id="${{esc(profile.profile_id)}}" title="${{esc(deleteTitle)}}" ${{deleteDisabled}}>Delete</button>
        </div>
      </div>`;
    }}

    function fillAgentProfileEditor(role) {{
      const select = role === 'affirmative' ? el.agentAffirmativeProfile : el.agentNegativeProfile;
      const idInput = role === 'affirmative' ? el.agentAffirmativeProfileId : el.agentNegativeProfileId;
      const promptInput = role === 'affirmative' ? el.agentAffirmativeInstructions : el.agentNegativeInstructions;
      const profile = findAgentProfile(role, select.value);
      idInput.value = profile ? profile.profile_id : '';
      promptInput.value = profile ? profile.instructions : '';
    }}

    async function saveAgentProfile(role) {{
      try {{
        const profileId = role === 'affirmative' ? el.agentAffirmativeProfileId.value.trim() : el.agentNegativeProfileId.value.trim();
        const instructions = role === 'affirmative' ? el.agentAffirmativeInstructions.value.trim() : el.agentNegativeInstructions.value.trim();
        const saved = await fetchJson('/agent-prompts', jsonPost({{ role, profile_id: profileId, instructions }}));
        await loadAgentPrompts();
        const select = role === 'affirmative' ? el.agentAffirmativeProfile : el.agentNegativeProfile;
        const runSelect = role === 'affirmative' ? el.runAffirmativeAgentProfile : el.runNegativeAgentProfile;
        select.value = saved.profile_id;
        runSelect.value = saved.profile_id;
        fillAgentProfileEditor(role);
        el.agentPromptsResult.textContent = JSON.stringify(saved, null, 2);
      }} catch (error) {{
        el.agentPromptsResult.textContent = error.message;
      }}
    }}

    async function toggleAgentStar(role, profileId, starred) {{
      try {{
        const profile = await fetchJson('/agent-prompts', jsonPost({{ action: 'star', role, profile_id: profileId, starred }}));
        await loadAgentPrompts();
        el.agentPromptsResult.textContent = JSON.stringify(profile, null, 2);
      }} catch (error) {{
        el.agentPromptsResult.textContent = error.message;
      }}
    }}

    async function deleteAgentProfile(role, profileId) {{
      try {{
        const result = await fetchJson(`/agent-prompts/${{encodeURIComponent(role)}}/${{encodeURIComponent(profileId)}}`, {{ method: 'DELETE' }});
        state.agentPrompts = result;
        renderAgentPrompts();
        el.agentPromptsResult.textContent = `Deleted ${{profileId}}`;
      }} catch (error) {{
        el.agentPromptsResult.textContent = error.message;
      }}
    }}

    async function resetAgentPrompts() {{
      try {{
        state.agentPrompts = await fetchJson('/agent-prompts', jsonPost({{ reset: true }}));
        renderAgentPrompts();
        el.agentPromptsResult.textContent = JSON.stringify(state.agentPrompts, null, 2);
      }} catch (error) {{
        el.agentPromptsResult.textContent = error.message;
      }}
    }}

    function renderProviders() {{
      el.providerList.innerHTML = state.providers.map(provider => `
        <button type="button" class="chip" data-provider-id="${{esc(provider.id)}}">${{esc(provider.name)}} / ${{esc(provider.model)}}</button>
      `).join('') || '<span class="muted">No providers configured.</span>';
      for (const button of el.providerList.querySelectorAll('button[data-provider-id]')) {{
        button.addEventListener('click', () => fillProvider(button.dataset.providerId));
      }}
      const options = '<option value="">None</option>' + state.providers.map(provider => (
        `<option value="${{esc(provider.id)}}">${{esc(provider.name)}} / ${{esc(provider.model)}}</option>`
      )).join('');
      el.defaultAffirmative.innerHTML = options;
      el.defaultNegative.innerHTML = options;
      el.runAffirmativeProvider.innerHTML = options;
      el.runNegativeProvider.innerHTML = options;
      el.defaultAffirmative.value = state.defaults.affirmative || '';
      el.defaultNegative.value = state.defaults.negative || '';
      el.runAffirmativeProvider.value = state.defaults.affirmative || '';
      el.runNegativeProvider.value = state.defaults.negative || '';
      enableRunLlmForSelectedProviders();
    }}

    function enableRunLlmForSelectedProviders() {{
      if (el.runAffirmativeProvider.value || el.runNegativeProvider.value) {{
        el.runLlm.checked = true;
      }}
    }}

    function fillProvider(providerId) {{
      const provider = state.providers.find(item => item.id === providerId);
      if (!provider) return;
      el.providerId.value = provider.id;
      el.providerName.value = provider.name;
      el.providerEndpoint.value = provider.endpoint;
      el.providerModel.value = provider.model;
      el.providerKeyEnv.value = provider.api_key_env || '';
      el.providerKey.value = '';
      el.providerExtra.value = JSON.stringify(provider.extra_json || {{}}, null, 2);
    }}

    async function saveProvider() {{
      try {{
        const payload = {{
          id: el.providerId.value.trim(),
          name: el.providerName.value.trim(),
          type: 'openai-compatible',
          endpoint: el.providerEndpoint.value.trim(),
          model: el.providerModel.value.trim(),
          api_key_env: el.providerKeyEnv.value.trim(),
          extra_json: el.providerExtra.value.trim() || {{}}
        }};
        if (el.providerKey.value.trim()) payload.api_key = el.providerKey.value.trim();
        const provider = await fetchJson('/providers', jsonPost(payload));
        el.providerResult.textContent = JSON.stringify(provider, null, 2);
        await loadProviders();
      }} catch (error) {{
        el.providerResult.textContent = error.message;
      }}
    }}

    async function testProvider() {{
      try {{
        const id = el.providerId.value.trim();
        if (!id) throw new Error('Select or enter a provider ID first.');
        const payload = el.providerKey.value.trim() ? {{ api_key: el.providerKey.value.trim() }} : {{}};
        const result = await fetchJson(`/providers/${{encodeURIComponent(id)}}/test`, jsonPost(payload));
        el.providerResult.textContent = JSON.stringify(result, null, 2);
      }} catch (error) {{
        el.providerResult.textContent = error.message;
      }}
    }}

    async function deleteProvider() {{
      try {{
        const id = el.providerId.value.trim();
        if (!id) throw new Error('Select or enter a provider ID first.');
        await fetchJson(`/providers/${{encodeURIComponent(id)}}`, {{ method: 'DELETE' }});
        el.providerResult.textContent = `Deleted ${{id}}`;
        await loadProviders();
      }} catch (error) {{
        el.providerResult.textContent = error.message;
      }}
    }}

    async function saveDefaults() {{
      try {{
        const defaults = await fetchJson('/providers/defaults', jsonPost({{
          affirmative: el.defaultAffirmative.value || null,
          negative: el.defaultNegative.value || null
        }}));
        state.defaults = defaults;
        el.providerResult.textContent = JSON.stringify(defaults, null, 2);
      }} catch (error) {{
        el.providerResult.textContent = error.message;
      }}
    }}

    function fillDemoRun() {{
      el.runSarif.value = 'fixtures/demo_sarif/report.sarif';
      el.runSource.value = 'fixtures/demo_sarif/source';
      el.runSkills.value = 'fixtures/demo_sarif/skills';
      el.runLanguages.value = 'java,cpp,python';
      el.runMaxRounds.value = '4';
      el.runExternalTools.checked = false;
      el.runAutoIndex.checked = false;
      enableRunLlmForSelectedProviders();
      el.runResult.textContent = 'Demo fixture paths filled.';
    }}

    function fillMarkdownDemoRun() {{
      el.runSarif.value = 'fixtures/demo_markdown/report.md';
      el.runSource.value = 'fixtures/demo_sarif/source';
      el.runSkills.value = 'fixtures/demo_sarif/skills';
      el.runLanguages.value = 'java,cpp,python';
      el.runMaxRounds.value = '4';
      el.runExternalTools.checked = false;
      el.runAutoIndex.checked = false;
      enableRunLlmForSelectedProviders();
      el.runResult.textContent = 'Markdown demo fixture paths filled.';
    }}

    async function startRun() {{
      try {{
        const payload = {{
          report_path: el.runSarif.value.trim(),
          source_path: el.runSource.value.trim(),
          skills_path: el.runSkills.value.trim() || null,
          languages: el.runLanguages.value.trim(),
          max_rounds: Number(el.runMaxRounds.value || 4),
          enable_external_tools: el.runExternalTools.checked,
          auto_index_tools: el.runAutoIndex.checked,
          enable_llm: el.runLlm.checked,
          affirmative_provider_id: el.runAffirmativeProvider.value || null,
          negative_provider_id: el.runNegativeProvider.value || null,
          affirmative_agent_profile: el.runAffirmativeAgentProfile.value || null,
          negative_agent_profile: el.runNegativeAgentProfile.value || null
        }};
        if (!payload.report_path || !payload.source_path) {{
          throw new Error('Report path and source path are required.');
        }}
        el.runResult.textContent = 'Starting run...';
        const created = await fetchJson('/runs', jsonPost(payload));
        el.runResult.textContent = JSON.stringify(created, null, 2);
        el.runConfigModal.classList.remove('open');
        await loadRuns();
        if (created.run_id) {{
          await selectRun(created.run_id);
          pollRun(created.run_id);
        }}
      }} catch (error) {{
        el.runResult.textContent = error.message;
      }}
    }}

    async function pollRun(runId) {{
      for (let attempt = 0; attempt < 60; attempt += 1) {{
        await new Promise(resolve => setTimeout(resolve, 1000));
        try {{
          const run = await fetchJson(`/runs/${{encodeURIComponent(runId)}}`);
          await loadRuns();
          await selectRun(runId);
          if (run.status === 'completed' || run.status === 'failed') return;
        }} catch (_error) {{
          return;
        }}
      }}
    }}

    async function loadRuns() {{
      el.subtitle.textContent = 'Loading records...';
      try {{
        state.runs = await fetchJson('/runs');
        renderRuns();
        el.subtitle.textContent = 'Static report adjudication run history';
        if (!state.selectedRun && state.runs.length > 0) {{
          await selectRun(state.runs[0].run_id);
        }} else if (!state.runs.length) {{
          renderEmpty('No records yet. Create a run with POST /runs or the CLI/API workflow.');
        }}
      }} catch (error) {{
        renderError(error);
      }}
    }}

    function renderRuns() {{
      el.count.textContent = `${{state.runs.length}} record${{state.runs.length === 1 ? '' : 's'}}`;
      el.list.innerHTML = state.runs.map(run => {{
        const counts = run.verdict_counts || {{}};
        return `<button class="run-item ${{state.selectedRun === run.run_id ? 'active' : ''}}" type="button" data-run-id="${{esc(run.run_id)}}">
          <div class="run-id">${{esc(run.run_id)}}</div>
          <div class="muted">${{esc(fmtDate(run.created_at))}}</div>
          <div class="path">${{esc(run.source_path || '')}}</div>
          <div class="chips">
            <span class="chip">${{esc(run.status || 'completed')}}</span>
            <span class="chip">${{esc(run.finding_count)}} findings</span>
            <span class="chip tp">TP ${{counts.TRUE_POSITIVE || 0}}</span>
            <span class="chip fp">FP ${{counts.FALSE_POSITIVE || 0}}</span>
            <span class="chip inc">INC ${{counts.INCONCLUSIVE || 0}}</span>
          </div>
        </button>`;
      }}).join('');
      for (const button of el.list.querySelectorAll('button[data-run-id]')) {{
        button.addEventListener('click', () => selectRun(button.dataset.runId));
      }}
    }}

    async function selectRun(runId) {{
      state.selectedRun = runId;
      state.selectedFinding = null;
      renderRuns();
      el.title.textContent = runId;
      el.status.textContent = 'Loading detail...';
      try {{
        const [run, findings] = await Promise.all([
          fetchJson(`/runs/${{encodeURIComponent(runId)}}`),
          fetchJson(`/runs/${{encodeURIComponent(runId)}}/findings`)
        ]);
        renderRunDetail(run, findings);
      }} catch (error) {{
        renderError(error);
      }}
    }}

    function renderRunDetail(run, findings) {{
      const counts = run.verdict_counts || {{}};
      const providers = run.llm_providers || {{}};
      const agents = run.agent_configs || {{}};
      const status = run.status || 'completed';
      el.status.textContent = `${{status}} / ${{findings.length}} findings`;
      if (status !== 'completed') {{
        el.detail.innerHTML = `
          <div class="detail">
            <h3>Run Status</h3>
            <div class="detail-body">
              <div class="chips"><span class="chip">${{esc(status)}}</span></div>
              <div><strong>Report:</strong> <span class="path">${{esc(run.sarif_path)}}</span></div>
              <div><strong>Source:</strong> <span class="path">${{esc(run.source_path)}}</span></div>
              <div><strong>Languages:</strong> ${{esc((run.languages || []).join(', '))}}</div>
              ${{run.error ? `<div class="error">${{esc(run.error)}}</div>` : '<div class="muted">The task is running in the background. This view refreshes automatically for newly started runs.</div>'}}
              ${{run.diagnostics && run.diagnostics.length ? `<pre>${{esc(run.diagnostics.join('\\n'))}}</pre>` : ''}}
            </div>
          </div>`;
        return;
      }}
      el.detail.innerHTML = `
        <div class="summary-grid">
          <div class="metric"><div class="label">Findings</div><div class="value">${{esc(run.finding_count)}}</div></div>
          <div class="metric"><div class="label">True Positive</div><div class="value">${{counts.TRUE_POSITIVE || 0}}</div></div>
          <div class="metric"><div class="label">False Positive</div><div class="value">${{counts.FALSE_POSITIVE || 0}}</div></div>
          <div class="metric"><div class="label">Inconclusive</div><div class="value">${{counts.INCONCLUSIVE || 0}}</div></div>
        </div>
        <div class="detail">
          <h3>Run Metadata</h3>
          <div class="detail-body">
            <div><strong>Created:</strong> ${{esc(fmtDate(run.created_at))}}</div>
            <div><strong>Report:</strong> <span class="path">${{esc(run.sarif_path)}}</span></div>
            <div><strong>Source:</strong> <span class="path">${{esc(run.source_path)}}</span></div>
            <div><strong>Languages:</strong> ${{esc((run.languages || []).join(', '))}}</div>
            <div><strong>Affirmative LLM:</strong> ${{esc(providerLabel(providers.affirmative, providers.enabled))}}</div>
            <div><strong>Negative LLM:</strong> ${{esc(providerLabel(providers.negative, providers.enabled))}}</div>
            <div><strong>Affirmative Agent:</strong> ${{esc(agentLabel(agents.affirmative))}}</div>
            <div><strong>Negative Agent:</strong> ${{esc(agentLabel(agents.negative))}}</div>
            ${{agentInstructions(agents) ? `<pre>${{esc(agentInstructions(agents))}}</pre>` : ''}}
            ${{run.diagnostics && run.diagnostics.length ? `<pre>${{esc(run.diagnostics.join('\\n'))}}</pre>` : ''}}
          </div>
        </div>
        <div class="detail">
          <h3>Findings</h3>
          <div class="scroll">
            <table>
              <thead><tr><th>Verdict</th><th>Rule</th><th>Confidence</th><th>Summary</th></tr></thead>
              <tbody>
                ${{findings.map(item => `<tr class="clickable" data-finding-id="${{esc(item.finding_id)}}">
                  <td><span class="chip ${{verdictClass(item.verdict)}}">${{esc(item.verdict)}}</span></td>
                  <td>${{esc(item.rule_id)}}<div class="path">${{esc(item.finding_id)}}</div></td>
                  <td>${{esc(item.confidence)}}</td>
                  <td>${{esc(item.summary)}}<div class="path">${{esc((item.source_locations || []).map(loc => loc.file + (loc.line ? ':' + loc.line : '')).join(', '))}}</div></td>
                </tr>`).join('')}}
              </tbody>
            </table>
          </div>
        </div>
        <div id="finding-detail"></div>
      `;
      for (const row of el.detail.querySelectorAll('tr[data-finding-id]')) {{
        row.addEventListener('click', () => selectFinding(row.dataset.findingId));
      }}
      if (findings.length) selectFinding(findings[0].finding_id);
    }}

    function providerLabel(value, llmEnabled) {{
      if (!value || (!value.provider_id && !value.provider_name && !value.model && !value.client_available)) {{
        return 'not configured';
      }}
      const label = `${{value.provider_name || value.provider_id || 'provider'}} / ${{value.model || 'model unknown'}}`;
      let status = value.status;
      if (!status) {{
        if (value.client_available) status = 'ready';
        else if (llmEnabled === false) status = 'llm_disabled';
        else status = 'client_unavailable';
      }}
      if (status === 'ready') return label;
      const statusText = {{
        llm_disabled: 'LLM disabled',
        missing_api_key: 'missing API key',
        client_unavailable: 'client unavailable',
        not_configured: 'not configured',
      }}[status] || status.replace(/_/g, ' ');
      if (status === 'not_configured') return statusText;
      return `${{label}} (${{statusText}})`;
    }}

    function agentLabel(value) {{
      if (!value) return 'default';
      if (value.profile_id && value.path) return `${{value.profile_id}} (${{value.path}})`;
      return value.name || value.profile_id || 'Agent';
    }}

    function agentInstructions(agents) {{
      const lines = [];
      if (agents.affirmative && agents.affirmative.instructions) {{
        lines.push(`Affirmative / ${{agentLabel(agents.affirmative)}}:\\n${{agents.affirmative.instructions}}`);
      }}
      if (agents.negative && agents.negative.instructions) {{
        lines.push(`Negative / ${{agentLabel(agents.negative)}}:\\n${{agents.negative.instructions}}`);
      }}
      return lines.join('\\n\\n');
    }}

    async function selectFinding(findingId) {{
      state.selectedFinding = findingId;
      const container = document.getElementById('finding-detail');
      if (!container) return;
      container.innerHTML = '<div class="empty">Loading finding detail...</div>';
      try {{
        const detail = await fetchJson(`/runs/${{encodeURIComponent(state.selectedRun)}}/findings/${{encodeURIComponent(findingId)}}`);
        container.innerHTML = renderFindingDetail(detail);
        container.scrollIntoView({{ block: 'nearest' }});
      }} catch (error) {{
        container.innerHTML = `<div class="empty error">${{esc(error.message)}}</div>`;
      }}
    }}

    function renderFindingDetail(detail) {{
      const evidence = detail.evidence_chain || [];
      const debate = detail.debate || [];
      return `
        <div class="detail">
          <h3>Finding Detail</h3>
          <div class="detail-body">
            <div class="chips">
              <span class="chip ${{verdictClass(detail.verdict)}}">${{esc(detail.verdict)}}</span>
              <span class="chip">confidence ${{esc(detail.confidence)}}</span>
              <span class="chip">${{esc(detail.rule_id)}}</span>
            </div>
            <div>${{esc(detail.reasoning_summary)}}</div>
            <div><strong>Protection:</strong> ${{esc(detail.protection_assessment)}}</div>
            <div><strong>Impact:</strong> ${{esc(detail.impact_assessment)}}</div>
            ${{(detail.disputed_points || []).length ? `<div><strong>Disputed points:</strong><ul>${{detail.disputed_points.map(point => `<li>${{esc(point)}}</li>`).join('')}}</ul></div>` : ''}}
          </div>
        </div>
        <div class="detail">
          <h3>Debate</h3>
          <div class="detail-body">
            ${{debate.map(turn => `<div>
              <strong>${{esc(turn.role)}} round ${{esc(turn.round_index)}}</strong>
              <div>${{esc(turn.claim)}}</div>
              <div class="path">evidence: ${{esc((turn.evidence_ids || []).join(', '))}}</div>
            </div>`).join('') || '<div class="muted">No debate turns recorded.</div>'}}
          </div>
        </div>
        <div class="detail">
          <h3>Evidence</h3>
          <div class="detail-body">
            ${{evidence.map(item => `<div>
              <div class="chips">
                <span class="chip">${{esc(item.evidence_id)}}</span>
                <span class="chip">${{esc(item.kind)}}</span>
                <span class="chip">${{esc(item.strength)}}</span>
                <span class="chip">${{esc(item.source)}}</span>
              </div>
              <div>${{esc(item.summary)}}</div>
              ${{item.snippet ? `<pre>${{esc(item.snippet)}}</pre>` : ''}}
            </div>`).join('') || '<div class="muted">No evidence recorded.</div>'}}
          </div>
        </div>`;
    }}

    function renderEmpty(message) {{
      el.title.textContent = 'Run Detail';
      el.status.textContent = 'No run selected';
      el.detail.innerHTML = `<div class="empty">${{esc(message)}}</div>`;
    }}
    function renderError(error) {{
      el.subtitle.textContent = 'Failed to load records';
      el.detail.innerHTML = `<div class="empty error">${{esc(error.message)}}</div>`;
    }}

    refreshAll();
  </script>
</body>
</html>"""
