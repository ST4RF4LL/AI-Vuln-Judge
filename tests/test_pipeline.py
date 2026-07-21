import http.client
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import date, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Event, Lock, Thread
from unittest.mock import patch

from vuln_judger.analyzers import AnalyzerSettings, AtlasAnalyzer
from vuln_judger.api import (
    _apply_reused_findings,
    _cli_session_accepts_input,
    _cli_sessions,
    _codex_event_log,
    _codex_terminal_page,
    _config_from_paused_payload,
    _config_from_payload,
    _finding_summary,
    _pause_payload,
    _request_pause,
    _request_resume,
    _resume_checkpoint_payload,
    _send_codex_session_input,
    _stop_codex_sessions,
    app_html,
    make_handler,
)
from vuln_judger.codex_runner import (
    OPENCODE_ENGINE,
    DEFAULT_CODEX_WORKSPACES_DIR,
    SILENCE_REMINDER_PROMPT,
    CodexDrivenRunner,
    CodexRunnerError,
    CodexRunnerStopped,
    CodexTmuxSession,
    _base_payload,
    _ensure_codex_project_trust,
    _finalize_markdown_findings,
    _moderator_report_prompt,
    _prepare_codex_agent_dirs,
    _safe_tmux_name,
    session_live,
    _validate_and_stamp_pipeline_output,
    _validate_report_findings_output,
    _validate_pipeline_output,
    _wait_for_cli_task_start,
    _wait_json,
)
from vuln_judger.codex_event_log import format_codex_ndjson
from vuln_judger.agents import AgentDirectoryStore
from vuln_judger.debate import DebateOrchestrator
from vuln_judger.evidence import EvidenceBundle
from vuln_judger.llm import LLMClient
from vuln_judger.logging_config import DEFAULT_LOG_RETENTION_DAYS, configure_logging, daily_log_path, logger
from vuln_judger.mcp import MCPStdioClient
from vuln_judger.mcp_config import MCPServerStore
from vuln_judger.mcp_server import JudgerMCPServer, JudgerMCPSettings, _tool_specs
from vuln_judger.models import (
    DEFAULT_SILENCE_REMINDER_MINUTES,
    REPORT_FINDINGS_SCHEMA,
    AgentConfig,
    CodeEvidence,
    EvidenceKind,
    EvidenceStrength,
    Finding,
    RunConfig,
    SourceLocation,
    Verdict,
    run_config_snapshot,
    to_jsonable,
)
from vuln_judger.opencode_runner import (
    OPENCODE_PERMISSION_CONFIG,
    OpenCodeCapabilities,
    OpenCodeDrivenRunner,
    OpenCodeTmuxSession,
    ensure_opencode_tui,
    probe_opencode,
    send_opencode_session_message,
)
from vuln_judger.opencode_prompt_client import send_prompt
from vuln_judger.pipeline import run_judgement
from vuln_judger.providers import ProviderStore
from vuln_judger.records import RunControlStore, RunRecordStore
from vuln_judger.sarif import ReportPreparationError, load_sarif, prepare_report_for_processing
from vuln_judger.skills import SkillSourceStore
from vuln_judger.source import SourceIndexer, detect_project_languages


class PipelineTests(unittest.TestCase):
    def test_run_record_store_supports_concurrent_progress_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RunRecordStore(root)
            start = Event()
            errors = []
            errors_lock = Lock()

            def write_progress(worker: int) -> None:
                start.wait()
                try:
                    for sequence in range(30):
                        store.save_payload({"run_id": "run-concurrent", "worker": worker, "sequence": sequence})
                except Exception as exc:
                    with errors_lock:
                        errors.append(exc)

            threads = [Thread(target=write_progress, args=(worker,)) for worker in range(6)]
            for thread in threads:
                thread.start()
            start.set()
            for thread in threads:
                thread.join(timeout=5)

            self.assertEqual(errors, [])
            self.assertIsNotNone(store.get("run-concurrent"))
            self.assertEqual(list(root.glob("*.tmp")), [])

    def test_project_languages_are_detected_from_source_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text("print('x')\n", encoding="utf-8")
            (root / "src" / "lib.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
            (root / "build").mkdir()
            (root / "build" / "Generated.java").write_text("class Generated {}\n", encoding="utf-8")

            profile = detect_project_languages(root)

            self.assertEqual(profile.file_counts, {"python": 1, "cpp": 1})
            self.assertEqual(profile.total_supported_files, 2)
            self.assertFalse(profile.fallback_used)
            self.assertEqual(set(profile.languages), {"python", "cpp"})

    def test_daily_logging_uses_dated_key_value_files_and_retention(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_target = root / "logs" / "vuln-judger.log"
            today = date.today()
            old_log = root / "logs" / f"vuln-judger-{(today - timedelta(days=45)).isoformat()}.log"
            keep_log = root / "logs" / f"vuln-judger-{(today - timedelta(days=5)).isoformat()}.log"
            old_log.parent.mkdir(parents=True)
            old_log.write_text("old\n", encoding="utf-8")
            keep_log.write_text("keep\n", encoding="utf-8")

            log_path = configure_logging(log_target, retention_days=DEFAULT_LOG_RETENTION_DAYS)
            logger("test").info(
                "hello world",
                extra={"event": "unit.test", "run_id": "run-1", "payload": {"a": 1}},
            )
            for handler in logger("test").parent.handlers:
                handler.flush()

            self.assertEqual(log_path, daily_log_path(log_target, day=today).resolve())
            self.assertTrue(log_path.exists())
            self.assertFalse(old_log.exists())
            self.assertTrue(keep_log.exists())
            text = log_path.read_text(encoding="utf-8")
            self.assertIn("event=unit.test", text)
            self.assertIn("run_id=run-1", text)
            self.assertIn('msg="hello world"', text)
            self.assertIn('payload={"a":1}', text)

    def test_run_uses_detected_project_languages_not_payload_languages(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, skills = write_python_fixture(root)
            report = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    skills_path=skills,
                    languages=["java"],
                    enable_external_tools=False,
                )
            )
            self.assertEqual(report.languages, ["python"])
            source_root = next(item for item in report.reports[0].evidence_chain if item.kind == EvidenceKind.SOURCE_ROOT)
            self.assertEqual(source_root.data["languages"], ["python"])
            self.assertEqual(source_root.data["language_file_counts"], {"python": 1})

    def test_api_command_uses_default_quick_start_paths(self):
        import vuln_judger.cli as cli

        with patch("vuln_judger.cli.serve") as serve:
            exit_code = cli.main(["api"])

        self.assertEqual(exit_code, 0)
        serve.assert_called_once()
        self.assertEqual(
            serve.call_args.args,
            (
                "127.0.0.1",
                8765,
                Path(".vuln-judger") / "runs",
                Path(".vuln-judger") / "providers.json",
                Path("agents"),
                Path(".vuln-judger") / "logs" / "vuln-judger.log",
                Path(".vuln-judger") / "mcp.json",
                Path(".vuln-judger") / "skills.json",
                DEFAULT_LOG_RETENTION_DAYS,
            ),
        )

    def test_python_code_flow_becomes_true_positive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, skills = write_python_fixture(root)
            report = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    skills_path=skills,
                    enable_external_tools=False,
                )
            )
            self.assertEqual(report.finding_count, 1)
            self.assertEqual(report.reports[0].verdict, Verdict.TRUE_POSITIVE)
            self.assertGreaterEqual(report.reports[0].confidence, 0.75)
            self.assertTrue(report.reports[0].evidence_chain)

    def test_markdown_report_requires_moderator_llm(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _sarif, skills = write_python_fixture(root)
            markdown = root / "report.md"
            markdown.write_text(
                "\n".join(
                    [
                        "# 静态分析 Markdown 报告",
                        "",
                        "## 发现 1：python-command-injection",
                        "",
                        "- 规则：python-command-injection",
                        "- 严重性：error",
                        "- 消息：用户输入可到达命令执行点",
                        "- 位置：app.py:5:5",
                        "",
                        "### 代码流",
                        "",
                        "- app.py:4:11",
                        "- app.py:5:5",
                    ]
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ReportPreparationError):
                run_judgement(
                    RunConfig(
                        sarif_path=markdown,
                        source_path=root,
                        skills_path=skills,
                        enable_external_tools=False,
                    )
                )

    def test_markdown_table_report_is_moderated_into_persistent_markdown_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            markdown = root / "report.md"
            markdown.write_text(
                "\n".join(
                    [
                        "# Markdown 表格报告",
                        "",
                        "| 漏洞类型 | 危险函数 | 漏洞描述 | 文件 | 行号 | 严重性 |",
                        "|------|-----|-----|-----|-----|-----|",
                        "| python-command-injection | os.system | 用户输入可到达命令执行点 | app.py | 5 | error |",
                    ]
                ),
                encoding="utf-8",
            )
            generated_markdown = "\n".join(
                [
                    "# python-command-injection",
                    "",
                    "| 漏洞类型 | 危险函数 | 漏洞描述 | 文件 | 行号 | 严重性 |",
                    "|------|-----|-----|-----|-----|-----|",
                    "| python-command-injection | os.system | 用户输入可到达命令执行点 | app.py | 5 | error |",
                ]
            )
            response = {"reports": [{"title": "python-command-injection", "markdown": generated_markdown}]}
            moderator = FakeLLM(json.dumps(response, ensure_ascii=False))

            tmp_dir = root / ".vuln-judger" / "tmp"
            with patch.dict(os.environ, {"VULN_JUDGER_TMP_DIR": str(tmp_dir)}):
                prepared = prepare_report_for_processing(markdown, moderator_client=moderator)
            self.assertNotEqual(prepared.effective_path, markdown.resolve())
            self.assertTrue(prepared.temporary)
            self.assertTrue(moderator.calls)
            self.assertTrue(prepared.effective_path.name.endswith(".md"))
            self.assertEqual(prepared.effective_path.parent, tmp_dir.resolve())
            self.assertEqual(len(prepared.findings or []), 1)
            finding = prepared.findings[0]
            self.assertEqual(finding.rule_id, "markdown-finding-1")
            self.assertEqual(finding.message, "python-command-injection")
            self.assertEqual(finding.locations, [])
            self.assertIn("| python-command-injection | os.system |", finding.raw["markdown"])
            self.assertEqual(prepared.effective_path.read_text(encoding="utf-8"), finding.raw["markdown"])
            self.assertEqual(finding.properties["source_report_format"], "markdown")
            self.assertTrue(finding.properties["generated_report_persisted"])
            self.assertIn("Markdown 报告原文开始", moderator.calls[0][1])
            self.assertIn("# Markdown 表格报告", moderator.calls[0][1])
            self.assertNotIn("0001 | # Markdown 表格报告", moderator.calls[0][1])
            self.assertNotIn("转换为 SARIF 2.1.0", moderator.calls[0][1])
            self.assertTrue(any("整理为 1 个持久单漏洞 Markdown 报告" in item for item in prepared.diagnostics))

    def test_moderator_llm_analyzes_markdown_before_sarif_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            markdown = root / "report.md"
            markdown.write_text(
                "\n".join(
                    [
                        "# 自然语言漏洞报告",
                        "",
                        "该报告描述了一个命令注入问题，危险函数是 os.system，位置在 app.py 第 5 行。",
                    ]
                ),
                encoding="utf-8",
            )
            generated_markdown = "# 自然语言漏洞报告\n\n该报告描述了一个命令注入问题，危险函数是 os.system，位置在 app.py 第 5 行。"
            response = {"reports": [{"title": "自然语言漏洞报告", "markdown": generated_markdown}]}
            moderator = FakeLLM(json.dumps(response, ensure_ascii=False))

            with patch.dict(os.environ, {"VULN_JUDGER_TMP_DIR": str(root / ".vuln-judger" / "tmp")}):
                prepared = prepare_report_for_processing(markdown, moderator_client=moderator)
            findings = prepared.findings or []

            self.assertTrue(moderator.calls)
            self.assertIn("Markdown 报告原文开始", moderator.calls[0][1])
            self.assertEqual(findings[0].rule_id, "markdown-finding-1")
            self.assertEqual(findings[0].message, "自然语言漏洞报告")
            self.assertNotIn("markdown_start_line", findings[0].properties)
            self.assertNotIn("markdown_end_line", findings[0].properties)
            self.assertIn("危险函数是 os.system", findings[0].raw["markdown"])
            self.assertTrue(any("Moderator LLM 已读取完整 Markdown 并生成 1 个单漏洞报告" in item for item in prepared.diagnostics))

    def test_markdown_moderation_retries_until_valid_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            markdown = root / "report.md"
            markdown.write_text("# 报告\n\napp.py 第 5 行存在命令注入，危险函数 os.system。", encoding="utf-8")
            response = {"reports": [{"title": "第三次重试后解析成功", "markdown": "# 报告\n\napp.py 第 5 行存在命令注入，危险函数 os.system。"}]}
            moderator = SequenceLLM(["不是 JSON", "", json.dumps(response, ensure_ascii=False)])

            with patch.dict(os.environ, {"VULN_JUDGER_TMP_DIR": str(root / ".vuln-judger" / "tmp")}):
                prepared = prepare_report_for_processing(markdown, moderator_client=moderator)
            findings = prepared.findings or []

            self.assertEqual(len(moderator.calls), 3)
            self.assertEqual(findings[0].rule_id, "markdown-finding-1")
            self.assertIn("os.system", findings[0].raw["markdown"])
            self.assertTrue(any("第 1/4 次失败" in item for item in prepared.diagnostics))
            self.assertTrue(any("第 2/4 次失败" in item for item in prepared.diagnostics))
            self.assertTrue(any("第 3/4 次尝试成功" in item for item in prepared.diagnostics))

    def test_markdown_moderation_accepts_findings_alias_and_body_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            markdown = root / "report.md"
            markdown.write_text(
                "\n".join(
                    [
                        "# 报告",
                        "第一个漏洞描述。",
                        "## 第二个漏洞",
                        "第二个漏洞描述。",
                        "第二个漏洞影响。",
                    ]
                ),
                encoding="utf-8",
            )
            response = {
                "findings": [
                    {"title": "第一个漏洞", "body": "# 第一个漏洞\n\n第一个漏洞描述。"},
                    {"title": "第二个漏洞", "body": "# 第二个漏洞\n\n第二个漏洞描述。\n第二个漏洞影响。"},
                ]
            }
            moderator = FakeLLM(json.dumps(response, ensure_ascii=False))

            with patch.dict(os.environ, {"VULN_JUDGER_TMP_DIR": str(root / ".vuln-judger" / "tmp")}):
                prepared = prepare_report_for_processing(markdown, moderator_client=moderator)
            findings = prepared.findings or []

            self.assertEqual(len(findings), 2)
            self.assertIn("第一个漏洞描述", findings[0].raw["markdown"])
            self.assertNotIn("第二个漏洞描述", findings[0].raw["markdown"])
            self.assertIn("第二个漏洞影响", findings[1].raw["markdown"])

    def test_markdown_moderation_accepts_plain_markdown_report_response(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            markdown = root / "report.md"
            markdown.write_text("# 报告\n\napp.py 第 5 行存在命令注入，危险函数 os.system。", encoding="utf-8")
            moderator = FakeLLM("# 命令注入单漏洞报告\n\napp.py 第 5 行存在命令注入，危险函数 os.system。")

            with patch.dict(os.environ, {"VULN_JUDGER_TMP_DIR": str(root / ".vuln-judger" / "tmp")}):
                prepared = prepare_report_for_processing(markdown, moderator_client=moderator)
            findings = prepared.findings or []

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].message, "命令注入单漏洞报告")
            self.assertIn("os.system", findings[0].raw["markdown"])

    def test_long_markdown_report_is_sent_to_moderator_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            markdown = root / "report.md"
            markdown.write_text(
                "\n".join(
                    [
                        "# 长 Markdown 报告",
                        "## 漏洞 A",
                        "A" * 600,
                        "",
                        "## 漏洞 B",
                        "B" * 600,
                    ]
                ),
                encoding="utf-8",
            )
            response = {
                "reports": [
                    {"title": "漏洞 A", "markdown": "# 漏洞 A\n\n" + "A" * 600},
                    {"title": "漏洞 B", "markdown": "# 漏洞 B\n\n" + "B" * 600},
                ]
            }
            moderator = SequenceLLM([json.dumps(response, ensure_ascii=False)])

            with patch.dict(os.environ, {"VULN_JUDGER_TMP_DIR": str(root / ".vuln-judger" / "tmp")}):
                prepared = prepare_report_for_processing(markdown, moderator_client=moderator)

            self.assertEqual(len(moderator.calls), 1)
            self.assertEqual(len(prepared.findings or []), 2)
            self.assertIn("A" * 60, prepared.findings[0].raw["markdown"])
            self.assertIn("B" * 60, prepared.findings[1].raw["markdown"])
            self.assertIn("A" * 60, moderator.calls[0][1])
            self.assertIn("B" * 60, moderator.calls[0][1])
            self.assertFalse(any("分段" in item for item in prepared.diagnostics))
            self.assertTrue(any("已读取完整 Markdown 并生成 2 个单漏洞报告" in item for item in prepared.diagnostics))

    def test_markdown_moderation_fails_after_three_retries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            markdown = root / "report.md"
            markdown.write_text("# 报告\n\n模型持续返回无效内容。", encoding="utf-8")
            moderator = SequenceLLM(["不是 JSON", "仍然不是 JSON", "bad", "invalid"])

            with self.assertRaisesRegex(ReportPreparationError, "4 次尝试后仍失败"):
                prepare_report_for_processing(markdown, moderator_client=moderator)

            self.assertEqual(len(moderator.calls), 4)

    def test_pipeline_uses_moderator_llm_for_markdown_moderation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _sarif, skills = write_python_fixture(root)
            markdown = root / "report.md"
            markdown.write_text(
                "\n".join(
                    [
                        "# 自然语言漏洞报告",
                        "",
                        "请由 Moderator 解读：app.py 第 5 行存在命令注入，危险函数 os.system。",
                    ]
                ),
                encoding="utf-8",
            )
            llm_server = ThreadingHTTPServer(("127.0.0.1", 0), FakeOpenAIHandler)
            llm_thread = Thread(target=llm_server.serve_forever, daemon=True)
            llm_thread.start()
            providers_file = root / "providers.json"
            store = ProviderStore(providers_file)
            endpoint = f"http://127.0.0.1:{llm_server.server_port}/v1/chat/completions"
            try:
                store.upsert(
                    {
                        "id": "fake",
                        "name": "Fake",
                        "endpoint": endpoint,
                        "model": "fake-model",
                        "api_key": "secret",
                    }
                )
                store.set_defaults("fake", "fake", "fake")

                with patch.dict(os.environ, {"VULN_JUDGER_TMP_DIR": str(root / ".vuln-judger" / "tmp")}):
                    report = run_judgement(
                        RunConfig(
                            sarif_path=markdown,
                            source_path=root,
                            skills_path=skills,
                            providers_file=providers_file,
                            enable_external_tools=False,
                            enable_llm=True,
                        )
                    )
            finally:
                llm_server.shutdown()
                llm_server.server_close()

            self.assertTrue(any("Moderator LLM 已读取完整 Markdown 并生成 1 个单漏洞报告" in item for item in report.diagnostics))
            self.assertEqual(report.reports[0].rule_id, "markdown-finding-1")
            report_evidence = next(item for item in report.reports[0].evidence_chain if item.kind == EvidenceKind.REPORT)
            self.assertIn("请由 Moderator 解读", report_evidence.snippet)
            self.assertIn("os.system", report_evidence.data["markdown_report"])

    def test_markdown_report_body_is_expanded_in_agent_evidence_prompt(self):
        from vuln_judger.debate import _evidence_prompt

        markdown_body = "# 单漏洞报告\n\n完整上下文包含危险函数 os.system 和调用前提。\n"
        evidence = CodeEvidence(
            evidence_id="report-1",
            kind=EvidenceKind.REPORT,
            strength=EvidenceStrength.STRONG,
            summary="输入 Markdown 单漏洞报告",
            source="input-report",
            snippet=markdown_body,
            data={"source_format": "markdown", "markdown_report": markdown_body},
        )

        prompt = _evidence_prompt([evidence])

        self.assertIn("报告正文：", prompt)
        self.assertIn("```markdown", prompt)
        self.assertIn("完整上下文包含危险函数 os.system", prompt)
        self.assertNotIn("代码片段：", prompt)

    def test_markdown_cpp_paths_keep_full_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "faiss" / "impl").mkdir(parents=True)
            (root / "faiss" / "impl" / "index_read.cpp").write_text("void read_index() {}\n", encoding="utf-8")
            (root / "faiss" / "IndexFastScan.cpp").write_text("void compute_quantized_LUT() {}\n", encoding="utf-8")
            markdown = root / "report.md"
            markdown.write_text(
                "\n".join(
                    [
                        "# FAISS report",
                        "",
                        "## Affected Code",
                        "",
                        "- `faiss/impl/index_read.cpp`: additive fast-scan deserialization branches",
                        "- `faiss/IndexFastScan.cpp`: `IndexFastScan::compute_quantized_LUT()`",
                    ]
                ),
                encoding="utf-8",
            )
            generated_markdown = "\n".join(
                [
                    "# FAISS report",
                    "",
                    "## Affected Code",
                    "",
                    "- `faiss/impl/index_read.cpp`: additive fast-scan deserialization branches",
                    "- `faiss/IndexFastScan.cpp`: `IndexFastScan::compute_quantized_LUT()`",
                ]
            )
            response = {"reports": [{"title": "FAISS report", "markdown": generated_markdown}]}
            with patch.dict(os.environ, {"VULN_JUDGER_TMP_DIR": str(root / ".vuln-judger" / "tmp")}):
                prepared = prepare_report_for_processing(markdown, moderator_client=FakeLLM(json.dumps(response)))
            finding = (prepared.findings or [])[0]
            self.assertEqual(finding.locations, [])
            self.assertIn("faiss/impl/index_read.cpp", finding.raw["markdown"])
            self.assertIn("faiss/IndexFastScan.cpp", finding.raw["markdown"])
            self.assertIn("faiss/impl/index_read.cpp", prepared.effective_path.read_text(encoding="utf-8"))

    def test_valid_sarif_reuses_local_parse_without_moderator(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, _skills = write_python_fixture(root)
            moderator = FakeLLM("unused")

            prepared = prepare_report_for_processing(sarif, moderator_client=moderator, source_path=root)

            self.assertFalse(prepared.temporary)
            self.assertEqual(len(prepared.findings or []), 1)
            self.assertEqual(prepared.findings[0].rule_id, "python-command-injection")
            self.assertEqual(moderator.calls, [])
            self.assertTrue(any("直接按原始 results 处理" in item for item in prepared.diagnostics))

    def test_structurally_invalid_sarif_uses_moderator_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif = root / "invalid.sarif"
            sarif.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")
            response = {
                "reports": [
                    {
                        "title": "恢复后的漏洞报告",
                        "markdown": "# 恢复后的漏洞报告\n\n- 原 SARIF 结构不完整，保留原文供后续核验。",
                    }
                ]
            }
            moderator = FakeLLM(json.dumps(response, ensure_ascii=False))

            prepared = prepare_report_for_processing(sarif, moderator_client=moderator, source_path=root)

            self.assertEqual(len(moderator.calls), 1)
            self.assertEqual(len(prepared.findings or []), 1)
            self.assertTrue(prepared.temporary)
            self.assertTrue(any("解析失败的 SARIF" in item for item in prepared.diagnostics))

    def test_ambiguous_sarif_report_is_moderated_with_source_into_markdown_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, _skills = write_python_fixture(root)
            sarif_data = json.loads(sarif.read_text(encoding="utf-8"))
            first_result = sarif_data["runs"][0]["results"][0]
            first_result["partialFingerprints"] = {"primaryLocationLineHash": "shared-fingerprint"}
            sarif_data["runs"][0]["results"].append(json.loads(json.dumps(first_result)))
            sarif.write_text(json.dumps(sarif_data), encoding="utf-8")
            response = {
                "reports": [
                    {
                        "title": "命令注入独立报告",
                        "result_indices": [0, 1],
                        "markdown": "\n".join(
                            [
                                "# 命令注入独立报告",
                                "",
                                "- SARIF 位置：app.py:5:5",
                                "- 源码上下文：request.args['cmd'] 进入 os.system。",
                                "- 待正反方核验：入口可达性和防护措施。",
                            ]
                        ),
                    }
                ]
            }
            moderator = FakeLLM(json.dumps(response, ensure_ascii=False))

            tmp_dir = root / ".vuln-judger" / "tmp"
            with patch.dict(os.environ, {"VULN_JUDGER_TMP_DIR": str(tmp_dir)}):
                prepared = prepare_report_for_processing(sarif, moderator_client=moderator, source_path=root)

            self.assertTrue(prepared.temporary)
            self.assertEqual(prepared.effective_path.parent, tmp_dir.resolve())
            self.assertEqual(len(prepared.findings or []), 1)
            finding = prepared.findings[0]
            self.assertEqual(finding.rule_id, "moderated-sarif-finding-1")
            self.assertEqual(finding.message, "命令注入独立报告")
            self.assertEqual(finding.locations[0].display(), "app.py:5:5")
            self.assertEqual(finding.code_flows[0][0].display(), "app.py:4:11")
            self.assertEqual(finding.properties["source_report_format"], "sarif")
            self.assertEqual(finding.properties["sarif_result_indices"], [0, 1])
            self.assertIn("request.args['cmd']", finding.raw["markdown"])
            self.assertEqual(prepared.effective_path.read_text(encoding="utf-8"), finding.raw["markdown"])
            self.assertIn("os.system(cmd)", moderator.calls[0][1])
            self.assertIn('"result_index": 0', moderator.calls[0][1])
            self.assertTrue(any("结合源码整理 SARIF" in item for item in prepared.diagnostics))

    def test_sarif_moderation_failure_falls_back_to_original_sarif(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, _skills = write_python_fixture(root)
            sarif_data = json.loads(sarif.read_text(encoding="utf-8"))
            first_result = sarif_data["runs"][0]["results"][0]
            first_result["partialFingerprints"] = {"primaryLocationLineHash": "shared-fingerprint"}
            sarif_data["runs"][0]["results"].append(json.loads(json.dumps(first_result)))
            sarif.write_text(json.dumps(sarif_data), encoding="utf-8")
            moderator = SequenceLLM(["不是 JSON", "仍然不是 JSON", "bad"])

            prepared = prepare_report_for_processing(sarif, moderator_client=moderator, source_path=root)

            self.assertEqual(len(prepared.findings or []), 2)
            self.assertFalse(prepared.temporary)
            self.assertEqual(len(moderator.calls), 3)
            self.assertTrue(any("Moderator SARIF 预处理失败，回退原始 SARIF" in item for item in prepared.diagnostics))
            fallback = load_sarif(prepared.effective_path)
            self.assertEqual(fallback[0].rule_id, "python-command-injection")

    def test_moderator_repairs_suspicious_sarif_message_in_temp_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _fixture_sarif, skills = write_python_fixture(root)
            sarif = root / "bad.sarif"
            sarif.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {"driver": {"name": "unit"}},
                                "results": [
                                    {
                                        "ruleId": "unknown-rule",
                                        "message": {"text": "|------|-----|"},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "app.py"},
                                                    "region": {"startLine": 5},
                                                }
                                            }
                                        ],
                                        "properties": {
                                            "markdown_vulnerabilitytype": "python-command-injection",
                                            "markdown_dangerousfunction": "os.system",
                                            "markdown_description": "用户输入可到达命令执行点",
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            prepared = prepare_report_for_processing(sarif)
            self.assertTrue(prepared.temporary)
            repaired = load_sarif(prepared.effective_path)
            self.assertEqual(repaired[0].rule_id, "python-command-injection")
            self.assertEqual(repaired[0].message, "用户输入可到达命令执行点")

            report = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    skills_path=skills,
                    enable_external_tools=False,
                )
            )
            self.assertTrue(any("修复 SARIF 读取异常" in item for item in report.diagnostics))
            summaries = "\n".join(item.summary for item in report.reports[0].evidence_chain)
            self.assertIn("用户输入可到达命令执行点", summaries)
            self.assertNotIn("|------|-----|", summaries)

    def test_source_indexer_resolves_markdown_symbol_locations_without_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "faiss").mkdir()
            source = root / "faiss" / "IndexFlat.cpp"
            source.write_text(
                "\n".join(
                    [
                        "namespace faiss {",
                        "",
                        "void helper();",
                        "",
                        "void IndexFlatPanorama::permute_entries(const idx_t* perm) {",
                        "    helper();",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            resolved = SourceIndexer(root, ["cpp"]).resolve_location(
                SourceLocation("faiss/IndexFlat.cpp", symbol="IndexFlatPanorama::permute_entries")
            )
            self.assertTrue(resolved.line_exists)
            self.assertEqual(resolved.requested.line, 5)
            self.assertEqual(resolved.symbol, "IndexFlatPanorama::permute_entries")
            self.assertIn("permute_entries", resolved.snippet)

    def test_numeric_report_path_does_not_read_missing_source_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "real.py").write_text("def handler():\n    return 1\n", encoding="utf-8")
            sarif = root / "report.sarif"
            sarif.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {"driver": {"name": "unit"}},
                                "results": [
                                    {
                                        "ruleId": "numeric-location",
                                        "message": {"text": "bad location parsed as a line number"},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "411"},
                                                    "region": {"startLine": 1},
                                                }
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            report = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    enable_external_tools=False,
                )
            )
            source_items = [
                item for item in report.reports[0].evidence_chain if item.kind == EvidenceKind.SOURCE_LOCATION
            ]
            self.assertTrue(source_items)
            self.assertFalse(source_items[0].data["exists"])
            self.assertIn("无法在源码根目录下解析", source_items[0].summary)

    def test_sarif_path_with_redundant_project_prefix_resolves_by_suffix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "faiss" / "impl").mkdir(parents=True)
            (root / "faiss" / "impl" / "index_read.cpp").write_text(
                "\n".join(["void read_index_up() {", "  int value = 1;", "}"]),
                encoding="utf-8",
            )
            sarif = root / "report.sarif"
            sarif.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {"driver": {"name": "unit"}},
                                "results": [
                                    {
                                        "ruleId": "cpp-demo",
                                        "message": {"text": "demo"},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "faiss/faiss/impl/index_read.cpp"},
                                                    "region": {"startLine": 2},
                                                }
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            report = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    enable_external_tools=False,
                )
            )
            source_evidence = next(
                item for item in report.reports[0].evidence_chain if item.kind == EvidenceKind.SOURCE_LOCATION
            )
            self.assertEqual(report.reports[0].source_locations[0].file, "faiss/impl/index_read.cpp")
            self.assertTrue(source_evidence.data["line_exists"])
            self.assertEqual(source_evidence.data["requested_file"], "faiss/faiss/impl/index_read.cpp")
            self.assertEqual(source_evidence.data["resolved_file"], "faiss/impl/index_read.cpp")

    def test_atlas_indexed_files_do_not_report_missing_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "app.py"
            source.write_text("def handler(): pass\n", encoding="utf-8")
            (root / ".atlas").mkdir()
            (root / ".atlas" / "atlas.db").write_text("fake", encoding="utf-8")
            atlas = root / "atlas"
            atlas.write_text(fake_atlas_mcp_script(), encoding="utf-8")
            atlas.chmod(0o755)
            finding = Finding(
                finding_id="f-atlas",
                rule_id="python-demo",
                message="demo",
                level="warning",
                locations=[SourceLocation("app.py", 1)],
            )
            evidence = AtlasAnalyzer(binary=str(atlas)).analyze(
                finding,
                SourceIndexer(root, ["python"]),
                AnalyzerSettings(enabled=True),
            )
            summaries = "\n".join(item.summary for item in evidence)
            self.assertIn("检测到 Atlas 持久缓存", summaries)
            self.assertIn("Atlas MCP 预分析 project/open 已激活项目", summaries)
            self.assertIn("Atlas MCP 预分析 project/status 确认项目状态", summaries)
            self.assertIn("Atlas MCP 预分析 project/files 找到报告路径候选", summaries)
            self.assertNotIn("缺少 .atlas/atlas.db", summaries)
            self.assertTrue(any(item.data.get("mcp_success") for item in evidence))
            self.assertTrue(any(item.data.get("focus_runtime") for item in evidence))
            self.assertTrue(any(item.source == "agentic-source-reader" for item in evidence))
            self.assertFalse(any(item.source == "atlas-mcp" for item in evidence))

    def test_atlas_mcp_runs_without_prebuilt_database_with_focus_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "app.py"
            source.write_text("def handler(request):\n    return request.args.get('cmd')\n", encoding="utf-8")
            atlas = root / "atlas"
            atlas.write_text(fake_atlas_mcp_script(), encoding="utf-8")
            atlas.chmod(0o755)
            finding = Finding(
                finding_id="f-atlas-focus",
                rule_id="python-demo",
                message="handler receives cmd",
                level="warning",
                locations=[SourceLocation("app.py", 2)],
            )

            evidence = AtlasAnalyzer(binary=str(atlas)).analyze(
                finding,
                SourceIndexer(root, ["python"]),
                AnalyzerSettings(enabled=True),
            )
            summaries = "\n".join(item.summary for item in evidence)

            self.assertIn("未检测到 Atlas 持久缓存", summaries)
            self.assertIn("无需预先执行 atlas index", summaries)
            self.assertIn("Atlas MCP 预分析 project/open 已激活项目", summaries)
            self.assertIn("Atlas MCP 预分析 project/status 确认项目状态", summaries)
            self.assertTrue(any(item.data.get("mcp_tool") == "trace" and item.data.get("precision") for item in evidence))
            self.assertFalse(any("缺少 .atlas/atlas.db" in item.summary for item in evidence))

    def test_mcp_stdio_client_reads_utf8_tool_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = root / "utf8_mcp.py"
            server.write_text(
                r'''
import json
import sys

def send(message):
    raw = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(raw + b"\n")
    sys.stdout.buffer.flush()

for raw in sys.stdin.buffer:
    if not raw.strip():
        continue
    message = json.loads(raw.decode("utf-8"))
    method = message.get("method")
    request_id = message.get("id")
    if method == "initialize":
        send({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "utf8-mcp", "version": "test"},
            },
        })
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        send({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"tools": [{"name": "trace", "description": "Atlas — 数据流"}]},
        })
''',
                encoding="utf-8",
            )
            with MCPStdioClient([sys.executable, str(server)], cwd=root, timeout=10) as client:
                tools = client.list_tools()
            self.assertEqual(tools[0]["description"], "Atlas — 数据流")

    def test_atlas_mcp_produces_trace_and_call_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".atlas").mkdir()
            (root / ".atlas" / "atlas.db").write_text("fake", encoding="utf-8")
            (root / "app.py").write_text(
                "\n".join(
                    [
                        "import os",
                        "def handler(request):",
                        "    cmd = request.args['cmd']",
                        "    os.system(cmd)",
                    ]
                ),
                encoding="utf-8",
            )
            atlas = root / "atlas"
            atlas.write_text(fake_atlas_mcp_script(), encoding="utf-8")
            atlas.chmod(0o755)
            finding = Finding(
                finding_id="f-atlas-mcp",
                rule_id="python-command-injection",
                message="用户输入可到达命令执行点",
                level="error",
                locations=[SourceLocation("app.py", 4, 5)],
            )
            evidence = AtlasAnalyzer(binary=str(atlas)).analyze(
                finding,
                SourceIndexer(root, ["python"]),
                AnalyzerSettings(enabled=True),
            )
            summaries = "\n".join(item.summary for item in evidence)
            self.assertIn("Atlas MCP 预分析 project/status 确认项目状态", summaries)
            self.assertIn("Atlas MCP 预分析 project/files 找到报告路径候选", summaries)
            self.assertIn("Atlas MCP 预分析 trace variable 返回 ok=True", summaries)
            self.assertIn("Atlas MCP 预分析 calls 提取 `handler` 调用图", summaries)
            self.assertTrue(any(item.kind == EvidenceKind.DATA_FLOW and item.source == "atlas-agent-mcp" for item in evidence))
            self.assertTrue(any(item.kind == EvidenceKind.CALL_CHAIN and item.source == "atlas-agent-mcp" for item in evidence))
            self.assertTrue(any(item.source == "agentic-source-reader" for item in evidence))
            self.assertFalse(any(item.source == "atlas-mcp" for item in evidence))
            self.assertNotIn("当前 Atlas CLI 未提供 trace 子命令", summaries)

    def test_atlas_focus_path_facts_are_flow_and_call_chain_evidence(self):
        from vuln_judger.debate import _build_verification_scorecard

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(
                "\n".join(
                    [
                        "def route(request):",
                        "    return handler(request)",
                        "def handler(request):",
                        "    payload = request.args['cmd']",
                        "    return sink(payload)",
                        "def sink(value):",
                        "    return value",
                    ]
                ),
                encoding="utf-8",
            )
            atlas = root / "atlas"
            atlas.write_text(fake_atlas_mcp_focus_graph_script(), encoding="utf-8")
            atlas.chmod(0o755)
            finding = Finding(
                finding_id="f-atlas-focus-graph",
                rule_id="python-command-injection",
                message="handler data reaches sink",
                level="error",
                locations=[SourceLocation("app.py", 5, 12)],
            )

            evidence = AtlasAnalyzer(binary=str(atlas)).analyze(
                finding,
                SourceIndexer(root, ["python"]),
                AnalyzerSettings(enabled=True),
            )

            point_flow = next(
                item
                for item in evidence
                if item.kind == EvidenceKind.DATA_FLOW
                and item.source == "atlas-agent-mcp"
                and item.data.get("trace_kind") == "point"
            )
            call_chain = next(
                item
                for item in evidence
                if item.kind == EvidenceKind.CALL_CHAIN
                and item.source == "atlas-agent-mcp"
                and item.data.get("mcp_tool") == "calls"
            )
            scorecard = _build_verification_scorecard(evidence, None)

            self.assertTrue(point_flow.data["focus_path_facts"])
            self.assertIn("app.py:4", [location.display() for location in point_flow.locations])
            self.assertIn("app.py:5", [location.display() for location in point_flow.locations])
            self.assertEqual(point_flow.strength, EvidenceStrength.MEDIUM)
            self.assertEqual(call_chain.strength, EvidenceStrength.MEDIUM)
            self.assertEqual(scorecard.data_flow, "confirmed")
            self.assertEqual(scorecard.call_chain, "confirmed")

    def test_atlas_focus_rescan_retries_trace_without_index_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(
                "\n".join(
                    [
                        "def handler(request):",
                        "    payload = request.args['cmd']",
                        "    return sink(payload)",
                    ]
                ),
                encoding="utf-8",
            )
            atlas = root / "atlas"
            atlas.write_text(fake_atlas_mcp_unmaterialized_then_focus_script(), encoding="utf-8")
            atlas.chmod(0o755)
            finding = Finding(
                finding_id="f-atlas-focus-rescan",
                rule_id="python-command-injection",
                message="handler data reaches sink",
                level="error",
                locations=[SourceLocation("app.py", 3, 12)],
            )

            evidence = AtlasAnalyzer(binary=str(atlas)).analyze(
                finding,
                SourceIndexer(root, ["python"]),
                AnalyzerSettings(enabled=True),
            )
            summaries = "\n".join(item.summary for item in evidence)
            flow = next(
                item
                for item in evidence
                if item.kind == EvidenceKind.DATA_FLOW
                and item.source == "atlas-agent-mcp"
                and item.data.get("focus_scan_retry")
            )

            self.assertIn("Focus scoped search 已触发项目事实", summaries)
            self.assertIn("Focus scoped search 触发项目事实后重试", flow.summary)
            self.assertTrue(flow.data["focus_path_facts"])
            self.assertFalse(any(item.data.get("mcp_tool") == "index" for item in evidence))

    def test_atlas_mcp_timeout_becomes_diagnostic_and_keeps_source_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".atlas").mkdir()
            (root / ".atlas" / "atlas.db").write_text("fake", encoding="utf-8")
            (root / "app.py").write_text(
                "\n".join(
                    [
                        "import os",
                        "def handler(request):",
                        "    cmd = request.args['cmd']",
                        "    os.system(cmd)",
                    ]
                ),
                encoding="utf-8",
            )
            atlas = root / "atlas"
            atlas.write_text(fake_atlas_mcp_timeout_script(), encoding="utf-8")
            atlas.chmod(0o755)
            finding = Finding(
                finding_id="f-atlas-timeout",
                rule_id="python-command-injection",
                message="用户输入可到达命令执行点",
                level="error",
                locations=[SourceLocation("app.py", 4, 5)],
            )
            evidence = AtlasAnalyzer(binary=str(atlas)).analyze(
                finding,
                SourceIndexer(root, ["python"]),
                AnalyzerSettings(enabled=True, timeout_seconds=1),
            )
            summaries = "\n".join(item.summary for item in evidence)
            self.assertIn("MCP request timed out after 1s: tools/call:trace", summaries)
            self.assertTrue(any(item.source == "agentic-source-reader" for item in evidence))
            self.assertFalse(any("适配器执行失败" in item.summary for item in evidence))

    def test_atlas_mcp_uses_resolved_sarif_suffix_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".atlas").mkdir()
            (root / ".atlas" / "atlas.db").write_text("fake", encoding="utf-8")
            (root / "faiss" / "impl").mkdir(parents=True)
            (root / "faiss" / "impl" / "index_read.cpp").write_text(
                "\n".join(
                    [
                        "std::unique_ptr<int> read_index_up(",
                        "        int f) {",
                        "    int value = f;",
                        "    return {};",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            atlas = root / "atlas"
            atlas.write_text(fake_atlas_mcp_script(), encoding="utf-8")
            atlas.chmod(0o755)
            finding = Finding(
                finding_id="f-atlas-suffix",
                rule_id="cpp-demo",
                message="demo",
                level="warning",
                locations=[SourceLocation("faiss/faiss/impl/index_read.cpp", 3)],
            )
            evidence = AtlasAnalyzer(binary=str(atlas)).analyze(
                finding,
                SourceIndexer(root, ["cpp"]),
                AnalyzerSettings(enabled=True),
            )
            summaries = "\n".join(item.summary for item in evidence)
            indexed = next(item for item in evidence if item.data.get("mcp_tool") == "project/files")
            self.assertIn("Atlas MCP 预分析 project/files 找到报告路径候选", summaries)
            self.assertEqual(indexed.data["matched_files"], ["faiss/impl/index_read.cpp"])
            self.assertTrue(any(item.data.get("trace_file") == "faiss/impl/index_read.cpp" for item in evidence))
            self.assertFalse(any("faiss/faiss/impl/index_read.cpp" in location.file for item in evidence for location in item.locations))

    def test_agentic_atlas_fallback_runs_when_report_path_does_not_resolve(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".atlas").mkdir()
            (root / ".atlas" / "atlas.db").write_text("fake", encoding="utf-8")
            (root / "app.py").write_text(
                "\n".join(
                    [
                        "import os",
                        "def handler(request):",
                        "    cmd = request.args['cmd']",
                        "    os.system(cmd)",
                    ]
                ),
                encoding="utf-8",
            )
            atlas = root / "atlas"
            atlas.write_text(fake_atlas_mcp_script(), encoding="utf-8")
            atlas.chmod(0o755)
            finding = Finding(
                finding_id="f-agentic-atlas",
                rule_id="python-command-injection",
                message="handler reaches os.system",
                level="error",
                locations=[SourceLocation("missing/report-only.py", 4, 5)],
            )
            evidence = AtlasAnalyzer(binary=str(atlas)).analyze(
                finding,
                SourceIndexer(root, ["python"]),
                AnalyzerSettings(enabled=True),
            )
            summaries = "\n".join(item.summary for item in evidence)
            self.assertIn("Atlas MCP 预分析补证启动", summaries)
            self.assertTrue(any(item.source == "atlas-agent-mcp" for item in evidence))
            self.assertTrue(any(item.kind == EvidenceKind.CALL_CHAIN and item.source == "atlas-agent-mcp" for item in evidence))

    def test_agentic_atlas_is_the_only_mcp_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".atlas").mkdir()
            (root / ".atlas" / "atlas.db").write_text("fake", encoding="utf-8")
            (root / "app.py").write_text("def handler(request): pass\n", encoding="utf-8")
            atlas = root / "atlas"
            atlas.write_text(fake_atlas_mcp_script(), encoding="utf-8")
            atlas.chmod(0o755)
            finding = Finding(
                finding_id="f-agentic-direct",
                rule_id="python-demo",
                message="handler",
                level="warning",
                locations=[SourceLocation("app.py", 1)],
            )
            evidence = AtlasAnalyzer(binary=str(atlas)).analyze(
                finding,
                SourceIndexer(root, ["python"]),
                AnalyzerSettings(enabled=True),
            )
            self.assertTrue(any(item.source == "atlas-agent-mcp" for item in evidence))
            self.assertFalse(any(item.source == "atlas-mcp" for item in evidence))

    def test_agentic_atlas_falls_back_to_source_reader_when_mcp_has_no_substantive_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".atlas").mkdir()
            (root / ".atlas" / "atlas.db").write_text("fake", encoding="utf-8")
            (root / "app.py").write_text(
                "\n".join(
                    [
                        "def handler(request):",
                        "    payload = request.args.get('cmd')",
                        "    return payload",
                    ]
                ),
                encoding="utf-8",
            )
            atlas = root / "atlas"
            atlas.write_text(fake_atlas_mcp_empty_script(), encoding="utf-8")
            atlas.chmod(0o755)
            finding = Finding(
                finding_id="f-agentic-source",
                rule_id="python-command-injection",
                message="handler receives cmd",
                level="warning",
                locations=[SourceLocation("missing/report-only.py", 2)],
            )
            evidence = AtlasAnalyzer(binary=str(atlas)).analyze(
                finding,
                SourceIndexer(root, ["python"]),
                AnalyzerSettings(enabled=True),
            )
            summaries = "\n".join(item.summary for item in evidence)
            self.assertIn("Atlas MCP 预分析 search 未找到报告相关符号或路径候选", summaries)
            self.assertTrue(any(item.source == "agentic-source-reader" for item in evidence))
            self.assertTrue(any(location.file == "app.py" for item in evidence for location in item.locations))

    def test_debate_outputs_structured_reports_and_final_conclusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, skills = write_python_fixture(root)
            report = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    skills_path=skills,
                    enable_external_tools=False,
                )
            )
            finding = report.reports[0]
            self.assertTrue(any(item.kind == EvidenceKind.REPORT for item in finding.evidence_chain))
            self.assertTrue(any(item.kind == EvidenceKind.SOURCE_ROOT for item in finding.evidence_chain))
            self.assertIn("回合摘要", finding.debate[0].claim)
            self.assertTrue(finding.debate[0].structured)
            self.assertIn("正方证据报告", finding.debate[0].raw_claim)
            self.assertIn("代码上下文业务逻辑说明", finding.debate[0].raw_claim)
            self.assertIn("行为目的候选", finding.debate[0].raw_claim)
            self.assertIn("攻击链", finding.debate[0].raw_claim)
            self.assertIn("攻击前提", finding.debate[0].raw_claim)
            self.assertIn("攻击影响", finding.debate[0].raw_claim)
            self.assertIn("反方质疑报告", finding.debate[1].raw_claim)
            self.assertIn("代码上下文业务逻辑核验", finding.debate[1].raw_claim)
            negative_evidence_ids = set(finding.debate[1].evidence_ids)
            report_evidence_ids = {item.evidence_id for item in finding.evidence_chain if item.kind == EvidenceKind.REPORT}
            flow_evidence_ids = {
                item.evidence_id
                for item in finding.evidence_chain
                if item.kind in {EvidenceKind.SARIF_CODE_FLOW, EvidenceKind.DATA_FLOW, EvidenceKind.CALL_CHAIN}
            }
            self.assertTrue(report_evidence_ids.issubset(negative_evidence_ids))
            self.assertTrue(flow_evidence_ids.issubset(negative_evidence_ids))
            self.assertTrue(finding.final_conclusion.startswith("【真实漏洞】"))
            self.assertEqual(finding.debate[-1].raw_claim, finding.final_conclusion)
            self.assertIn("### 调用链 / 数据流概览", finding.final_conclusion)
            self.assertNotIn("```mermaid", finding.final_conclusion)
            self.assertTrue(finding.verification_case)
            self.assertTrue(finding.evidence_ledger)
            self.assertTrue(finding.scorecard)
            self.assertTrue(finding.evidence_graph["nodes"])
            self.assertTrue(finding.evidence_graph["edges"])
            self.assertIn("path_overview", finding.evidence_graph)
            self.assertNotIn("mermaid", finding.evidence_graph)
            self.assertIn("数据流状态", finding.evidence_graph["path_overview"])
            self.assertIn("app.py:4:11", finding.evidence_graph["path_overview"])
            self.assertIn("app.py:5:5", finding.evidence_graph["path_overview"])
            self.assertNotIn("ev-", finding.evidence_graph["path_overview"])
            self.assertIn("breaks", finding.evidence_graph)

    def test_negative_challenges_sensitive_info_semantics_before_impact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(
                "\n".join(
                    [
                        "def handler(request):",
                        "    key = request.args.get('key')",
                        "    return {'key': key}",
                    ]
                ),
                encoding="utf-8",
            )
            sarif = root / "report.sarif"
            sarif.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {"driver": {"name": "unit"}},
                                "results": [
                                    {
                                        "ruleId": "key-exposure",
                                        "level": "warning",
                                        "message": {"text": "key 参数可能被返回"},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "app.py"},
                                                    "region": {"startLine": 3, "startColumn": 5},
                                                }
                                            }
                                        ],
                                        "codeFlows": [
                                            {
                                                "threadFlows": [
                                                    {
                                                        "locations": [
                                                            {
                                                                "location": {
                                                                    "physicalLocation": {
                                                                        "artifactLocation": {"uri": "app.py"},
                                                                        "region": {"startLine": 2, "startColumn": 11},
                                                                    }
                                                                }
                                                            },
                                                            {
                                                                "location": {
                                                                    "physicalLocation": {
                                                                        "artifactLocation": {"uri": "app.py"},
                                                                        "region": {"startLine": 3, "startColumn": 5},
                                                                    }
                                                                }
                                                            },
                                                        ]
                                                    }
                                                ]
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            report = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    enable_external_tools=False,
                )
            )
            negative_claim = report.reports[0].debate[1].raw_claim
            self.assertIn("代码上下文业务逻辑核验", negative_claim)
            self.assertIn("敏感信息真实性", negative_claim)
            self.assertIn("key 可能为密钥", negative_claim)
            self.assertIn("普通标识", negative_claim)
            self.assertIn("真实敏感性", negative_claim)
            self.assertIn("未见加解密", negative_claim)

    def test_local_vulnerability_without_entry_reachability_is_doubtful(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "legacy.py").write_text(
                "\n".join(
                    [
                        "import os",
                        "",
                        "def legacy_exec(cmd):",
                        "    os.system(cmd)",
                    ]
                ),
                encoding="utf-8",
            )
            sarif = root / "report.sarif"
            sarif.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {"driver": {"name": "unit"}},
                                "results": [
                                    {
                                        "ruleId": "python-command-injection",
                                        "level": "warning",
                                        "message": {"text": "legacy helper command reaches os.system"},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "legacy.py"},
                                                    "region": {"startLine": 4, "startColumn": 5},
                                                }
                                            }
                                        ],
                                        "codeFlows": [
                                            {
                                                "threadFlows": [
                                                    {
                                                        "locations": [
                                                            {
                                                                "location": {
                                                                    "physicalLocation": {
                                                                        "artifactLocation": {"uri": "legacy.py"},
                                                                        "region": {"startLine": 3, "startColumn": 17},
                                                                    }
                                                                }
                                                            },
                                                            {
                                                                "location": {
                                                                    "physicalLocation": {
                                                                        "artifactLocation": {"uri": "legacy.py"},
                                                                        "region": {"startLine": 4, "startColumn": 5},
                                                                    }
                                                                }
                                                            },
                                                        ]
                                                    }
                                                ]
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            report = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    enable_external_tools=False,
                )
            )
            finding = report.reports[0]
            self.assertEqual(finding.verdict, Verdict.INCONCLUSIVE)
            self.assertTrue(finding.final_conclusion.startswith("【可达性存疑】"))
            self.assertTrue(any("REST/API/接口入口" in point for point in finding.disputed_points))

    def test_affirmative_planner_pushes_evidence_hunting_when_chain_is_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(
                "\n".join(
                    [
                        "def handler(request):",
                        "    value = request.args.get('cmd')",
                        "    return value",
                    ]
                ),
                encoding="utf-8",
            )
            sarif = root / "report.sarif"
            sarif.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {"driver": {"name": "unit"}},
                                "results": [
                                    {
                                        "ruleId": "python-command-injection",
                                        "level": "warning",
                                        "message": {"text": "handler receives command input"},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "app.py"},
                                                    "region": {"startLine": 2, "startColumn": 13},
                                                }
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            report = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    enable_external_tools=False,
                )
            )
            finding = report.reports[0]
            plans = [item for item in finding.evidence_chain if item.source == "affirmative-evidence-planner"]
            self.assertTrue(plans)
            self.assertIn("data_flow", plans[0].data["missing_evidence"])
            self.assertIn("call_chain", plans[0].data["missing_evidence"])
            self.assertTrue(any("Atlas trace" in action for action in plans[0].data["suggested_actions"]))
            self.assertIn("正方补证策略", finding.debate[0].raw_claim)
            self.assertIn("应继续主动补证", finding.debate[0].raw_claim)

    def test_agentic_rg_is_scoped_to_report_files_for_sink_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "safe.py").write_text(
                "\n".join(
                    [
                        "def handler(request):",
                        "    value = request.args.get('cmd')",
                        "    return value",
                    ]
                ),
                encoding="utf-8",
            )
            (root / "danger.py").write_text(
                "import os\n\ndef unrelated(cmd):\n    os.system(cmd)\n",
                encoding="utf-8",
            )
            sarif = root / "report.sarif"
            sarif.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {"driver": {"name": "unit"}},
                                "results": [
                                    {
                                        "ruleId": "python-command-injection",
                                        "level": "warning",
                                        "message": {"text": "handler receives command input"},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "safe.py"},
                                                    "region": {"startLine": 2, "startColumn": 13},
                                                }
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            report = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    enable_external_tools=False,
                )
            )
            evidence = report.reports[0].evidence_chain
            rg_items = [item for item in evidence if item.source == "agentic-rg"]
            self.assertTrue(rg_items)
            self.assertTrue(all("safe.py" in item.data.get("scoped_paths", []) for item in rg_items))
            self.assertFalse(any(location.file == "danger.py" for item in rg_items for location in item.locations))
            self.assertFalse(any(item.data.get("sink_terms") for item in rg_items))

    def test_agentic_rg_does_not_use_unrelated_protection_as_mitigation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "safe.py").write_text(
                "def handler(request):\n    return request.args.get('cmd')\n",
                encoding="utf-8",
            )
            (root / "guard.py").write_text(
                "def guard(user):\n    return authorize(user) and check(user)\n",
                encoding="utf-8",
            )
            sarif = root / "report.sarif"
            sarif.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {"driver": {"name": "unit"}},
                                "results": [
                                    {
                                        "ruleId": "python-command-injection",
                                        "level": "warning",
                                        "message": {"text": "handler receives command input"},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "safe.py"},
                                                    "region": {"startLine": 2, "startColumn": 12},
                                                }
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            report = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    enable_external_tools=False,
                )
            )
            finding = report.reports[0]
            self.assertFalse(any(item.kind == EvidenceKind.PROTECTION for item in finding.evidence_chain))
            self.assertIn("未发现针对报告路径的防护消减证据", finding.protection_assessment)
            self.assertNotIn("guard.py", finding.protection_assessment)

    def test_sarif_without_locations_still_passes_source_root_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "summary.sarif"
            report_path.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {"driver": {"name": "unit"}},
                                "results": [
                                    {
                                        "ruleId": "faiss-deserialization-risk",
                                        "level": "warning",
                                        "message": {
                                            "text": "发现 IndexAdditiveQuantizerFastScan 可能存在反序列化风险，但报告未给出源码路径。"
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            report = run_judgement(
                RunConfig(
                    sarif_path=report_path,
                    source_path=root,
                    enable_external_tools=False,
                )
            )
            finding = report.reports[0]
            source_root = next(item for item in finding.evidence_chain if item.kind == EvidenceKind.SOURCE_ROOT)
            self.assertEqual(source_root.data["source_root"], str(root.resolve()))
            self.assertTrue(source_root.data["source_root_exists"])
            self.assertIn(source_root.evidence_id, finding.debate[0].evidence_ids)
            self.assertIn("任务源码根目录已配置", finding.debate[0].claim)
            self.assertIn("报告未提供可解析到源码的具体文件/行号", finding.debate[0].claim)

    def test_run_judgement_emits_progressive_debate_snapshots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, skills = write_python_fixture(root)
            snapshots = []
            report = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    skills_path=skills,
                    enable_external_tools=False,
                ),
                progress_callback=lambda item: snapshots.append(to_jsonable(item)),
            )
            debate_lengths = [
                len(snapshot["reports"][0]["debate"])
                for snapshot in snapshots
                if snapshot.get("reports") and snapshot["reports"][0].get("debate")
            ]
            self.assertGreaterEqual(len(debate_lengths), 3)
            self.assertEqual(debate_lengths[0], 1)
            self.assertEqual(debate_lengths[-1], len(report.reports[0].debate))
            self.assertEqual(snapshots[-1]["reports"][0]["final_conclusion"], report.reports[0].final_conclusion)

    def test_record_store_saves_and_lists_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, skills = write_python_fixture(root)
            report = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    skills_path=skills,
                    enable_external_tools=False,
                )
            )
            store = RunRecordStore(root / "records")
            store.save(report)
            records = store.list()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["run_id"], report.run_id)
            self.assertEqual(records[0]["verdict_counts"]["TRUE_POSITIVE"], 1)
            self.assertIsNotNone(store.get(report.run_id))
            self.assertTrue(store.delete(report.run_id))
            self.assertIsNone(store.get(report.run_id))
            self.assertFalse(store.delete(report.run_id))

    def test_record_store_recovers_unfinished_run_after_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RunRecordStore(Path(tmp) / "records")
            store.save_payload(
                {
                    "run_id": "run-recover",
                    "status": "running",
                    "engine": "codex",
                    "created_at": "2026-06-09T00:00:00Z",
                    "source_path": "/src",
                    "sarif_path": "/report.sarif",
                    "finding_count": 3,
                    "completed_finding_count": 1,
                    "current_finding_id": "finding-2",
                    "current_finding_index": 1,
                    "reports": [
                        {"finding_id": "finding-1", "finding_status": "completed", "verdict": "TRUE_POSITIVE"},
                        {"finding_id": "finding-2", "finding_status": "in_progress", "verdict": "INCONCLUSIVE"},
                        {"finding_id": "finding-3", "finding_status": "pending", "verdict": None},
                    ],
                    "diagnostics": [],
                    "config": {"engine": "codex", "report_path": "/report.sarif", "source_path": "/src"},
                }
            )

            recovered = store.recover_unfinished()

            self.assertEqual(len(recovered), 1)
            saved = store.get("run-recover")
            self.assertEqual(saved["status"], "paused")
            self.assertEqual(saved["completed_finding_count"], 1)
            self.assertEqual(saved["resume_from_finding_id"], "finding-2")
            self.assertEqual(saved["resume_from_finding_index"], 1)
            self.assertEqual(len(saved["reports"]), 3)
            self.assertEqual([item["finding_status"] for item in saved["reports"]], ["completed", "pending", "pending"])
            self.assertIn("服务重启时发现任务未完成", saved["diagnostics"][-1])

    def test_run_control_store_serializes_worker_ownership_and_pause_signal(self):
        with tempfile.TemporaryDirectory() as tmp:
            control = RunControlStore(Path(tmp) / "records")
            owner = control.claim("run-control", origin="mcp")

            self.assertIsNotNone(owner)
            self.assertIsNone(control.claim("run-control", origin="web"))
            persisted = []
            self.assertTrue(
                control.request(
                    "run-control",
                    "pause",
                    requested_by="web",
                    before_signal=lambda: persisted.append("pausing"),
                )
            )
            self.assertEqual(persisted, ["pausing"])
            self.assertEqual(control.requested_action("run-control", owner), "pause")

            replacement = control.claim("run-control", origin="mcp", allow_paused_takeover=True)
            self.assertIsNotNone(replacement)
            self.assertNotEqual(replacement, owner)
            self.assertIsNone(control.requested_action("run-control", owner))
            self.assertIsNone(control.requested_action("run-control", replacement))
            self.assertFalse(control.release("run-control", owner))
            self.assertTrue(control.release("run-control", replacement))

    def test_record_store_does_not_recover_run_owned_by_live_mcp_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RunRecordStore(Path(tmp) / "records")
            store.save_payload(
                {
                    "run_id": "run-live-mcp",
                    "status": "running",
                    "run_origin": "mcp",
                    "engine": "opencode",
                    "finding_count": 1,
                    "completed_finding_count": 0,
                    "reports": [],
                    "diagnostics": [],
                }
            )
            control = RunControlStore(store.root)
            owner = control.claim("run-live-mcp", origin="mcp")

            self.assertEqual(store.recover_unfinished(), [])
            self.assertEqual(store.get("run-live-mcp")["status"], "running")
            self.assertTrue(control.release("run-live-mcp", owner))
            self.assertEqual(len(store.recover_unfinished()), 1)
            self.assertEqual(store.get("run-live-mcp")["status"], "paused")

    def test_record_store_preserves_latest_manual_review_across_pipeline_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RunRecordStore(Path(tmp) / "records")
            pipeline_payload = {
                "run_id": "run-manual-review",
                "status": "running",
                "reports": [
                    {
                        "finding_id": "finding-1",
                        "rule_id": "rule-1",
                        "finding_status": "completed",
                        "verdict": "INCONCLUSIVE",
                    }
                ],
            }
            store.save_payload(dict(pipeline_payload))

            created, was_created = store.update_manual_review(
                "run-manual-review",
                "finding-1",
                decision="TRUE_POSITIVE",
                evidence="人工确认入口可达。",
            )
            self.assertTrue(was_created)
            self.assertEqual(created["decision"], "TRUE_POSITIVE")
            self.assertEqual(created["created_at"], created["updated_at"])

            stale_pipeline_payload = dict(pipeline_payload)
            stale_pipeline_payload["manual_reviews"] = {
                "finding-1": {"decision": "FALSE_POSITIVE", "evidence": "stale"}
            }
            store.save_payload(stale_pipeline_payload)
            preserved = store.get("run-manual-review")["manual_reviews"]["finding-1"]
            self.assertEqual(preserved["decision"], "TRUE_POSITIVE")
            self.assertEqual(preserved["evidence"], "人工确认入口可达。")

            updated, was_created = store.update_manual_review(
                "run-manual-review",
                "finding-1",
                decision="FALSE_POSITIVE",
                evidence="固定白名单映射，无法注入。",
            )
            self.assertFalse(was_created)
            self.assertEqual(updated["created_at"], created["created_at"])
            self.assertEqual(updated["decision"], "FALSE_POSITIVE")
            self.assertTrue(store.delete_manual_review("run-manual-review", "finding-1"))

            # A stale worker payload must not resurrect a review after the user clears it.
            store.save_payload(stale_pipeline_payload)
            self.assertEqual(store.get("run-manual-review")["manual_reviews"], {})
            self.assertFalse(store.delete_manual_review("run-manual-review", "finding-1"))

    def test_record_store_preserves_opencode_stage_checkpoint_after_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = RunRecordStore(Path(tmp) / "records")
            affirmative = {
                "role": "affirmative",
                "finding_id": "finding-2",
                "attempt_id": "attempt-a",
                "position": "TRUE_POSITIVE",
                "confidence": 0.8,
            }
            store.save_payload(
                {
                    "run_id": "run-opencode-recover",
                    "status": "running",
                    "engine": "opencode",
                    "created_at": "2026-07-14T00:00:00Z",
                    "source_path": "/src",
                    "sarif_path": "/report.sarif",
                    "finding_count": 2,
                    "completed_finding_count": 1,
                    "current_finding_ids": {"negative": "finding-2"},
                    "reports": [
                        {"finding_id": "finding-1", "finding_status": "completed", "verdict": "TRUE_POSITIVE"},
                        {
                            "finding_id": "finding-2",
                            "finding_status": "in_progress",
                            "cli_workflow": {
                                "affirmative": affirmative,
                                "negative": {},
                                "moderator": {},
                                "pipeline": {
                                    "version": 1,
                                    "stages": {
                                        "affirmative": {"status": "succeeded", "attempt": 1},
                                        "negative": {"status": "running", "attempt": 1},
                                        "moderator": {"status": "pending", "attempt": 0},
                                    },
                                },
                            },
                        },
                    ],
                    "diagnostics": [],
                    "config": {"engine": "opencode", "report_path": "/report.sarif", "source_path": "/src"},
                }
            )

            store.recover_unfinished()

            saved = store.get("run-opencode-recover")
            self.assertEqual(len(saved["reports"]), 2)
            self.assertEqual(saved["reports"][1]["cli_workflow"]["affirmative"], affirmative)
            stages = saved["reports"][1]["cli_workflow"]["pipeline"]["stages"]
            self.assertEqual(stages["affirmative"]["status"], "succeeded")
            self.assertEqual(stages["negative"]["status"], "interrupted")
            self.assertEqual(saved["current_finding_ids"], {})

    def test_mcp_store_migrates_default_atlas_to_focus_args(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mcp.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "defaults": {"atlas": None},
                        "servers": [
                            {
                                "id": "atlas-default",
                                "name": "Atlas 默认 MCP",
                                "transport": "stdio",
                                "kind": "atlas",
                                "command": "atlas",
                                "args": ["mcp", "--project", "{project}", "--log-format", "json"],
                                "cwd": "{project}",
                                "env": {},
                                "enabled": True,
                                "description": "使用本地 atlas mcp 启动项目代码图 MCP Server。",
                            }
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            store = MCPServerStore(path)
            store.ensure_default_atlas()
            migrated = next(item for item in store.list() if item["id"] == "atlas-default")

            self.assertEqual(migrated["args"], ["mcp", "--log-format", "json"])
            self.assertNotIn("--project", migrated["args"])
            self.assertEqual(store.defaults()["atlas"], "atlas-default")

    def test_api_serves_records_and_html(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, skills = write_python_fixture(root)
            store = RunRecordStore(root / "records")
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(store))
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                request = urllib.request.Request(
                    f"{base}/runs",
                    data=json.dumps(
                        {
                            "sarif_path": str(sarif),
                            "source_path": str(root),
                            "skills_path": str(skills),
                            "enable_external_tools": False,
                        }
                    ).encode("utf-8"),
                    headers={"content-type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    created = json.loads(response.read().decode("utf-8"))
                run = wait_for_run_completed(base, created["run_id"])
                with urllib.request.urlopen(f"{base}/runs", timeout=5) as response:
                    runs = json.loads(response.read().decode("utf-8"))
                with urllib.request.urlopen(f"{base}/runs/{created['run_id']}/findings", timeout=5) as response:
                    findings = json.loads(response.read().decode("utf-8"))
                finding_id = findings[0]["finding_id"]
                manual_review_url = f"{base}/runs/{created['run_id']}/findings/{finding_id}/manual-review"
                create_review_request = urllib.request.Request(
                    manual_review_url,
                    data=json.dumps(
                        {"decision": "TRUE_POSITIVE", "evidence": "人工确认请求参数可到达危险函数。"}
                    ).encode("utf-8"),
                    headers={"content-type": "application/json"},
                    method="PUT",
                )
                with urllib.request.urlopen(create_review_request, timeout=5) as response:
                    created_review = json.loads(response.read().decode("utf-8"))
                    self.assertEqual(response.status, HTTPStatus.CREATED)
                self.assertTrue(created_review["created"])
                first_created_at = created_review["manual_review"]["created_at"]

                update_review_request = urllib.request.Request(
                    manual_review_url,
                    data=json.dumps(
                        {"decision": "FALSE_POSITIVE", "evidence": "人工复核确认存在固定白名单映射。"}
                    ).encode("utf-8"),
                    headers={"content-type": "application/json"},
                    method="PUT",
                )
                with urllib.request.urlopen(update_review_request, timeout=5) as response:
                    updated_review = json.loads(response.read().decode("utf-8"))
                    self.assertEqual(response.status, HTTPStatus.OK)
                self.assertFalse(updated_review["created"])
                self.assertEqual(updated_review["manual_review"]["created_at"], first_created_at)

                with urllib.request.urlopen(f"{base}/runs/{created['run_id']}/findings", timeout=5) as response:
                    reviewed_findings = json.loads(response.read().decode("utf-8"))
                with urllib.request.urlopen(
                    f"{base}/runs/{created['run_id']}/findings/{finding_id}", timeout=5
                ) as response:
                    reviewed_detail = json.loads(response.read().decode("utf-8"))
                self.assertEqual(reviewed_findings[0]["manual_review"]["decision"], "FALSE_POSITIVE")
                self.assertEqual(reviewed_detail["manual_review"]["evidence"], "人工复核确认存在固定白名单映射。")
                with urllib.request.urlopen(
                    f"{base}/runs/{created['run_id']}/export?format=markdown",
                    timeout=5,
                ) as response:
                    markdown_report = response.read().decode("utf-8")
                    self.assertEqual(response.headers.get_content_type(), "text/markdown")
                    self.assertIn("attachment;", response.headers.get("content-disposition", ""))
                with urllib.request.urlopen(
                    f"{base}/runs/{created['run_id']}/export?format=json",
                    timeout=5,
                ) as response:
                    json_report = json.loads(response.read().decode("utf-8"))
                    self.assertEqual(response.headers.get_content_type(), "application/json")
                with urllib.request.urlopen(f"{base}/", timeout=5) as response:
                    html = response.read().decode("utf-8")
                self.assertEqual(len(runs), 1)
                self.assertEqual(run["run_origin"], "web")
                self.assertEqual(runs[0]["run_origin"], "web")
                self.assertEqual(json_report["run_id"], run["run_id"])
                self.assertEqual(json_report["run_origin"], "web")
                self.assertEqual(json_report["manual_reviews"][finding_id]["decision"], "FALSE_POSITIVE")
                self.assertIn("# 漏洞研判报告", markdown_report)
                self.assertIn(f"- 任务 ID：{created['run_id']}", markdown_report)
                self.assertIn("- 任务来源：Web 端", markdown_report)
                self.assertIn("## 发现 1:", markdown_report)
                self.assertIn("### 人工复核", markdown_report)
                self.assertIn("- 人工结论：误报", markdown_report)
                self.assertIn("人工复核确认存在固定白名单映射。", markdown_report)
                self.assertIn("### 调用链 / 数据流概览", markdown_report)
                self.assertNotIn("```mermaid", markdown_report)
                overview_section = markdown_report.split("### 调用链 / 数据流概览", 1)[1].split("### 摘要", 1)[0]
                self.assertIn("数据流状态", overview_section)
                self.assertIn("app.py:4:11", overview_section)
                self.assertIn("app.py:5:5", overview_section)
                self.assertIn("↓", overview_section)
                self.assertNotIn("ev-", overview_section)
                self.assertIn("### 博弈过程", markdown_report)
                self.assertIn("evidence_graph", json_report["reports"][0])
                self.assertEqual(findings[0]["verdict"], "TRUE_POSITIVE")
                self.assertIn("漏洞研判记录", html)
                invalid_review_request = urllib.request.Request(
                    manual_review_url,
                    data=json.dumps({"decision": "UNKNOWN", "evidence": "invalid"}).encode("utf-8"),
                    headers={"content-type": "application/json"},
                    method="PUT",
                )
                with self.assertRaises(urllib.error.HTTPError) as invalid_context:
                    urllib.request.urlopen(invalid_review_request, timeout=5)
                self.assertEqual(invalid_context.exception.code, HTTPStatus.BAD_REQUEST)

                clear_review_request = urllib.request.Request(manual_review_url, method="DELETE")
                with urllib.request.urlopen(clear_review_request, timeout=5) as response:
                    cleared_review = json.loads(response.read().decode("utf-8"))
                self.assertTrue(cleared_review["deleted"])
                with urllib.request.urlopen(
                    f"{base}/runs/{created['run_id']}/findings/{finding_id}", timeout=5
                ) as response:
                    cleared_detail = json.loads(response.read().decode("utf-8"))
                self.assertIsNone(cleared_detail["manual_review"])
                delete_request = urllib.request.Request(f"{base}/runs/{created['run_id']}", method="DELETE")
                with urllib.request.urlopen(delete_request, timeout=5) as response:
                    deleted = json.loads(response.read().decode("utf-8"))
                self.assertTrue(deleted["deleted"])
                with urllib.request.urlopen(f"{base}/runs", timeout=5) as response:
                    runs_after_delete = json.loads(response.read().decode("utf-8"))
                self.assertEqual(runs_after_delete, [])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_app_html_contains_core_mount_points(self):
        html = app_html()
        self.assertIn('<html lang="zh-CN">', html)
        self.assertIn('id="run-list"', html)
        self.assertIn('id="detail"', html)
        self.assertIn('id="open-run-config"', html)
        self.assertIn('id="run-config-modal"', html)
        self.assertIn('id="run-config-panel"', html)
        self.assertIn('id="open-providers"', html)
        self.assertIn('id="providers-modal"', html)
        self.assertIn('id="provider-panel"', html)
        self.assertIn('id="open-agent-prompts"', html)
        self.assertIn('id="agent-prompts-modal"', html)
        self.assertIn('id="open-integrations"', html)
        self.assertIn('id="integrations-modal"', html)
        self.assertIn('id="auto-refresh"', html)
        self.assertIn('自动刷新：关', html)
        self.assertIn('state.autoRefreshEnabled', html)
        self.assertIn('function toggleAutoRefresh()', html)
        self.assertIn('function updateAutoRefreshControl()', html)
        self.assertIn('async function refreshSelectedRun(resetFinding = false)', html)
        self.assertIn('await refreshSelectedRun(false)', html)
        self.assertIn('id="mcp-server-panel"', html)
        self.assertIn('id="skill-source-panel"', html)
        self.assertIn('#mcp-server-panel', html)
        self.assertIn('#integrations-modal .settings-body', html)
        self.assertIn('flex-direction: column', html)
        self.assertIn('flex: 1 1 auto', html)
        self.assertIn('class="wide checkbox-row"', html)
        self.assertIn('启用 MCP Server', html)
        self.assertNotIn('min-height: 720px', html)
        self.assertIn('#skill-source-panel', html)
        self.assertNotIn('min-height: 520px', html)
        self.assertIn('id="mcp-list"', html)
        self.assertIn('id="skill-list"', html)
        self.assertIn('id="default-atlas-mcp"', html)
        self.assertIn('id="default-skill-source"', html)
        self.assertIn('id="run-skill-source"', html)
        self.assertNotIn('id="run-languages"', html)
        self.assertIn('预热 Atlas 持久缓存', html)
        self.assertNotIn('自动索引工具', html)
        self.assertNotIn('id="run-agentic-atlas"', html)
        self.assertNotIn('id="run-agentic-atlas-direct"', html)
        self.assertNotIn('直接 AI 自主运行 Atlas MCP', html)
        self.assertIn('function runOriginLabel(run)', html)
        self.assertIn('任务来源', html)
        self.assertIn('chip origin', html)
        self.assertIn('class="run-agent-grid"', html)
        self.assertLess(html.index('id="run-affirmative-provider"'), html.index('id="run-affirmative-agent-profile"'))
        self.assertLess(html.index('id="run-negative-provider"'), html.index('id="run-negative-agent-profile"'))
        self.assertLess(html.index('id="run-moderator-provider"'), html.index('id="run-moderator-agent-profile"'))
        self.assertIn('id="agent-affirmative-profile-panel"', html)
        self.assertIn('id="agent-negative-profile-panel"', html)
        self.assertIn('id="agent-moderator-profile-panel"', html)
        self.assertIn('#agent-affirmative-profile-panel', html)
        self.assertIn('min-height: 560px', html)
        self.assertIn('overflow: visible', html)
        self.assertIn('id="agent-affirmative-profile-list"', html)
        self.assertIn('id="agent-negative-profile-list"', html)
        self.assertIn('id="agent-moderator-profile-list"', html)
        self.assertIn('id="new-affirmative-agent"', html)
        self.assertIn('id="new-negative-agent"', html)
        self.assertIn('id="new-moderator-agent"', html)
        self.assertIn('id="agent-profile-actions"', html)
        self.assertIn('id="run-affirmative-agent-profile"', html)
        self.assertIn('id="run-negative-agent-profile"', html)
        self.assertIn('id="run-moderator-agent-profile"', html)
        self.assertIn('id="default-moderator"', html)
        self.assertIn('id="run-moderator-provider"', html)
        self.assertIn('function renderMarkdown(value)', html)
        self.assertIn('function plainText(value)', html)
        self.assertIn('function rawText(value)', html)
        self.assertIn('function displayText(value)', html)
        self.assertIn('line.match(/^(#{1,6})\\s+(.+)$/)', html)
        self.assertNotIn('#(1, 6)', html)
        self.assertIn('promptEchoPatterns', html)
        self.assertIn('markdownBlock(turn.claim)', html)
        self.assertNotIn('plainText(turn.claim)', html)
        self.assertIn('class="plain-text"', html)
        self.assertIn('原始报告详情', html)
        self.assertIn('renderOriginalReportSection(detail)', html)
        self.assertIn('raw_result', html)
        self.assertIn('调用链 / 数据流概览', html)
        self.assertIn('function renderPathOverviewSection(detail)', html)
        self.assertIn('function buildPathOverview(graph)', html)
        self.assertIn('class="path-overview"', html)
        self.assertNotIn('function renderEvidenceGraphSection(detail)', html)
        self.assertNotIn('class="graph-edge-row"', html)
        self.assertIn('function conclusionWithoutEvidenceGraph(value)', html)
        self.assertIn('function uniqueDebateTurns(debate)', html)
        self.assertIn('function renderTable(start)', html)
        self.assertIn('function bindRunExportButtons()', html)
        self.assertIn('function exportRun(runId, format)', html)
        self.assertIn('data-run-export="markdown"', html)
        self.assertIn('data-run-export="json"', html)
        self.assertIn('data-run-copy-config="true"', html)
        self.assertIn('async function copyRunToConfig(runId)', html)
        self.assertIn('function fillRunConfigFromHistory(run)', html)
        self.assertIn('id="run-reuse-findings" type="checkbox" checked', html)
        self.assertIn('复用报告拆分结果', html)
        self.assertIn('function configureRunFindingsReuse(run)', html)
        self.assertIn('state.reuseFindingsFromRunId = available ? run.run_id : null', html)
        self.assertIn('reuse_findings_from_run_id: el.runReuseFindings.checked ? state.reuseFindingsFromRunId : null', html)
        self.assertIn('可调整参数后再启动', html)
        self.assertIn('function statusChipClass(status)', html)
        self.assertIn('.chip.status-completed', html)
        self.assertIn('.chip.status-running', html)
        self.assertIn('.chip.status-stopped', html)
        self.assertIn('${statusChipClass(status)}', html)
        self.assertNotIn('fill-demo-run', html)
        self.assertNotIn('fill-markdown-demo-run', html)
        self.assertNotIn('填入 SARIF 示例', html)
        self.assertNotIn('填入 Markdown 示例', html)
        self.assertIn('.markdown-body table', html)
        self.assertIn('class="task-item"', html)
        self.assertIn('final_conclusion', html)
        self.assertIn("REPORT: '输入报告'", html)
        self.assertIn('ensurePolling(runId)', html)
        self.assertIn('renderFindingsSection(findings)', html)
        self.assertIn('每完成一次 LLM 对话', html)
        self.assertIn('自动刷新已关闭', html)
        self.assertIn("replace(/\\r\\n?/g, '\\n')", html)
        self.assertIn('data-run-delete="true"', html)
        self.assertIn('deleteConfirmRunId: null', html)
        self.assertIn("deleteConfirming ? '确认删除？' : '删除'", html)
        self.assertIn('function handleDeleteRunClick(runId)', html)
        self.assertIn('handleDeleteRunClick(button.dataset.runId)', html)
        self.assertIn("state.deleteConfirmRunId !== runId", html)
        self.assertIn("!target?.closest('[data-run-delete]')", html)
        self.assertIn('async function deleteRun(runId)', html)
        self.assertIn('data-run-stop="true"', html)
        self.assertIn('data-run-pause="true"', html)
        self.assertIn('data-run-resume="true"', html)
        self.assertIn('class="run-item-actions"', html)
        self.assertIn('.run-item-actions', html)
        self.assertIn('class="chips run-verdict-chips"', html)
        self.assertIn('.run-verdict-chips', html)
        self.assertIn('flex-wrap: nowrap', html)
        self.assertIn('async function stopRun(runId)', html)
        self.assertIn('async function pauseRun(runId)', html)
        self.assertIn('async function resumeRun(runId)', html)
        self.assertIn('<th>人工复核</th>', html)
        self.assertIn('data-manual-review-toggle="true"', html)
        self.assertIn('class="manual-review-card"', html)
        self.assertIn('data-selected-finding-review="${esc(finding.finding_id)}"', html)
        self.assertIn('>复核</button>', html)
        self.assertLess(
            html.index('data-selected-finding-review="${esc(finding.finding_id)}"'),
            html.index('data-finding-nav="next"'),
        )
        self.assertIn('function openManualReviewFromSticky(findingId)', html)
        self.assertIn("state.expandedManualReviewKey = manualReviewKey(state.selectedRun, findingId)", html)
        self.assertIn("card.scrollIntoView({ behavior: 'smooth', block: 'center' })", html)
        self.assertIn("option('TRUE_POSITIVE', '真实漏洞')", html)
        self.assertIn("option('FALSE_POSITIVE', '误报')", html)
        self.assertIn("option('INCONCLUSIVE', '证据不足')", html)
        self.assertIn('async function saveManualReview(findingId, button)', html)
        self.assertIn('async function clearManualReview(findingId, button)', html)
        self.assertIn('state.manualReviewDrafts[key]', html)
        self.assertIn('draft.dirty = true', html)
        self.assertIn("method: 'PUT'", html)
        self.assertIn("paused: '已暂停'", html)
        self.assertIn("pausing: '正在暂停'", html)
        self.assertIn('function isTerminalStatus(status)', html)
        self.assertIn("stopped: '已停止'", html)
        self.assertIn("status === 'paused' || status === 'failed'", html)
        self.assertIn("从失败断点恢复任务", html)
        self.assertIn("任务执行失败，可点击“恢复”从断点继续", html)
        self.assertIn("SOURCE_ROOT: '源码根目录'", html)
        self.assertIn("fetchJson('/mcp-servers')", html)
        self.assertIn("fetchJson('/skill-sources')", html)
        self.assertIn('id="run-provider-agent-grid"', html)
        self.assertIn('class="run-provider-control"', html)
        self.assertIn('class="run-provider-control" hidden', html)
        self.assertIn('class="run-agent-control"', html)
        self.assertIn('class="run-builtin-control" hidden>最大回合数', html)
        self.assertIn('[hidden] { display: none !important; }', html)
        self.assertIn('id="run-tool-provider-options"', html)
        self.assertIn('id="run-codex-config-note"', html)
        self.assertIn('id="run-silence-reminder-minutes"', html)
        self.assertIn('静默提醒时间（分钟）', html)
        self.assertIn("silence_reminder_minutes: Number(el.runSilenceReminderMinutes.value || 30)", html)
        self.assertIn("config.silence_reminder_minutes || 30", html)
        self.assertIn('function updateRunEngineVisibility()', html)
        self.assertIn("el.runProviderAgentGrid.hidden = false", html)
        self.assertIn("document.querySelectorAll('.run-provider-control')", html)
        self.assertIn("document.querySelectorAll('.run-builtin-control').forEach(item => item.hidden = cliMode)", html)
        self.assertIn("affirmative_agent_profile: el.runAffirmativeAgentProfile.value || null", html)
        self.assertNotIn("affirmative_agent_profile: codexMode ? null", html)
        self.assertNotIn("el.runProviderAgentGrid.hidden = codexMode", html)
        self.assertIn('Codex 三方复核使用项目 .codex/config.toml', html)
        self.assertIn('当前活动 Agent', html)
        self.assertIn('function renderCodexActiveAgent(run, findings, status)', html)
        self.assertIn('function inferCodexActiveAgent(run, findings, status)', html)
        self.assertIn('codex_delivery', html)
        self.assertIn('function findingStatusChip(finding)', html)
        self.assertIn("pending: '未完成'", html)
        self.assertIn("in_progress: '处理中'", html)
        self.assertIn(".chip.status-pending", html)
        self.assertIn("该漏洞报告尚未完成三方复核", html)
        self.assertIn("ensurePolling(created.run_id);", html)
        self.assertLess(html.index("ensurePolling(created.run_id);"), html.index("await loadRuns();"))
        self.assertIn('正方验证阶段，等待正方 result.json', html)
        self.assertIn('反方复核阶段，正方已交付', html)
        self.assertIn('最终裁决阶段，正反方已交付', html)
        self.assertIn('/terminal-ui', html)
        self.assertIn('id="codex-terminal-frame-modal"', html)
        self.assertIn('id="close-codex-terminal-frame"', html)
        self.assertIn('id="codex-terminal-frame"', html)
        self.assertIn('在当前页面打开 Codex 隔离执行日志', html)
        self.assertIn("el.codexTerminalFrame.src = url", html)
        self.assertIn("el.codexTerminalFrame.src = 'about:blank'", html)
        self.assertIn('button.danger-button', html)
        self.assertIn('class="danger-button"', html)
        self.assertIn('data-codex-stop-sessions="true"', html)
        self.assertIn('关闭全部 Codex Sessions', html)
        self.assertIn('async function stopCodexSessions(runId, button)', html)
        self.assertIn('/codex-sessions/stop', html)
        self.assertIn('关闭当前任务的全部 Codex tmux session', html)
        self.assertLess(html.index('data-codex-terminal-role'), html.index('data-codex-stop-sessions="true"'))
        self.assertIn('function markdownBlock(value', html)
        self.assertIn('function renderCodexStructuredContent(data', html)
        self.assertIn('function renderDebateStructuredTurn(turn)', html)
        self.assertIn("markdownField('最终结论'", html)
        self.assertIn("markdownField('防护研判'", html)
        self.assertIn('markdownBlock(turn.claim)', html)
        self.assertIn('renderDebateStructuredTurn(turn)', html)
        self.assertIn('class="debate-structured"', html)
        self.assertNotIn('plainText(moderatorText', html)
        self.assertNotIn('plainText(summary ||', html)
        self.assertNotIn("window.open(url", html)
        self.assertNotIn('id="codex-terminal-modal"', html)
        self.assertNotIn('id="codex-terminal-input"', html)

    def test_finding_summary_exposes_codex_delivery_state(self):
        summary = _finding_summary(
            {
                "finding_id": "finding-1",
                "rule_id": "demo-rule",
                "verdict": "INCONCLUSIVE",
                "confidence": 0.3,
                "reasoning_summary": "等待反方复核。",
                "evidence_chain": [],
                "debate": [],
                "codex_workflow": {
                    "affirmative": {"summary": "正方已交付"},
                    "negative": {},
                    "moderator": None,
                },
            }
        )

        self.assertEqual(
            summary["codex_delivery"],
            {"affirmative": True, "negative": False, "moderator": False},
        )
        self.assertEqual(summary["finding_status"], "in_progress")
        self.assertNotIn("codex_workflow", summary)

    def test_codex_terminal_page_polls_persisted_execution_log(self):
        html = _codex_terminal_page(
            "run-1",
            "moderator",
            {
                "backend": "codex",
                "transport": "exec-ephemeral-json",
                "target": "vj-run-1-moderator:slot",
                "session_name": "vj-run-1-moderator",
            },
        )
        self.assertIn('/runs/run-1/cli-sessions/moderator/terminal', html)
        self.assertIn('window.setTimeout(pollLog, 1000)', html)
        self.assertIn('data-log-mode="readable"', html)
        self.assertIn('data-log-mode="raw"', html)
        self.assertIn('payload.formatted_output || rawOutput', html)
        self.assertIn('id="follow-log"', html)
        self.assertNotIn('/static/vendor/xterm/', html)
        self.assertNotIn('new TerminalCtor(', html)
        self.assertNotIn('new WebSocket(', html)
        self.assertNotIn('id="message-form"', html)

    def test_codex_terminal_page_uses_bidirectional_native_tui(self):
        html = _codex_terminal_page(
            "run-1",
            "affirmative",
            {
                "backend": "codex",
                "transport": "tmux-tui",
                "target": "vj-run-1-affirmative:codex",
                "session_name": "vj-run-1-affirmative",
            },
        )

        self.assertIn('/runs/run-1/cli-sessions/affirmative/ws', html)
        self.assertIn('/static/vendor/xterm/xterm.js', html)
        self.assertIn('new WebSocket(', html)
        self.assertIn('term.onData(data =>', html)
        self.assertIn('原生 tmux TUI', html)
        self.assertNotIn('data-log-mode="readable"', html)

    def test_codex_ndjson_is_rendered_as_readable_execution_log(self):
        raw = "\n".join(
            [
                json.dumps({"type": "thread.started", "thread_id": "thread-1"}),
                json.dumps({"type": "turn.started"}),
                json.dumps(
                    {
                        "type": "item.completed",
                        "item": {"type": "agent_message", "text": "已完成复核。"},
                    },
                    ensure_ascii=False,
                ),
                json.dumps(
                    {
                        "type": "item.completed",
                        "item": {
                            "type": "command_execution",
                            "command": ["rg", "dangerous_call"],
                            "aggregated_output": "src/demo.py:12",
                            "status": "completed",
                            "exit_code": 0,
                        },
                    }
                ),
                json.dumps(
                    {
                        "type": "turn.completed",
                        "usage": {"input_tokens": 12, "output_tokens": 7},
                    }
                ),
                "not-json",
            ]
        )

        output = format_codex_ndjson(raw)

        self.assertIn("[会话]\nthread-1", output)
        self.assertIn("[Codex]\n已完成复核。", output)
        self.assertIn("[命令完成]\n$ rg dangerous_call", output)
        self.assertIn("src/demo.py:12", output)
        self.assertIn("输入 12 tokens", output)
        self.assertIn("输出 7 tokens", output)
        self.assertIn("not-json", output)

    def test_codex_event_log_remains_readable_without_tmux(self):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path(tmp)
            log_dir = cwd / ".vuln-judger-codex"
            log_dir.mkdir()
            current = log_dir / "current.ndjson"
            current.write_text('{"type":"turn.started"}\n{"type":"turn.completed"}\n', encoding="utf-8")

            output = _codex_event_log(
                {
                    "cwd": str(cwd),
                    "event_log": str(current),
                    "target": "missing:slot",
                }
            )

        self.assertIn('turn.started', output)
        self.assertIn('turn.completed', output)

    def test_codex_log_http_routes_work_without_tmux(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cwd = root / "session"
            log_dir = cwd / ".vuln-judger-codex"
            log_dir.mkdir(parents=True)
            current = log_dir / "current.ndjson"
            current.write_text(
                json.dumps(
                    {
                        "type": "item.completed",
                        "item": {"type": "agent_message", "text": "route output"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            store = RunRecordStore(root / "records")
            store.save_payload(
                {
                    "run_id": "run-log",
                    "engine": "codex",
                    "status": "completed",
                    "cli_sessions": [
                        {
                            "backend": "codex",
                            "transport": "exec-ephemeral-json",
                            "role": "moderator",
                            "session_name": "vj-run-log-moderator",
                            "target": "vj-run-log-moderator:slot",
                            "cwd": str(cwd),
                            "event_log": str(current),
                        }
                    ],
                }
            )
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(store))
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                with urllib.request.urlopen(
                    f"{base}/runs/run-log/cli-sessions/moderator/terminal-ui",
                    timeout=5,
                ) as response:
                    html = response.read().decode("utf-8")
                with urllib.request.urlopen(
                    f"{base}/runs/run-log/cli-sessions/moderator/terminal",
                    timeout=5,
                ) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(
                        f"{base}/runs/run-log/cli-sessions/moderator/ws",
                        timeout=5,
                    )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

        self.assertIn('data-log-mode="readable"', html)
        self.assertNotIn('/static/vendor/xterm/', html)
        self.assertIn('"type": "item.completed"', payload["output"])
        self.assertIn("[Codex]\nroute output", payload["formatted_output"])
        self.assertEqual(caught.exception.code, HTTPStatus.CONFLICT)
        self.assertIn("不提供 tmux WebSocket", caught.exception.read().decode("utf-8"))

    def test_stop_codex_sessions_closes_all_live_sessions(self):
        payload = {
            "run_id": "run-1",
            "codex_sessions": [
                {"role": "moderator", "session_name": "vj-run-1-moderator"},
                {"role": "affirmative", "session_name": "vj-run-1-affirmative"},
                {"role": "negative", "session_name": "vj-run-1-negative"},
            ],
        }

        class Store:
            def get(self, run_id):
                return payload if run_id == "run-1" else None

        before = [
            {"role": "moderator", "live": True},
            {"role": "affirmative", "live": True},
            {"role": "negative", "live": False},
        ]
        after = [
            {"role": "moderator", "live": False},
            {"role": "affirmative", "live": False},
            {"role": "negative", "live": False},
        ]
        with patch("vuln_judger.api._codex_sessions", side_effect=[before, after]) as sessions:
            with patch("vuln_judger.api.stop_sessions") as stop:
                result = _stop_codex_sessions(Store(), {}, Lock(), "run-1")

        self.assertEqual(result["run_id"], "run-1")
        self.assertEqual(result["stopped"], 2)
        self.assertEqual(result["sessions"], after)
        self.assertEqual(sessions.call_count, 2)
        stop.assert_called_once()

    def test_codex_start_creates_native_tui_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            run_dir = root / "workspace"
            source.mkdir()
            run_dir.mkdir()
            session = CodexTmuxSession(
                role="moderator",
                run_id="run-1",
                cwd=run_dir,
                source_path=source,
                run_dir=run_dir,
                command="codex",
            )
            completed = subprocess.CompletedProcess(["tmux"], 0, "", "")
            with patch.object(session, "is_live", return_value=False), patch.object(
                session, "_accept_trust_prompt"
            ), patch.object(
                session, "_wait_until_input_ready"
            ), patch(
                "vuln_judger.codex_runner._run_tmux", return_value=completed
            ) as run_tmux:
                session.start()

            launch_args = run_tmux.call_args.args[0]
            self.assertIn("new-session", launch_args)
            self.assertIn("codex", launch_args)
            self.assertIn("--no-alt-screen", launch_args)
            self.assertIn("--dangerously-bypass-approvals-and-sandbox", launch_args)
            self.assertNotIn("exec", launch_args)
            self.assertNotIn("--json", launch_args)
            self.assertEqual(session.target, "vj-run-1-moderator:codex")
            self.assertEqual(session.info().transport, "tmux-tui")
            self.assertIsNone(session.info().event_log)

    def test_codex_send_respawns_native_tui_and_uses_bracketed_paste(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            run_dir = root / "workspace"
            source.mkdir()
            run_dir.mkdir()
            session = CodexTmuxSession(
                role="moderator",
                run_id="run-1",
                cwd=run_dir,
                source_path=source,
                run_dir=run_dir,
                command="codex",
            )
            completed = subprocess.CompletedProcess(["tmux"], 0, "", "")

            with patch.object(session, "is_live", return_value=True), patch(
                "vuln_judger.codex_runner._tmux_target_live", return_value=True
            ), patch.object(
                session, "_accept_trust_prompt"
            ), patch.object(
                session, "_wait_until_input_ready"
            ), patch.object(
                session, "_wait_until_task_started"
            ) as wait_started, patch(
                "vuln_judger.codex_runner.subprocess.run", return_value=completed
            ) as run, patch(
                "vuln_judger.codex_runner._run_tmux", return_value=completed
            ) as run_tmux, patch.dict(
                os.environ,
                {"VULN_JUDGER_CODEX_PASTE_SETTLE": "0", "VULN_JUDGER_CODEX_SUBMIT_KEY": "C-m"},
                clear=False,
            ):
                session.send("line one\r\nline two")

            self.assertEqual(run.call_args.kwargs["input"], "line one\nline two")
            tmux_calls = [call.args[0] for call in run_tmux.call_args_list]
            respawn = next(args for args in tmux_calls if "respawn-pane" in args)
            self.assertIn("-k", respawn)
            self.assertIn(session.target, respawn)
            self.assertIn("codex", respawn)
            self.assertIn("--no-alt-screen", respawn)
            self.assertNotIn("exec", respawn)
            self.assertIn(
                [
                    "tmux",
                    "paste-buffer",
                    "-d",
                    "-p",
                    "-r",
                    "-b",
                    "vj-run-1-moderator-input",
                    "-t",
                    session.target,
                ],
                tmux_calls,
            )
            self.assertIn(["tmux", "send-keys", "-t", session.target, "C-m"], tmux_calls)
            wait_started.assert_called_once()

    def test_codex_accept_output_resets_turn_and_reuses_fresh_tui(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = CodexTmuxSession(
                role="negative",
                run_id="run-1",
                cwd=root,
                source_path=root,
                run_dir=root,
                command="codex",
            )
            session._task_started = True
            completed = subprocess.CompletedProcess(["tmux"], 0, "", "")

            with patch(
                "vuln_judger.codex_runner._tmux_target_live", return_value=True
            ), patch(
                "vuln_judger.codex_runner._run_tmux", return_value=completed
            ) as run_tmux:
                session.accept_output()

            tmux_calls = [call.args[0] for call in run_tmux.call_args_list]
            self.assertTrue(any("respawn-pane" in args and "-k" in args for args in tmux_calls))
            self.assertFalse(session._task_started)
            self.assertTrue(session._fresh_tui)

            with patch.object(session, "is_live", return_value=True), patch.object(
                session, "_accept_trust_prompt"
            ), patch.object(
                session, "_wait_until_input_ready"
            ), patch.object(
                session, "_capture_visible", return_value="fresh Codex prompt"
            ), patch.object(
                session, "_restart_tui"
            ) as restart, patch.object(
                session, "_wait_until_task_started"
            ), patch(
                "vuln_judger.codex_runner._send_text_to_tmux_target"
            ):
                session.send("next isolated stage")

            restart.assert_not_called()
            self.assertFalse(session._fresh_tui)

    def test_codex_restart_missing_target_does_not_respawn_twice(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = CodexTmuxSession(
                role="moderator",
                run_id="run-1",
                cwd=root,
                source_path=root,
                run_dir=root,
                command="codex",
            )
            with patch(
                "vuln_judger.codex_runner._tmux_target_live", return_value=False
            ), patch.object(
                session, "is_live", return_value=False
            ), patch.object(
                session, "start"
            ) as start, patch(
                "vuln_judger.codex_runner._run_tmux"
            ) as run_tmux:
                session._restart_tui()

            start.assert_called_once_with()
            run_tmux.assert_not_called()

    def test_codex_task_start_accepts_fast_completed_screen_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = CodexTmuxSession(
                role="affirmative",
                run_id="run-1",
                cwd=root,
                source_path=root,
                run_dir=root,
                command="codex",
            )
            with patch.object(
                session,
                "_capture_visible",
                return_value="Codex\n› submitted task\n• wrote result.json\n›",
            ), patch(
                "vuln_judger.codex_runner._tmux_target_live", return_value=True
            ):
                session._wait_until_task_started("Codex\n›")

            self.assertTrue(session._task_started)

    def test_codex_trust_prompt_uses_visible_pane_and_dedicated_enter_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = CodexTmuxSession(
                role="moderator",
                run_id="run-1",
                cwd=root,
                source_path=root,
                run_dir=root,
                command="codex",
            )
            modal = "Do you trust the contents of this directory?\n› 1. Yes, continue\n  2. No, quit"
            completed = subprocess.CompletedProcess(["tmux"], 0, "", "")
            with patch.object(
                session, "_capture_visible", side_effect=[modal, "Codex ready\n›"]
            ), patch(
                "vuln_judger.codex_runner._run_tmux", return_value=completed
            ) as run_tmux, patch(
                "vuln_judger.codex_runner.time.sleep"
            ):
                session._accept_trust_prompt()

            run_tmux.assert_called_once_with(
                ["tmux", "send-keys", "-t", session.target, "Enter"], timeout=5
            )

    def test_codex_activity_snapshot_ignores_elapsed_timer_only_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = CodexTmuxSession(
                role="affirmative",
                run_id="run-1",
                cwd=root,
                source_path=root,
                run_dir=root,
                command="codex",
            )
            captures = [
                "working\n(12s • esc to interrupt)",
                "working\n(13s • esc to interrupt)",
            ]
            with patch.object(session, "capture", side_effect=captures):
                first = session.activity_snapshot()
                second = session.activity_snapshot()

            self.assertEqual(first[0], second[0])
            self.assertTrue(first[1])
            self.assertTrue(second[1])

    def test_long_tmux_names_keep_distinct_hash_suffixes(self):
        common = "run-" + "a" * 100
        first = _safe_tmux_name(f"{common}-one")
        second = _safe_tmux_name(f"{common}-two")

        self.assertLessEqual(len(first), 80)
        self.assertLessEqual(len(second), 80)
        self.assertNotEqual(first, second)

    def test_cli_launch_without_start_marker_fails_instead_of_stalling_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {"VULN_JUDGER_CLI_START_TIMEOUT": "0.01"},
        ):
            root = Path(tmp)
            with self.assertRaisesRegex(CodexRunnerError, "正方 任务未确认启动"):
                _wait_for_cli_task_start(
                    label="Codex 正方",
                    started_path=root / "started.txt",
                    event_path=root / "events.ndjson",
                    exit_path=root / "exit.txt",
                    is_running=lambda: False,
                )

    def test_codex_tui_exit_during_task_is_reported_as_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = CodexTmuxSession(
                role="affirmative",
                run_id="run-1",
                cwd=root,
                source_path=root,
                run_dir=root,
                command="codex",
            )
            session._task_started = True

            with patch("vuln_judger.codex_runner._tmux_target_live", return_value=False):
                self.assertFalse(session.task_finished())
                failure = session.failure_message()

            self.assertIn("任务执行期间退出", failure)
            self.assertIn(session.target, failure)

    def test_pipeline_output_identity_rejects_cross_finding_or_attempt(self):
        valid = {
            "role": "affirmative",
            "finding_id": "finding-1",
            "attempt_id": "attempt-1",
            "position": "TRUE_POSITIVE",
            "confidence": 0.8,
        }
        _validate_pipeline_output(
            valid,
            finding_id="finding-1",
            role="affirmative",
            attempt_id="attempt-1",
            strict_identity=True,
        )
        with self.assertRaises(CodexRunnerError):
            _validate_pipeline_output(
                {**valid, "finding_id": "finding-2"},
                finding_id="finding-1",
                role="affirmative",
                attempt_id="attempt-1",
                strict_identity=True,
            )
        with self.assertRaises(CodexRunnerError):
            _validate_pipeline_output(
                {**valid, "attempt_id": "old-attempt"},
                finding_id="finding-1",
                role="affirmative",
                attempt_id="attempt-1",
                strict_identity=True,
            )

    def test_pipeline_output_stamps_only_a_missing_attempt_id(self):
        result = {
            "role": "negative",
            "finding_id": "finding-1",
            "position": "TRUE_POSITIVE",
            "confidence": 0.8,
        }
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "result.json"
            output.write_text(json.dumps(result), encoding="utf-8")

            _validate_and_stamp_pipeline_output(
                result,
                output_path=output,
                finding_id="finding-1",
                role="negative",
                attempt_id="attempt-current",
            )

            self.assertEqual(result["attempt_id"], "attempt-current")
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["attempt_id"], "attempt-current")
            with self.assertRaisesRegex(CodexRunnerError, "attempt_id 不匹配"):
                _validate_and_stamp_pipeline_output(
                    {**result, "attempt_id": "attempt-stale"},
                    output_path=output,
                    finding_id="finding-1",
                    role="negative",
                    attempt_id="attempt-current",
                )

    def test_wait_json_reports_missing_output_file(self):
        class FinishedSession:
            role = "affirmative"

            def task_finished(self):
                return True

        with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(
            CodexRunnerError,
            "最后错误：文件不存在",
        ):
            _wait_json(
                Path(tmp) / "result.json",
                should_stop=None,
                reminder_session=FinishedSession(),
                timeout_seconds=1,
                poll_interval_seconds=0.001,
            )

    def test_markdown_single_finding_is_finalized_from_source_report(self):
        report_text = "# Finding\n\nEvidence\n\n"
        data = {
            "findings": [
                {
                    "finding_id": "finding-1",
                    "rule_id": "demo",
                    "message": "demo",
                    "level": "warning",
                    "locations": [],
                    "code_flows": [],
                    "report_markdown": "# Finding\n\nEvidence\n",
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "findings.json"
            finalized = _finalize_markdown_findings(path, data, report_text)
            persisted = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(finalized["findings"][0]["report_markdown"], report_text)
        self.assertEqual(persisted["findings"][0]["report_markdown"], report_text)
        self.assertEqual(data["findings"][0]["report_markdown"], "# Finding\n\nEvidence\n")

        prompt = _moderator_report_prompt({"report_path": "/tmp/report.md"}, Path("/tmp/findings.json"))
        self.assertIn("单 finding 时可留空", prompt)
        self.assertIn("不要对 report_markdown 与源文件做逐字节相等校验", prompt)

    def test_wait_json_reminds_idle_next_agent_after_previous_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = root / "affirmative.json"
            output = root / "negative.json"
            previous.write_text('{"position":"TRUE_POSITIVE"}\n', encoding="utf-8")
            events = []

            class FakeSession:
                role = "negative"

                def __init__(self):
                    self.sent = []

                def is_live(self):
                    return True

                def capture(self):
                    return "idle prompt"

                def send(self, text):
                    self.sent.append(text)
                    output.write_text('{"position":"FALSE_POSITIVE"}\n', encoding="utf-8")

            session = FakeSession()
            result = _wait_json(
                output,
                should_stop=None,
                timeout_seconds=1,
                reminder_session=session,
                previous_output_path=previous,
                stage_prompt="full negative prompt",
                silence_reminder_seconds=0.03,
                watchdog_callback=events.append,
                poll_interval_seconds=0.002,
                activity_poll_seconds=0.01,
            )

            self.assertEqual(result["position"], "FALSE_POSITIVE")
            self.assertEqual(len(session.sent), 1)
            self.assertTrue(session.sent[0].startswith("调度器没有找到当前阶段要求的交付文件"))
            self.assertIn(f"缺失的目标输出文件：{output}", session.sent[0])
            self.assertIn(f"上游交付件：{previous}", session.sent[0])
            self.assertIn("拒绝原因：文件不存在", session.sent[0])
            self.assertIn("full negative prompt", session.sent[0])
            self.assertEqual(events[0]["kind"], "reminder")
            self.assertEqual(events[0]["role"], "negative")
            self.assertEqual(events[0]["artifact_state"], "missing")

    def test_wait_json_resets_silence_timer_while_agent_is_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = root / "previous.json"
            output = root / "result.json"
            previous.write_text("{}\n", encoding="utf-8")

            class ActiveSession:
                role = "affirmative"

                def __init__(self):
                    self.capture_count = 0
                    self.sent = []

                def is_live(self):
                    return True

                def capture(self):
                    self.capture_count += 1
                    if self.capture_count == 5:
                        output.write_text('{"summary":"done"}\n', encoding="utf-8")
                    return f"agent output {self.capture_count}"

                def send(self, text):
                    self.sent.append(text)

            session = ActiveSession()
            result = _wait_json(
                output,
                should_stop=None,
                timeout_seconds=1,
                reminder_session=session,
                previous_output_path=previous,
                stage_prompt="full affirmative prompt",
                silence_reminder_seconds=0.025,
                poll_interval_seconds=0.002,
                activity_poll_seconds=0.007,
            )

            self.assertEqual(result["summary"], "done")
            self.assertEqual(session.sent, [])

    def test_wait_json_does_not_remind_when_previous_output_is_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = root / "previous.json"
            output = root / "result.json"
            previous.write_text("{invalid", encoding="utf-8")

            class IdleSession:
                role = "negative"

                def __init__(self):
                    self.sent = []

                def is_live(self):
                    return True

                def capture(self):
                    return "idle prompt"

                def send(self, text):
                    self.sent.append(text)

            session = IdleSession()
            with self.assertRaises(CodexRunnerError):
                _wait_json(
                    output,
                    should_stop=None,
                    timeout_seconds=0.06,
                    reminder_session=session,
                    previous_output_path=previous,
                    stage_prompt="full negative prompt",
                    silence_reminder_seconds=0.015,
                    poll_interval_seconds=0.002,
                    activity_poll_seconds=0.005,
                )

            self.assertEqual(session.sent, [])

    def test_wait_json_does_not_redeliver_prompt_when_session_exited(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "findings.json"
            events = []

            class ExitedSession:
                role = "moderator"

                def __init__(self):
                    self.live = False
                    self.sent = []

                def is_live(self):
                    return self.live

                def capture(self):
                    return "restarted"

                def send(self, text):
                    self.live = True
                    self.sent.append(text)
                    output.write_text('{"findings":[]}\n', encoding="utf-8")

            session = ExitedSession()
            with self.assertRaises(CodexRunnerError):
                _wait_json(
                    output,
                    should_stop=None,
                    timeout_seconds=0.06,
                    reminder_session=session,
                    stage_prompt="full moderator prompt",
                    silence_reminder_seconds=0.02,
                    watchdog_callback=events.append,
                    poll_interval_seconds=0.002,
                    activity_poll_seconds=0.01,
                )

            self.assertEqual(session.sent, [])
            self.assertEqual(events, [])

    def test_wait_json_reminds_moderator_without_upstream_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "findings.json"
            events = []

            class IdleModeratorSession:
                role = "moderator"

                def __init__(self):
                    self.sent = []

                def is_live(self):
                    return True

                def capture(self):
                    return "idle prompt"

                def send(self, text):
                    self.sent.append(text)
                    output.write_text('{"findings":[]}\n', encoding="utf-8")

            session = IdleModeratorSession()
            result = _wait_json(
                output,
                should_stop=None,
                timeout_seconds=1,
                reminder_session=session,
                stage_prompt="full report split prompt",
                silence_reminder_seconds=0.02,
                watchdog_callback=events.append,
                poll_interval_seconds=0.002,
                activity_poll_seconds=0.005,
            )

            self.assertEqual(result, {"findings": []})
            self.assertEqual(len(session.sent), 1)
            self.assertIn("full report split prompt", session.sent[0])
            self.assertNotIn("上游交付件：", session.sent[0])
            self.assertEqual(events[0]["kind"], "reminder")

    def test_wait_json_watchdog_explains_semantically_invalid_delivery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = root / "affirmative.json"
            output = root / "negative.json"
            previous.write_text('{"position":"TRUE_POSITIVE"}\n', encoding="utf-8")
            output.write_text('{"position":"FALSE_POSITIVE"}\n', encoding="utf-8")
            events = []

            def validate(data):
                if "confidence" not in data:
                    raise CodexRunnerError("negative 输出缺少 confidence")

            class IdleSession:
                role = "negative"

                def __init__(self):
                    self.sent = []

                def is_live(self):
                    return True

                def capture(self):
                    return "idle prompt"

                def send(self, text):
                    self.sent.append(text)
                    output.write_text(
                        '{"position":"FALSE_POSITIVE","confidence":0.9}\n',
                        encoding="utf-8",
                    )

            session = IdleSession()
            result = _wait_json(
                output,
                should_stop=None,
                timeout_seconds=1,
                reminder_session=session,
                previous_output_path=previous,
                stage_prompt="full negative correction prompt",
                silence_reminder_seconds=0.02,
                watchdog_callback=events.append,
                validator=validate,
                poll_interval_seconds=0.002,
                activity_poll_seconds=0.005,
            )

            self.assertEqual(result["confidence"], 0.9)
            self.assertEqual(len(session.sent), 1)
            correction = session.sent[0]
            self.assertTrue(correction.startswith(SILENCE_REMINDER_PROMPT))
            self.assertIn("交付状态：文件已经存在", correction)
            self.assertIn("拒绝原因：negative 输出缺少 confidence", correction)
            self.assertIn(f"被拒绝的输出文件：{output}", correction)
            self.assertIn(f"上游交付件：{previous}", correction)
            self.assertIn("full negative correction prompt", correction)
            self.assertIn('"position":"FALSE_POSITIVE"', correction)
            self.assertEqual(events[0]["kind"], "delivery_correction")
            self.assertEqual(events[0]["artifact_state"], "invalid")
            self.assertEqual(events[0]["validation_error"], "negative 输出缺少 confidence")

    def test_wait_json_watchdog_shows_malformed_artifact_and_parse_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = root / "affirmative.json"
            output = root / "negative.json"
            previous.write_text('{"position":"TRUE_POSITIVE"}\n', encoding="utf-8")
            output.write_text('{"position": invalid}', encoding="utf-8")
            events = []

            class IdleSession:
                role = "negative"

                def __init__(self):
                    self.sent = []

                def is_live(self):
                    return True

                def capture(self):
                    return "idle prompt"

                def send(self, text):
                    self.sent.append(text)
                    output.write_text('{"position":"FALSE_POSITIVE"}\n', encoding="utf-8")

            session = IdleSession()
            result = _wait_json(
                output,
                should_stop=None,
                timeout_seconds=1,
                reminder_session=session,
                previous_output_path=previous,
                stage_prompt="full malformed correction prompt",
                silence_reminder_seconds=0.02,
                watchdog_callback=events.append,
                poll_interval_seconds=0.002,
                activity_poll_seconds=0.005,
            )

            self.assertEqual(result["position"], "FALSE_POSITIVE")
            self.assertEqual(len(session.sent), 1)
            correction = session.sent[0]
            self.assertTrue(correction.startswith(SILENCE_REMINDER_PROMPT))
            self.assertIn("拒绝原因：", correction)
            self.assertIn("Expecting value", correction)
            self.assertIn('{"position": invalid}', correction)
            self.assertIn("full malformed correction prompt", correction)
            self.assertEqual(events[0]["kind"], "delivery_correction")

    def test_wait_json_watchdog_interrupts_stuck_busy_opencode_turn(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = root / "affirmative.json"
            output = root / "negative.json"
            previous.write_text('{"position":"TRUE_POSITIVE"}\n', encoding="utf-8")
            output.write_text('{"position":"FALSE_POSITIVE"}\n', encoding="utf-8")
            events = []

            def validate(data):
                if "confidence" not in data:
                    raise CodexRunnerError("negative 输出缺少 confidence")

            class BusyOpenCodeSession:
                role = "negative"

                def __init__(self):
                    self.busy = True
                    self.interrupt_count = 0
                    self.sent = []

                def is_live(self):
                    return True

                def activity_snapshot(self):
                    return "unchanged-provider-turn", self.busy

                def interrupt(self):
                    self.interrupt_count += 1
                    self.busy = False

                def send(self, text):
                    self.sent.append(text)
                    output.write_text(
                        '{"position":"FALSE_POSITIVE","confidence":0.9}\n',
                        encoding="utf-8",
                    )

            session = BusyOpenCodeSession()
            result = _wait_json(
                output,
                should_stop=None,
                timeout_seconds=1,
                reminder_session=session,
                previous_output_path=previous,
                stage_prompt="full negative correction prompt",
                silence_reminder_seconds=0.02,
                watchdog_callback=events.append,
                validator=validate,
                poll_interval_seconds=0.002,
                activity_poll_seconds=0.005,
            )

            self.assertEqual(result["confidence"], 0.9)
            self.assertEqual(session.interrupt_count, 1)
            self.assertEqual(len(session.sent), 1)
            self.assertIn("negative 输出缺少 confidence", session.sent[0])
            self.assertTrue(events[0]["preempted_busy_turn"])

    def test_wait_json_only_sends_silence_reminder_for_idle_isolated_transport(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = root / "previous.json"
            output = root / "result.json"
            previous.write_text('{"position":"TRUE_POSITIVE"}\n', encoding="utf-8")
            events = []

            class IsolatedSession:
                role = "negative"

                def __init__(self):
                    self.sent = []

                def info(self):
                    return {"role": self.role, "transport": "exec-ephemeral-json"}

                def is_live(self):
                    return True

                def activity_snapshot(self):
                    return "idle", False

                def send(self, text):
                    self.sent.append(text)
                    output.write_text('{"summary":"recovered"}\n', encoding="utf-8")

            session = IsolatedSession()
            result = _wait_json(
                output,
                should_stop=None,
                timeout_seconds=1,
                reminder_session=session,
                previous_output_path=previous,
                stage_prompt="full isolated stage prompt",
                silence_reminder_seconds=0.02,
                watchdog_callback=events.append,
                poll_interval_seconds=0.002,
                activity_poll_seconds=0.005,
            )

            self.assertEqual(result, {"summary": "recovered"})
            self.assertEqual(len(session.sent), 1)
            self.assertTrue(session.sent[0].startswith("调度器没有找到当前阶段要求的交付文件"))
            self.assertIn("full isolated stage prompt", session.sent[0])
            self.assertIn(f"缺失的目标输出文件：{output}", session.sent[0])
            self.assertEqual(events[0]["kind"], "reminder")

    def test_wait_json_accepts_valid_pipeline_output_while_opencode_is_retrying(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "result.json"
            expected = {
                "finding_id": "finding-1",
                "role": "affirmative",
                "position": "TRUE_POSITIVE",
                "confidence": 0.9,
            }
            output.write_text(json.dumps(expected), encoding="utf-8")

            class RetryingSession:
                role = "affirmative"

                def __init__(self):
                    self.accepted = 0

                def task_finished(self):
                    return False

                def accept_output(self):
                    self.accepted += 1

            session = RetryingSession()

            def validate(data):
                _validate_and_stamp_pipeline_output(
                    data,
                    output_path=output,
                    finding_id="finding-1",
                    role="affirmative",
                    attempt_id="attempt-1",
                )

            result = _wait_json(
                output,
                should_stop=None,
                timeout_seconds=1,
                reminder_session=session,
                validator=validate,
                complete_on_valid=True,
                poll_interval_seconds=0.002,
            )

            self.assertEqual(result, {**expected, "attempt_id": "attempt-1"})
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["attempt_id"], "attempt-1")
            self.assertEqual(session.accepted, 1)

    def test_wait_json_accepts_existing_codex_artifact_without_started_turn(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "findings.json"
            expected = {"findings": []}
            output.write_text(json.dumps(expected), encoding="utf-8")
            session = CodexTmuxSession(
                role="moderator",
                run_id="run-resume",
                cwd=root,
                source_path=root,
                run_dir=root,
                command="codex",
            )

            with patch.object(session, "_reset_tui_after_turn") as reset:
                result = _wait_json(
                    output,
                    should_stop=None,
                    timeout_seconds=0.1,
                    reminder_session=session,
                    complete_on_valid=True,
                    poll_interval_seconds=0.002,
                )

            self.assertEqual(result, expected)
            reset.assert_not_called()

    def test_wait_json_corrects_completed_malformed_turn_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "result.json"
            output.write_text('{"position": invalid}', encoding="utf-8")
            events = []

            class CompletedSession:
                role = "negative"

                def __init__(self):
                    self.sent = []
                    self.accepted = 0

                def is_live(self):
                    return True

                def task_finished(self):
                    return True

                def activity_snapshot(self):
                    return "idle", False

                def send(self, text):
                    self.sent.append(text)
                    output.write_text(
                        '{"position":"FALSE_POSITIVE","confidence":0.9}\n',
                        encoding="utf-8",
                    )

                def accept_output(self):
                    self.accepted += 1

            def validate(data):
                if "confidence" not in data:
                    raise CodexRunnerError("negative 输出缺少 confidence")

            session = CompletedSession()
            result = _wait_json(
                output,
                should_stop=None,
                timeout_seconds=1,
                reminder_session=session,
                stage_prompt="full correction context",
                watchdog_callback=events.append,
                validator=validate,
                complete_on_valid=True,
                poll_interval_seconds=0.002,
            )

            self.assertEqual(result["confidence"], 0.9)
            self.assertEqual(len(session.sent), 1)
            self.assertEqual(session.accepted, 1)
            self.assertIn("Expecting value", session.sent[0])
            self.assertEqual(events[0]["trigger"], "turn_completed_without_valid_artifact")

    def test_wait_json_does_not_loop_completed_missing_turn_corrections(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "result.json"

            class CompletedSession:
                role = "negative"

                def __init__(self):
                    self.sent = []

                def is_live(self):
                    return True

                def task_finished(self):
                    return True

                def activity_snapshot(self):
                    return "idle", False

                def send(self, text):
                    self.sent.append(text)

            session = CompletedSession()
            with self.assertRaisesRegex(CodexRunnerError, "已结束但未生成合法 JSON"):
                _wait_json(
                    output,
                    should_stop=None,
                    timeout_seconds=1,
                    reminder_session=session,
                    stage_prompt="full correction context",
                    complete_on_valid=True,
                    poll_interval_seconds=0.002,
                )

            self.assertEqual(len(session.sent), 1)

    def test_wait_json_stops_invalid_opencode_delivery_and_corrects_immediately(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = root / "affirmative.json"
            output = root / "negative.json"
            previous.write_text('{"position":"TRUE_POSITIVE"}\n', encoding="utf-8")
            output.write_text(
                json.dumps(
                    {
                        "finding_id": "finding-1",
                        "role": "negative",
                        "position": "FALSE_POSITIVE",
                    }
                ),
                encoding="utf-8",
            )
            events = []

            class BusySession:
                role = "negative"

                def __init__(self):
                    self.busy = True
                    self.interrupted = 0
                    self.accepted = 0
                    self.sent = []

                def is_live(self):
                    return True

                def task_finished(self):
                    return False

                def activity_snapshot(self):
                    return "provider-turn", self.busy

                def interrupt(self):
                    self.interrupted += 1
                    self.busy = False

                def send(self, text):
                    self.sent.append(text)
                    self.busy = True
                    output.write_text(
                        json.dumps(
                            {
                                "finding_id": "finding-1",
                                "role": "negative",
                                "position": "FALSE_POSITIVE",
                                "confidence": 0.9,
                            }
                        ),
                        encoding="utf-8",
                    )

                def accept_output(self):
                    self.accepted += 1
                    self.busy = False

            session = BusySession()

            def validate(data):
                _validate_and_stamp_pipeline_output(
                    data,
                    output_path=output,
                    finding_id="finding-1",
                    role="negative",
                    attempt_id="attempt-1",
                )

            started = time.monotonic()
            result = _wait_json(
                output,
                should_stop=None,
                timeout_seconds=1,
                reminder_session=session,
                previous_output_path=previous,
                stage_prompt="full negative correction prompt",
                silence_reminder_seconds=600,
                watchdog_callback=events.append,
                validator=validate,
                complete_on_valid=True,
                poll_interval_seconds=0.002,
            )

            self.assertLess(time.monotonic() - started, 0.5)
            self.assertEqual(result["confidence"], 0.9)
            self.assertEqual(session.interrupted, 1)
            self.assertEqual(session.accepted, 1)
            self.assertEqual(len(session.sent), 1)
            self.assertIn("stage 输出缺少 confidence", session.sent[0])
            self.assertEqual(events[0]["trigger"], "artifact_validation")
            self.assertTrue(events[0]["preempted_busy_turn"])

    def test_wait_json_accepts_valid_moderator_findings_while_opencode_is_retrying(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "report.md"
            report.write_text("# report\n", encoding="utf-8")
            output = root / "findings.json"
            expected = {
                "findings": [
                    {
                        "finding_id": "finding-1",
                        "rule_id": "rule-1",
                        "message": "demo finding",
                        "level": "warning",
                    }
                ]
            }
            output.write_text(json.dumps(expected), encoding="utf-8")

            class RetryingSession:
                role = "moderator"

                def __init__(self):
                    self.accepted = 0

                def task_finished(self):
                    return False

                def accept_output(self):
                    self.accepted += 1

            session = RetryingSession()
            result = _wait_json(
                output,
                should_stop=None,
                timeout_seconds=1,
                reminder_session=session,
                validator=lambda data: _validate_report_findings_output(data, report),
                complete_on_valid=True,
                poll_interval_seconds=0.002,
            )

            self.assertEqual(result, expected)
            self.assertEqual(session.accepted, 1)

    def test_report_findings_validator_rejects_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.md"
            duplicate = {
                "findings": [
                    {"finding_id": "same", "rule_id": "rule-1", "message": "first"},
                    {"finding_id": "same", "rule_id": "rule-2", "message": "second"},
                ]
            }

            with self.assertRaisesRegex(CodexRunnerError, "重复 finding_id"):
                _validate_report_findings_output(duplicate, report)

    def test_opencode_runner_accepts_valid_report_split_before_moderator_turn_exits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "app.py").write_text("print('demo')\n", encoding="utf-8")
            report = root / "report.md"
            report.write_text("# Demo report\n", encoding="utf-8")
            records = RunRecordStore(root / "records")
            findings_data = {
                "findings": [
                    {
                        "finding_id": "finding-1",
                        "rule_id": "rule-1",
                        "message": "demo finding",
                        "level": "warning",
                    }
                ]
            }
            wait_calls = []

            class FakeSession:
                def __init__(self, role):
                    self.role = role
                    self.sent = []
                    self.stopped = False

                def info(self):
                    return {"role": self.role, "target": f"vj-run-opencode-split-{self.role}:tui"}

                def start(self):
                    return None

                def send(self, prompt):
                    self.sent.append(prompt)

                def stop(self):
                    self.stopped = True

            sessions = {role: FakeSession(role) for role in ("moderator", "affirmative", "negative")}

            def stage_result(path, **kwargs):
                wait_calls.append((path, kwargs))
                if str(path).endswith("findings.json"):
                    return findings_data
                prompt = kwargs["stage_prompt"]

                def field(name):
                    return prompt.split(f'"{name}": "', 1)[1].split('"', 1)[0]

                role = field("role")
                identity = {
                    "role": role,
                    "finding_id": field("finding_id"),
                    "attempt_id": field("attempt_id"),
                    "confidence": 0.8,
                }
                if role == "moderator":
                    return {
                        **identity,
                        "verdict": "TRUE_POSITIVE",
                        "reasoning_summary": "final",
                        "final_conclusion": "final",
                    }
                return {**identity, "position": "TRUE_POSITIVE", "summary": role}

            runner = CodexDrivenRunner(
                records_dir=records.root,
                codex_runs_dir=root / ".workspaces" / "runs",
                codex_command="codex",
            )
            runner.engine = OPENCODE_ENGINE
            runner.cli_name = "OpenCode"
            config = RunConfig(
                sarif_path=report,
                source_path=source,
                engine=OPENCODE_ENGINE,
                run_id="run-opencode-split",
            )

            with patch("vuln_judger.codex_runner._ensure_codex_project_trust"), patch.object(
                runner,
                "_sessions",
                return_value=sessions,
            ), patch("vuln_judger.codex_runner._wait_json", side_effect=stage_result):
                completed = runner.run(config, store=records)

            findings_wait = next(kwargs for path, kwargs in wait_calls if str(path).endswith("findings.json"))
            self.assertTrue(findings_wait["complete_on_valid"])
            self.assertIsNotNone(findings_wait["validator"])
            findings_wait["validator"](findings_data)
            self.assertEqual(completed["finding_count"], 1)
            self.assertEqual([role for role, session in sessions.items() if session.sent], ["moderator", "affirmative", "negative"])
            self.assertTrue(all(session.stopped for session in sessions.values()))

    def test_codex_project_trust_is_written_for_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "config.toml"
            workspace = root / ".workspaces" / "runs" / "run-1"
            workspace.mkdir(parents=True)

            _ensure_codex_project_trust(workspace, config_path=config_path)
            _ensure_codex_project_trust(workspace, config_path=config_path)

            config = config_path.read_text(encoding="utf-8")
            self.assertEqual(config.count(f'[projects."{workspace.resolve()}"]'), 1)
            self.assertIn('trust_level = "trusted"', config)

    def test_codex_project_trust_preserves_concurrent_workspace_updates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "config.toml"
            workspaces = [root / "runs" / f"run-{index}" for index in range(24)]
            for workspace in workspaces:
                workspace.mkdir(parents=True)

            with ThreadPoolExecutor(max_workers=12) as executor:
                list(
                    executor.map(
                        lambda workspace: _ensure_codex_project_trust(
                            workspace, config_path=config_path
                        ),
                        workspaces,
                    )
                )

            config = config_path.read_text(encoding="utf-8")
            for workspace in workspaces:
                self.assertEqual(config.count(f'[projects."{workspace.resolve()}"]'), 1)
            self.assertEqual(config.count('trust_level = "trusted"'), len(workspaces))

    def test_codex_project_trust_preserves_symlinked_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            actual_config = root / "dotfiles" / "codex-config.toml"
            actual_config.parent.mkdir()
            actual_config.write_text("model = \"demo\"\n", encoding="utf-8")
            config_link = root / "config.toml"
            config_link.symlink_to(actual_config)
            workspace = root / "workspace"
            workspace.mkdir()

            _ensure_codex_project_trust(workspace, config_path=config_link)

            self.assertTrue(config_link.is_symlink())
            self.assertIn(
                f'[projects."{workspace.resolve()}"]',
                actual_config.read_text(encoding="utf-8"),
            )

    def test_codex_default_workspaces_dir_uses_dot_workspaces_runs(self):
        self.assertEqual(DEFAULT_CODEX_WORKSPACES_DIR.name, "runs")
        self.assertEqual(DEFAULT_CODEX_WORKSPACES_DIR.parent.name, ".workspaces")
        self.assertNotIn(".vuln_judger", str(DEFAULT_CODEX_WORKSPACES_DIR))

    def test_cli_payload_preserves_opencode_model_for_history_and_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agents = {
                role: AgentConfig(role.title(), role=role, profile_id=f"{role}-profile")
                for role in ("affirmative", "negative", "moderator")
            }

            class FakeSession:
                def __init__(self, role):
                    self.role = role

                def info(self):
                    return {"role": self.role, "target": f"vj-run-model-{self.role}:tui"}

            config = RunConfig(
                sarif_path=root / "report.md",
                source_path=root / "source",
                engine=OPENCODE_ENGINE,
                run_id="run-model",
                llm_model="subapis/grok-4.5-latest",
                reuse_findings_from_run_id="run-source",
                affirmative_agent=agents["affirmative"],
                negative_agent=agents["negative"],
                moderator_agent=agents["moderator"],
            )
            payload = _base_payload(
                config,
                "run-model",
                "2026-07-15T00:00:00Z",
                [],
                root / ".workspaces" / "runs" / "run-model",
                {role: FakeSession(role) for role in ("affirmative", "negative", "moderator")},
                agents,
                "web",
                engine=OPENCODE_ENGINE,
            )

            self.assertEqual(payload["config"], run_config_snapshot(config))
            self.assertEqual(payload["config"]["llm_model"], "subapis/grok-4.5-latest")
            copied = _config_from_payload(payload["config"], root / "providers.json")
            resumed = _config_from_paused_payload(
                {**payload, "status": "paused"},
                root / "providers.json",
                AgentDirectoryStore(root / "agents"),
                root / "mcp.json",
                SkillSourceStore(root / "skills.json"),
            )

            self.assertEqual(copied.llm_model, "subapis/grok-4.5-latest")
            self.assertEqual(resumed.llm_model, "subapis/grok-4.5-latest")

    def test_codex_config_ignores_legacy_llm_and_mcp_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = {
                "report_path": str(root / "report.sarif"),
                "source_path": str(root / "source"),
                "engine": "codex",
                "enable_external_tools": False,
                "auto_index_tools": True,
                "enable_llm": True,
                "llm_model": "legacy-model",
                "llm_endpoint": "http://127.0.0.1/v1/chat/completions",
                "affirmative_provider_id": "affirmative-provider",
                "negative_provider_id": "negative-provider",
                "moderator_provider_id": "moderator-provider",
                "affirmative_agent": {"name": "old-affirmative"},
                "negative_agent": {"name": "old-negative"},
                "moderator_agent": {"name": "old-moderator"},
            }

            config = _config_from_payload(
                payload,
                providers_file=root / "providers.json",
                mcp_servers_file=root / "mcp.json",
            )

            self.assertEqual(config.engine, "codex")
            self.assertIsNone(config.mcp_servers_file)
            self.assertTrue(config.enable_external_tools)
            self.assertFalse(config.auto_index_tools)
            self.assertFalse(config.enable_llm)
            self.assertIsNone(config.llm_model)
            self.assertIsNone(config.llm_endpoint)
            self.assertIsNone(config.affirmative_provider_id)
            self.assertIsNone(config.negative_provider_id)
            self.assertIsNone(config.moderator_provider_id)
            self.assertIsNone(config.affirmative_agent)
            self.assertIsNone(config.negative_agent)
            self.assertIsNone(config.moderator_agent)

    def test_codex_silence_reminder_config_defaults_and_bounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base_payload = {
                "report_path": str(root / "report.sarif"),
                "source_path": str(root / "source"),
                "engine": "codex",
            }

            default_config = _config_from_payload(base_payload, root / "providers.json")
            minimum_config = _config_from_payload(
                {**base_payload, "silence_reminder_minutes": 0},
                root / "providers.json",
            )
            maximum_config = _config_from_payload(
                {**base_payload, "silence_reminder_minutes": 9999},
                root / "providers.json",
            )

            self.assertEqual(DEFAULT_SILENCE_REMINDER_MINUTES, 30)
            self.assertEqual(default_config.silence_reminder_minutes, DEFAULT_SILENCE_REMINDER_MINUTES)
            self.assertEqual(minimum_config.silence_reminder_minutes, 1)
            self.assertEqual(maximum_config.silence_reminder_minutes, 1440)

    def test_api_loads_and_validates_reused_report_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "report.md"
            report.write_text("# report\n", encoding="utf-8")
            source = root / "source"
            source.mkdir()
            source_run_id = "run-source-findings"
            run_dir = root / ".workspaces" / "runs" / source_run_id
            run_dir.mkdir(parents=True)
            findings_path = run_dir / "findings.json"
            findings_path.write_text(
                json.dumps(
                    {
                        "findings": [
                            {"finding_id": "finding-1", "rule_id": "rule-1", "message": "first"},
                            {"finding_id": "finding-2", "rule_id": "rule-2", "message": "second"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            records = RunRecordStore(root / "records")
            records.save_payload(
                {
                    "run_id": source_run_id,
                    "sarif_path": str(report),
                    "cli_workflow": {
                        "run_dir": str(run_dir),
                        "findings_path": str(findings_path),
                    },
                }
            )
            config = _config_from_payload(
                {
                    "report_path": str(report),
                    "source_path": str(source),
                    "engine": "codex",
                    "reuse_findings_from_run_id": source_run_id,
                },
                root / "providers.json",
            )

            _apply_reused_findings(config, records, {}, Lock())

            self.assertEqual([item.finding_id for item in config.reused_findings], ["finding-1", "finding-2"])
            self.assertEqual(config.reused_findings_payload["schema"], REPORT_FINDINGS_SCHEMA)
            self.assertEqual(config.reused_findings_payload["reused_from_run_id"], source_run_id)

            mismatched = _config_from_payload(
                {
                    "report_path": str(root / "other.md"),
                    "source_path": str(source),
                    "engine": "codex",
                    "reuse_findings_from_run_id": source_run_id,
                },
                root / "providers.json",
            )
            with self.assertRaisesRegex(ValueError, "报告路径与来源任务不一致"):
                _apply_reused_findings(mismatched, records, {}, Lock())

            findings_path.write_text(
                json.dumps(
                    {
                        "findings": [
                            {"finding_id": "duplicate", "rule_id": "rule-1", "message": "first"},
                            {"finding_id": "duplicate", "rule_id": "rule-2", "message": "second"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            duplicate = _config_from_payload(
                {
                    "report_path": str(report),
                    "source_path": str(source),
                    "engine": "codex",
                    "reuse_findings_from_run_id": source_run_id,
                },
                root / "providers.json",
            )
            with self.assertRaisesRegex(ValueError, "重复 finding_id"):
                _apply_reused_findings(duplicate, records, {}, Lock())

    def test_builtin_runner_skips_report_preparation_for_reused_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "app.py").write_text("print('demo')\n", encoding="utf-8")
            report_path = root / "report.md"
            report_path.write_text("# report that would require Moderator\n", encoding="utf-8")
            finding = Finding(
                finding_id="reused-builtin",
                rule_id="rule-reused",
                message="reused report finding",
                level="warning",
                locations=[SourceLocation(file="app.py", line=1)],
            )
            config = RunConfig(
                sarif_path=report_path,
                source_path=source,
                engine="builtin",
                run_id="run-builtin-reused",
                enable_external_tools=False,
                reuse_findings_from_run_id="run-source",
                reused_findings=[finding],
            )

            with patch("vuln_judger.pipeline.prepare_report_for_processing", side_effect=AssertionError("unexpected")):
                completed = run_judgement(config)

            self.assertEqual(completed.finding_count, 1)
            self.assertEqual(completed.report_findings["origin"], "reused")
            self.assertEqual(completed.report_findings["reused_from_run_id"], "run-source")
            self.assertIn("已复用任务 run-source 的报告拆分结果", completed.diagnostics)

    def test_codex_config_uses_agent_profiles_from_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = AgentDirectoryStore(root / "agents")
            store.save_profile("affirmative", "Affirmative_custom", "Codex 正方初始约束。")
            store.save_profile("negative", "Negative_default", "Codex 反方默认约束。")
            store.save_profile("moderator", "Moderator_default", "Codex Moderator 默认约束。")
            payload = {
                "report_path": str(root / "report.sarif"),
                "source_path": str(root / "source"),
                "engine": "codex",
                "enable_external_tools": False,
                "auto_index_tools": True,
                "enable_llm": True,
                "affirmative_provider_id": "ignored-provider",
                "affirmative_agent_profile": "Affirmative_custom",
                "negative_agent_profile": "Negative_default",
                "moderator_agent_profile": "Moderator_default",
            }

            config = _config_from_payload(
                payload,
                providers_file=root / "providers.json",
                agent_store=store,
                mcp_servers_file=root / "mcp.json",
            )

            self.assertEqual(config.engine, "codex")
            self.assertIsNone(config.mcp_servers_file)
            self.assertFalse(config.enable_llm)
            self.assertIsNone(config.affirmative_provider_id)
            self.assertEqual(config.affirmative_agent.profile_id, "Affirmative_custom")
            self.assertEqual(config.affirmative_agent.instructions, "Codex 正方初始约束。")
            self.assertEqual(config.negative_agent.instructions, "Codex 反方默认约束。")
            self.assertEqual(config.moderator_agent.instructions, "Codex Moderator 默认约束。")

    def test_codex_resume_config_preserves_all_findings_and_uses_first_pending_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = {
                "run_id": "run-resume",
                "status": "paused",
                "engine": "codex",
                "created_at": "2026-07-09T00:00:00Z",
                "source_path": str(root / "source"),
                "sarif_path": str(root / "report.md"),
                "finding_count": 3,
                "completed_finding_count": 1,
                "reports": [
                    {"finding_id": "finding-1", "finding_status": "completed", "verdict": "TRUE_POSITIVE"},
                    {"finding_id": "finding-2", "finding_status": "pending", "verdict": None},
                    {"finding_id": "finding-3", "finding_status": "pending", "verdict": None},
                ],
                "config": {
                    "engine": "codex",
                    "report_path": str(root / "report.md"),
                    "source_path": str(root / "source"),
                    "silence_reminder_minutes": 17,
                },
            }

            config = _config_from_paused_payload(
                payload,
                root / "providers.json",
                AgentDirectoryStore(root / "agents"),
                root / "mcp.json",
                SkillSourceStore(root / "skills.json"),
            )

            self.assertEqual(config.engine, "codex")
            self.assertEqual(len(config.resume_reports), 3)
            self.assertEqual(config.resume_from_finding_index, 1)
            self.assertEqual(config.resume_reports[0]["finding_id"], "finding-1")
            self.assertEqual(config.silence_reminder_minutes, 17)

    def test_failed_cli_task_can_resume_from_first_incomplete_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = RunRecordStore(root / "records")
            failed = {
                "run_id": "run-failed-resume",
                "status": "failed",
                "engine": OPENCODE_ENGINE,
                "created_at": "2026-07-16T00:00:00Z",
                "source_path": str(root / "source"),
                "sarif_path": str(root / "report.sarif"),
                "finding_count": 2,
                "completed_finding_count": 1,
                "current_finding_id": "finding-2",
                "current_finding_index": 1,
                "current_finding_ids": {"negative": "finding-2"},
                "resume_from_finding_id": "finding-2",
                "resume_from_finding_index": 1,
                "reports": [
                    {
                        "finding_id": "finding-1",
                        "finding_status": "completed",
                        "verdict": "TRUE_POSITIVE",
                    },
                    {
                        "finding_id": "finding-2",
                        "finding_status": "in_progress",
                        "verdict": None,
                        "cli_workflow": {
                            "affirmative": {
                                "role": "affirmative",
                                "finding_id": "finding-2",
                                "position": "TRUE_POSITIVE",
                            },
                            "pipeline": {
                                "stages": {
                                    "affirmative": {"status": "succeeded", "attempt": 1},
                                    "negative": {"status": "running", "attempt": 1},
                                    "moderator": {"status": "pending", "attempt": 0},
                                }
                            },
                        },
                    },
                ],
                "diagnostics": ["OpenCode negative failed"],
                "error": "OpenCode negative failed",
                "config": {
                    "engine": OPENCODE_ENGINE,
                    "report_path": str(root / "report.sarif"),
                    "source_path": str(root / "source"),
                    "silence_reminder_minutes": 30,
                },
                "cli_sessions": [
                    {
                        "role": "negative",
                        "session_name": "vj-run-failed-resume-negative",
                    }
                ],
            }
            store.save_payload(failed)
            tasks = {}
            stop_events = {}
            pause_events = {}
            tasks_lock = Lock()

            with patch("vuln_judger.api.stop_sessions") as stop_sessions_mock, patch(
                "vuln_judger.api.Thread"
            ) as thread_mock:
                resumed = _request_resume(
                    store,
                    tasks,
                    stop_events,
                    pause_events,
                    tasks_lock,
                    failed["run_id"],
                    root / "providers.json",
                    AgentDirectoryStore(root / "agents"),
                    root / "mcp.json",
                    SkillSourceStore(root / "skills.json"),
                )

            self.assertIsNotNone(resumed)
            self.assertEqual(resumed["run_id"], failed["run_id"])
            self.assertEqual(resumed["status"], "running")
            self.assertIsNone(resumed["error"])
            self.assertEqual(resumed["completed_finding_count"], 1)
            self.assertEqual(resumed["resume_from_finding_index"], 1)
            self.assertEqual(resumed["resume_from_finding_id"], "finding-2")
            self.assertEqual(resumed["current_finding_ids"], {})
            self.assertEqual(resumed["reports"][1]["finding_status"], "pending")
            self.assertEqual(
                resumed["reports"][1]["cli_workflow"]["pipeline"]["stages"]["negative"]["status"],
                "interrupted",
            )
            self.assertIn("任务从 failed 状态恢复", resumed["diagnostics"][-1])
            self.assertEqual(store.get(failed["run_id"])["status"], "running")
            self.assertIn(failed["run_id"], stop_events)
            self.assertIn(failed["run_id"], pause_events)
            stop_sessions_mock.assert_called_once_with(failed)
            thread_mock.return_value.start.assert_called_once_with()
            resume_config = thread_mock.call_args.kwargs["args"][0]
            self.assertEqual(resume_config.created_at, failed["created_at"])
            self.assertEqual(resume_config.resume_from_finding_index, 1)
            self.assertEqual(len(resume_config.resume_reports), 2)

    def test_failed_builtin_resume_discards_partial_finding_report(self):
        checkpoint = _resume_checkpoint_payload(
            {
                "run_id": "run-failed-builtin",
                "status": "failed",
                "engine": "builtin",
                "finding_count": 2,
                "completed_finding_count": 1,
                "resume_from_finding_id": "finding-2",
                "reports": [
                    {"finding_id": "finding-1", "finding_status": "completed", "verdict": "TRUE_POSITIVE"},
                    {"finding_id": "finding-2", "finding_status": "in_progress", "verdict": "INCONCLUSIVE"},
                ],
            }
        )

        self.assertEqual(len(checkpoint["reports"]), 1)
        self.assertEqual(checkpoint["completed_finding_count"], 1)
        self.assertEqual(checkpoint["resume_from_finding_index"], 1)
        self.assertEqual(checkpoint["resume_from_finding_id"], "finding-2")

    def test_codex_agent_profile_files_are_written_per_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            run_dir = root / ".workspaces" / "runs" / "run-1"
            source.mkdir(parents=True)
            run_dir.mkdir(parents=True)
            agents = {
                "moderator": AgentConfig("Moderator_custom", "中立裁决约束。", role="Moderator", profile_id="Moderator_custom"),
                "affirmative": AgentConfig("Affirmative_custom", "正方验证约束。", role="Affirmative", profile_id="Affirmative_custom"),
                "negative": AgentConfig("Negative_custom", "反方复核约束。", role="Negative", profile_id="Negative_custom"),
            }

            with patch("vuln_judger.codex_runner._ensure_codex_project_trust") as trust:
                session_dirs = _prepare_codex_agent_dirs(run_dir, agents, source)

            self.assertEqual(set(session_dirs), {"moderator", "affirmative", "negative"})
            self.assertEqual(trust.call_count, 3)
            affirmative_dir = session_dirs["affirmative"]
            agents_md = affirmative_dir / "AGENTS.md"
            agent_md = affirmative_dir / "AGENT.md"
            self.assertTrue(agents_md.exists())
            self.assertTrue(agent_md.exists())
            self.assertEqual(agents_md.read_text(encoding="utf-8"), agent_md.read_text(encoding="utf-8"))
            text = agents_md.read_text(encoding="utf-8")
            self.assertIn("Affirmative_custom", text)
            self.assertIn("正方验证约束。", text)
            self.assertIn(str(source), text)
            self.assertIn(str(run_dir), text)
            self.assertIn("Atlas MCP", text)
            runner = CodexDrivenRunner(records_dir=root / "records", codex_command="codex")
            sessions = runner._sessions("run-1", source, run_dir, session_dirs)
            self.assertEqual(sessions["affirmative"].cwd, affirmative_dir.resolve())
            self.assertEqual(sessions["moderator"].cwd, session_dirs["moderator"].resolve())

    def test_codex_runner_emits_session_metadata_before_tui_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            report = root / "report.sarif"
            report.write_text("{}", encoding="utf-8")
            captured = []

            class Store:
                def __init__(self, records_root):
                    self.root = records_root

                def save_payload(self, payload):
                    captured.append(dict(payload))

            config = RunConfig(
                sarif_path=report,
                source_path=source,
                engine="codex",
                run_id="run-session-buttons",
            )
            runner = CodexDrivenRunner(
                records_dir=root / "records",
                codex_runs_dir=root / ".workspaces" / "runs",
                codex_command="codex",
            )

            with patch("vuln_judger.codex_runner._ensure_codex_project_trust"), patch.object(
                CodexTmuxSession,
                "start",
                side_effect=RuntimeError("stop before tmux"),
            ):
                with self.assertRaises(RuntimeError):
                    runner.run(
                        config,
                        store=Store(root / "records"),
                        run_origin="mcp",
                        progress_callback=lambda payload: captured.append(dict(payload)),
                    )

            first_with_sessions = next(item for item in captured if item.get("codex_sessions"))
            self.assertEqual({item["role"] for item in first_with_sessions["codex_sessions"]}, {"moderator", "affirmative", "negative"})
            self.assertIn("Codex-driven session 元数据已创建", "\n".join(first_with_sessions["diagnostics"]))
            self.assertEqual(first_with_sessions["status"], "running")
            self.assertEqual(first_with_sessions["run_origin"], "mcp")

    def test_codex_runner_reuses_valid_sarif_and_one_run_level_source_indexer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, _skills = write_python_fixture(root)
            sarif_data = json.loads(sarif.read_text(encoding="utf-8"))
            first_result = sarif_data["runs"][0]["results"][0]
            first_result["properties"] = {"fixture_marker": "preserved"}
            second_result = json.loads(json.dumps(first_result))
            second_result["ruleId"] = "python-secondary-check"
            second_result["message"] = {"text": "第二个独立发现"}
            second_result["locations"][0]["physicalLocation"]["region"]["startLine"] = 4
            sarif_data["runs"][0]["results"].append(second_result)
            sarif.write_text(json.dumps(sarif_data), encoding="utf-8")
            records = RunRecordStore(root / "records")
            sent = []

            class FakeSession:
                def __init__(self, role):
                    self.role = role

                def info(self):
                    return {
                        "role": self.role,
                        "session_name": f"vj-run-local-sarif-{self.role}",
                        "target": f"vj-run-local-sarif-{self.role}:codex",
                    }

                def start(self):
                    return None

                def send(self, prompt):
                    sent.append((self.role, prompt))

            sessions = {role: FakeSession(role) for role in ("moderator", "affirmative", "negative")}
            def stage_result(_path, **kwargs):
                prompt = kwargs["stage_prompt"]

                def field(name):
                    return prompt.split(f'"{name}": "', 1)[1].split('"', 1)[0]

                role = field("role")
                identity = {
                    "role": role,
                    "finding_id": field("finding_id"),
                    "attempt_id": field("attempt_id"),
                    "confidence": 0.7,
                }
                if role == "moderator":
                    return {
                        **identity,
                        "verdict": "INCONCLUSIVE",
                        "reasoning_summary": f"final-{identity['finding_id']}",
                        "final_conclusion": f"final-{identity['finding_id']}",
                    }
                return {
                    **identity,
                    "position": "TRUE_POSITIVE" if role == "affirmative" else "FALSE_POSITIVE",
                    "summary": role,
                }
            runner = CodexDrivenRunner(
                records_dir=records.root,
                codex_runs_dir=root / ".workspaces" / "runs",
                codex_command="codex",
            )
            config = RunConfig(
                sarif_path=sarif,
                source_path=root,
                engine="codex",
                run_id="run-local-sarif",
            )

            with patch("vuln_judger.codex_runner._ensure_codex_project_trust"), patch.object(
                runner,
                "_sessions",
                return_value=sessions,
            ), patch("vuln_judger.codex_runner._wait_json", side_effect=stage_result), patch(
                "vuln_judger.codex_runner.SourceIndexer",
                wraps=SourceIndexer,
            ) as indexer_factory:
                completed = runner.run(config, store=records)

            self.assertEqual(indexer_factory.call_count, 1)
            self.assertEqual({role: sum(1 for sent_role, _ in sent if sent_role == role) for role in ("affirmative", "negative", "moderator")}, {"affirmative": 2, "negative": 2, "moderator": 2})
            for finding_id in {stage_result(None, stage_prompt=prompt)["finding_id"] for _role, prompt in sent}:
                roles = [role for role, prompt in sent if f'"finding_id": "{finding_id}"' in prompt]
                self.assertLess(roles.index("affirmative"), roles.index("negative"))
                self.assertLess(roles.index("negative"), roles.index("moderator"))
            self.assertFalse(any("当前阶段：报告拆分" in prompt for _role, prompt in sent))
            self.assertEqual(completed["finding_count"], 2)
            self.assertEqual(completed["cli_workflow"]["report_preparation_origin"], "local_sarif")
            self.assertEqual(completed["cli_workflow"]["pipeline"]["slot_count"], 3)
            self.assertEqual(completed["cli_workflow"]["pipeline"]["context_mode"], "isolated-per-finding-stage")
            findings_path = root / ".workspaces" / "runs" / "run-local-sarif" / "findings.json"
            persisted = json.loads(findings_path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["origin"], "local_sarif")
            self.assertEqual(persisted["findings"][0]["properties"]["fixture_marker"], "preserved")
            brief_paths = sorted((findings_path.parent / "findings").glob("*/brief.json"))
            self.assertEqual(len(brief_paths), 2)
            briefs = [json.loads(path.read_text(encoding="utf-8")) for path in brief_paths]
            self.assertTrue(any(brief["properties"].get("fixture_marker") == "preserved" for brief in briefs))
            self.assertTrue(all(brief["raw"].get("message") for brief in briefs))

    def test_codex_runner_reuses_copied_findings_without_report_moderation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "app.py").write_text("print('demo')\n", encoding="utf-8")
            report = root / "report.md"
            report.write_text("# Demo report\n", encoding="utf-8")
            records = RunRecordStore(root / "records")
            sent = []

            class FakeSession:
                def __init__(self, role):
                    self.role = role

                def info(self):
                    return {
                        "role": self.role,
                        "session_name": f"vj-run-reused-{self.role}",
                        "target": f"vj-run-reused-{self.role}:codex",
                    }

                def start(self):
                    return None

                def send(self, prompt):
                    sent.append((self.role, prompt))

            sessions = {role: FakeSession(role) for role in ("moderator", "affirmative", "negative")}

            def stage_result(path, **kwargs):
                self.assertFalse(str(path).endswith("findings.json"))
                prompt = kwargs["stage_prompt"]

                def field(name):
                    return prompt.split(f'"{name}": "', 1)[1].split('"', 1)[0]

                role = field("role")
                identity = {
                    "role": role,
                    "finding_id": field("finding_id"),
                    "attempt_id": field("attempt_id"),
                    "confidence": 0.8,
                }
                if role == "moderator":
                    return {
                        **identity,
                        "verdict": "TRUE_POSITIVE",
                        "reasoning_summary": "reused-final",
                        "final_conclusion": "reused-final",
                    }
                return {**identity, "position": "TRUE_POSITIVE", "summary": role}

            reused_finding = Finding(
                finding_id="reused-finding",
                rule_id="reused-rule",
                message="copied split result",
                level="warning",
                locations=[SourceLocation(file="app.py", line=1)],
            )
            config = RunConfig(
                sarif_path=report,
                source_path=source,
                engine="codex",
                run_id="run-reused",
                reuse_findings_from_run_id="run-source",
                reused_findings=[reused_finding],
                reused_findings_payload={
                    "schema": REPORT_FINDINGS_SCHEMA,
                    "origin": "moderator",
                    "finding_count": 1,
                    "findings": [to_jsonable(reused_finding)],
                    "reused_from_run_id": "run-source",
                },
            )
            runner = CodexDrivenRunner(
                records_dir=records.root,
                codex_runs_dir=root / ".workspaces" / "runs",
                codex_command="codex",
            )

            with patch("vuln_judger.codex_runner._ensure_codex_project_trust"), patch.object(
                runner,
                "_sessions",
                return_value=sessions,
            ), patch("vuln_judger.codex_runner._wait_json", side_effect=stage_result):
                completed = runner.run(config, store=records)

            self.assertFalse(any("当前阶段：报告拆分" in prompt for _role, prompt in sent))
            self.assertEqual([role for role, _prompt in sent], ["affirmative", "negative", "moderator"])
            self.assertEqual(completed["finding_count"], 1)
            self.assertEqual(completed["cli_workflow"]["report_preparation_origin"], "reused")
            self.assertEqual(completed["cli_workflow"]["reused_findings_from_run_id"], "run-source")
            persisted = json.loads(
                (root / ".workspaces" / "runs" / "run-reused" / "findings.json").read_text(encoding="utf-8")
            )
            self.assertEqual(persisted["reused_from_run_id"], "run-source")

    def test_codex_runner_persists_all_findings_and_resumes_from_first_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "app.py").write_text("print('demo')\n", encoding="utf-8")
            report = root / "report.md"
            report.write_text("# Demo report\n", encoding="utf-8")
            records = RunRecordStore(root / "records")
            run_dir = root / ".workspaces" / "runs" / "run-multi"
            findings_data = {
                "findings": [
                    {"finding_id": f"finding-{index}", "rule_id": f"rule-{index}", "message": f"message-{index}"}
                    for index in range(1, 4)
                ]
            }

            class FakeSession:
                def __init__(self, role, sent):
                    self.role = role
                    self.sent = sent

                def info(self):
                    return {
                        "role": self.role,
                        "session_name": f"vj-run-multi-{self.role}",
                        "target": f"vj-run-multi-{self.role}:codex",
                    }

                def start(self):
                    return None

                def send(self, prompt):
                    self.sent.append((self.role, prompt))

            def sessions(sent):
                return {role: FakeSession(role, sent) for role in ("moderator", "affirmative", "negative")}

            def stage_result(prompt):
                def field(name):
                    return prompt.split(f'"{name}": "', 1)[1].split('"', 1)[0]

                role = field("role")
                finding_id = field("finding_id")
                identity = {
                    "role": role,
                    "finding_id": finding_id,
                    "attempt_id": field("attempt_id"),
                    "confidence": 0.8,
                }
                if role == "moderator":
                    suffix = finding_id.rsplit("-", 1)[-1]
                    return {
                        **identity,
                        "verdict": "TRUE_POSITIVE",
                        "reasoning_summary": f"final-{suffix}",
                        "final_conclusion": f"final-{suffix}",
                    }
                return {
                    **identity,
                    "position": "TRUE_POSITIVE",
                    "summary": role,
                }

            initial_sent = []
            initial_progress = []
            final_one_done = Event()

            def initial_wait(path, **kwargs):
                if str(path).endswith("findings.json"):
                    return findings_data
                prompt = kwargs["stage_prompt"]
                result = stage_result(prompt)
                if result["role"] == "moderator" and result["finding_id"] == "finding-1":
                    final_one_done.set()
                if result["role"] == "negative" and result["finding_id"] == "finding-2":
                    self.assertTrue(final_one_done.wait(2))
                    raise CodexRunnerStopped("pause during finding-2 negative stage")
                return result

            config = RunConfig(
                sarif_path=report,
                source_path=source,
                engine="codex",
                run_id="run-multi",
            )
            runner = CodexDrivenRunner(
                records_dir=records.root,
                codex_runs_dir=root / ".workspaces" / "runs",
                codex_command="codex",
            )
            with patch("vuln_judger.codex_runner._ensure_codex_project_trust"), patch.object(
                runner,
                "_sessions",
                return_value=sessions(initial_sent),
            ), patch("vuln_judger.codex_runner._wait_json", side_effect=initial_wait):
                with self.assertRaises(CodexRunnerStopped):
                    runner.run(
                        config,
                        store=records,
                        progress_callback=lambda payload: initial_progress.append(json.loads(json.dumps(payload))),
                    )

            running = records.get("run-multi")
            self.assertTrue(
                any(
                    payload.get("current_finding_ids")
                    == {
                        "affirmative": "finding-3",
                        "negative": "finding-2",
                        "moderator": "finding-1",
                    }
                    for payload in initial_progress
                )
            )
            self.assertEqual(len(running["reports"]), 3)
            self.assertEqual(
                [item["finding_status"] for item in running["reports"]],
                ["completed", "in_progress", "pending"],
            )
            self.assertEqual(running["reports"][0]["final_conclusion"], "final-1")
            self.assertTrue(
                all(
                    (run_dir / "findings" / f"finding-{index}" / "brief.json").exists()
                    for index in range(1, 4)
                )
            )
            (run_dir / "findings.json").write_text(
                json.dumps(findings_data, ensure_ascii=False),
                encoding="utf-8",
            )

            paused = _pause_payload(config, running, "pause requested")
            records.save_payload(paused)
            self.assertEqual(len(paused["reports"]), 3)
            self.assertEqual(
                [item["finding_status"] for item in paused["reports"]],
                ["completed", "pending", "pending"],
            )
            self.assertEqual(paused["completed_finding_count"], 1)
            self.assertEqual(paused["resume_from_finding_id"], "finding-2")
            self.assertEqual(paused["resume_from_finding_index"], 1)

            stale_result = run_dir / "findings" / "finding-2" / "affirmative" / "result.json"
            stale_result.parent.mkdir(parents=True, exist_ok=True)
            stale_result.write_text('{"summary":"stale"}\n', encoding="utf-8")

            resumed_sent = []
            resumed_progress = []
            resumed_wait_options = []

            def resumed_wait(path, **_kwargs):
                resumed_wait_options.append(_kwargs["complete_on_valid"])
                value = str(path)
                if value.endswith("findings.json"):
                    return findings_data
                return stage_result(_kwargs["stage_prompt"])

            resume_config = RunConfig(
                sarif_path=report,
                source_path=source,
                engine="codex",
                run_id="run-multi",
                created_at=paused["created_at"],
                resume_reports=paused["reports"],
                resume_diagnostics=paused["diagnostics"],
                resume_from_finding_index=paused["resume_from_finding_index"],
            )
            with patch("vuln_judger.codex_runner._ensure_codex_project_trust"), patch.object(
                runner,
                "_sessions",
                return_value=sessions(resumed_sent),
            ), patch("vuln_judger.codex_runner._wait_json", side_effect=resumed_wait):
                completed = runner.run(
                    resume_config,
                    store=records,
                    progress_callback=lambda payload: resumed_progress.append(
                        json.loads(json.dumps(payload))
                    ),
                )

            self.assertTrue(resumed_progress)
            self.assertTrue(resumed_wait_options)
            self.assertTrue(all(resumed_wait_options))
            self.assertTrue(all(len(payload["reports"]) == 3 for payload in resumed_progress))
            self.assertTrue(all(payload["reports"][0]["final_conclusion"] == "final-1" for payload in resumed_progress))
            resumed_roles = [role for role, _ in resumed_sent]
            self.assertEqual(resumed_roles.count("affirmative"), 1)
            self.assertEqual(resumed_roles.count("negative"), 2)
            self.assertEqual(resumed_roles.count("moderator"), 2)
            self.assertFalse(
                any(role == "affirmative" and '"finding_id": "finding-2"' in prompt for role, prompt in resumed_sent)
            )
            restored_affirmative = json.loads(stale_result.read_text(encoding="utf-8"))
            self.assertEqual(restored_affirmative["finding_id"], "finding-2")
            self.assertEqual(completed["completed_finding_count"], 3)
            self.assertEqual([item["finding_status"] for item in completed["reports"]], ["completed"] * 3)
            self.assertEqual([item["final_conclusion"] for item in completed["reports"]], ["final-1", "final-2", "final-3"])

    def test_provider_store_masks_key_and_resolves_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ProviderStore(Path(tmp) / "providers.json")
            public = store.upsert(
                {
                    "id": "main",
                    "name": "Main",
                    "type": "openai-compatible",
                    "endpoint": "http://127.0.0.1/v1/chat/completions",
                    "model": "fake-model",
                    "api_key": "secret",
                    "extra_json": {"temperature": 0.2},
                }
            )
            self.assertEqual(public["api_key"], "********")
            self.assertTrue(public["api_key_saved"])
            store.set_defaults("main", "main")
            affirmative, negative = store.resolve_pair(None, None)
            self.assertEqual(affirmative.id, "main")
            self.assertEqual(negative.id, "main")
            affirmative, negative, moderator = store.resolve_trio(None, None, None)
            self.assertEqual(affirmative.id, "main")
            self.assertEqual(negative.id, "main")
            self.assertEqual(moderator.id, "main")
            self.assertIsNone(store.defaults()["moderator"])
            store.set_defaults("main", "main", "main")
            self.assertEqual(store.defaults()["moderator"], "main")
            raw = json.loads((Path(tmp) / "providers.json").read_text(encoding="utf-8"))
            self.assertEqual(raw["providers"][0]["api_key"], "secret")

    def test_openai_compatible_llm_default_timeout_is_300_seconds(self):
        from vuln_judger.llm import OpenAICompatibleLLM

        client = OpenAICompatibleLLM(api_key="secret", model="fake-model")
        self.assertEqual(client.timeout_seconds, 300)

    def test_openai_compatible_llm_handles_incomplete_read(self):
        from vuln_judger.llm import OpenAICompatibleLLM

        class BrokenChunkedResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                raise http.client.IncompleteRead(b"")

        client = OpenAICompatibleLLM(api_key="secret", model="fake-model", endpoint="http://127.0.0.1/llm")

        with patch("urllib.request.urlopen", return_value=BrokenChunkedResponse()):
            result = client.request("system", "user")

        self.assertFalse(result["ok"])
        self.assertIn("IncompleteRead", result["error"])

    def test_openai_compatible_llm_retries_empty_content_with_reasoning_content(self):
        from vuln_judger.llm import OpenAICompatibleLLM

        class JsonResponse:
            status = 200

            def __init__(self, payload):
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return json.dumps(self.payload).encode("utf-8")

        reasoning_only = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "reasoning_content": "是否继续下一轮：是\n分析：仍需补证。",
                    }
                }
            ]
        }
        final_answer = {"choices": [{"message": {"role": "assistant", "content": "最终正文"}}]}
        client = OpenAICompatibleLLM(api_key="secret", model="fake-model", endpoint="http://127.0.0.1/llm")

        with patch("urllib.request.urlopen", side_effect=[JsonResponse(reasoning_only), JsonResponse(final_answer)]) as mocked:
            response = client.complete("system", "user")

        self.assertEqual(response, "最终正文")
        self.assertEqual(mocked.call_count, 2)
        retry_request = mocked.call_args_list[1].args[0]
        retry_payload = json.loads(retry_request.data.decode("utf-8"))
        self.assertIn("message.content 为空", retry_payload["messages"][1]["content"])

    def test_to_jsonable_decodes_nested_bytes(self):
        evidence = CodeEvidence(
            evidence_id="ev-bytes",
            kind=EvidenceKind.TOOL_DIAGNOSTIC,
            strength=EvidenceStrength.WEAK,
            summary="bytes test",
            source="unit",
            data={"raw": b"hello", "nested": [b"\xe4\xb8\xad\xe6\x96\x87"], "bad": b"\xff"},
        )
        payload = to_jsonable(evidence)
        self.assertEqual(payload["data"]["raw"], "hello")
        self.assertEqual(payload["data"]["nested"][0], "中文")
        json.dumps(payload, ensure_ascii=False)

    def test_provider_store_rejects_reserved_extra_json_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ProviderStore(Path(tmp) / "providers.json")
            with self.assertRaises(ValueError):
                store.upsert(
                    {
                        "id": "bad",
                        "endpoint": "http://127.0.0.1/v1/chat/completions",
                        "model": "fake-model",
                        "extra_json": {"messages": []},
                    }
                )

    def test_api_provider_crud_defaults_and_connectivity(self):
        with tempfile.TemporaryDirectory() as tmp:
            llm_server = ThreadingHTTPServer(("127.0.0.1", 0), FakeOpenAIHandler)
            llm_thread = Thread(target=llm_server.serve_forever, daemon=True)
            llm_thread.start()
            store = RunRecordStore(Path(tmp) / "records")
            provider_store = ProviderStore(Path(tmp) / "providers.json")
            api_server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(store, provider_store))
            api_thread = Thread(target=api_server.serve_forever, daemon=True)
            api_thread.start()
            base = f"http://127.0.0.1:{api_server.server_port}"
            endpoint = f"http://127.0.0.1:{llm_server.server_port}/v1/chat/completions"
            try:
                created = post_json(
                    f"{base}/providers",
                    {
                        "id": "fake",
                        "name": "Fake",
                        "endpoint": endpoint,
                        "model": "fake-model",
                        "api_key": "secret",
                        "extra_json": {"temperature": 0.3},
                    },
                )
                self.assertEqual(created["api_key"], "********")
                defaults = post_json(
                    f"{base}/providers/defaults",
                    {"affirmative": "fake", "negative": "fake", "moderator": "fake"},
                )
                self.assertEqual(defaults["affirmative"], "fake")
                self.assertEqual(defaults["moderator"], "fake")
                test = post_json(f"{base}/providers/fake/test", {})
                self.assertTrue(test["ok"])
                self.assertEqual(test["response_excerpt"], "OK")
                with urllib.request.urlopen(f"{base}/providers", timeout=5) as response:
                    providers = json.loads(response.read().decode("utf-8"))
                self.assertEqual(providers[0]["id"], "fake")
                self.assertNotEqual(providers[0].get("api_key"), "secret")
            finally:
                api_server.shutdown()
                api_server.server_close()
                api_thread.join(timeout=5)
                llm_server.shutdown()
                llm_server.server_close()
                llm_thread.join(timeout=5)

    def test_api_agent_prompt_crud_and_run_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, skills = write_python_fixture(root)
            store = RunRecordStore(root / "records")
            provider_store = ProviderStore(root / "providers.json")
            agent_store = AgentDirectoryStore(root / "agents")
            api_server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(store, provider_store, agent_store))
            api_thread = Thread(target=api_server.serve_forever, daemon=True)
            api_thread.start()
            base = f"http://127.0.0.1:{api_server.server_port}"
            try:
                with urllib.request.urlopen(f"{base}/agent-prompts", timeout=5) as response:
                    defaults = json.loads(response.read().decode("utf-8"))
                self.assertEqual(defaults["defaults"]["affirmative"], "Affirmative_default")
                self.assertEqual(defaults["defaults"]["moderator"], "Moderator_default")
                affirmative_default = next(
                    profile for profile in defaults["roles"]["affirmative"] if profile["profile_id"] == "Affirmative_default"
                )
                negative_default = next(
                    profile for profile in defaults["roles"]["negative"] if profile["profile_id"] == "Negative_default"
                )
                moderator_default = next(
                    profile for profile in defaults["roles"]["moderator"] if profile["profile_id"] == "Moderator_default"
                )
                self.assertIn("外部输入源头", affirmative_default["instructions"])
                self.assertIn("grep/ripgrep", affirmative_default["instructions"])
                self.assertIn("转回 Atlas", affirmative_default["instructions"])
                self.assertIn("代码上下文业务逻辑", affirmative_default["instructions"])
                self.assertIn("自主达成反方目标", negative_default["instructions"])
                self.assertIn("代码上下文业务逻辑", negative_default["instructions"])
                self.assertIn("key 可能是密钥", negative_default["instructions"])
                self.assertIn("自主达成 Moderator 目标", moderator_default["instructions"])
                self.assertIn("代码上下文业务逻辑", moderator_default["instructions"])
                self.assertIn("异常读取", moderator_default["instructions"])
                saved = post_json(
                    f"{base}/agent-prompts",
                    {
                        "role": "affirmative",
                        "profile_id": "Affirmative_default",
                        "instructions": "优先关注价值资产影响。",
                    },
                )
                self.assertEqual(saved["profile_id"], "Affirmative_default")
                custom = post_json(
                    f"{base}/agent-prompts",
                    {
                        "role": "affirmative",
                        "profile_id": "Affirmative_custom",
                        "instructions": "自定义正方配置档案。",
                    },
                )
                self.assertTrue(custom["deletable"])
                starred = post_json(
                    f"{base}/agent-prompts",
                    {
                        "action": "star",
                        "role": "affirmative",
                        "profile_id": "Affirmative_custom",
                        "starred": True,
                    },
                )
                self.assertTrue(starred["starred"])
                post_json(
                    f"{base}/agent-prompts",
                    {
                        "role": "negative",
                        "profile_id": "Negative_default",
                        "instructions": "质疑可达性和防护条件。",
                    },
                )
                post_json(
                    f"{base}/agent-prompts",
                    {
                        "role": "moderator",
                        "profile_id": "Moderator_default",
                        "instructions": "中立总结双方核心争议。",
                    },
                )
                created = post_json(
                    f"{base}/runs",
                    {
                        "report_path": str(sarif),
                        "source_path": str(root),
                        "skills_path": str(skills),
                        "enable_external_tools": False,
                    },
                )
                run = wait_for_run_completed(base, created["run_id"])
                self.assertEqual(run["agent_configs"]["affirmative"]["profile_id"], "Affirmative_default")
                self.assertTrue(run["agent_configs"]["affirmative"]["is_default"])
                self.assertFalse(run["agent_configs"]["affirmative"]["deletable"])
                self.assertEqual(run["agent_configs"]["affirmative"]["instructions"], "优先关注价值资产影响。")
                self.assertEqual(run["agent_configs"]["negative"]["instructions"], "质疑可达性和防护条件。")
                self.assertEqual(run["agent_configs"]["moderator"]["profile_id"], "Moderator_default")
                self.assertEqual(run["agent_configs"]["moderator"]["instructions"], "中立总结双方核心争议。")
                delete_request = urllib.request.Request(
                    f"{base}/agent-prompts/affirmative/Affirmative_custom",
                    method="DELETE",
                )
                with urllib.request.urlopen(delete_request, timeout=5) as response:
                    deleted = json.loads(response.read().decode("utf-8"))
                self.assertFalse(
                    any(profile["profile_id"] == "Affirmative_custom" for profile in deleted["roles"]["affirmative"])
                )
                default_delete_request = urllib.request.Request(
                    f"{base}/agent-prompts/affirmative/Affirmative_default",
                    method="DELETE",
                )
                with self.assertRaises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(default_delete_request, timeout=5)
                self.assertEqual(error.exception.code, 400)
                reset = post_json(f"{base}/agent-prompts", {"reset": True})
                self.assertEqual(reset["defaults"]["negative"], "Negative_default")
                self.assertEqual(reset["defaults"]["moderator"], "Moderator_default")
            finally:
                api_server.shutdown()
                api_server.server_close()
                api_thread.join(timeout=5)

    def test_api_mcp_and_skill_management(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, skills = write_python_fixture(root)
            atlas = root / "atlas"
            atlas.write_text(fake_atlas_mcp_script(), encoding="utf-8")
            atlas.chmod(0o755)
            store = RunRecordStore(root / "records")
            provider_store = ProviderStore(root / "providers.json")
            agent_store = AgentDirectoryStore(root / "agents")
            mcp_store = MCPServerStore(root / "mcp.json")
            skill_store = SkillSourceStore(root / "skills.json")
            api_server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                make_handler(store, provider_store, agent_store, mcp_store, skill_store),
            )
            api_thread = Thread(target=api_server.serve_forever, daemon=True)
            api_thread.start()
            base = f"http://127.0.0.1:{api_server.server_port}"
            try:
                with urllib.request.urlopen(f"{base}/mcp-servers", timeout=5) as response:
                    default_mcp_servers = json.loads(response.read().decode("utf-8"))
                default_atlas = next(item for item in default_mcp_servers if item["id"] == "atlas-default")
                self.assertEqual(default_atlas["args"], ["mcp", "--log-format", "json"])
                self.assertNotIn("--project", default_atlas["args"])

                mcp = post_json(
                    f"{base}/mcp-servers",
                    {
                        "id": "atlas-test",
                        "name": "Atlas Test",
                        "kind": "atlas",
                        "command": str(atlas),
                        "args": ["mcp"],
                        "cwd": "{project}",
                        "enabled": True,
                    },
                )
                self.assertEqual(mcp["id"], "atlas-test")
                defaults = post_json(f"{base}/mcp-servers/defaults", {"atlas": "atlas-test"})
                self.assertEqual(defaults["atlas"], "atlas-test")
                mcp_test = post_json(f"{base}/mcp-servers/atlas-test/test", {"project_path": str(root)})
                self.assertTrue(mcp_test["ok"])
                self.assertIn("trace", mcp_test["tools"])
                skill = post_json(
                    f"{base}/skill-sources",
                    {
                        "id": "demo-skills",
                        "name": "Demo Skills",
                        "path": str(skills),
                        "description": "demo",
                        "enabled": True,
                        "starred": True,
                    },
                )
                self.assertEqual(skill["id"], "demo-skills")
                skill_defaults = post_json(f"{base}/skill-sources/defaults", {"project": "demo-skills"})
                self.assertEqual(skill_defaults["project"], "demo-skills")
                skill_test = post_json(f"{base}/skill-sources/demo-skills/test", {})
                self.assertTrue(skill_test["ok"])
                self.assertEqual(skill_test["fact_count"], 1)
                created = post_json(
                    f"{base}/runs",
                    {
                        "report_path": str(sarif),
                        "source_path": str(root),
                        "skill_source_id": "demo-skills",
                        "enable_external_tools": False,
                    },
                )
                run = wait_for_run_completed(base, created["run_id"])
                self.assertEqual(run["project_context_facts"], 1)
                with urllib.request.urlopen(f"{base}/mcp-servers", timeout=5) as response:
                    mcp_servers = json.loads(response.read().decode("utf-8"))
                self.assertTrue(any(item["id"] == "atlas-test" for item in mcp_servers))
                delete_skill = urllib.request.Request(f"{base}/skill-sources/demo-skills", method="DELETE")
                with urllib.request.urlopen(delete_skill, timeout=5) as response:
                    deleted = json.loads(response.read().decode("utf-8"))
                self.assertTrue(deleted["deleted"])
            finally:
                api_server.shutdown()
                api_server.server_close()
                api_thread.join(timeout=5)

    def test_api_can_stop_running_task(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, skills = write_python_fixture(root)
            llm_server = ThreadingHTTPServer(("127.0.0.1", 0), SlowFakeOpenAIHandler)
            llm_thread = Thread(target=llm_server.serve_forever, daemon=True)
            llm_thread.start()
            store = RunRecordStore(root / "records")
            provider_store = ProviderStore(root / "providers.json")
            provider_store.upsert(
                {
                    "id": "slow",
                    "name": "Slow",
                    "endpoint": f"http://127.0.0.1:{llm_server.server_port}/v1/chat/completions",
                    "model": "fake-model",
                    "api_key": "secret",
                }
            )
            provider_store.set_defaults("slow", "slow")
            api_server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(store, provider_store))
            api_thread = Thread(target=api_server.serve_forever, daemon=True)
            api_thread.start()
            base = f"http://127.0.0.1:{api_server.server_port}"
            try:
                created = post_json(
                    f"{base}/runs",
                    {
                        "report_path": str(sarif),
                        "source_path": str(root),
                        "skills_path": str(skills),
                        "enable_external_tools": False,
                        "enable_llm": True,
                        "max_rounds": 4,
                    },
                )
                stop = post_json(f"{base}/runs/{created['run_id']}/stop", {})
                self.assertEqual(stop["status"], "stopping")
                stopped = wait_for_run_status(base, created["run_id"], {"stopped"})
                self.assertEqual(stopped["status"], "stopped")
                with urllib.request.urlopen(f"{base}/runs", timeout=5) as response:
                    runs = json.loads(response.read().decode("utf-8"))
                saved = next(item for item in runs if item["run_id"] == created["run_id"])
                self.assertEqual(saved["status"], "stopped")
                with urllib.request.urlopen(f"{base}/runs/{created['run_id']}/findings", timeout=5) as response:
                    findings = json.loads(response.read().decode("utf-8"))
                self.assertIsInstance(findings, list)
            finally:
                api_server.shutdown()
                api_server.server_close()
                api_thread.join(timeout=5)
                llm_server.shutdown()
                llm_server.server_close()
                llm_thread.join(timeout=5)

    def test_api_can_pause_and_resume_running_task_from_current_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, skills = write_python_fixture(root)
            llm_server = ThreadingHTTPServer(("127.0.0.1", 0), SlowFakeOpenAIHandler)
            llm_thread = Thread(target=llm_server.serve_forever, daemon=True)
            llm_thread.start()
            store = RunRecordStore(root / "records")
            provider_store = ProviderStore(root / "providers.json")
            provider_store.upsert(
                {
                    "id": "slow",
                    "name": "Slow",
                    "endpoint": f"http://127.0.0.1:{llm_server.server_port}/v1/chat/completions",
                    "model": "fake-model",
                    "api_key": "secret",
                }
            )
            provider_store.set_defaults("slow", "slow", "slow")
            api_server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(store, provider_store))
            api_thread = Thread(target=api_server.serve_forever, daemon=True)
            api_thread.start()
            base = f"http://127.0.0.1:{api_server.server_port}"
            try:
                created = post_json(
                    f"{base}/runs",
                    {
                        "report_path": str(sarif),
                        "source_path": str(root),
                        "skills_path": str(skills),
                        "enable_external_tools": False,
                        "enable_llm": True,
                        "max_rounds": 4,
                    },
                )
                running = wait_for_run_field(base, created["run_id"], "current_finding_id")
                self.assertEqual(running["current_finding_index"], 0)
                persisted_running = store.get(created["run_id"])
                self.assertIsNotNone(persisted_running)
                self.assertEqual(persisted_running["status"], "running")
                self.assertEqual(persisted_running["current_finding_id"], running["current_finding_id"])

                pause = post_json(f"{base}/runs/{created['run_id']}/pause", {})
                self.assertEqual(pause["status"], "pausing")
                paused = wait_for_run_status(base, created["run_id"], {"paused"})
                self.assertEqual(paused["status"], "paused")
                self.assertEqual(paused["completed_finding_count"], 0)
                self.assertEqual(paused["resume_from_finding_index"], 0)
                self.assertEqual(paused["resume_from_finding_id"], running["current_finding_id"])
                with urllib.request.urlopen(f"{base}/runs/{created['run_id']}/findings", timeout=5) as response:
                    paused_findings = json.loads(response.read().decode("utf-8"))
                self.assertEqual(paused_findings, [])

                resumed = post_json(f"{base}/runs/{created['run_id']}/resume", {})
                self.assertEqual(resumed["status"], "running")
                with urllib.request.urlopen(f"{base}/runs", timeout=5) as response:
                    running_runs = json.loads(response.read().decode("utf-8"))
                listed = next(item for item in running_runs if item["run_id"] == created["run_id"])
                self.assertEqual(listed["status"], "running")
                completed = wait_for_run_status(base, created["run_id"], {"completed"})
                self.assertEqual(completed["status"], "completed")
                self.assertEqual(completed["completed_finding_count"], 1)
                with urllib.request.urlopen(f"{base}/runs/{created['run_id']}/findings", timeout=5) as response:
                    findings = json.loads(response.read().decode("utf-8"))
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["rule_id"], "python-command-injection")
            finally:
                api_server.shutdown()
                api_server.server_close()
                api_thread.join(timeout=5)
                llm_server.shutdown()
                llm_server.server_close()
                llm_thread.join(timeout=5)

    def test_vuln_judger_mcp_server_defaults_to_async_opencode_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            captured = {}

            class FakeOpenCodeRunner:
                def __init__(self, *, records_dir):
                    captured["records_dir"] = records_dir

                def run(self, config, *, store, run_origin, should_stop=None):
                    captured["config"] = config
                    captured["run_origin"] = run_origin
                    payload = {
                        "run_id": config.run_id,
                        "status": "completed",
                        "run_origin": run_origin,
                        "engine": "opencode",
                        "created_at": "2026-07-09T00:00:00Z",
                        "source_path": str(config.source_path),
                        "sarif_path": str(config.sarif_path),
                        "finding_count": 0,
                        "completed_finding_count": 0,
                        "reports": [],
                        "diagnostics": [],
                        "config": {"engine": "opencode"},
                    }
                    store.save_payload(payload)
                    return payload

            server = JudgerMCPServer(
                JudgerMCPSettings(
                    records_dir=root / "records",
                    providers_file=root / "providers.json",
                    mcp_servers_file=root / "mcp.json",
                    skills_file=root / "skills.json",
                    agents_dir=root / "agents",
                )
            )
            with patch("vuln_judger.mcp_server.OpenCodeDrivenRunner", FakeOpenCodeRunner):
                started = server._judge_report(
                    {
                        "report_path": str(root / "report.md"),
                        "source_path": str(root / "source"),
                        "silence_reminder_minutes": 23,
                    }
                )
                deadline = time.monotonic() + 2
                completed = None
                while time.monotonic() < deadline:
                    completed = server.records.get(started["run_id"])
                    if completed and completed.get("status") == "completed":
                        break
                    time.sleep(0.01)

            server.close()
            self.assertTrue(started["asynchronous"])
            self.assertEqual(started["engine"], "opencode")
            self.assertEqual(started["poll"]["tool"], "get_run")
            self.assertEqual(started["pause"]["tool"], "pause_run")
            self.assertEqual(completed["status"], "completed")
            self.assertEqual(completed["run_origin"], "mcp")
            self.assertEqual(captured["config"].engine, "opencode")
            self.assertIsNone(captured["config"].mcp_servers_file)
            self.assertFalse(captured["config"].enable_llm)
            self.assertEqual(captured["config"].silence_reminder_minutes, 23)
            self.assertEqual(captured["run_origin"], "mcp")

    def test_vuln_judger_mcp_server_can_stop_async_codex_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            class BlockingCodexRunner:
                def __init__(self, *, records_dir):
                    self.records_dir = records_dir

                def run(self, config, *, store, run_origin, should_stop=None):
                    while should_stop is None or not should_stop():
                        time.sleep(0.01)
                    raise CodexRunnerStopped("stopped by test")

            server = JudgerMCPServer(
                JudgerMCPSettings(
                    records_dir=root / "records",
                    providers_file=root / "providers.json",
                    mcp_servers_file=root / "mcp.json",
                    skills_file=root / "skills.json",
                    agents_dir=root / "agents",
                )
            )
            with patch("vuln_judger.mcp_server.CodexDrivenRunner", BlockingCodexRunner):
                started = server._judge_report(
                    {
                        "report_path": str(root / "report.md"),
                        "source_path": str(root / "source"),
                        "engine": "codex",
                    }
                )
                stopping = server._stop_run({"run_id": started["run_id"]})
                deadline = time.monotonic() + 2
                stopped = None
                while time.monotonic() < deadline:
                    stopped = server.records.get(started["run_id"])
                    if stopped and stopped.get("status") == "stopped":
                        break
                    time.sleep(0.01)

            server.close()
            self.assertTrue(stopping["stop_requested"])
            self.assertEqual(stopped["status"], "stopped")
            self.assertEqual(stopped["run_origin"], "mcp")

    def test_web_can_pause_and_resume_run_owned_by_mcp_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = JudgerMCPSettings(
                records_dir=root / "records",
                providers_file=root / "providers.json",
                mcp_servers_file=root / "mcp.json",
                skills_file=root / "skills.json",
                agents_dir=root / "agents",
            )
            server = JudgerMCPServer(settings)
            resumed = {}

            class BlockingOpenCodeRunner:
                def __init__(self, *, records_dir):
                    self.records_dir = records_dir

                def run(self, config, *, store, run_origin, should_stop=None):
                    while should_stop is None or not should_stop():
                        time.sleep(0.005)
                    # Exercise the completion race: a CLI adapter may return just
                    # as pause is requested instead of raising CodexRunnerStopped.
                    return {
                        "run_id": str(config.run_id),
                        "status": "completed",
                        "run_origin": run_origin,
                        "engine": "opencode",
                        "finding_count": 0,
                        "completed_finding_count": 0,
                        "reports": [],
                        "diagnostics": [],
                    }

            class CompletingOpenCodeRunner:
                def __init__(self, *, records_dir):
                    self.records_dir = records_dir

                def run(self, config, *, store, progress_callback=None, run_origin, should_stop=None):
                    resumed["run_origin"] = run_origin
                    resumed["config"] = config
                    payload = dict(store.get(str(config.run_id)) or {})
                    payload.update(
                        {
                            "run_id": str(config.run_id),
                            "status": "completed",
                            "run_origin": run_origin,
                            "engine": "opencode",
                            "finding_count": 0,
                            "completed_finding_count": 0,
                            "reports": [],
                            "diagnostics": payload.get("diagnostics") or [],
                        }
                    )
                    return payload

            try:
                with patch("vuln_judger.mcp_server.OpenCodeDrivenRunner", BlockingOpenCodeRunner):
                    started = server._judge_report(
                        {
                            "report_path": str(root / "report.md"),
                            "source_path": str(root / "source"),
                            "engine": "opencode",
                        }
                    )
                    run_id = started["run_id"]

                    # A Dashboard process starting while MCP owns the run must not
                    # mistake it for an abandoned run and auto-pause it.
                    self.assertEqual(server.records.recover_unfinished(), [])

                    pause_result = _request_pause(
                        {},
                        {},
                        Lock(),
                        run_id,
                        store=server.records,
                        control_store=RunControlStore(server.records.root),
                    )
                    self.assertEqual(pause_result["status"], "pausing")
                    deadline = time.monotonic() + 2
                    paused = None
                    while time.monotonic() < deadline:
                        paused = server.records.get(run_id)
                        if paused and paused.get("status") == "paused":
                            break
                        time.sleep(0.01)
                    self.assertEqual(paused["status"], "paused")
                    self.assertEqual(paused["run_origin"], "mcp")

                tasks = {}
                stop_events = {}
                pause_events = {}
                tasks_lock = Lock()
                with patch("vuln_judger.api.OpenCodeDrivenRunner", CompletingOpenCodeRunner):
                    resume_result = _request_resume(
                        server.records,
                        tasks,
                        stop_events,
                        pause_events,
                        tasks_lock,
                        run_id,
                        settings.providers_file,
                        server.agent_store,
                        settings.mcp_servers_file,
                        server.skill_store,
                        RunControlStore(server.records.root),
                    )
                    self.assertEqual(resume_result["status"], "running")
                    deadline = time.monotonic() + 2
                    completed = None
                    while time.monotonic() < deadline:
                        completed = server.records.get(run_id)
                        if completed and completed.get("status") == "completed":
                            break
                        time.sleep(0.01)

                self.assertEqual(completed["status"], "completed")
                self.assertEqual(completed["run_origin"], "mcp")
                self.assertEqual(resumed["run_origin"], "mcp")
            finally:
                server.close()

    def test_vuln_judger_mcp_server_tools_run_and_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, skills = write_python_fixture(root)
            records = root / "records"
            command = [
                sys.executable,
                "-m",
                "vuln_judger",
                "mcp",
                "--records-dir",
                str(records),
                "--providers-file",
                str(root / "providers.json"),
                "--mcp-servers-file",
                str(root / "mcp.json"),
                "--skills-file",
                str(root / "skills.json"),
                "--agents-dir",
                str(root / "agents"),
            ]
            with MCPStdioClient(command, cwd=Path.cwd(), timeout=10) as client:
                tool_specs = client.list_tools()
                tools = {tool.get("name") for tool in tool_specs}
                self.assertIn("judge_report", tools)
                self.assertIn("one_round_judge", tools)
                self.assertIn("collect_evidence", tools)
                self.assertIn("export_run_markdown", tools)
                self.assertIn("export_run_report", tools)
                self.assertIn("stop_run", tools)
                self.assertIn("pause_run", tools)
                self.assertIn("resume_run", tools)
                judge_spec = next(tool for tool in tool_specs if tool.get("name") == "judge_report")
                self.assertEqual(judge_spec["inputSchema"]["properties"]["engine"]["default"], "opencode")
                self.assertEqual(
                    judge_spec["inputSchema"]["properties"]["silence_reminder_minutes"]["default"],
                    DEFAULT_SILENCE_REMINDER_MINUTES,
                )
                tool_schema_text = json.dumps(tool_specs, ensure_ascii=False)
                self.assertNotIn("agentic_atlas", tool_schema_text)
                self.assertNotIn("agentic_atlas_direct", tool_schema_text)

                resolved = mcp_tool_json(
                    client.call_tool(
                        "resolve_report_locations",
                        {"report_path": str(sarif), "source_path": str(root)},
                    )
                )
                self.assertEqual(resolved["finding_count"], 1)
                self.assertTrue(resolved["findings"][0]["locations"][0]["line_exists"])

                evidence = mcp_tool_json(
                    client.call_tool(
                        "collect_evidence",
                        {
                            "report_path": str(sarif),
                            "source_path": str(root),
                            "skills_path": str(skills),
                            "enable_external_tools": False,
                        },
                    )
                )
                self.assertTrue(any(item["kind"] == "SOURCE_LOCATION" for item in evidence["evidence"]))

                quick = mcp_tool_json(
                    client.call_tool(
                        "one_round_judge",
                        {
                            "report_path": str(sarif),
                            "source_path": str(root),
                            "skills_path": str(skills),
                            "enable_external_tools": False,
                        },
                    )
                )
                self.assertEqual(quick["mode"], "one_round_judge")
                self.assertEqual(quick["run_origin"], "mcp")
                self.assertEqual(quick["response_mode"], "compact")
                self.assertEqual(quick["configuration"]["max_rounds"], 1)
                self.assertFalse(quick["configuration"]["enable_llm"])
                self.assertTrue(quick["saved"])
                self.assertTrue(Path(quick["record_path"]).exists())
                self.assertEqual(quick["finding_count"], 1)
                self.assertEqual(quick["judged_finding_count"], 1)
                self.assertEqual(quick["selected_finding"]["rule_id"], "python-command-injection")
                self.assertEqual(quick["verdict"]["verdict"], "TRUE_POSITIVE")
                self.assertEqual(quick["verdict"]["label"], "真实漏洞")
                self.assertIn("path_overview", quick)
                self.assertIn("call_chain", quick["path_overview"])
                self.assertIn("data_flow", quick["path_overview"])
                self.assertIn("app.py:4:11", quick["path_overview"]["data_flow"])
                self.assertIn("app.py:5:5", quick["path_overview"]["data_flow"])
                self.assertNotIn("ev-", json.dumps(quick["path_overview"], ensure_ascii=False))
                self.assertIn("key_gaps", quick)
                self.assertIn("next_actions", quick)
                self.assertIn("full_report_access", quick)
                self.assertEqual(quick["full_report_access"]["mcp_get_finding"]["tool"], "get_finding")
                self.assertEqual(quick["full_report_access"]["mcp_export_report"]["tool"], "export_run_report")
                self.assertNotIn("agent_configs", quick)
                self.assertNotIn("evidence_summary", quick)
                self.assertNotIn("missing_evidence", quick)
                self.assertNotIn("evidence", quick)
                self.assertNotIn("debate", quick)
                quick_runs = mcp_tool_json(client.call_tool("list_runs", {"limit": 5}))
                quick_run = next(item for item in quick_runs["runs"] if item["run_id"] == quick["run_id"])
                self.assertEqual(quick_run["run_origin"], "mcp")
                quick_finding_args = quick["full_report_access"]["mcp_get_finding"]["arguments"]
                quick_finding = mcp_tool_json(client.call_tool("get_finding", quick_finding_args))
                self.assertEqual(quick_finding["finding_id"], quick["selected_finding"]["finding_id"])
                self.assertIn("evidence_chain", quick_finding)
                review_store = RunRecordStore(records)
                saved_review = review_store.update_manual_review(
                    quick["run_id"],
                    quick["selected_finding"]["finding_id"],
                    decision="TRUE_POSITIVE",
                    evidence="MCP 读取人工复核测试。",
                )
                self.assertIsNotNone(saved_review)
                reviewed_quick_finding = mcp_tool_json(client.call_tool("get_finding", quick_finding_args))
                self.assertEqual(reviewed_quick_finding["manual_review"]["decision"], "TRUE_POSITIVE")
                reviewed_quick_run = mcp_tool_json(client.call_tool("get_run", {"run_id": quick["run_id"]}))
                self.assertEqual(reviewed_quick_run["manual_review_count"], 1)
                self.assertEqual(reviewed_quick_run["findings"][0]["manual_review"]["evidence"], "MCP 读取人工复核测试。")

                judged = mcp_tool_json(
                    client.call_tool(
                        "judge_report",
                        {
                            "report_path": str(sarif),
                            "source_path": str(root),
                            "engine": "builtin",
                            "skills_path": str(skills),
                            "enable_external_tools": False,
                            "save": True,
                        },
                    )
                )
                self.assertEqual(judged["finding_count"], 1)
                self.assertEqual(judged["run_origin"], "mcp")
                self.assertTrue(judged["saved"])
                run_id = judged["run_id"]

                runs = mcp_tool_json(client.call_tool("list_runs", {"limit": 5}))
                judged_run = next(item for item in runs["runs"] if item["run_id"] == run_id)
                self.assertEqual(judged_run["run_origin"], "mcp")
                run_summary = mcp_tool_json(client.call_tool("get_run", {"run_id": run_id}))
                self.assertEqual(run_summary["run_origin"], "mcp")
                finding_id = run_summary["findings"][0]["finding_id"]
                finding = mcp_tool_json(client.call_tool("get_finding", {"run_id": run_id, "finding_id": finding_id}))
                self.assertEqual(finding["finding_id"], finding_id)
                exported = mcp_tool_json(client.call_tool("export_run_markdown", {"run_id": run_id}))
                self.assertIn("# 漏洞研判报告", exported["markdown"])
                structured = mcp_tool_json(client.call_tool("export_run_report", {"run_id": run_id}))
                self.assertEqual(structured["schema_version"], 1)
                self.assertEqual(structured["detail_level"], "detail")
                self.assertEqual(structured["run"]["run_id"], run_id)
                self.assertEqual(structured["coverage"]["returned"], 1)
                self.assertEqual(structured["findings"][0]["finding_id"], finding_id)
                self.assertIsNotNone(structured["findings"][0]["report_detail"])
                self.assertIsNotNone(structured["findings"][0]["finding_detail"])

    def test_mcp_structured_export_covers_split_pending_findings_and_detail_levels(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = JudgerMCPServer(
                JudgerMCPSettings(
                    records_dir=root / "records",
                    providers_file=root / "providers.json",
                    mcp_servers_file=root / "mcp.json",
                    skills_file=root / "skills.json",
                    agents_dir=root / "agents",
                )
            )
            try:
                split_findings = [
                    {
                        "finding_id": "F-1",
                        "rule_id": "RULE-1",
                        "level": "error",
                        "message": "first report",
                        "locations": [{"file": "one.py", "line": 1}],
                        "code_flows": [],
                        "report_markdown": "# Original report one",
                    },
                    {
                        "finding_id": "F-2",
                        "rule_id": "RULE-2",
                        "level": "warning",
                        "message": "second report",
                        "locations": [{"file": "two.py", "line": 2}],
                        "code_flows": [],
                        "report_markdown": "# Original report two",
                    },
                    {
                        "finding_id": "F-3",
                        "rule_id": "RULE-3",
                        "level": "note",
                        "message": "third report",
                        "locations": [],
                        "code_flows": [],
                        "report_markdown": "# Original report three",
                    },
                ]
                completed_report = {
                    "finding_id": "F-1",
                    "rule_id": "RULE-1",
                    "verdict": "TRUE_POSITIVE",
                    "confidence": 0.9,
                    "reasoning_summary": "confirmed path",
                    "final_conclusion": "real vulnerability",
                    "source_locations": [{"file": "one.py", "line": 1}],
                    "protection_assessment": "no guard",
                    "impact_assessment": "command execution",
                    "disputed_points": [],
                    "recommended_next_steps": ["fix it"],
                    "verification_case": {"vulnerability_type": "RULE-1"},
                    "scorecard": {"call_chain": "confirmed"},
                    "evidence_graph": {"nodes": [{"id": "source"}], "edges": []},
                    "evidence_ledger": [{"claim": "entry", "status": "confirmed"}],
                    "evidence_chain": [
                        {
                            "kind": "REPORT",
                            "source": "input-report",
                            "summary": "first report",
                            "data": {
                                "rule_id": "RULE-1",
                                "level": "error",
                                "message": "first report",
                            },
                        },
                        {"kind": "SOURCE_LOCATION", "snippet": "dangerous()"},
                    ],
                    "debate": [{"role": "affirmative", "claim": "long debate"}],
                    "cli_workflow": {
                        "affirmative": {"position": "TRUE_POSITIVE", "summary": "reachable"},
                        "negative": {"position": "INCONCLUSIVE", "limitations": ["guard unknown"]},
                        "moderator": {"verdict": "TRUE_POSITIVE", "final_conclusion": "real vulnerability"},
                        "pipeline": {"stage": "completed"},
                    },
                }
                in_progress_report = {
                    "finding_id": "F-2",
                    "rule_id": "RULE-2",
                    "finding_status": "in_progress",
                    "cli_workflow": {"affirmative": {"position": "TRUE_POSITIVE", "summary": "checking"}},
                }
                server.records.save_payload(
                    {
                        "run_id": "run-structured",
                        "status": "failed",
                        "engine": "opencode",
                        "run_origin": "mcp",
                        "created_at": "2026-01-01T00:00:00Z",
                        "updated_at": "2026-01-01T00:05:00Z",
                        "source_path": str(root / "source"),
                        "sarif_path": str(root / "report.sarif"),
                        "finding_count": 3,
                        "completed_finding_count": 1,
                        "current_finding_ids": {"negative": "F-2"},
                        "resume_from_finding_id": "F-2",
                        "resume_from_finding_index": 1,
                        "report_findings": {"origin": "sarif-local", "findings": split_findings},
                        "reports": [completed_report, in_progress_report],
                        "manual_reviews": {
                            "F-3": {"decision": "INCONCLUSIVE", "evidence": "needs reproduction"}
                        },
                        "diagnostics": ["stage failed"],
                        "error": "delivery missing",
                    }
                )

                detail = server._call_tool(
                    "export_run_report",
                    {"run_id": "run-structured", "offset": 1, "limit": 2},
                )
                self.assertEqual(detail["coverage"]["source"], "report_findings")
                self.assertEqual(detail["coverage"]["split_origin"], "sarif-local")
                self.assertEqual(detail["coverage"]["completed"], 1)
                self.assertEqual(detail["coverage"]["in_progress"], 1)
                self.assertEqual(detail["coverage"]["pending"], 1)
                self.assertEqual(detail["coverage"]["missing_detail"], 1)
                self.assertEqual([item["finding_id"] for item in detail["findings"]], ["F-2", "F-3"])
                self.assertEqual(detail["findings"][0]["status"], "in_progress")
                self.assertEqual(detail["findings"][1]["status"], "pending")
                self.assertEqual(detail["findings"][1]["report_detail"]["message"], "third report")
                self.assertIsNone(detail["findings"][1]["finding_detail"])
                self.assertEqual(detail["findings"][1]["missing_detail_reason"], "adjudication_not_started")
                self.assertEqual(detail["findings"][1]["manual_review"]["evidence"], "needs reproduction")

                summary = server._call_tool(
                    "export_run_report",
                    {"run_id": "run-structured", "detail_level": "summary", "finding_ids": ["F-1"]},
                )
                self.assertIsNone(summary["findings"][0]["report_detail"])
                self.assertIsNone(summary["findings"][0]["finding_detail"])
                self.assertEqual(summary["findings"][0]["conclusion"]["verdict"], "TRUE_POSITIVE")

                raw = server._call_tool(
                    "export_run_report",
                    {"run_id": "run-structured", "detail_level": "raw", "finding_ids": ["F-1"]},
                )
                raw_finding = raw["findings"][0]
                self.assertEqual(raw_finding["raw"]["split_finding"]["report_markdown"], "# Original report one")
                self.assertEqual(raw_finding["raw"]["report"]["debate"][0]["claim"], "long debate")
                self.assertNotIn("debate", raw_finding["finding_detail"])
                self.assertNotIn("pipeline", raw_finding["finding_detail"]["role_conclusions"])

                server.records.save_payload(
                    {
                        "run_id": "run-legacy",
                        "status": "completed",
                        "finding_count": 1,
                        "reports": [completed_report],
                    }
                )
                legacy = server._call_tool("export_run_report", {"run_id": "run-legacy"})
                self.assertEqual(legacy["coverage"]["source"], "reports")
                self.assertTrue(legacy["coverage"]["canonical_complete"])

                with self.assertRaisesRegex(ValueError, "Finding not found: missing"):
                    server._call_tool(
                        "export_run_report",
                        {"run_id": "run-structured", "finding_ids": ["missing"]},
                    )
            finally:
                server.close()

    def test_vuln_judger_mcp_server_supports_content_length_framing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "vuln_judger",
                    "mcp",
                    "--records-dir",
                    str(root / "records"),
                    "--providers-file",
                    str(root / "providers.json"),
                    "--mcp-servers-file",
                    str(root / "mcp.json"),
                    "--skills-file",
                    str(root / "skills.json"),
                    "--agents-dir",
                    str(root / "agents"),
                ],
                cwd=str(Path.cwd()),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                send_mcp_header_message(
                    process,
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "unit", "version": "test"},
                        },
                    },
                )
                initialized = read_mcp_header_message(process)
                self.assertEqual(initialized["result"]["serverInfo"]["name"], "vuln-judger-mcp")
                send_mcp_header_message(process, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
                tools = read_mcp_header_message(process)
                self.assertTrue(any(tool["name"] == "judge_report" for tool in tools["result"]["tools"]))
            finally:
                if process.stdin is not None:
                    try:
                        process.stdin.close()
                    except OSError:
                        pass
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except OSError:
                            pass

    def test_affirmative_negative_and_moderator_use_independent_clients(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, _skills = write_python_fixture(root)
            finding = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    enable_external_tools=False,
                )
            ).reports[0]
            bundle = EvidenceBundle(
                finding=type("FindingLike", (), {})(),
                evidence=finding.evidence_chain,
                diagnostics=[],
            )
            bundle.finding.finding_id = finding.finding_id
            bundle.finding.rule_id = finding.rule_id
            bundle.finding.message = "demo"
            bundle.finding.locations = finding.source_locations
            affirmative = FakeLLM("AFFIRMATIVE_FROM_CLIENT")
            negative = FakeLLM("NEGATIVE_FROM_CLIENT")
            moderator = FakeLLM("MODERATOR_FROM_CLIENT")
            report = DebateOrchestrator(
                affirmative_client=affirmative,
                negative_client=negative,
                moderator_client=moderator,
            ).adjudicate(bundle)
            self.assertIn("AFFIRMATIVE_FROM_CLIENT", report.debate[0].claim)
            self.assertIn("NEGATIVE_FROM_CLIENT", report.debate[1].claim)
            self.assertIn("MODERATOR_FROM_CLIENT", report.final_conclusion)
            self.assertIn("MODERATOR_FROM_CLIENT", report.debate[-1].claim)
            self.assertTrue(affirmative.calls)
            self.assertTrue(negative.calls)
            self.assertTrue(moderator.calls)

    def test_llm_agent_can_autonomously_call_atlas_mcp_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, _skills = write_python_fixture(root)
            atlas = root / "atlas"
            atlas.write_text(fake_atlas_mcp_focus_graph_script(), encoding="utf-8")
            atlas.chmod(0o755)
            mcp_file = root / "mcp.json"
            mcp_file.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "defaults": {"atlas": "atlas-test"},
                        "servers": [
                            {
                                "id": "atlas-test",
                                "name": "Atlas Test",
                                "kind": "atlas",
                                "transport": "stdio",
                                "command": str(atlas),
                                "args": ["mcp"],
                                "cwd": "{project}",
                                "enabled": True,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            finding = load_sarif(sarif)[0]
            bundle = EvidenceBundle(
                finding=finding,
                evidence=[
                    CodeEvidence(
                        evidence_id="ev-report",
                        kind=EvidenceKind.REPORT,
                        strength=EvidenceStrength.STRONG,
                        summary="输入报告",
                        source="test",
                        locations=list(finding.locations),
                    )
                ],
                diagnostics=[],
            )
            affirmative = SequenceLLM(
                [
                    json.dumps(
                        {
                            "atlas_tool_calls": [
                                {
                                    "tool": "project",
                                    "arguments": {
                                        "action": "open",
                                        "project_path": str(root),
                                        "storage": "auto",
                                    },
                                },
                                {"tool": "search", "arguments": {"query": "handler", "limit": 5}},
                                {
                                    "tool": "trace",
                                    "arguments": {"kind": "point", "file_path": "app.py", "line": 4, "column": 5},
                                },
                            ]
                        },
                        ensure_ascii=False,
                    ),
                    "AFFIRMATIVE_AFTER_ATLAS",
                    "AFFIRMATIVE_FINAL",
                ]
            )
            report = DebateOrchestrator(
                max_rounds=1,
                affirmative_client=affirmative,
                negative_client=FakeLLM("NEGATIVE"),
                moderator_client=FakeLLM("MODERATOR"),
                source_path=root,
                mcp_servers_file=mcp_file,
                enable_atlas_tools=True,
            ).adjudicate(bundle)

            self.assertGreaterEqual(len(affirmative.calls), 2)
            self.assertIn("atlas_tool_calls", affirmative.calls[0][1])
            self.assertIn("Atlas MCP 工具观察", affirmative.calls[1][1])
            self.assertTrue(any(item.source == "agent-atlas-mcp:affirmative" for item in report.evidence_chain))
            self.assertTrue(any(item.kind == EvidenceKind.DATA_FLOW and item.source == "agent-atlas-mcp:affirmative" for item in report.evidence_chain))

    def test_llm_agent_atlas_mcp_timeout_uses_environment_setting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, _skills = write_python_fixture(root)
            atlas = root / "atlas"
            atlas.write_text(fake_atlas_mcp_timeout_script(), encoding="utf-8")
            atlas.chmod(0o755)
            mcp_file = root / "mcp.json"
            mcp_file.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "defaults": {"atlas": "atlas-test"},
                        "servers": [
                            {
                                "id": "atlas-test",
                                "name": "Atlas Test",
                                "kind": "atlas",
                                "transport": "stdio",
                                "command": str(atlas),
                                "args": ["mcp"],
                                "cwd": "{project}",
                                "enabled": True,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            finding = load_sarif(sarif)[0]
            bundle = EvidenceBundle(
                finding=finding,
                evidence=[
                    CodeEvidence(
                        evidence_id="ev-report",
                        kind=EvidenceKind.REPORT,
                        strength=EvidenceStrength.STRONG,
                        summary="输入报告",
                        source="test",
                        locations=list(finding.locations),
                    )
                ],
                diagnostics=[],
            )
            affirmative = SequenceLLM(
                [
                    json.dumps(
                        {
                            "atlas_tool_calls": [
                                {
                                    "tool": "project",
                                    "arguments": {
                                        "action": "open",
                                        "project_path": str(root),
                                        "storage": "auto",
                                    },
                                },
                                {
                                    "tool": "trace",
                                    "arguments": {"kind": "point", "file_path": "app.py", "line": 4, "column": 5},
                                },
                            ]
                        },
                        ensure_ascii=False,
                    ),
                    "AFFIRMATIVE_AFTER_TIMEOUT",
                    "AFFIRMATIVE_FINAL",
                ]
            )

            with patch.dict(
                "os.environ",
                {"VULN_JUDGER_ATLAS_MCP_TIMEOUT": "1", "VULN_JUDGER_MCP_TIMEOUT": "1"},
            ):
                report = DebateOrchestrator(
                    max_rounds=1,
                    affirmative_client=affirmative,
                    negative_client=FakeLLM("NEGATIVE"),
                    moderator_client=FakeLLM("MODERATOR"),
                    source_path=root,
                    mcp_servers_file=mcp_file,
                    enable_atlas_tools=True,
                ).adjudicate(bundle)

            summaries = "\n".join(item.summary for item in report.evidence_chain)
            self.assertIn("MCP request timed out after 1s: tools/call:trace", summaries)
            self.assertIn("AFFIRMATIVE_AFTER_TIMEOUT", report.debate[0].claim)

    def test_llm_agent_tool_json_after_round_limit_does_not_become_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, _skills = write_python_fixture(root)
            atlas = root / "atlas"
            atlas.write_text(fake_atlas_mcp_focus_graph_script(), encoding="utf-8")
            atlas.chmod(0o755)
            mcp_file = root / "mcp.json"
            mcp_file.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "defaults": {"atlas": "atlas-test"},
                        "servers": [
                            {
                                "id": "atlas-test",
                                "name": "Atlas Test",
                                "kind": "atlas",
                                "transport": "stdio",
                                "command": str(atlas),
                                "args": ["mcp"],
                                "cwd": "{project}",
                                "enabled": True,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            finding = load_sarif(sarif)[0]
            bundle = EvidenceBundle(
                finding=finding,
                evidence=[
                    CodeEvidence(
                        evidence_id="ev-report",
                        kind=EvidenceKind.REPORT,
                        strength=EvidenceStrength.STRONG,
                        summary="输入报告",
                        source="test",
                        locations=list(finding.locations),
                    )
                ],
                diagnostics=[],
            )
            tool_json = json.dumps(
                {"atlas_tool_calls": [{"tool": "search", "arguments": {"query": "handler"}}]},
                ensure_ascii=False,
            )
            affirmative = SequenceLLM([tool_json, tool_json, tool_json, "SHOULD_NOT_BE_USED"])

            with patch.dict("os.environ", {"VULN_JUDGER_AGENT_ATLAS_TOOL_ROUNDS": "2"}):
                report = DebateOrchestrator(
                    max_rounds=1,
                    affirmative_client=affirmative,
                    negative_client=FakeLLM("NEGATIVE"),
                    moderator_client=FakeLLM("MODERATOR"),
                    source_path=root,
                    mcp_servers_file=mcp_file,
                    enable_atlas_tools=True,
                ).adjudicate(bundle)

            first_claim = report.debate[0].raw_claim or report.debate[0].claim
            summaries = "\n".join(item.summary for item in report.evidence_chain)
            self.assertNotIn("atlas_tool_calls", first_claim)
            self.assertIn("正方证据报告", first_claim)
            self.assertIn("工具轮次耗尽", summaries)

    def test_llm_agent_default_budget_allows_five_llm_and_twenty_mcp_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, _skills = write_python_fixture(root)
            atlas = root / "atlas"
            atlas.write_text(fake_atlas_mcp_focus_graph_script(), encoding="utf-8")
            atlas.chmod(0o755)
            mcp_file = root / "mcp.json"
            mcp_file.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "defaults": {"atlas": "atlas-test"},
                        "servers": [
                            {
                                "id": "atlas-test",
                                "name": "Atlas Test",
                                "kind": "atlas",
                                "transport": "stdio",
                                "command": str(atlas),
                                "args": ["mcp"],
                                "cwd": "{project}",
                                "enabled": True,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            finding = load_sarif(sarif)[0]
            bundle = EvidenceBundle(
                finding=finding,
                evidence=[
                    CodeEvidence(
                        evidence_id="ev-report",
                        kind=EvidenceKind.REPORT,
                        strength=EvidenceStrength.STRONG,
                        summary="输入报告",
                        source="test",
                        locations=list(finding.locations),
                    )
                ],
                diagnostics=[],
            )
            tool_json = json.dumps(
                {
                    "atlas_tool_calls": [
                        {"tool": "search", "arguments": {"query": f"handler_{index}"}}
                        for index in range(5)
                    ]
                },
                ensure_ascii=False,
            )
            affirmative = SequenceLLM([tool_json, tool_json, tool_json, tool_json, "AFFIRMATIVE_FINAL"])

            report = DebateOrchestrator(
                max_rounds=1,
                affirmative_client=affirmative,
                negative_client=FakeLLM("NEGATIVE"),
                moderator_client=FakeLLM("MODERATOR"),
                source_path=root,
                mcp_servers_file=mcp_file,
                enable_atlas_tools=True,
            ).adjudicate(bundle)

            agent_evidence = [
                item
                for item in report.evidence_chain
                if item.source == "agent-atlas-mcp:affirmative" and item.data.get("mcp_tool") == "search"
            ]
            budget_evidence = [
                item
                for item in report.evidence_chain
                if item.source == "agent-atlas-mcp:affirmative" and item.data.get("budget_exhausted")
            ]
            self.assertEqual(len(affirmative.calls), 5)
            self.assertEqual(len(agent_evidence), 20)
            self.assertEqual(len(budget_evidence), 1)
            self.assertEqual(budget_evidence[0].data["used_mcp_calls"], 20)
            self.assertIn("不能等同于已证明路径不可达", report.final_conclusion)
            self.assertTrue(any("增大工具预算" in step for step in report.recommended_next_steps))
            self.assertIn("AFFIRMATIVE_FINAL", report.debate[0].raw_claim or report.debate[0].claim)

    def test_llm_agent_scopes_wide_search_to_report_file(self):
        from vuln_judger.debate import _normalize_agent_atlas_tool_arguments

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "faiss" / "impl").mkdir(parents=True)
            (root / "faiss" / "impl" / "index_read.cpp").write_text("void read_index_up() {}\n", encoding="utf-8")
            bundle = EvidenceBundle(
                finding=Finding(
                    finding_id="f-scope",
                    rule_id="rule",
                    message="demo",
                    level="error",
                    locations=[SourceLocation("faiss/faiss/impl/index_read.cpp", 1493)],
                ),
                evidence=[],
                diagnostics=[],
            )

            normalized = _normalize_agent_atlas_tool_arguments(
                "search",
                {"query": "read_index_up"},
                root,
                bundle,
            )

            self.assertEqual(normalized["scope"], "faiss/impl/index_read.cpp")
            self.assertEqual(normalized["limit"], 20)

            directory_scope = _normalize_agent_atlas_tool_arguments(
                "search",
                {"query": "IndexFlatPanorama", "scope": "faiss/impl", "limit": 20},
                root,
                bundle,
            )
            self.assertEqual(directory_scope["scope"], "faiss/impl/index_read.cpp")

    def test_llm_agent_normalizes_common_atlas_argument_aliases(self):
        from vuln_judger.debate import _normalize_agent_atlas_tool_arguments

        project_args = _normalize_agent_atlas_tool_arguments(
            "project",
            {"action": "open", "storage": "auto", "scan_files": True, "background": True},
            Path("/tmp/source"),
            None,
        )
        calls_args = _normalize_agent_atlas_tool_arguments(
            "calls",
            {"function": "read_index", "scope": "faiss/impl/index_read.cpp", "direction": "upstream"},
            None,
            None,
        )
        symbol_args = _normalize_agent_atlas_tool_arguments(
            "symbol",
            {"query": "search", "kind": "member", "scope": "faiss/IndexFlat.cpp", "limit": 10, "include_details": True},
            None,
            None,
        )
        trace_args = _normalize_agent_atlas_tool_arguments(
            "trace",
            {
                "start": "faiss/impl/index_read.cpp:1493",
                "end": "faiss/impl/Panorama.cpp:193",
                "variables": ["batch_size", "n_levels", "cum_sums"],
            },
            None,
            None,
        )

        self.assertEqual(project_args, {"action": "open", "project_path": "/tmp/source"})
        self.assertEqual(calls_args, {"symbol": "read_index", "direction": "incoming"})
        self.assertEqual(
            symbol_args,
            {"symbol": "search", "file_path": "faiss/IndexFlat.cpp", "limit": 10, "includeCode": True},
        )
        self.assertEqual(
            trace_args,
            {
                "from": "faiss/impl/index_read.cpp:1493",
                "to": "faiss/impl/Panorama.cpp:193",
                "kind": "forward",
            },
        )

    def test_agent_config_is_used_by_llm_prompts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, _skills = write_python_fixture(root)
            finding = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    enable_external_tools=False,
                )
            ).reports[0]
            bundle = EvidenceBundle(
                finding=type("FindingLike", (), {})(),
                evidence=finding.evidence_chain,
                diagnostics=[],
            )
            bundle.finding.finding_id = finding.finding_id
            bundle.finding.rule_id = finding.rule_id
            bundle.finding.message = "demo"
            bundle.finding.locations = finding.source_locations
            affirmative = FakeLLM("AFFIRMATIVE_FROM_CLIENT")
            negative = FakeLLM("NEGATIVE_FROM_CLIENT")
            moderator = FakeLLM("MODERATOR_FROM_CLIENT")
            DebateOrchestrator(
                affirmative_client=affirmative,
                negative_client=negative,
                moderator_client=moderator,
                affirmative_agent=AgentConfig("利用证据指证员", "优先关注资产窃取证据。"),
                negative_agent=AgentConfig("可达性复核员", "质疑死代码和缓解措施。"),
                moderator_agent=AgentConfig("中立主持人", "只总结双方核心观点。"),
            ).adjudicate(bundle)
            self.assertIn("利用证据指证员", affirmative.calls[0][0])
            self.assertIn("优先关注资产窃取证据。", affirmative.calls[0][0])
            self.assertIn("正方证据不足补强策略", affirmative.calls[0][1])
            self.assertIn("源码分析、Atlas 检查和交叉验证路径", affirmative.calls[0][1])
            self.assertIn("外部输入源头", affirmative.calls[0][1])
            self.assertIn("grep/ripgrep", affirmative.calls[0][1])
            self.assertIn("回到 Atlas", affirmative.calls[0][1])
            self.assertIn("误报、不可利用漏洞或证据不足", affirmative.calls[0][1])
            self.assertIn("代码上下文业务逻辑说明", affirmative.calls[0][1])
            self.assertIn("可达性复核员", negative.calls[0][0])
            self.assertIn("质疑死代码和缓解措施。", negative.calls[0][0])
            self.assertIn("敏感信息", negative.calls[0][1])
            self.assertIn("key 可能是密钥", negative.calls[0][1])
            self.assertIn("普通标识", negative.calls[0][1])
            self.assertIn("代码上下文业务逻辑", negative.calls[0][1])
            self.assertIn("加解密、签名、凭证校验", negative.calls[0][1])
            self.assertIn("反方自主验证策略", negative.calls[0][1])
            self.assertIn("独立围绕原始报告", negative.calls[0][1])
            self.assertIn("主动寻找能推翻、削弱或限定正方主张", negative.calls[0][1])
            self.assertIn("中立主持人", moderator.calls[0][0])
            self.assertIn("只总结双方核心观点。", moderator.calls[0][0])
            self.assertIn("Moderator 自主审查策略", moderator.calls[0][1])
            self.assertIn("独立审查报告读取", moderator.calls[0][1])
            self.assertIn("代码上下文业务逻辑", moderator.calls[0][1])
            self.assertIn("异常报告读取", moderator.calls[0][1])

    def test_final_conclusion_rejects_llm_task_echo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, _skills = write_python_fixture(root)
            finding = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    enable_external_tools=False,
                )
            ).reports[0]
            bundle = EvidenceBundle(
                finding=type("FindingLike", (), {})(),
                evidence=finding.evidence_chain,
                diagnostics=[],
            )
            bundle.finding.finding_id = finding.finding_id
            bundle.finding.rule_id = finding.rule_id
            bundle.finding.message = "demo"
            bundle.finding.locations = finding.source_locations
            bad_final = (
                "【真实漏洞】，分析用户请求**： 方向**：真实漏洞。 "
                "约束**：中文 Markdown，引用证据 ID，不编造，不重复指令。"
            )
            bad_summary = (
                "理解目标**：用户希望我担任“正方 Agent”（Positive_default），"
                "对“反方”提出的质疑进行反驳，并提交最终结案报告。 "
                "分析输入**： 角色**：正方 Agent（Positive_default）。 "
                "任务**：反驳反方质疑，坚持漏洞主张。 反方质疑摘要**："
            )
            report = DebateOrchestrator(
                affirmative_client=FakeLLM(bad_final),
                negative_client=FakeLLM(bad_final),
                moderator_client=FakeLLM(bad_summary),
            ).adjudicate(bundle)
            serialized = to_jsonable(report)
            for field in (report.final_conclusion, report.reasoning_summary, serialized["reasoning_summary"]):
                self.assertNotIn("我需要", field)
                self.assertNotIn("间断", field)
                self.assertNotIn("用户要求", field)
                self.assertNotIn("结论标签固定", field)
                self.assertNotIn("只输出1到3句话", field)
                self.assertNotIn("分析请求", field)
                self.assertNotIn("分析用户请求", field)
                self.assertNotIn("理解目标", field)
                self.assertNotIn("Positive_default", field)
                self.assertNotIn("反方质疑摘要", field)
                self.assertNotIn("强约束", field)
                self.assertNotIn("标签约束", field)
                self.assertNotIn("必须遵守", field)
                self.assertNotIn("之前的分析", field)
            self.assertFalse(any(turn["claim"].startswith("## 正方结案") for turn in serialized["debate"]))
            self.assertFalse(any(turn["claim"].startswith("## 反方结案") for turn in serialized["debate"]))
            self.assertIn("报告、源码位置和数据流/调用链证据形成闭环", report.final_conclusion)
            self.assertIn("报告、源码位置和数据流/调用链证据形成闭环", report.reasoning_summary)

    def test_negative_dispute_prevents_default_web_debate_from_closing_after_first_round(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, _skills = write_python_fixture(root)
            finding = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    enable_external_tools=False,
                )
            ).reports[0]
            bundle = EvidenceBundle(
                finding=type("FindingLike", (), {})(),
                evidence=finding.evidence_chain,
                diagnostics=[],
            )
            bundle.finding.finding_id = finding.finding_id
            bundle.finding.rule_id = finding.rule_id
            bundle.finding.message = "demo"
            bundle.finding.locations = finding.source_locations
            affirmative = SequenceLLM(
                [
                    "正方证据报告：调用链和数据流已按证据闭环。",
                    "正方第 2 回合澄清：补充 HTTP handler 到 service 层的入口证据 ev-a。",
                    "正方第 3 回合澄清：补充 service 调用 sink 的参数传递证据 ev-b。",
                    "正方第 4 回合澄清：继续围绕剩余质疑提交边界条件证据 ev-c。",
                ]
            )
            negative = SequenceLLM(
                [
                    "## 反方质疑报告\n### 仍未闭环的问题\n- 调用链仍未闭环，报告无法证明外部输入可达。\n### 是否继续质疑：是",
                    "## 反方第 2 回合复审报告\n### 仍未闭环的问题\n- handler 证据仍未证明文件输入会到达 parser，反方继续质疑。",
                    "## 反方第 3 回合复审报告\n### 仍未闭环的问题\n- service 到 sink 的参数别名关系仍未被 trace 支持，反方继续质疑。",
                    "## 反方第 4 回合复审报告\n### 仍未闭环的问题\n- 边界条件证据仍未覆盖异常路径，反方继续质疑。",
                ]
            )
            report = DebateOrchestrator(
                max_rounds=4,
                affirmative_client=affirmative,
                negative_client=negative,
                moderator_client=FakeLLM("主持人总结正文。"),
            ).adjudicate(bundle)

            moderator_rounds = [
                turn for turn in report.debate if turn.role.value == "MODERATOR" and turn.round_index == 1
            ]
            self.assertTrue(moderator_rounds)
            self.assertIn("是否继续下一轮：是", moderator_rounds[0].claim)
            affirmative_rounds = [
                turn for turn in report.debate if turn.role.value == "AFFIRMATIVE" and turn.round_index == 2
            ]
            self.assertTrue(affirmative_rounds)
            self.assertNotIn("正方结案", affirmative_rounds[0].claim)
            self.assertTrue(
                any(turn.role.value == "NEGATIVE" and turn.round_index == 2 for turn in report.debate)
            )
            self.assertNotEqual(report.debate[-1].round_index, 2)
            self.assertEqual(report.debate[-1].round_index, 5)
            affirmative_round4 = next(
                turn for turn in report.debate if turn.role.value == "AFFIRMATIVE" and turn.round_index == 4
            )
            negative_round4 = next(
                turn for turn in report.debate if turn.role.value == "NEGATIVE" and turn.round_index == 4
            )
            self.assertIn("继续围绕剩余质疑提交边界条件证据", affirmative_round4.raw_claim)
            self.assertIn("继续质疑", negative_round4.raw_claim)
            self.assertNotIn("正方结案", affirmative_round4.claim)
            self.assertNotIn("反方结案", negative_round4.claim)
            self.assertEqual(report.debate[-1].role.value, "MODERATOR")
            self.assertFalse(any("正方结案" in turn.claim or "反方结案" in turn.claim for turn in report.debate))

    def test_moderator_can_stop_next_round_even_when_negative_disputes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, _skills = write_python_fixture(root)
            finding = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    enable_external_tools=False,
                )
            ).reports[0]
            bundle = EvidenceBundle(
                finding=type("FindingLike", (), {})(),
                evidence=finding.evidence_chain,
                diagnostics=[],
            )
            bundle.finding.finding_id = finding.finding_id
            bundle.finding.rule_id = finding.rule_id
            bundle.finding.message = "demo"
            bundle.finding.locations = finding.source_locations
            affirmative = SequenceLLM(["正方证据报告。", "正方最终总结正文。"])
            negative = SequenceLLM(
                [
                    "## 反方质疑报告\n- 调用链仍未闭环，报告无法证明外部输入可达。",
                    "反方最终总结正文。",
                ]
            )
            report = DebateOrchestrator(
                max_rounds=4,
                affirmative_client=affirmative,
                negative_client=negative,
                moderator_client=SequenceLLM(
                    [
                        "是否继续下一轮：否\n未闭环争议：无\n分析：Moderator 裁定当前争议不需要继续下一轮。",
                        "Moderator 最终总结正文。",
                    ]
                ),
            ).adjudicate(bundle)

            moderator_round = next(
                turn for turn in report.debate if turn.role.value == "MODERATOR" and turn.round_index == 1
            )
            self.assertIn("是否继续下一轮：否", moderator_round.claim)
            self.assertEqual(report.debate[-1].round_index, 2)
            self.assertFalse(
                any(
                    turn.role.value == "AFFIRMATIVE"
                    and turn.round_index == 2
                    for turn in report.debate
                )
            )
            self.assertEqual(len(affirmative.calls), 1)
            self.assertEqual(len(negative.calls), 1)
            self.assertIn("Moderator 最终总结正文", report.final_conclusion)

    def test_moderator_ends_debate_when_agents_repeat(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, _skills = write_python_fixture(root)
            finding = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    enable_external_tools=False,
                )
            ).reports[0]
            bundle = EvidenceBundle(
                finding=type("FindingLike", (), {})(),
                evidence=finding.evidence_chain,
                diagnostics=[],
            )
            bundle.finding.finding_id = finding.finding_id
            bundle.finding.rule_id = finding.rule_id
            bundle.finding.message = "demo"
            bundle.finding.locations = finding.source_locations
            repeated = "重复观点：报告位置、调用链、影响和防护结论全部照抄上一轮，没有新增证据。" * 3

            report = DebateOrchestrator(
                max_rounds=4,
                affirmative_client=FakeLLM(repeated),
                negative_client=FakeLLM(repeated),
            ).adjudicate(bundle)

            self.assertEqual(report.debate[-1].role.value, "MODERATOR")
            moderator_round = next(
                turn for turn in report.debate if turn.role.value == "MODERATOR" and turn.round_index == 1
            )
            self.assertIn("是否继续下一轮：否", moderator_round.claim)
            self.assertIn("高度复读", moderator_round.claim)
            self.assertFalse(any("正方结案" in turn.claim or "反方结案" in turn.claim for turn in report.debate))
            self.assertEqual(report.debate[-1].round_index, 2)

    def test_run_report_records_provider_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, skills = write_python_fixture(root)
            providers_file = root / "providers.json"
            store = ProviderStore(providers_file)
            store.upsert(
                {
                    "id": "fake",
                    "name": "Fake",
                    "endpoint": "http://127.0.0.1:9/v1/chat/completions",
                    "model": "fake-model",
                    "api_key": "secret",
                }
            )
            store.set_defaults("fake", "fake", "fake")
            report = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    skills_path=skills,
                    providers_file=providers_file,
                    enable_external_tools=False,
                    enable_llm=True,
                )
            )
            self.assertEqual(report.llm_providers["affirmative"]["provider_id"], "fake")
            self.assertEqual(report.llm_providers["negative"]["provider_id"], "fake")
            self.assertEqual(report.llm_providers["moderator"]["provider_id"], "fake")
            self.assertTrue(report.llm_providers["affirmative"]["client_available"])
            self.assertTrue(report.llm_providers["moderator"]["client_available"])
            self.assertEqual(report.llm_providers["affirmative"]["status"], "ready")

    def test_run_report_records_agent_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, skills = write_python_fixture(root)
            report = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    skills_path=skills,
                    enable_external_tools=False,
                    affirmative_agent=AgentConfig("利用证据指证员", "关注价值资产。"),
                    negative_agent=AgentConfig("缓解措施复核员", "关注可达缓解措施。"),
                    moderator_agent=AgentConfig("中立主持人", "总结双方核心观点。"),
                )
            )
            self.assertEqual(report.agent_configs["affirmative"]["name"], "利用证据指证员")
            self.assertEqual(report.agent_configs["negative"]["instructions"], "关注可达缓解措施。")
            self.assertEqual(report.agent_configs["moderator"]["instructions"], "总结双方核心观点。")

    def test_run_report_records_disabled_provider_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, skills = write_python_fixture(root)
            providers_file = root / "providers.json"
            store = ProviderStore(providers_file)
            store.upsert(
                {
                    "id": "fake",
                    "name": "Fake",
                    "endpoint": "http://127.0.0.1:9/v1/chat/completions",
                    "model": "fake-model",
                    "api_key": "secret",
                }
            )
            store.set_defaults("fake", "fake", "fake")
            report = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    skills_path=skills,
                    providers_file=providers_file,
                    enable_external_tools=False,
                    enable_llm=False,
                )
            )
            self.assertFalse(report.llm_providers["enabled"])
            self.assertEqual(report.llm_providers["affirmative"]["provider_id"], "fake")
            self.assertEqual(report.llm_providers["moderator"]["provider_id"], "fake")
            self.assertEqual(report.llm_providers["affirmative"]["status"], "llm_disabled")
            self.assertEqual(report.llm_providers["moderator"]["status"], "llm_disabled")
            self.assertFalse(report.llm_providers["affirmative"]["client_available"])
            self.assertFalse(report.llm_providers["moderator"]["client_available"])

    def test_missing_source_location_becomes_false_positive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif = root / "report.sarif"
            sarif.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {"driver": {"name": "unit"}},
                                "results": [
                                    {
                                        "ruleId": "missing-file",
                                        "message": {"text": "reported code does not exist"},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "does_not_exist.py"},
                                                    "region": {"startLine": 10},
                                                }
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            report = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    enable_external_tools=False,
                )
            )
            self.assertEqual(report.reports[0].verdict, Verdict.FALSE_POSITIVE)

    def test_cpp_uses_source_evidence_without_build_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "main.cpp"
            source.write_text(
                "\n".join(
                    [
                        "#include <cstdlib>",
                        "int main(int argc, char** argv) {",
                        "  if (argc > 1) system(argv[1]);",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            sarif = root / "report.sarif"
            sarif.write_text(
                json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {"driver": {"name": "unit"}},
                                "results": [
                                    {
                                        "ruleId": "cpp-command-injection",
                                        "message": {"text": "command execution"},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "main.cpp"},
                                                    "region": {"startLine": 3, "startColumn": 16},
                                                }
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            report = run_judgement(
                RunConfig(
                    sarif_path=sarif,
                    source_path=root,
                    enable_external_tools=False,
                )
            )
            self.assertEqual(report.reports[0].verdict, Verdict.INCONCLUSIVE)
            self.assertNotIn("编译数据库", report.reports[0].reasoning_summary)
            summaries = "\n".join(item.summary for item in report.reports[0].evidence_chain)
            self.assertNotIn("compile_commands.json", summaries)


def write_python_fixture(root: Path):
    app = root / "app.py"
    app.write_text(
        "\n".join(
            [
                "import os",
                "",
                "def handler(request):",
                "    cmd = request.args['cmd']",
                "    os.system(cmd)",
            ]
        ),
        encoding="utf-8",
    )
    skills = root / "skills"
    skills.mkdir()
    (skills / "SKILL.md").write_text(
        "# 支付系统威胁模型\napp.py 处理支付管理命令和客户数据。",
        encoding="utf-8",
    )
    sarif = root / "report.sarif"
    sarif.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "unit", "rules": [{"id": "python-command-injection"}]}},
                        "results": [
                            {
                                "ruleId": "python-command-injection",
                                "level": "error",
                                "message": {"text": "用户输入可到达命令执行点"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": 5, "startColumn": 5},
                                        }
                                    }
                                ],
                                "codeFlows": [
                                    {
                                        "threadFlows": [
                                            {
                                                "locations": [
                                                    {
                                                        "location": {
                                                            "physicalLocation": {
                                                                "artifactLocation": {"uri": "app.py"},
                                                                "region": {"startLine": 4, "startColumn": 11},
                                                            }
                                                        }
                                                    },
                                                    {
                                                        "location": {
                                                            "physicalLocation": {
                                                                "artifactLocation": {"uri": "app.py"},
                                                                "region": {"startLine": 5, "startColumn": 5},
                                                            }
                                                        }
                                                    },
                                                ]
                                            }
                                        ]
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return sarif, skills


def fake_atlas_mcp_script():
    return r'''#!/usr/bin/env python3
import json
import sys

if "--help" in sys.argv:
    print("Commands:")
    print("  mcp     Start MCP server")
    sys.exit(0)

if len(sys.argv) < 2 or sys.argv[1] != "mcp":
    sys.exit(2)

TOOLS = [{"name": name} for name in ("project", "trace", "search", "calls")]

def send(message):
    print(json.dumps(message, separators=(",", ":")), flush=True)

def tool_response(request_id, payload, is_error=False):
    send({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [{"type": "text", "text": json.dumps(payload, separators=(",", ":"))}],
            "isError": is_error,
        },
    })

for raw in sys.stdin:
    if not raw.strip():
        continue
    message = json.loads(raw)
    method = message.get("method")
    request_id = message.get("id")
    if method == "initialize":
        send({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "atlas-mcp", "version": "fake"},
            },
        })
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "project" and args.get("action") == "open":
            tool_response(request_id, {
                "project": {"path": args.get("project_path"), "storage": args.get("storage", "auto")},
                "analysis": {"state": "focus-ready", "scope": "project"},
                "precision": {"coverage_tier": "scoped", "semantic_confidence": "medium"},
                "work": {"items": []},
            })
        elif name == "project" and args.get("action") == "status":
            tool_response(request_id, {
                "summary": {"files": 1, "symbols": 1, "edges": 2},
                "project": {"db_path": ".atlas/atlas.db"},
                "server": {"atlas_version": "fake", "tool_contract_version": 1},
                "language_capabilities": [{"language": "python", "capability_level": "dataflow_full"}],
                "analysis": {"state": "focus-ready"},
                "precision": {"coverage_tier": "scoped", "semantic_confidence": "medium"},
                "work": {"items": []},
            })
        elif name == "project" and args.get("action") == "files":
            path = args.get("path_prefix", "app.py")
            tool_response(request_id, {"files": [{"path": path, "language": "python", "status": "success"}]})
        elif name == "trace":
            tool_response(request_id, {
                "ok": True,
                "partial_result": False,
                "diagnostics": [],
                "query_id": "q_fake",
                "kind": "trace_" + args.get("kind", "unknown"),
                "capability": {"language": "python", "capability_level": "dataflow_full"},
                "analysis": {"state": "focus-query"},
                "precision": {"coverage_tier": "scoped", "semantic_confidence": "medium"},
                "work": {"items": [{"phase": "focus", "status": "done"}]},
                "result": {"path": [{"file": "app.py", "line": 3}, {"file": "app.py", "line": 4}]},
            })
        elif name == "search":
            tool_response(request_id, {
                "results": [{
                    "name": "handler",
                    "qualified_name": "handler",
                    "kind": "function",
                    "file": "app.py",
                    "line": 2,
                }]
            })
        elif name == "calls":
            tool_response(request_id, {
                "hops": [{
                    "depth": 1,
                    "callers": [{
                        "qualified_name": "route",
                        "name": "route",
                        "kind": "function",
                        "file": "app.py",
                        "line": 1,
                        "edge": "calls",
                    }],
                    "callees": [{
                        "qualified_name": "os.system",
                        "name": "system",
                        "kind": "function",
                        "file": "app.py",
                        "line": 4,
                        "edge": "calls",
                    }],
                }]
            })
        else:
            tool_response(request_id, {"error": "unknown tool"}, True)
'''


def fake_atlas_mcp_empty_script():
    return r'''#!/usr/bin/env python3
import json
import sys

if "--help" in sys.argv:
    print("Commands:")
    print("  mcp     Start MCP server")
    sys.exit(0)

if len(sys.argv) < 2 or sys.argv[1] != "mcp":
    sys.exit(2)

TOOLS = [{"name": name} for name in ("project", "search", "trace", "calls")]

def send(message):
    print(json.dumps(message, separators=(",", ":")), flush=True)

def tool_response(request_id, payload, is_error=False):
    send({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [{"type": "text", "text": json.dumps(payload, separators=(",", ":"))}],
            "isError": is_error,
        },
    })

for raw in sys.stdin:
    if not raw.strip():
        continue
    message = json.loads(raw)
    method = message.get("method")
    request_id = message.get("id")
    if method == "initialize":
        send({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "atlas-mcp", "version": "fake-empty"},
            },
        })
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "project" and args.get("action") == "open":
            tool_response(request_id, {
                "project": {"path": args.get("project_path"), "storage": args.get("storage", "auto")},
                "analysis": {"state": "focus-ready"},
                "precision": {"coverage_tier": "scoped", "semantic_confidence": "low"},
                "work": {"items": []},
            })
        elif name == "project" and args.get("action") == "status":
            tool_response(request_id, {
                "summary": {"files": 1, "symbols": 0, "edges": 0},
                "project": {"db_path": ".atlas/atlas.db"},
                "server": {"atlas_version": "fake-empty", "tool_contract_version": 1},
            })
        elif name == "project" and args.get("action") == "files":
            tool_response(request_id, {"files": []})
        elif name == "search":
            tool_response(request_id, {"results": []})
        elif name == "trace":
            tool_response(request_id, {"ok": False, "partial_result": False, "diagnostics": ["empty"]})
        elif name == "calls":
            tool_response(request_id, {"hops": []})
        else:
            tool_response(request_id, {"error": "unknown tool"}, True)
'''


def fake_atlas_mcp_focus_graph_script():
    return r'''#!/usr/bin/env python3
import json
import sys

if "--help" in sys.argv:
    print("Commands:")
    print("  mcp     Start MCP server")
    sys.exit(0)

if len(sys.argv) < 2 or sys.argv[1] != "mcp":
    sys.exit(2)

TOOLS = [{"name": name} for name in ("project", "search", "trace", "calls")]

def send(message):
    print(json.dumps(message, separators=(",", ":")), flush=True)

def tool_response(request_id, payload, is_error=False):
    send({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [{"type": "text", "text": json.dumps(payload, separators=(",", ":"))}],
            "isError": is_error,
        },
    })

for raw in sys.stdin:
    if not raw.strip():
        continue
    message = json.loads(raw)
    method = message.get("method")
    request_id = message.get("id")
    if method == "initialize":
        send({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "atlas-mcp", "version": "fake-focus-graph"},
            },
        })
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "project" and args.get("action") == "open":
            tool_response(request_id, {
                "project": {"path": args.get("project_path"), "storage": args.get("storage", "auto")},
                "analysis": {"state": "focus-ready", "scope": "project"},
                "precision": {"coverage_tier": "focus", "semantic_confidence": "medium"},
                "work": {"items": [{"phase": "focus", "status": "done"}]},
            })
        elif name == "project" and args.get("action") == "status":
            tool_response(request_id, {
                "summary": {"files": 1, "symbols": 4, "edges": 3},
                "project": {"db_path": None},
                "server": {"atlas_version": "fake-focus-graph", "tool_contract_version": 2},
                "analysis": {"state": "focus-ready"},
                "precision": {"coverage_tier": "focus", "semantic_confidence": "medium"},
            })
        elif name == "project" and args.get("action") == "files":
            tool_response(request_id, {"files": [{"path": "app.py", "language": "python", "status": "focus-ready"}]})
        elif name == "search":
            tool_response(request_id, {
                "results": [{
                    "name": "handler",
                    "qualified_name": "handler",
                    "kind": "function",
                    "file": "app.py",
                    "line": 3,
                }]
            })
        elif name == "trace" and args.get("kind") == "point":
            tool_response(request_id, {
                "ok": True,
                "partial_result": False,
                "diagnostics": [],
                "query_id": "q_focus_point",
                "kind": "trace_point",
                "capability": {"language": "python", "capability_level": "dataflow_full"},
                "analysis": {"state": "focus-query"},
                "precision": {"coverage_tier": "focus", "semantic_confidence": "medium"},
                "work": {"items": [{"phase": "focus", "status": "done"}]},
                "result": {
                    "path": [
                        {"kind": "source", "file": "app.py", "line": 4, "name": "payload"},
                        {"kind": "sink", "file": "app.py", "line": 5, "name": "sink"},
                    ]
                },
            })
        elif name == "trace" and args.get("kind") == "callers":
            tool_response(request_id, {
                "ok": True,
                "partial_result": False,
                "diagnostics": [],
                "query_id": "q_focus_callers",
                "kind": "trace_callers",
                "analysis": {"state": "focus-query"},
                "precision": {"coverage_tier": "focus", "semantic_confidence": "medium"},
                "result": {
                    "path": [
                        {"kind": "function", "qualified_name": "route", "file": "app.py", "line": 1},
                        {"kind": "function", "qualified_name": "handler", "file": "app.py", "line": 3},
                    ]
                },
            })
        elif name == "trace":
            tool_response(request_id, {"ok": False, "partial_result": False, "diagnostics": ["variable trace unavailable in fixture"]})
        elif name == "calls":
            tool_response(request_id, {
                "nodes": [
                    {"id": "route", "qualified_name": "route", "name": "route", "file": "app.py", "line": 1},
                    {"id": "handler", "qualified_name": "handler", "name": "handler", "file": "app.py", "line": 3},
                    {"id": "sink", "qualified_name": "sink", "name": "sink", "file": "app.py", "line": 6},
                ],
                "edges": [
                    {"from": "route", "to": "handler", "kind": "calls"},
                    {"from": "handler", "to": "sink", "kind": "calls"},
                ],
                "analysis": {"state": "focus-query"},
                "precision": {"coverage_tier": "focus", "semantic_confidence": "medium"},
            })
        else:
            tool_response(request_id, {"error": "unknown tool"}, True)
'''


def fake_atlas_mcp_unmaterialized_then_focus_script():
    return r'''#!/usr/bin/env python3
import json
import sys

if "--help" in sys.argv:
    print("Commands:")
    print("  mcp     Start MCP server")
    sys.exit(0)

if len(sys.argv) < 2 or sys.argv[1] != "mcp":
    sys.exit(2)

TOOLS = [{"name": name} for name in ("project", "search", "trace", "calls")]
search_count = 0
focus_ready = False

def send(message):
    print(json.dumps(message, separators=(",", ":")), flush=True)

def tool_response(request_id, payload, is_error=False):
    send({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [{"type": "text", "text": json.dumps(payload, separators=(",", ":"))}],
            "isError": is_error,
        },
    })

for raw in sys.stdin:
    if not raw.strip():
        continue
    message = json.loads(raw)
    method = message.get("method")
    request_id = message.get("id")
    if method == "initialize":
        send({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "atlas-mcp", "version": "fake-unmaterialized"},
            },
        })
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "project" and args.get("action") == "open":
            tool_response(request_id, {
                "project": {"path": args.get("project_path"), "storage": args.get("storage", "auto")},
                "analysis": {"state": "focus-ready" if focus_ready else "project-opened"},
                "precision": {"coverage_tier": "focus", "semantic_confidence": "medium"},
            })
        elif name == "project" and args.get("action") == "status":
            tool_response(request_id, {
                "summary": {"files": 1, "symbols": 2 if focus_ready else 0, "edges": 1 if focus_ready else 0},
                "analysis": {"state": "focus-ready" if focus_ready else "project-opened"},
                "precision": {"coverage_tier": "focus", "semantic_confidence": "medium"},
            })
        elif name == "project" and args.get("action") == "files":
            tool_response(request_id, {"files": [{"path": "app.py", "language": "python", "status": "focus-ready" if focus_ready else "pending"}]})
        elif name == "search":
            search_count += 1
            if args.get("scope") and search_count > 1:
                focus_ready = True
            tool_response(request_id, {
                "results": [{
                    "name": "handler",
                    "qualified_name": "handler",
                    "kind": "function",
                    "file": "app.py",
                    "line": 1,
                }]
            })
        elif name == "trace" and not focus_ready:
            tool_response(request_id, {"error": "No project facts have been materialized yet"}, True)
        elif name == "trace":
            tool_response(request_id, {
                "ok": True,
                "partial_result": False,
                "diagnostics": [],
                "query_id": "q_focus_after_rescan",
                "kind": "trace_" + args.get("kind", "unknown"),
                "analysis": {"state": "focus-query"},
                "precision": {"coverage_tier": "focus", "semantic_confidence": "medium"},
                "result": {
                    "path": [
                        {"kind": "source", "file": "app.py", "line": 2, "name": "payload"},
                        {"kind": "sink", "file": "app.py", "line": 3, "name": "sink"},
                    ]
                },
            })
        elif name == "calls":
            tool_response(request_id, {"hops": []})
        else:
            tool_response(request_id, {"error": "unknown tool"}, True)
'''


def fake_atlas_mcp_timeout_script():
    return r'''#!/usr/bin/env python3
import json
import sys
import time

if "--help" in sys.argv:
    print("Commands:")
    print("  mcp     Start MCP server")
    sys.exit(0)

if len(sys.argv) < 2 or sys.argv[1] != "mcp":
    sys.exit(2)

TOOLS = [{"name": name} for name in ("project", "search", "trace", "calls")]

def send(message):
    print(json.dumps(message, separators=(",", ":")), flush=True)

def tool_response(request_id, payload, is_error=False):
    send({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [{"type": "text", "text": json.dumps(payload, separators=(",", ":"))}],
            "isError": is_error,
        },
    })

for raw in sys.stdin:
    if not raw.strip():
        continue
    message = json.loads(raw)
    method = message.get("method")
    request_id = message.get("id")
    if method == "initialize":
        send({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "atlas-mcp", "version": "fake-timeout"},
            },
        })
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}})
    elif method == "tools/call":
        params = message.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "project" and args.get("action") == "open":
            tool_response(request_id, {
                "project": {"path": args.get("project_path"), "storage": args.get("storage", "auto")},
                "analysis": {"state": "focus-ready"},
                "precision": {"coverage_tier": "scoped", "semantic_confidence": "medium"},
                "work": {"items": []},
            })
        elif name == "project" and args.get("action") == "status":
            tool_response(request_id, {
                "summary": {"files": 1, "symbols": 1, "edges": 2},
                "project": {"db_path": ".atlas/atlas.db"},
                "server": {"atlas_version": "fake-timeout", "tool_contract_version": 1},
                "language_capabilities": [{"language": "python", "capability_level": "dataflow_full"}],
            })
        elif name == "project" and args.get("action") == "files":
            tool_response(request_id, {"files": [{"path": args.get("path_prefix", "app.py"), "language": "python", "status": "success"}]})
        elif name == "search":
            tool_response(request_id, {
                "results": [{
                    "name": "handler",
                    "qualified_name": "handler",
                    "kind": "function",
                    "file": "app.py",
                    "line": 2,
                }]
            })
        elif name == "trace":
            time.sleep(2)
            tool_response(request_id, {"ok": True, "partial_result": False, "diagnostics": []})
        elif name == "calls":
            tool_response(request_id, {"hops": []})
        else:
            tool_response(request_id, {"error": "unknown tool"}, True)
'''


def mcp_tool_json(response):
    result = response.get("result") or {}
    content = result.get("content") or []
    text = "\n".join(item.get("text") or "" for item in content if item.get("type") == "text")
    return json.loads(text)


def send_mcp_header_message(process, payload):
    assert process.stdin is not None
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    process.stdin.write(f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii") + raw)
    process.stdin.flush()


def read_mcp_header_message(process):
    assert process.stdout is not None
    headers = []
    while True:
        line = process.stdout.readline()
        if not line:
            raise AssertionError("MCP server closed stdout")
        if line in {b"\n", b"\r\n"}:
            break
        headers.append(line)
    length = None
    for header in headers:
        name, _, value = header.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
            break
    if length is None:
        raise AssertionError(f"Missing content-length in {headers!r}")
    body = process.stdout.read(length)
    return json.loads(body.decode("utf-8"))


def post_json(url, payload):
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def wait_for_run_completed(base, run_id):
    for _ in range(50):
        with urllib.request.urlopen(f"{base}/runs/{run_id}", timeout=5) as response:
            run = json.loads(response.read().decode("utf-8"))
        if run.get("status") == "completed":
            return run
        if run.get("status") == "failed":
            raise AssertionError(run.get("error"))
    raise AssertionError(f"run did not complete: {run_id}")


def wait_for_run_status(base, run_id, statuses):
    for _ in range(80):
        with urllib.request.urlopen(f"{base}/runs/{run_id}", timeout=5) as response:
            run = json.loads(response.read().decode("utf-8"))
        if run.get("status") in statuses:
            return run
        if run.get("status") == "failed":
            raise AssertionError(run.get("error"))
        time.sleep(0.1)
    raise AssertionError(f"run did not reach {statuses}: {run_id}")


def wait_for_run_field(base, run_id, field):
    for _ in range(80):
        with urllib.request.urlopen(f"{base}/runs/{run_id}", timeout=5) as response:
            run = json.loads(response.read().decode("utf-8"))
        if run.get(field):
            return run
        if run.get("status") == "failed":
            raise AssertionError(run.get("error"))
        time.sleep(0.1)
    raise AssertionError(f"run did not populate {field}: {run_id}")


class OpenCodeRunnerTests(unittest.TestCase):
    def test_legacy_opencode_session_metadata_targets_tui_window(self):
        payload = {
            "engine": "opencode",
            "cli_sessions": [
                {
                    "backend": "opencode",
                    "role": "moderator",
                    "session_name": "vj-run-1-moderator",
                    "target": "vj-run-1-moderator:server",
                    "window_name": "server",
                }
            ],
        }

        with patch("vuln_judger.api.session_live", side_effect=lambda target: str(target).endswith(":server")):
            sessions = _cli_sessions(payload)

        self.assertEqual(sessions[0]["target"], "vj-run-1-moderator:tui")
        self.assertEqual(sessions[0]["window_name"], "tui")
        self.assertTrue(sessions[0]["live"])
        self.assertFalse(sessions[0]["terminal_live"])

    def test_opencode_engine_config_is_parsed_as_cli_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = _config_from_payload(
                {
                    "engine": "opencode",
                    "report_path": str(root / "report.sarif"),
                    "source_path": str(root / "source"),
                    "llm_model": "openai/gpt-5",
                },
                root / "providers.json",
                agent_store=AgentDirectoryStore(root / "agents"),
                mcp_servers_file=root / "mcp.json",
            )

        self.assertEqual(config.engine, OPENCODE_ENGINE)
        self.assertEqual(config.llm_model, "openai/gpt-5")
        self.assertIsNone(config.mcp_servers_file)
        self.assertFalse(config.enable_llm)
        self.assertIsNotNone(config.affirmative_agent)

    def test_opencode_agent_dirs_include_unattended_permission_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            runner = OpenCodeDrivenRunner(
                records_dir=root / "records",
                opencode_runs_dir=root / "runs",
                opencode_command="opencode",
            )
            agents = {
                "moderator": AgentConfig("Moderator", "裁决。", role="Moderator"),
                "affirmative": AgentConfig("Affirmative", "验证。", role="Affirmative"),
                "negative": AgentConfig("Negative", "质疑。", role="Negative"),
            }
            role_dirs = runner._prepare_agent_dirs(root / "run-1", agents, source)

            for role_dir in role_dirs.values():
                config_path = role_dir / ".opencode" / "opencode.json"
                self.assertTrue(config_path.exists())
                self.assertEqual(json.loads(config_path.read_text(encoding="utf-8"))["permission"], "allow")
                self.assertIn("OpenCode Agent", (role_dir / "AGENTS.md").read_text(encoding="utf-8"))

    def test_opencode_probe_only_requires_attach_tui_capabilities(self):
        responses = [
            subprocess.CompletedProcess(["opencode", "--version"], 0, "1.17.10\n", ""),
            subprocess.CompletedProcess(
                ["opencode", "attach", "--help"],
                0,
                "--dir --session --mini",
                "",
            ),
        ]
        with patch("vuln_judger.opencode_runner.subprocess.run", side_effect=responses):
            capabilities = probe_opencode("opencode")

        self.assertEqual(capabilities.version, "1.17.10")
        self.assertTrue(capabilities.attach_mini)

    def test_opencode_tui_attach_uses_saved_session_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path(tmp)
            completed = subprocess.CompletedProcess(["tmux"], 0, "", "")

            def target_live(target):
                return str(target).endswith(":server")

            with patch("vuln_judger.opencode_runner._tmux_target_live", side_effect=target_live), patch(
                "vuln_judger.opencode_runner._run_tmux", return_value=completed
            ) as run_tmux, patch(
                "vuln_judger.opencode_runner._wait_for_opencode_tui"
            ) as wait_tui, patch(
                "vuln_judger.opencode_runner._run_opencode",
                return_value=subprocess.CompletedProcess(["opencode", "attach", "--help"], 0, "--mini", ""),
            ):
                target = ensure_opencode_tui(
                    {
                        "session_name": "vj-run-1-moderator",
                        "cwd": str(cwd),
                        "server_url": "http://127.0.0.1:4096",
                        "provider_session_id": "ses-123",
                    }
                )

            self.assertEqual(target, "vj-run-1-moderator:tui")
            launch = run_tmux.call_args.args[0]
            self.assertIn("new-window", launch)
            self.assertTrue(any(Path(str(item)).name == "opencode" for item in launch))
            self.assertIn("attach", launch)
            self.assertIn("--session", launch)
            self.assertIn("ses-123", launch)
            self.assertIn("--mini", launch)
            self.assertNotIn("run", launch)
            wait_tui.assert_called_once_with("vj-run-1-moderator:tui")

    def test_opencode_start_creates_provider_session_before_tui(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cwd = root / "role"
            cwd.mkdir()
            session = OpenCodeTmuxSession(
                role="moderator",
                run_id="run-1",
                cwd=cwd,
                source_path=root,
                run_dir=root,
                command="opencode",
                capabilities=OpenCodeCapabilities("1.17.10"),
            )
            completed = subprocess.CompletedProcess(["tmux"], 0, "", "")

            def target_live(target):
                return str(target).endswith(":server")

            with patch("vuln_judger.opencode_runner._tmux_target_live", side_effect=target_live), patch(
                "vuln_judger.opencode_runner._server_healthy", return_value=True
            ), patch(
                "vuln_judger.opencode_runner._create_opencode_session", return_value="ses-created"
            ) as create_session, patch(
                "vuln_judger.opencode_runner._wait_for_opencode_tui"
            ), patch(
                "vuln_judger.opencode_runner._run_tmux", return_value=completed
            ) as run_tmux:
                session.start()

            self.assertEqual(session.info().provider_session_id, "ses-created")
            create_session.assert_called_once_with(
                session.server_url,
                title="vuln-judger run-1 moderator",
                directory=session.cwd,
                model=None,
            )
            tui_launch = run_tmux.call_args.args[0]
            self.assertIn("attach", tui_launch)
            self.assertIn("ses-created", tui_launch)

    def test_opencode_prompt_rotates_provider_session_per_task(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cwd = root / "role"
            cwd.mkdir()
            config_path = cwd / ".opencode" / "opencode.json"
            config_path.parent.mkdir()
            config_path.write_text(json.dumps(OPENCODE_PERMISSION_CONFIG), encoding="utf-8")
            session = OpenCodeTmuxSession(
                role="moderator",
                run_id="run-1",
                cwd=cwd,
                source_path=root,
                run_dir=root,
                command="opencode",
                capabilities=OpenCodeCapabilities("1.17.10"),
                model="openai/gpt-5",
            )

            def target_live(target):
                return str(target).endswith(":server")

            completed = subprocess.CompletedProcess(["tmux"], 0, "", "")
            with patch("vuln_judger.opencode_runner._tmux_target_live", side_effect=target_live), patch(
                "vuln_judger.opencode_runner._create_opencode_session", side_effect=["ses-1", "ses-2"]
            ) as create_session, patch(
                "vuln_judger.opencode_runner._wait_for_opencode_tui"
            ), patch(
                "vuln_judger.opencode_runner._wait_for_cli_task_start"
            ), patch(
                "vuln_judger.opencode_runner._run_tmux", return_value=completed
            ) as run_tmux:
                session.send("first prompt")
                first_event = session._current_event_path
                self.assertIsNotNone(first_event)
                first_event.write_text('{"type":"session","sessionID":"ses-1"}\n', encoding="utf-8")
                session.activity_snapshot()
                session.send("second\r\nprompt\rtail")

            launch = run_tmux.call_args_list[-1].args[0]
            shell = launch[-1]
            request_payload = json.loads(session._current_request_path.read_text(encoding="utf-8"))
            self.assertIn("opencode_prompt_client.py", shell)
            self.assertIn("--server-url", shell)
            self.assertIn("--session-id ses-2", shell)
            self.assertIn("--request-file", shell)
            self.assertNotIn("opencode run", shell)
            self.assertNotIn("second prompt", shell)
            self.assertNotIn("paste-buffer", shell)
            self.assertNotIn("send-keys", shell)
            self.assertEqual(
                request_payload["parts"],
                [{"type": "text", "text": "second\nprompt\ntail"}],
            )
            self.assertNotIn(b"\r", session._current_prompt_path.read_bytes())
            self.assertNotIn(b"\r", session._current_request_path.read_bytes())
            self.assertEqual(
                request_payload["model"],
                {"providerID": "openai", "modelID": "gpt-5"},
            )
            self.assertEqual(create_session.call_count, 2)
            self.assertEqual(create_session.call_args.kwargs["directory"], session.cwd)
            self.assertEqual(create_session.call_args.kwargs["model"], "openai/gpt-5")
            self.assertEqual(session.info().provider_session_id, "ses-2")
            self.assertEqual(session.info().transport, "serve+prompt-api")

    def test_opencode_prompt_records_tmux_launch_without_waiting_for_worker_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cwd = root / "role"
            cwd.mkdir()
            session = OpenCodeTmuxSession(
                role="negative",
                run_id="run-concurrent",
                cwd=cwd,
                source_path=root,
                run_dir=root,
                command="opencode",
                capabilities=OpenCodeCapabilities("1.17.20"),
            )
            completed = subprocess.CompletedProcess(["tmux"], 0, "", "")

            def target_live(target):
                return str(target).endswith(":server")

            with patch(
                "vuln_judger.opencode_runner._tmux_target_live",
                side_effect=target_live,
            ), patch(
                "vuln_judger.opencode_runner._create_opencode_session",
                return_value="ses-concurrent",
            ), patch(
                "vuln_judger.opencode_runner._wait_for_opencode_tui"
            ), patch(
                "vuln_judger.opencode_runner._run_tmux",
                return_value=completed,
            ):
                session.send("review this finding")

            self.assertIsNotNone(session._current_started_path)
            self.assertEqual(
                session._current_started_path.read_text(encoding="utf-8"),
                "tmux-window-created\n",
            )
            self.assertFalse(session._current_exit_path.exists())

    def test_opencode_nonzero_run_exit_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cwd = root / "role"
            cwd.mkdir()
            session = OpenCodeTmuxSession(
                role="negative",
                run_id="run-1",
                cwd=cwd,
                source_path=root,
                run_dir=root,
                command="opencode",
                capabilities=OpenCodeCapabilities("1.17.10"),
            )
            event_path = cwd / "event.ndjson"
            exit_path = cwd / "exit.txt"
            event_path.write_text("authentication failed\n", encoding="utf-8")
            exit_path.write_text("1\n", encoding="utf-8")
            session._current_event_path = event_path
            session._current_exit_path = exit_path
            with patch("vuln_judger.opencode_runner._tmux_target_live", return_value=False):
                failure = session.failure_message()

        self.assertIn("退出码 1", failure)
        self.assertIn("authentication failed", failure)

    def test_opencode_invalid_session_is_reported_without_prompt_redelivery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cwd = root / "role"
            cwd.mkdir()
            session = OpenCodeTmuxSession(
                role="affirmative",
                run_id="run-1",
                cwd=cwd,
                source_path=root,
                run_dir=root,
                command="opencode",
                capabilities=OpenCodeCapabilities("1.17.10"),
            )
            session.logs_dir.mkdir()
            prompt_path = session.logs_dir / "prompt-0001.txt"
            event_path = session.logs_dir / "events-0001.ndjson"
            exit_path = session.logs_dir / "exit-0001.txt"
            prompt_path.write_text("resume this stage", encoding="utf-8")
            event_path.write_text("Session not found: ses-old\n", encoding="utf-8")
            exit_path.write_text("1\n", encoding="utf-8")
            session._sequence = 1
            session._provider_session_id = "ses-old"
            session._current_prompt_path = prompt_path
            session._current_event_path = event_path
            session._current_exit_path = exit_path
            with patch("vuln_judger.opencode_runner._tmux_target_live", return_value=False), patch(
                "vuln_judger.opencode_runner._create_opencode_session"
            ) as create_session, patch.object(session, "_launch_prompt") as launch_prompt:
                failure = session.failure_message()

            self.assertIn("退出码 1", failure)
            self.assertIn("Session not found", failure)
            self.assertEqual(session._provider_session_id, "ses-old")
            create_session.assert_not_called()
            launch_prompt.assert_not_called()

    def test_opencode_accept_output_aborts_turn_and_releases_worker_slot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cwd = root / "role"
            cwd.mkdir()
            session = OpenCodeTmuxSession(
                role="negative",
                run_id="run-1",
                cwd=cwd,
                source_path=root,
                run_dir=root,
                command="opencode",
                capabilities=OpenCodeCapabilities("1.17.15"),
            )
            session.logs_dir.mkdir()
            session._provider_session_id = "ses-active"
            session._current_exit_path = session.logs_dir / "exit-0001.txt"

            def target_live(target):
                return target in {session.server_target, session.run_target}

            completed = subprocess.CompletedProcess(["tmux"], 0, "", "")
            order = []

            def abort_turn(*_args):
                order.append("abort")
                return True

            def run_tmux(args, **_kwargs):
                if args[:2] == ["tmux", "kill-window"]:
                    order.append("kill")
                return completed

            with patch("vuln_judger.opencode_runner._tmux_target_live", side_effect=target_live), patch(
                "vuln_judger.opencode_runner._abort_opencode_session", side_effect=abort_turn
            ) as abort, patch(
                "vuln_judger.opencode_runner._wait_for_opencode_session_idle", return_value=True
            ) as wait_idle, patch(
                "vuln_judger.opencode_runner._run_tmux", side_effect=run_tmux
            ) as run_tmux:
                session.accept_output()

            abort.assert_called_once_with(session.server_url, "ses-active", session.cwd)
            wait_idle.assert_called_once_with(
                session.server_url,
                "ses-active",
                session.cwd,
                timeout=5.0,
            )
            run_tmux.assert_called_once_with(
                ["tmux", "kill-window", "-t", session.run_target],
                timeout=10,
                check=False,
            )
            self.assertEqual(order, ["kill", "abort"])
            self.assertEqual(session._current_exit_path.read_text(encoding="utf-8"), "0\n")

    def test_opencode_accept_output_stops_server_when_abort_does_not_finish_turn(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cwd = root / "role"
            cwd.mkdir()
            session = OpenCodeTmuxSession(
                role="negative",
                run_id="run-1",
                cwd=cwd,
                source_path=root,
                run_dir=root,
                command="opencode",
                capabilities=OpenCodeCapabilities("1.17.15"),
            )
            session.logs_dir.mkdir()
            session._provider_session_id = "ses-stuck"
            session._current_exit_path = session.logs_dir / "exit-0001.txt"

            def target_live(target):
                return target in {session.server_target, session.run_target}

            completed = subprocess.CompletedProcess(["tmux"], 0, "", "")
            with patch("vuln_judger.opencode_runner._tmux_target_live", side_effect=target_live), patch(
                "vuln_judger.opencode_runner._abort_opencode_session", return_value=True
            ), patch(
                "vuln_judger.opencode_runner._wait_for_opencode_session_idle", return_value=False
            ), patch(
                "vuln_judger.opencode_runner._run_tmux", return_value=completed
            ), patch.object(session, "stop") as stop:
                session.accept_output()

            stop.assert_called_once_with()
            self.assertIsNone(session._provider_session_id)
            self.assertEqual(session._current_exit_path.read_text(encoding="utf-8"), "0\n")

    def test_opencode_tui_session_rotation_respawns_stable_pane(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cwd = root / "role"
            cwd.mkdir()
            session = OpenCodeTmuxSession(
                role="affirmative",
                run_id="run-1",
                cwd=cwd,
                source_path=root,
                run_dir=root,
                command="opencode",
                capabilities=OpenCodeCapabilities("1.17.10"),
            )
            session._provider_session_id = "ses-new"
            completed = subprocess.CompletedProcess(["tmux"], 0, "", "")

            with patch("vuln_judger.opencode_runner._tmux_target_live", return_value=True), patch(
                "vuln_judger.opencode_runner._wait_for_opencode_tui"
            ) as wait_tui, patch(
                "vuln_judger.opencode_runner._run_tmux", return_value=completed
            ) as run_tmux:
                session._ensure_tui(restart=True)

            launch = run_tmux.call_args.args[0]
            self.assertIn("respawn-pane", launch)
            self.assertNotIn("new-window", launch)
            self.assertIn("vj-run-1-affirmative:tui", launch)
            self.assertIn("opencode", launch)
            self.assertIn("ses-new", launch)
            wait_tui.assert_called_once_with("vj-run-1-affirmative:tui")

    def test_opencode_manual_message_uses_prompt_async_api(self):
        received = {}

        class ManualPromptHandler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("content-length") or 0)
                received["path"] = self.path
                received["body"] = json.loads(self.rfile.read(length).decode("utf-8"))
                self.send_response(HTTPStatus.NO_CONTENT)
                self.send_header("content-length", "0")
                self.end_headers()

            def log_message(self, format, *args):  # noqa: A002
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), ManualPromptHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp, patch(
                "vuln_judger.opencode_prompt_client._new_message_id",
                return_value="msg-manual",
            ):
                result = send_opencode_session_message(
                    {
                        "server_url": f"http://127.0.0.1:{server.server_port}",
                        "provider_session_id": "ses-manual",
                        "cwd": tmp,
                        "session_name": "vj-run-1-affirmative",
                    },
                    "line one\r\nline two",
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertEqual(result["message_id"], "msg-manual")
        self.assertTrue(received["path"].startswith("/session/ses-manual/prompt_async?"))
        self.assertEqual(
            received["body"],
            {
                "parts": [{"type": "text", "text": "line one\nline two"}],
                "messageID": "msg-manual",
            },
        )

    def test_opencode_prompt_client_posts_directly_to_local_server(self):
        received = {"get_paths": []}
        statuses = []

        class PromptHandler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("content-length") or 0)
                received["path"] = self.path
                received["body"] = json.loads(self.rfile.read(length).decode("utf-8"))
                self.send_response(HTTPStatus.NO_CONTENT)
                self.send_header("content-length", "0")
                self.end_headers()

            def do_GET(self):  # noqa: N802
                received["get_paths"].append(self.path)
                if self.path.startswith("/session/ses%2Fwith%20space/message?"):
                    payload = [
                        {
                            "info": {
                                "id": "msg-assistant-1",
                                "sessionID": "ses/with space",
                                "role": "assistant",
                                "parentID": "msg-user-1",
                                "time": {"created": 1, "completed": 2},
                                "finish": "stop",
                            },
                            "parts": [],
                        }
                    ]
                else:
                    payload = {"ses/with space": {"type": "idle"}}
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, format, *args):  # noqa: A002
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), PromptHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch(
                "vuln_judger.opencode_prompt_client._new_message_id",
                return_value="msg-user-1",
            ):
                response = send_prompt(
                    server_url=f"http://127.0.0.1:{server.server_port}",
                    session_id="ses/with space",
                    directory="/mnt/c/source tree",
                    payload={
                        "model": {"providerID": "openai", "modelID": "gpt-5"},
                        "parts": [{"type": "text", "text": "line one\r\nline two\rline three"}],
                    },
                    timeout=5,
                    status_callback=statuses.append,
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertEqual(response["messageID"], "msg-user-1")
        self.assertEqual(response["assistant"]["info"]["id"], "msg-assistant-1")
        self.assertEqual([status["state"] for status in statuses], ["submitted", "completed"])
        self.assertEqual(statuses[-1]["model"], {"providerID": "openai", "modelID": "gpt-5"})
        self.assertTrue(
            received["path"].startswith(
                "/session/ses%2Fwith%20space/prompt_async?"
            )
        )
        self.assertIn("directory=%2Fmnt%2Fc%2Fsource+tree", received["path"])
        self.assertEqual(
            received["body"],
            {
                "model": {"providerID": "openai", "modelID": "gpt-5"},
                "parts": [{"type": "text", "text": "line one\nline two\nline three"}],
                "messageID": "msg-user-1",
            },
        )
        self.assertTrue(
            any(
                path.startswith("/session/ses%2Fwith%20space/message?")
                and "directory=%2Fmnt%2Fc%2Fsource+tree" in path
                for path in received["get_paths"]
            )
        )

    def test_opencode_prompt_client_waits_past_tool_call_finish(self):
        state = {"message_polls": 0}
        statuses = []

        class ToolCallPromptHandler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("content-length") or 0)
                self.rfile.read(length)
                self.send_response(HTTPStatus.NO_CONTENT)
                self.send_header("content-length", "0")
                self.end_headers()

            def do_GET(self):  # noqa: N802
                if self.path.startswith("/session/ses-tools/message?"):
                    state["message_polls"] += 1
                    finish = "tool-calls" if state["message_polls"] == 1 else "stop"
                    payload = [
                        {
                            "info": {
                                "id": "msg-assistant-tools",
                                "sessionID": "ses-tools",
                                "role": "assistant",
                                "parentID": "msg-tools",
                                "time": {"created": 1},
                                "finish": finish,
                            },
                            "parts": [],
                        }
                    ]
                else:
                    status = "busy" if state["message_polls"] == 1 else "idle"
                    payload = {"ses-tools": {"type": status}}
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, format, *args):  # noqa: A002
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), ToolCallPromptHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch(
                "vuln_judger.opencode_prompt_client._new_message_id",
                return_value="msg-tools",
            ), patch.dict(
                os.environ,
                {"VULN_JUDGER_OPENCODE_POLL_INTERVAL": "0.01"},
            ):
                response = send_prompt(
                    server_url=f"http://127.0.0.1:{server.server_port}",
                    session_id="ses-tools",
                    directory="/tmp/source",
                    payload={"parts": [{"type": "text", "text": "review"}]},
                    timeout=5,
                    status_callback=statuses.append,
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertEqual(state["message_polls"], 2)
        self.assertEqual(response["assistant"]["info"]["finish"], "stop")
        self.assertEqual([status["state"] for status in statuses], ["submitted", "running", "completed"])

    def test_opencode_prompt_client_fails_when_async_session_stays_idle(self):
        class IdlePromptHandler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("content-length") or 0)
                self.rfile.read(length)
                self.send_response(HTTPStatus.NO_CONTENT)
                self.send_header("content-length", "0")
                self.end_headers()

            def do_GET(self):  # noqa: N802
                payload = {} if self.path.startswith("/session/status?") else []
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, format, *args):  # noqa: A002
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), IdlePromptHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch(
                "vuln_judger.opencode_prompt_client._new_message_id",
                return_value="msg-idle",
            ), patch.dict(
                os.environ,
                {
                    "VULN_JUDGER_OPENCODE_AGENT_START_TIMEOUT": "0.1",
                    "VULN_JUDGER_OPENCODE_POLL_INTERVAL": "0.01",
                },
            ), self.assertRaisesRegex(
                RuntimeError,
                "accepted prompt msg-idle via prompt_async but remained idle",
            ):
                send_prompt(
                    server_url=f"http://127.0.0.1:{server.server_port}",
                    session_id="ses-idle",
                    directory="/mnt/c/source",
                    payload={"parts": [{"type": "text", "text": "review finding"}]},
                    timeout=5,
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_opencode_prompt_client_does_not_treat_busy_session_as_not_started(self):
        statuses = []

        class BusyPromptHandler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("content-length") or 0)
                self.rfile.read(length)
                self.send_response(HTTPStatus.NO_CONTENT)
                self.send_header("content-length", "0")
                self.end_headers()

            def do_GET(self):  # noqa: N802
                payload = {"ses-busy": {"type": "busy"}} if self.path.startswith(
                    "/session/status?"
                ) else []
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, format, *args):  # noqa: A002
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), BusyPromptHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch(
                "vuln_judger.opencode_prompt_client._new_message_id",
                return_value="msg-busy",
            ), patch.dict(
                os.environ,
                {
                    "VULN_JUDGER_OPENCODE_AGENT_START_TIMEOUT": "0.1",
                    "VULN_JUDGER_OPENCODE_POLL_INTERVAL": "0.01",
                },
            ), self.assertRaisesRegex(RuntimeError, "prompt timed out"):
                send_prompt(
                    server_url=f"http://127.0.0.1:{server.server_port}",
                    session_id="ses-busy",
                    directory="/mnt/c/source",
                    payload={"parts": [{"type": "text", "text": "review finding"}]},
                    timeout=0.25,
                    status_callback=statuses.append,
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertEqual(statuses[0]["state"], "submitted")
        self.assertTrue(any(status["state"] == "running" for status in statuses))

    def test_opencode_prompt_client_records_native_retry_status(self):
        statuses = []

        class RetryPromptHandler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("content-length") or 0)
                self.rfile.read(length)
                self.send_response(HTTPStatus.NO_CONTENT)
                self.send_header("content-length", "0")
                self.end_headers()

            def do_GET(self):  # noqa: N802
                payload = (
                    {
                        "ses-retry": {
                            "type": "retry",
                            "attempt": 2,
                            "message": "Upstream rate limit exceeded",
                            "next": 123456,
                        }
                    }
                    if self.path.startswith("/session/status?")
                    else []
                )
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, format, *args):  # noqa: A002
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), RetryPromptHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch(
                "vuln_judger.opencode_prompt_client._new_message_id",
                return_value="msg-retry",
            ), patch.dict(
                os.environ,
                {
                    "VULN_JUDGER_OPENCODE_AGENT_START_TIMEOUT": "0.1",
                    "VULN_JUDGER_OPENCODE_POLL_INTERVAL": "0.01",
                },
            ), self.assertRaisesRegex(RuntimeError, "prompt timed out"):
                send_prompt(
                    server_url=f"http://127.0.0.1:{server.server_port}",
                    session_id="ses-retry",
                    directory="/mnt/c/source",
                    payload={"parts": [{"type": "text", "text": "review finding"}]},
                    timeout=0.25,
                    status_callback=statuses.append,
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        retry = next(status for status in statuses if status["state"] == "retrying")
        self.assertEqual(retry["status"]["attempt"], 2)
        self.assertIn("rate limit", retry["status"]["message"].lower())

    def test_opencode_dashboard_terminal_accepts_input_for_api_transport(self):
        payload = {
            "engine": OPENCODE_ENGINE,
            "cli_sessions": [
                {
                    "backend": OPENCODE_ENGINE,
                    "role": "affirmative",
                    "session_name": "vj-run-1-affirmative",
                    "target": "vj-run-1-affirmative:tui",
                    "transport": "serve+prompt-api",
                }
            ],
        }
        self.assertTrue(_cli_session_accepts_input(payload, payload["cli_sessions"][0]))
        self.assertFalse(
            _cli_session_accepts_input(
                {"engine": "codex"},
                {"backend": "codex", "transport": "exec-ephemeral-json"},
            )
        )
        html = _codex_terminal_page("run-1", "affirmative", payload["cli_sessions"][0])
        self.assertIn("/runs/run-1/cli-sessions/affirmative/ws", html)
        self.assertIn("只读 TUI · HTTP 消息", html)
        self.assertIn('id="message-form"', html)
        self.assertIn("/runs/run-1/cli-sessions/affirmative/input", html)
        self.assertNotIn("term.onData", html)

        submitted = {
            "message_id": "msg-manual",
            "session_id": "ses-1",
            "target": "vj-run-1-affirmative:tui",
        }
        with tempfile.TemporaryDirectory() as tmp, patch(
            "vuln_judger.api.send_opencode_session_message",
            return_value=submitted,
        ) as send_message:
            result = _send_codex_session_input(
                RunRecordStore(Path(tmp)),
                {"run-1": payload},
                Lock(),
                "run-1",
                "affirmative",
                "manual review",
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["message_id"], "msg-manual")
        send_message.assert_called_once()
        submitted_session, submitted_text = send_message.call_args.args
        self.assertEqual(submitted_text, "manual review")
        self.assertEqual(submitted_session["session_name"], "vj-run-1-affirmative")
        self.assertEqual(submitted_session["target"], "vj-run-1-affirmative:tui")

    def test_session_live_validates_exact_tmux_window(self):
        completed = subprocess.CompletedProcess(["tmux"], 0, "", "")
        with patch("vuln_judger.codex_runner._run_tmux", return_value=completed) as run_tmux:
            self.assertTrue(session_live("vj-run-1-affirmative:tui"))

        run_tmux.assert_called_once_with(
            ["tmux", "list-panes", "-t", "vj-run-1-affirmative:tui"],
            timeout=5,
            check=False,
        )

    def test_web_and_mcp_surface_opencode_engine(self):
        html = app_html()
        self.assertIn('<option value="opencode">OpenCode 三方复核</option>', html)
        judge_report = next(item for item in _tool_specs() if item["name"] == "judge_report")
        engines = judge_report["inputSchema"]["properties"]["engine"]["enum"]
        self.assertIn(OPENCODE_ENGINE, engines)


class FakeOpenAIHandler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("content-length") or 0)
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        if self.headers.get("authorization") != "Bearer secret":
            self.send_response(HTTPStatus.UNAUTHORIZED)
            raw = b'{"error":"unauthorized"}'
        else:
            self.send_response(HTTPStatus.OK)
            system_prompt = body["messages"][0]["content"]
            user_prompt = body["messages"][1]["content"] if len(body.get("messages") or []) > 1 else ""
            if "connectivity" in system_prompt:
                content = "OK"
            elif "预处理 SARIF" in system_prompt or "SARIF 与源码上下文 JSON" in user_prompt:
                content = json.dumps(
                    {
                        "reports": [
                            {
                                "title": "命令注入独立报告",
                                "result_indices": [0],
                                "markdown": "# 命令注入独立报告\n\nSARIF 指向 app.py:5，源码上下文显示 request.args['cmd'] 进入 os.system。",
                            }
                        ]
                    },
                    ensure_ascii=False,
                )
            elif "完整 Markdown 静态漏洞报告" in system_prompt or "Markdown 报告原文开始" in user_prompt:
                content = json.dumps(
                    {
                        "reports": [
                            {
                                "title": "自然语言漏洞报告",
                                "markdown": "# 自然语言漏洞报告\n\n请由 Moderator 解读：app.py 第 5 行存在命令注入，危险函数 os.system。",
                            },
                        ]
                    },
                    ensure_ascii=False,
                )
            else:
                content = "LLM"
            raw = json.dumps({"choices": [{"message": {"content": content}}]}).encode("utf-8")
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format, *args):  # noqa: A002
        return


class SlowFakeOpenAIHandler(FakeOpenAIHandler):
    def do_POST(self):  # noqa: N802
        time.sleep(0.25)
        super().do_POST()


class FakeLLM(LLMClient):
    def __init__(self, response):
        self.response = response
        self.calls = []

    def complete(self, system_prompt: str, user_prompt: str):
        self.calls.append((system_prompt, user_prompt))
        return self.response


class SequenceLLM(LLMClient):
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def complete(self, system_prompt: str, user_prompt: str):
        self.calls.append((system_prompt, user_prompt))
        if not self.responses:
            return ""
        if len(self.responses) == 1:
            return self.responses[0]
        return self.responses.pop(0)


if __name__ == "__main__":
    unittest.main()
