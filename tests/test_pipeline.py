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
from datetime import date, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Lock, Thread
from unittest.mock import patch

from vuln_judger.analyzers import AnalyzerSettings, AtlasAnalyzer
from vuln_judger.api import (
    _codex_terminal_page,
    _config_from_payload,
    _finding_summary,
    _stop_codex_sessions,
    app_html,
    make_handler,
)
from vuln_judger.codex_runner import (
    DEFAULT_CODEX_WORKSPACES_DIR,
    CodexDrivenRunner,
    CodexTmuxSession,
    _ensure_codex_project_trust,
    _prepare_codex_agent_dirs,
)
from vuln_judger.agents import AgentDirectoryStore
from vuln_judger.debate import DebateOrchestrator
from vuln_judger.evidence import EvidenceBundle
from vuln_judger.llm import LLMClient
from vuln_judger.logging_config import DEFAULT_LOG_RETENTION_DAYS, configure_logging, daily_log_path, logger
from vuln_judger.mcp import MCPStdioClient
from vuln_judger.mcp_config import MCPServerStore
from vuln_judger.models import AgentConfig, CodeEvidence, EvidenceKind, EvidenceStrength, Finding, RunConfig, SourceLocation, Verdict, to_jsonable
from vuln_judger.pipeline import run_judgement
from vuln_judger.providers import ProviderStore
from vuln_judger.records import RunRecordStore
from vuln_judger.sarif import ReportPreparationError, load_sarif, prepare_report_for_processing
from vuln_judger.skills import SkillSourceStore
from vuln_judger.source import SourceIndexer, detect_project_languages


class PipelineTests(unittest.TestCase):
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

    def test_sarif_report_is_moderated_with_source_into_markdown_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, _skills = write_python_fixture(root)
            response = {
                "reports": [
                    {
                        "title": "命令注入独立报告",
                        "result_indices": [0],
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
            self.assertEqual(finding.rule_id, "python-command-injection")
            self.assertEqual(finding.message, "命令注入独立报告")
            self.assertEqual(finding.locations[0].display(), "app.py:5:5")
            self.assertEqual(finding.code_flows[0][0].display(), "app.py:4:11")
            self.assertEqual(finding.properties["source_report_format"], "sarif")
            self.assertEqual(finding.properties["sarif_result_indices"], [0])
            self.assertIn("request.args['cmd']", finding.raw["markdown"])
            self.assertEqual(prepared.effective_path.read_text(encoding="utf-8"), finding.raw["markdown"])
            self.assertIn("os.system(cmd)", moderator.calls[0][1])
            self.assertIn('"result_index": 0', moderator.calls[0][1])
            self.assertTrue(any("结合源码整理 SARIF" in item for item in prepared.diagnostics))

    def test_sarif_moderation_failure_falls_back_to_original_sarif(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sarif, _skills = write_python_fixture(root)
            moderator = SequenceLLM(["不是 JSON", "仍然不是 JSON", "bad"])

            prepared = prepare_report_for_processing(sarif, moderator_client=moderator, source_path=root)

            self.assertIsNone(prepared.findings)
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
                    "created_at": "2026-06-09T00:00:00Z",
                    "source_path": "/src",
                    "sarif_path": "/report.sarif",
                    "finding_count": 3,
                    "completed_finding_count": 1,
                    "current_finding_id": "finding-2",
                    "current_finding_index": 1,
                    "reports": [{"finding_id": "finding-1", "verdict": "TRUE_POSITIVE"}, {"finding_id": "partial"}],
                    "diagnostics": [],
                    "config": {"report_path": "/report.sarif", "source_path": "/src"},
                }
            )

            recovered = store.recover_unfinished()

            self.assertEqual(len(recovered), 1)
            saved = store.get("run-recover")
            self.assertEqual(saved["status"], "paused")
            self.assertEqual(saved["completed_finding_count"], 1)
            self.assertEqual(saved["resume_from_finding_id"], "finding-2")
            self.assertEqual(saved["resume_from_finding_index"], 1)
            self.assertEqual(len(saved["reports"]), 1)
            self.assertIn("服务重启时发现任务未完成", saved["diagnostics"][-1])

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
                self.assertIn("# 漏洞研判报告", markdown_report)
                self.assertIn(f"- 任务 ID：{created['run_id']}", markdown_report)
                self.assertIn("- 任务来源：Web 端", markdown_report)
                self.assertIn("## 发现 1:", markdown_report)
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
        self.assertIn("paused: '已暂停'", html)
        self.assertIn("pausing: '正在暂停'", html)
        self.assertIn('function isTerminalStatus(status)', html)
        self.assertIn("stopped: '已停止'", html)
        self.assertIn("status === 'paused'", html)
        self.assertIn("SOURCE_ROOT: '源码根目录'", html)
        self.assertIn("fetchJson('/mcp-servers')", html)
        self.assertIn("fetchJson('/skill-sources')", html)
        self.assertIn('id="run-provider-agent-grid"', html)
        self.assertIn('class="run-provider-control"', html)
        self.assertIn('class="run-agent-control"', html)
        self.assertIn('id="run-tool-provider-options"', html)
        self.assertIn('id="run-codex-config-note"', html)
        self.assertIn('function updateRunEngineVisibility()', html)
        self.assertIn("el.runProviderAgentGrid.hidden = false", html)
        self.assertIn("document.querySelectorAll('.run-provider-control')", html)
        self.assertIn("affirmative_agent_profile: el.runAffirmativeAgentProfile.value || null", html)
        self.assertNotIn("affirmative_agent_profile: codexMode ? null", html)
        self.assertNotIn("el.runProviderAgentGrid.hidden = codexMode", html)
        self.assertIn('Codex 三方复核使用项目 .codex/config.toml', html)
        self.assertIn('当前活动 Agent', html)
        self.assertIn('function renderCodexActiveAgent(run, findings, status)', html)
        self.assertIn('function inferCodexActiveAgent(run, findings, status)', html)
        self.assertIn('codex_delivery', html)
        self.assertIn("ensurePolling(created.run_id);", html)
        self.assertLess(html.index("ensurePolling(created.run_id);"), html.index("await loadRuns();"))
        self.assertIn('正方验证阶段，等待正方 result.json', html)
        self.assertIn('反方复核阶段，正方已交付', html)
        self.assertIn('最终裁决阶段，正反方已交付', html)
        self.assertIn('/terminal-ui', html)
        self.assertIn('id="codex-terminal-frame-modal"', html)
        self.assertIn('id="close-codex-terminal-frame"', html)
        self.assertIn('id="codex-terminal-frame"', html)
        self.assertIn('在当前页面打开原始 Codex TUI', html)
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
        self.assertNotIn("codex_workflow", summary)

    def test_codex_terminal_page_uses_xterm_websocket(self):
        html = _codex_terminal_page(
            "run-1",
            "moderator",
            {"target": "vj-run-1-moderator:codex", "session_name": "vj-run-1-moderator"},
        )
        self.assertIn('/static/vendor/xterm/xterm.css', html)
        self.assertIn('/static/vendor/xterm/xterm.js', html)
        self.assertIn('/static/vendor/xterm/addon-fit.js', html)
        self.assertIn('/runs/run-1/codex-sessions/moderator/ws', html)
        self.assertIn('new WebSocket(websocketURL(websocketPath))', html)
        self.assertIn("tmux attach · raw TUI", html)

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

    def test_codex_start_uses_yolo_mode_by_default(self):
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
            completed = [
                subprocess.CompletedProcess(["tmux"], 1, "", ""),
                subprocess.CompletedProcess(["tmux"], 0, "", ""),
            ]
            with patch("vuln_judger.codex_runner._run_tmux", side_effect=completed) as run_tmux:
                with patch.object(CodexTmuxSession, "_accept_trust_prompt"), patch.object(
                    CodexTmuxSession, "_wait_until_input_ready"
                ):
                    session.start()

            launch_args = run_tmux.call_args_list[1].args[0]
            self.assertIn("--dangerously-bypass-approvals-and-sandbox", launch_args)
            self.assertNotIn("--sandbox", launch_args)
            self.assertNotIn("--ask-for-approval", launch_args)
            self.assertEqual(launch_args[launch_args.index("--cd") + 1], str(run_dir.resolve()))

    def test_codex_send_uses_bracketed_paste_and_control_submit(self):
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
            with patch.object(session, "is_live", return_value=True), patch.object(
                session, "_wait_until_input_ready"
            ), patch("vuln_judger.codex_runner.subprocess.run", return_value=completed) as run, patch(
                "vuln_judger.codex_runner._run_tmux", return_value=completed
            ) as run_tmux, patch.dict(
                os.environ,
                {"VULN_JUDGER_CODEX_PASTE_SETTLE": "0", "VULN_JUDGER_CODEX_SUBMIT_KEY": "C-m"},
                clear=False,
            ):
                session.send("line one\r\nline two")

            self.assertEqual(run.call_args.kwargs["input"], "line one\nline two")
            tmux_calls = [call.args[0] for call in run_tmux.call_args_list]
            self.assertIn(
                ["tmux", "paste-buffer", "-d", "-p", "-r", "-b", "vj-run-1-moderator-input", "-t", session.target],
                tmux_calls,
            )
            self.assertIn(["tmux", "send-keys", "-t", session.target, "C-m"], tmux_calls)
            self.assertNotIn(["tmux", "send-keys", "-t", session.target, "Enter"], tmux_calls)

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

    def test_codex_default_workspaces_dir_uses_dot_workspaces_runs(self):
        self.assertEqual(DEFAULT_CODEX_WORKSPACES_DIR.name, "runs")
        self.assertEqual(DEFAULT_CODEX_WORKSPACES_DIR.parent.name, ".workspaces")
        self.assertNotIn(".vuln_judger", str(DEFAULT_CODEX_WORKSPACES_DIR))

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
                        progress_callback=lambda payload: captured.append(dict(payload)),
                    )

            first_with_sessions = next(item for item in captured if item.get("codex_sessions"))
            self.assertEqual({item["role"] for item in first_with_sessions["codex_sessions"]}, {"moderator", "affirmative", "negative"})
            self.assertIn("Codex-driven session 元数据已创建", "\n".join(first_with_sessions["diagnostics"]))
            self.assertEqual(first_with_sessions["status"], "running")

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

                judged = mcp_tool_json(
                    client.call_tool(
                        "judge_report",
                        {
                            "report_path": str(sarif),
                            "source_path": str(root),
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
