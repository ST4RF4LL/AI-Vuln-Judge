import json
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from vuln_judger.analyzers import AnalyzerSettings, AtlasAnalyzer
from vuln_judger.api import app_html, make_handler
from vuln_judger.agents import AgentDirectoryStore
from vuln_judger.debate import DebateOrchestrator
from vuln_judger.evidence import EvidenceBundle
from vuln_judger.llm import LLMClient
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

    def test_markdown_table_report_is_moderated_into_temp_sarif(self):
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
            llm_sarif = {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "moderator-llm"}},
                        "results": [
                            {
                                "ruleId": "python-command-injection",
                                "level": "error",
                                "message": {"text": "用户输入可到达命令执行点"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": 5},
                                        }
                                    }
                                ],
                                "properties": {"markdown_dangerousfunction": "os.system"},
                            }
                        ],
                    }
                ],
            }
            moderator = FakeLLM(json.dumps(llm_sarif, ensure_ascii=False))

            prepared = prepare_report_for_processing(markdown, moderator_client=moderator)
            self.assertNotEqual(prepared.effective_path, markdown.resolve())
            self.assertTrue(prepared.temporary)
            self.assertTrue(moderator.calls)
            findings = load_sarif(prepared.effective_path)
            self.assertEqual(findings[0].message, "用户输入可到达命令执行点")
            self.assertEqual(findings[0].rule_id, "python-command-injection")
            self.assertEqual(findings[0].locations[0].display(), "app.py:5")
            self.assertTrue(any("SARIF 格式验证通过" in item for item in prepared.diagnostics))

    def test_moderator_llm_interprets_markdown_before_sarif_validation(self):
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
            llm_sarif = {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "moderator-llm"}},
                        "results": [
                            {
                                "ruleId": "LLM-MARKDOWN-COMMAND-INJECTION",
                                "level": "error",
                                "message": {"text": "LLM 解读：用户输入可到达 os.system。"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {"startLine": 5},
                                        }
                                    }
                                ],
                                "properties": {"markdown_dangerousfunction": "os.system"},
                            }
                        ],
                    }
                ],
            }
            moderator = FakeLLM(json.dumps(llm_sarif, ensure_ascii=False))

            prepared = prepare_report_for_processing(markdown, moderator_client=moderator)
            findings = load_sarif(prepared.effective_path)

            self.assertTrue(moderator.calls)
            self.assertIn("Markdown 报告开始", moderator.calls[0][1])
            self.assertEqual(findings[0].rule_id, "LLM-MARKDOWN-COMMAND-INJECTION")
            self.assertEqual(findings[0].message, "LLM 解读：用户输入可到达 os.system。")
            self.assertTrue(any("Moderator LLM 已解读 Markdown 并生成 SARIF" in item for item in prepared.diagnostics))

    def test_pipeline_uses_moderator_llm_for_markdown_conversion(self):
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

            self.assertTrue(any("Moderator LLM 已解读 Markdown 并生成 SARIF" in item for item in report.diagnostics))
            self.assertEqual(report.reports[0].rule_id, "LLM-MARKDOWN-COMMAND-INJECTION")
            summaries = "\n".join(item.summary for item in report.reports[0].evidence_chain)
            self.assertIn("LLM 解读：用户输入可到达 os.system。", summaries)

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
            llm_sarif = {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "moderator-llm"}},
                        "results": [
                            {
                                "ruleId": "faiss-report",
                                "message": {"text": "FAISS affected code"},
                                "locations": [
                                    {"physicalLocation": {"artifactLocation": {"uri": "faiss/impl/index_read.cpp"}}},
                                    {"physicalLocation": {"artifactLocation": {"uri": "faiss/IndexFastScan.cpp"}}},
                                ],
                            }
                        ],
                    }
                ],
            }
            prepared = prepare_report_for_processing(markdown, moderator_client=FakeLLM(json.dumps(llm_sarif)))
            locations = [location.file for finding in load_sarif(prepared.effective_path) for location in finding.locations]
            self.assertEqual(locations, ["faiss/impl/index_read.cpp", "faiss/IndexFastScan.cpp"])

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
            self.assertIn("检测到 Atlas 数据库", summaries)
            self.assertIn("AI 自主 Atlas MCP project/status 确认索引状态", summaries)
            self.assertIn("AI 自主 Atlas MCP project/files 找到报告路径候选", summaries)
            self.assertNotIn("缺少 .atlas/atlas.db", summaries)
            self.assertTrue(any(item.data.get("mcp_success") for item in evidence))
            self.assertTrue(any(item.source == "agentic-source-reader" for item in evidence))
            self.assertFalse(any(item.source == "atlas-mcp" for item in evidence))

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
            self.assertIn("AI 自主 Atlas MCP project/status 确认索引状态", summaries)
            self.assertIn("AI 自主 Atlas MCP project/files 找到报告路径候选", summaries)
            self.assertIn("AI 自主 Atlas MCP trace variable 返回 ok=True", summaries)
            self.assertIn("AI 自主 Atlas MCP calls 提取 `handler` 调用图", summaries)
            self.assertTrue(any(item.kind == EvidenceKind.DATA_FLOW and item.source == "atlas-agent-mcp" for item in evidence))
            self.assertTrue(any(item.kind == EvidenceKind.CALL_CHAIN and item.source == "atlas-agent-mcp" for item in evidence))
            self.assertTrue(any(item.source == "agentic-source-reader" for item in evidence))
            self.assertFalse(any(item.source == "atlas-mcp" for item in evidence))
            self.assertNotIn("当前 Atlas CLI 未提供 trace 子命令", summaries)

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
            self.assertIn("AI 自主 Atlas MCP project/files 找到报告路径候选", summaries)
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
            self.assertIn("AI 自主 Atlas MCP 补证启动", summaries)
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
            self.assertIn("AI 自主 Atlas MCP search 未找到报告相关符号或路径候选", summaries)
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
            self.assertIn("正方证据报告", finding.debate[0].claim)
            self.assertIn("攻击链", finding.debate[0].claim)
            self.assertIn("攻击前提", finding.debate[0].claim)
            self.assertIn("攻击影响", finding.debate[0].claim)
            self.assertIn("反方质疑报告", finding.debate[1].claim)
            self.assertTrue(finding.final_conclusion.startswith("【真实漏洞】"))
            self.assertEqual(finding.debate[-1].claim, finding.final_conclusion)

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
            self.assertIn("正方补证策略", finding.debate[0].claim)
            self.assertIn("应继续主动补证", finding.debate[0].claim)

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
                self.assertEqual(json_report["run_id"], run["run_id"])
                self.assertIn("# 漏洞研判报告", markdown_report)
                self.assertIn(f"- 任务 ID：{created['run_id']}", markdown_report)
                self.assertIn("## 发现 1:", markdown_report)
                self.assertIn("### 博弈过程", markdown_report)
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
        self.assertIn('自动 Atlas 构建索引', html)
        self.assertNotIn('自动索引工具', html)
        self.assertNotIn('id="run-agentic-atlas"', html)
        self.assertNotIn('id="run-agentic-atlas-direct"', html)
        self.assertNotIn('直接 AI 自主运行 Atlas MCP', html)
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
        self.assertIn('promptEchoPatterns', html)
        self.assertIn('plainText(turn.claim)', html)
        self.assertNotIn('renderMarkdown(turn.claim)', html)
        self.assertIn('class="plain-text"', html)
        self.assertIn('原始报告详情', html)
        self.assertIn('renderOriginalReportSection(detail)', html)
        self.assertIn('raw_result', html)
        self.assertIn('function uniqueDebateTurns(debate)', html)
        self.assertIn('function renderTable(start)', html)
        self.assertIn('function bindRunExportButtons()', html)
        self.assertIn('function exportRun(runId, format)', html)
        self.assertIn('data-run-export="markdown"', html)
        self.assertIn('data-run-export="json"', html)
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
                self.assertIn("外部输入源头", affirmative_default["instructions"])
                self.assertIn("grep/ripgrep", affirmative_default["instructions"])
                self.assertIn("转回 Atlas", affirmative_default["instructions"])
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
                mcp = post_json(
                    f"{base}/mcp-servers",
                    {
                        "id": "atlas-test",
                        "name": "Atlas Test",
                        "kind": "atlas",
                        "command": str(atlas),
                        "args": ["mcp", "--project", "{project}"],
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
                            "include_evidence": True,
                            "evidence_limit": 5,
                        },
                    )
                )
                self.assertEqual(quick["mode"], "one_round_judge")
                self.assertEqual(quick["configuration"]["max_rounds"], 1)
                self.assertFalse(quick["configuration"]["enable_llm"])
                self.assertFalse(quick["saved"])
                self.assertEqual(quick["finding_count"], 1)
                self.assertEqual(quick["judged_finding_count"], 1)
                self.assertEqual(quick["selected_finding"]["rule_id"], "python-command-injection")
                self.assertEqual(quick["verdict"]["verdict"], "TRUE_POSITIVE")
                self.assertEqual(quick["agent_configs"]["moderator"]["profile_id"], "Moderator_default")
                self.assertIn("evidence_summary", quick)
                self.assertIn("missing_evidence", quick)
                self.assertLessEqual(len(quick["evidence"]), 5)
                self.assertTrue(quick["debate"])

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
                self.assertTrue(judged["saved"])
                run_id = judged["run_id"]

                runs = mcp_tool_json(client.call_tool("list_runs", {"limit": 5}))
                self.assertTrue(any(item["run_id"] == run_id for item in runs["runs"]))
                run_summary = mcp_tool_json(client.call_tool("get_run", {"run_id": run_id}))
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
            self.assertIn("可达性复核员", negative.calls[0][0])
            self.assertIn("质疑死代码和缓解措施。", negative.calls[0][0])
            self.assertIn("中立主持人", moderator.calls[0][0])
            self.assertIn("只总结双方核心观点。", moderator.calls[0][0])

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
            for turn in serialized["debate"]:
                if turn["claim"].startswith("## 正方结案") or turn["claim"].startswith("## 反方结案"):
                    self.assertNotIn("分析请求", turn["claim"])
                    self.assertNotIn("分析用户请求", turn["claim"])
                    self.assertNotIn("强约束", turn["claim"])
                    self.assertNotIn("标签约束", turn["claim"])
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
                    "正方第 2 回合澄清：继续补充外部输入可达性证据。",
                    "正方第 3 回合澄清：继续补充调用链证据。",
                    "正方结案正文。",
                ]
            )
            negative = SequenceLLM(
                [
                    "## 反方质疑报告\n### 仍未闭环的问题\n- 调用链仍未闭环，报告无法证明外部输入可达。\n### 是否继续质疑：是",
                    "## 反方第 2 回合复审报告\n### 仍未闭环的问题\n- 调用链仍未闭环，反方继续质疑。",
                    "## 反方第 3 回合复审报告\n### 仍未闭环的问题\n- 调用链仍未闭环，反方继续质疑。",
                    "反方结案正文。",
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
            self.assertEqual(report.debate[-1].round_index, 4)
            self.assertTrue(
                any(turn.role.value == "AFFIRMATIVE" and turn.round_index == 4 and "正方结案" in turn.claim for turn in report.debate)
            )

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
            report = DebateOrchestrator(
                max_rounds=4,
                affirmative_client=SequenceLLM(["正方证据报告。", "正方最终总结正文。"]),
                negative_client=SequenceLLM(
                    [
                        "## 反方质疑报告\n- 调用链仍未闭环，报告无法证明外部输入可达。",
                        "反方最终总结正文。",
                    ]
                ),
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
                    and "正方结案" not in turn.claim
                    for turn in report.debate
                )
            )
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
            self.assertTrue(
                any(turn.role.value == "AFFIRMATIVE" and turn.round_index == 2 and "正方结案" in turn.claim for turn in report.debate)
            )
            self.assertTrue(
                any(turn.role.value == "NEGATIVE" and turn.round_index == 2 and "反方结案" in turn.claim for turn in report.debate)
            )
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
        if name == "project" and args.get("action") == "status":
            tool_response(request_id, {
                "summary": {"files": 1, "symbols": 1, "edges": 2},
                "project": {"db_path": ".atlas/atlas.db"},
                "server": {"atlas_version": "fake", "tool_contract_version": 1},
                "language_capabilities": [{"language": "python", "capability_level": "dataflow_full"}],
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
        if name == "project" and args.get("action") == "status":
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
            elif "转换为 SARIF 2.1.0" in system_prompt or "Markdown 报告开始" in user_prompt:
                content = json.dumps(
                    {
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {"driver": {"name": "moderator-llm"}},
                                "results": [
                                    {
                                        "ruleId": "LLM-MARKDOWN-COMMAND-INJECTION",
                                        "level": "error",
                                        "message": {"text": "LLM 解读：用户输入可到达 os.system。"},
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {"uri": "app.py"},
                                                    "region": {"startLine": 5},
                                                }
                                            }
                                        ],
                                        "properties": {"markdown_dangerousfunction": "os.system"},
                                    }
                                ],
                            }
                        ],
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
