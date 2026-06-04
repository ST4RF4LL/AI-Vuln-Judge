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
from vuln_judger.sarif import parse_markdown_report
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

    def test_markdown_report_becomes_true_positive(self):
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
            report = run_judgement(
                RunConfig(
                    sarif_path=markdown,
                    source_path=root,
                    skills_path=skills,
                    enable_external_tools=False,
                )
            )
            self.assertEqual(report.finding_count, 1)
            self.assertEqual(report.reports[0].rule_id, "python-command-injection")
            self.assertEqual(report.reports[0].source_locations[0].file, "app.py")
            self.assertEqual(report.reports[0].verdict, Verdict.TRUE_POSITIVE)

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
            report = run_judgement(
                RunConfig(
                    sarif_path=markdown,
                    source_path=root,
                    enable_external_tools=False,
                )
            )
            locations = [location.file for location in report.reports[0].source_locations]
            self.assertEqual(locations, ["faiss/impl/index_read.cpp", "faiss/IndexFastScan.cpp"])
            source_evidence = [
                item for item in report.reports[0].evidence_chain if item.kind == EvidenceKind.SOURCE_LOCATION
            ]
            self.assertTrue(all(item.data["line_exists"] for item in source_evidence))

    def test_markdown_single_vulnerability_report_sections_are_merged(self):
        markdown = "\n".join(
            [
                "# FAISS-PANORAMA-DESER-OOB",
                "",
                "## Summary",
                "",
                "Malformed serialized `IndexFlatPanorama` objects are accepted by `faiss::read_index()`.",
                "",
                "Severity: High",
                "",
                "## Affected Code",
                "",
                "- `/tmp/faiss/faiss/impl/index_read.cpp`: `IxFP` branch in `read_index_up()`",
                "- `/tmp/faiss/faiss/impl/Panorama.h`: search-time cumulative-sum reads",
                "- `/tmp/faiss/faiss/IndexFlat.cpp`: `IndexFlatPanorama::permute_entries()`",
                "- `/tmp/faiss/faiss/impl/Panorama.cpp`: `Panorama::copy_entry()`",
                "",
                "## Root Cause",
                "",
                "The deserializer does not validate serialized vector sizes.",
                "",
                "## Evidence",
                "",
                "- `pocs/panorama_exp.py`",
                "- `pocs/panorama_trigger.cpp`",
                "",
                "## Recommended Fix",
                "",
                "Reject malformed `IxFP` objects during deserialization.",
            ]
        )
        findings = parse_markdown_report(markdown)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "FAISS-PANORAMA-DESER-OOB")
        self.assertEqual(findings[0].level, "high")
        self.assertIn("Malformed serialized", findings[0].message)
        self.assertEqual(
            [location.file for location in findings[0].locations],
            [
                "/tmp/faiss/faiss/impl/index_read.cpp",
                "/tmp/faiss/faiss/impl/Panorama.h",
                "/tmp/faiss/faiss/IndexFlat.cpp",
                "/tmp/faiss/faiss/impl/Panorama.cpp",
            ],
        )
        self.assertEqual(
            [location.symbol for location in findings[0].locations],
            [
                "read_index_up",
                None,
                "IndexFlatPanorama::permute_entries",
                "Panorama::copy_entry",
            ],
        )

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
            self.assertIn("Atlas MCP project/status 确认索引可用", summaries)
            self.assertIn("Atlas MCP project/files 确认索引中包含报告源码文件", summaries)
            self.assertNotIn("缺少 .atlas/atlas.db", summaries)
            self.assertTrue(any(item.data.get("mcp_success") for item in evidence))

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
            self.assertIn("Atlas MCP project/status 确认索引可用", summaries)
            self.assertIn("Atlas MCP project/files 确认索引中包含报告源码文件", summaries)
            self.assertIn("Atlas MCP trace variable 返回 ok=True", summaries)
            self.assertIn("Atlas MCP calls 提取 `handler` 调用图", summaries)
            self.assertTrue(any(item.kind == EvidenceKind.DATA_FLOW and item.source == "atlas-mcp" for item in evidence))
            self.assertTrue(any(item.kind == EvidenceKind.CALL_CHAIN and item.source == "atlas-mcp" for item in evidence))
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
            self.assertIn("Atlas MCP project/files 确认索引中包含报告源码文件", summaries)
            self.assertEqual(indexed.data["indexed_files"], ["faiss/impl/index_read.cpp"])
            self.assertTrue(any(item.data.get("trace_file") == "faiss/impl/index_read.cpp" for item in evidence))
            self.assertFalse(any("faiss/faiss/impl/index_read.cpp" in location.file for item in evidence for location in item.locations))

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

    def test_markdown_without_locations_still_passes_source_root_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "summary.md"
            report_path.write_text(
                "\n".join(
                    [
                        "# 静态分析总结",
                        "",
                        "## Summary",
                        "",
                        "- 规则：faiss-deserialization-risk",
                        "- 严重性：warning",
                        "- 消息：发现 IndexAdditiveQuantizerFastScan 可能存在反序列化风险，但报告未给出源码路径。",
                    ]
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
        self.assertIn('id="mcp-server-panel"', html)
        self.assertIn('id="skill-source-panel"', html)
        self.assertIn('#mcp-server-panel', html)
        self.assertIn('flex: 1 1 auto', html)
        self.assertIn('class="wide checkbox-row"', html)
        self.assertIn('启用 MCP Server', html)
        self.assertNotIn('min-height: 720px', html)
        self.assertIn('#skill-source-panel', html)
        self.assertIn('min-height: 520px', html)
        self.assertIn('id="mcp-list"', html)
        self.assertIn('id="skill-list"', html)
        self.assertIn('id="default-atlas-mcp"', html)
        self.assertIn('id="default-skill-source"', html)
        self.assertIn('id="run-skill-source"', html)
        self.assertNotIn('id="run-languages"', html)
        self.assertIn('自动 Atlas 构建索引', html)
        self.assertNotIn('自动索引工具', html)
        self.assertIn('id="agent-affirmative-profile-panel"', html)
        self.assertIn('id="agent-negative-profile-panel"', html)
        self.assertIn('#agent-affirmative-profile-panel', html)
        self.assertIn('min-height: 560px', html)
        self.assertIn('overflow: visible', html)
        self.assertIn('id="agent-affirmative-profile-list"', html)
        self.assertIn('id="agent-negative-profile-list"', html)
        self.assertIn('id="new-affirmative-agent"', html)
        self.assertIn('id="new-negative-agent"', html)
        self.assertIn('id="agent-profile-actions"', html)
        self.assertIn('id="run-affirmative-agent-profile"', html)
        self.assertIn('id="run-negative-agent-profile"', html)
        self.assertIn('function renderMarkdown(value)', html)
        self.assertIn('class="markdown-body"', html)
        self.assertIn('renderMarkdown(turn.claim)', html)
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
        self.assertIn('class="run-item-actions"', html)
        self.assertIn('.run-item-actions', html)
        self.assertIn('class="chips run-verdict-chips"', html)
        self.assertIn('.run-verdict-chips', html)
        self.assertIn('flex-wrap: nowrap', html)
        self.assertIn('async function stopRun(runId)', html)
        self.assertIn('function isTerminalStatus(status)', html)
        self.assertIn("stopped: '已停止'", html)
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
            raw = json.loads((Path(tmp) / "providers.json").read_text(encoding="utf-8"))
            self.assertEqual(raw["providers"][0]["api_key"], "secret")

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
                defaults = post_json(f"{base}/providers/defaults", {"affirmative": "fake", "negative": "fake"})
                self.assertEqual(defaults["affirmative"], "fake")
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
                tools = {tool.get("name") for tool in client.list_tools()}
                self.assertIn("judge_report", tools)
                self.assertIn("one_round_judge", tools)
                self.assertIn("collect_evidence", tools)
                self.assertIn("export_run_markdown", tools)

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

    def test_affirmative_and_negative_use_independent_clients(self):
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
            report = DebateOrchestrator(affirmative_client=affirmative, negative_client=negative).adjudicate(bundle)
            self.assertIn("AFFIRMATIVE_FROM_CLIENT", report.debate[0].claim)
            self.assertIn("NEGATIVE_FROM_CLIENT", report.debate[1].claim)
            self.assertTrue(affirmative.calls)
            self.assertTrue(negative.calls)

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
            DebateOrchestrator(
                affirmative_client=affirmative,
                negative_client=negative,
                affirmative_agent=AgentConfig("利用证据指证员", "优先关注资产窃取证据。"),
                negative_agent=AgentConfig("可达性复核员", "质疑死代码和缓解措施。"),
            ).adjudicate(bundle)
            self.assertIn("利用证据指证员", affirmative.calls[0][0])
            self.assertIn("优先关注资产窃取证据。", affirmative.calls[0][0])
            self.assertIn("可达性复核员", negative.calls[0][0])
            self.assertIn("质疑死代码和缓解措施。", negative.calls[0][0])

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
            store.set_defaults("fake", "fake")
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
            self.assertTrue(report.llm_providers["affirmative"]["client_available"])
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
                )
            )
            self.assertEqual(report.agent_configs["affirmative"]["name"], "利用证据指证员")
            self.assertEqual(report.agent_configs["negative"]["instructions"], "关注可达缓解措施。")

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
            store.set_defaults("fake", "fake")
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
            self.assertEqual(report.llm_providers["affirmative"]["status"], "llm_disabled")
            self.assertFalse(report.llm_providers["affirmative"]["client_available"])

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

    def test_cpp_without_compile_database_is_inconclusive(self):
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
            self.assertIn("编译数据库", report.reports[0].reasoning_summary)


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


class FakeOpenAIHandler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("content-length") or 0)
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        if self.headers.get("authorization") != "Bearer secret":
            self.send_response(HTTPStatus.UNAUTHORIZED)
            raw = b'{"error":"unauthorized"}'
        else:
            self.send_response(HTTPStatus.OK)
            content = "OK" if "connectivity" in body["messages"][0]["content"] else "LLM"
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


if __name__ == "__main__":
    unittest.main()
