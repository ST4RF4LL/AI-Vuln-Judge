import json
import tempfile
import unittest
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from vuln_judger.api import app_html, make_handler
from vuln_judger.agents import AgentDirectoryStore
from vuln_judger.debate import DebateOrchestrator
from vuln_judger.evidence import EvidenceBundle
from vuln_judger.llm import LLMClient
from vuln_judger.models import AgentConfig, RunConfig, Verdict
from vuln_judger.pipeline import run_judgement
from vuln_judger.providers import ProviderStore
from vuln_judger.records import RunRecordStore


class PipelineTests(unittest.TestCase):
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
                        "# Static Analysis Markdown Report",
                        "",
                        "## Finding 1: python-command-injection",
                        "",
                        "- Rule: python-command-injection",
                        "- Severity: error",
                        "- Message: user input reaches command execution",
                        "- Location: app.py:5:5",
                        "",
                        "### Code Flow",
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
                wait_for_run_completed(base, created["run_id"])
                with urllib.request.urlopen(f"{base}/runs", timeout=5) as response:
                    runs = json.loads(response.read().decode("utf-8"))
                with urllib.request.urlopen(f"{base}/runs/{created['run_id']}/findings", timeout=5) as response:
                    findings = json.loads(response.read().decode("utf-8"))
                with urllib.request.urlopen(f"{base}/", timeout=5) as response:
                    html = response.read().decode("utf-8")
                self.assertEqual(len(runs), 1)
                self.assertEqual(findings[0]["verdict"], "TRUE_POSITIVE")
                self.assertIn("Vulnerability Judger Records", html)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_app_html_contains_core_mount_points(self):
        html = app_html()
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
        self.assertIn('id="agent-prompt-panel"', html)
        self.assertIn('id="run-affirmative-agent-profile"', html)
        self.assertIn('id="run-negative-agent-profile"', html)

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
                self.assertEqual(defaults["defaults"]["affirmative"], "Affirmative_1")
                saved = post_json(
                    f"{base}/agent-prompts",
                    {
                        "role": "affirmative",
                        "profile_id": "Affirmative_1",
                        "instructions": "Prioritize value asset impact.",
                    },
                )
                self.assertEqual(saved["profile_id"], "Affirmative_1")
                post_json(
                    f"{base}/agent-prompts",
                    {
                        "role": "negative",
                        "profile_id": "Negative_web",
                        "instructions": "Challenge reachability and guards.",
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
                self.assertEqual(run["agent_configs"]["affirmative"]["profile_id"], "Affirmative_1")
                self.assertEqual(run["agent_configs"]["affirmative"]["instructions"], "Prioritize value asset impact.")
                self.assertEqual(run["agent_configs"]["negative"]["instructions"], "Challenge reachability and guards.")
                reset = post_json(f"{base}/agent-prompts", {"reset": True})
                self.assertEqual(reset["defaults"]["negative"], "Negative_web")
            finally:
                api_server.shutdown()
                api_server.server_close()
                api_thread.join(timeout=5)

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
                affirmative_agent=AgentConfig("Exploit Prosecutor", "Prioritize asset-theft evidence."),
                negative_agent=AgentConfig("Reachability Reviewer", "Challenge dead code and mitigations."),
            ).adjudicate(bundle)
            self.assertIn("Exploit Prosecutor", affirmative.calls[0][0])
            self.assertIn("Prioritize asset-theft evidence.", affirmative.calls[0][0])
            self.assertIn("Reachability Reviewer", negative.calls[0][0])
            self.assertIn("Challenge dead code and mitigations.", negative.calls[0][0])

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
                    affirmative_agent=AgentConfig("Exploit Prosecutor", "Focus on value assets."),
                    negative_agent=AgentConfig("Mitigation Reviewer", "Focus on reachable mitigations."),
                )
            )
            self.assertEqual(report.agent_configs["affirmative"]["name"], "Exploit Prosecutor")
            self.assertEqual(report.agent_configs["negative"]["instructions"], "Focus on reachable mitigations.")

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
            self.assertIn("compile", report.reports[0].reasoning_summary.lower())


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
        "# Payments threat model\napp.py handles payment admin commands and customer data.",
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
                                "message": {"text": "user input reaches command execution"},
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


class FakeLLM(LLMClient):
    def __init__(self, response):
        self.response = response
        self.calls = []

    def complete(self, system_prompt: str, user_prompt: str):
        self.calls.append((system_prompt, user_prompt))
        return self.response


if __name__ == "__main__":
    unittest.main()
