from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .api import DEFAULT_RECORDS_DIR, serve
from .models import RunConfig, to_jsonable
from .pipeline import run_judgement
from .providers import DEFAULT_PROVIDERS_FILE
from .records import RunRecordStore


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="vuln-judger")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run static report vulnerability adjudication")
    run_parser.add_argument("--sarif", "--report", dest="sarif", required=True, type=Path, help="Path to a SARIF or Markdown report")
    run_parser.add_argument("--source", required=True, type=Path, help="Path to the matching source tree")
    run_parser.add_argument("--skills", type=Path, help="Path to project knowledge skills")
    run_parser.add_argument("--languages", default="java,cpp,python", help="Comma-separated language allowlist")
    run_parser.add_argument("--max-rounds", type=int, default=4, help="Maximum debate rounds")
    run_parser.add_argument("--auto-index-tools", action="store_true", help="Allow analyzers to create local indexes")
    run_parser.add_argument("--no-external-tools", action="store_true", help="Disable Atlas/CodeGraph/CodeQL probing")
    run_parser.add_argument("--llm", action="store_true", help="Use an OpenAI-compatible LLM for debate turn drafting")
    run_parser.add_argument("--llm-model", help="Model name for --llm; can also use VULN_JUDGER_LLM_MODEL")
    run_parser.add_argument("--llm-endpoint", help="Chat completions endpoint for --llm")
    run_parser.add_argument("--providers-file", type=Path, default=DEFAULT_PROVIDERS_FILE, help="Path to provider configuration")
    run_parser.add_argument("--affirmative-provider", help="Provider id for the affirmative agent")
    run_parser.add_argument("--negative-provider", help="Provider id for the negative agent")
    run_parser.add_argument("--out", type=Path, help="Write JSON report to this path")
    run_parser.add_argument("--record", action="store_true", help="Save this run to the UI records directory")
    run_parser.add_argument("--records-dir", type=Path, default=DEFAULT_RECORDS_DIR, help="Directory for saved run records")

    api_parser = subparsers.add_parser("api", help="Start the minimal HTTP API")
    api_parser.add_argument("--host", default="127.0.0.1")
    api_parser.add_argument("--port", default=8765, type=int)
    api_parser.add_argument("--records-dir", type=Path, default=DEFAULT_RECORDS_DIR, help="Directory for saved run records")
    api_parser.add_argument("--providers-file", type=Path, default=DEFAULT_PROVIDERS_FILE, help="Path to provider configuration")

    args = parser.parse_args(argv)
    if args.command == "api":
        serve(args.host, args.port, args.records_dir, args.providers_file)
        return 0
    if args.command == "run":
        config = RunConfig(
            sarif_path=args.sarif,
            source_path=args.source,
            skills_path=args.skills,
            languages=_parse_languages(args.languages),
            max_rounds=args.max_rounds,
            auto_index_tools=args.auto_index_tools,
            enable_external_tools=not args.no_external_tools,
            enable_llm=args.llm,
            llm_model=args.llm_model,
            llm_endpoint=args.llm_endpoint,
            providers_file=args.providers_file,
            affirmative_provider_id=args.affirmative_provider,
            negative_provider_id=args.negative_provider,
        )
        report = run_judgement(config)
        if args.record:
            RunRecordStore(args.records_dir).save(report)
        payload = json.dumps(to_jsonable(report), ensure_ascii=False, indent=2, sort_keys=True)
        if args.out:
            args.out.expanduser().resolve().write_text(payload + "\n", encoding="utf-8")
            print(_summary(report))
        else:
            print(payload)
        return 0
    return 2


def _parse_languages(raw: str) -> List[str]:
    languages = [item.strip().lower() for item in raw.split(",") if item.strip()]
    return languages or ["java", "cpp", "python"]


def _summary(report) -> str:
    counts = {}
    for item in report.reports:
        counts[item.verdict.value] = counts.get(item.verdict.value, 0) + 1
    counts_text = ", ".join(f"{key}={value}" for key, value in sorted(counts.items())) or "no findings"
    return f"{report.run_id}: {report.finding_count} findings adjudicated ({counts_text})"


if __name__ == "__main__":
    sys.exit(main())
