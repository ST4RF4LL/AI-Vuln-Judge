from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from .api import DEFAULT_RECORDS_DIR, serve
from .agents import DEFAULT_AGENTS_DIR, AgentDirectoryStore
from .logging_config import DEFAULT_LOG_FILE, configure_logging, logger
from .mcp_config import DEFAULT_MCP_SERVERS_FILE
from .models import AgentConfig, RunConfig, to_jsonable
from .pipeline import run_judgement
from .providers import DEFAULT_PROVIDERS_FILE
from .records import RunRecordStore
from .skills import DEFAULT_SKILLS_FILE, SkillSourceStore

LOG = logger("cli")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="vuln-judger")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="运行静态报告漏洞研判")
    run_parser.add_argument("--sarif", "--report", dest="sarif", required=True, type=Path, help="SARIF 或 Markdown 报告路径")
    run_parser.add_argument("--source", required=True, type=Path, help="报告对应的源码目录")
    run_parser.add_argument("--skills", type=Path, help="项目知识库 skill 目录")
    run_parser.add_argument("--languages", default="java,cpp,python", help="逗号分隔的语言白名单")
    run_parser.add_argument("--max-rounds", type=int, default=4, help="最大博弈回合数")
    run_parser.add_argument("--auto-index-tools", action="store_true", help="允许分析器创建本地索引")
    run_parser.add_argument("--no-external-tools", action="store_true", help="禁用 Atlas/CodeQL 探测")
    run_parser.add_argument("--llm", action="store_true", help="使用 OpenAI-compatible LLM 生成正反方回合")
    run_parser.add_argument("--llm-model", help="--llm 使用的模型名；也可使用 VULN_JUDGER_LLM_MODEL")
    run_parser.add_argument("--llm-endpoint", help="--llm 使用的 Chat Completions endpoint")
    run_parser.add_argument("--providers-file", type=Path, default=DEFAULT_PROVIDERS_FILE, help="provider 配置文件路径")
    run_parser.add_argument("--mcp-servers-file", type=Path, default=DEFAULT_MCP_SERVERS_FILE, help="MCP Server 配置文件路径")
    run_parser.add_argument("--skills-file", type=Path, default=DEFAULT_SKILLS_FILE, help="Skill Source 配置文件路径")
    run_parser.add_argument("--skill-source", help="Skill Source ID；未显式传 --skills 时使用该知识库路径")
    run_parser.add_argument("--affirmative-provider", help="正方 Agent 使用的 provider ID")
    run_parser.add_argument("--negative-provider", help="反方 Agent 使用的 provider ID")
    run_parser.add_argument("--affirmative-agent-name", help="正方 Agent 显示名称")
    run_parser.add_argument("--affirmative-agent-instructions", help="正方 Agent 自定义提示词")
    run_parser.add_argument("--negative-agent-name", help="反方 Agent 显示名称")
    run_parser.add_argument("--negative-agent-instructions", help="反方 Agent 自定义提示词")
    run_parser.add_argument("--agents-dir", type=Path, default=DEFAULT_AGENTS_DIR, help="包含角色 Agent 配置的目录")
    run_parser.add_argument("--affirmative-agent-profile", help="agents/Affirmative 下的正方 profile 目录")
    run_parser.add_argument("--negative-agent-profile", help="agents/Negative 下的反方 profile 目录")
    run_parser.add_argument("--out", type=Path, help="将 JSON 研判报告写入该路径")
    run_parser.add_argument("--record", action="store_true", help="将本次运行保存到 Web 记录目录")
    run_parser.add_argument("--records-dir", type=Path, default=DEFAULT_RECORDS_DIR, help="运行记录保存目录")
    run_parser.add_argument("--log-file", type=Path, default=DEFAULT_LOG_FILE, help="日志文件路径")

    api_parser = subparsers.add_parser("api", help="启动本地 HTTP API 和 Web 界面")
    api_parser.add_argument("--host", default="127.0.0.1")
    api_parser.add_argument("--port", default=8765, type=int)
    api_parser.add_argument("--records-dir", type=Path, default=DEFAULT_RECORDS_DIR, help="运行记录保存目录")
    api_parser.add_argument("--providers-file", type=Path, default=DEFAULT_PROVIDERS_FILE, help="provider 配置文件路径")
    api_parser.add_argument("--mcp-servers-file", type=Path, default=DEFAULT_MCP_SERVERS_FILE, help="MCP Server 配置文件路径")
    api_parser.add_argument("--skills-file", type=Path, default=DEFAULT_SKILLS_FILE, help="Skill Source 配置文件路径")
    api_parser.add_argument("--agents-dir", type=Path, default=DEFAULT_AGENTS_DIR, help="包含角色 Agent 配置的目录")
    api_parser.add_argument("--log-file", type=Path, default=DEFAULT_LOG_FILE, help="日志文件路径")

    args = parser.parse_args(argv)
    if args.command == "api":
        serve(args.host, args.port, args.records_dir, args.providers_file, args.agents_dir, args.log_file, args.mcp_servers_file, args.skills_file)
        return 0
    if args.command == "run":
        log_path = configure_logging(args.log_file)
        LOG.info("CLI 运行开始 report=%s source=%s log=%s", args.sarif, args.source, log_path)
        agent_store = AgentDirectoryStore(args.agents_dir)
        skills_path = args.skills
        if skills_path is None and args.skill_source:
            source = SkillSourceStore(args.skills_file).get(args.skill_source)
            if source is None:
                raise ValueError(f"未知 Skill Source：{args.skill_source}")
            skills_path = Path(source.path)
        config = RunConfig(
            sarif_path=args.sarif,
            source_path=args.source,
            skills_path=skills_path,
            languages=_parse_languages(args.languages),
            max_rounds=args.max_rounds,
            auto_index_tools=args.auto_index_tools,
            enable_external_tools=not args.no_external_tools,
            enable_llm=args.llm,
            llm_model=args.llm_model,
            llm_endpoint=args.llm_endpoint,
            providers_file=args.providers_file,
            mcp_servers_file=args.mcp_servers_file,
            affirmative_provider_id=args.affirmative_provider,
            negative_provider_id=args.negative_provider,
            affirmative_agent=_agent_config(args.affirmative_agent_name, args.affirmative_agent_instructions)
            or agent_store.agent("affirmative", args.affirmative_agent_profile),
            negative_agent=_agent_config(args.negative_agent_name, args.negative_agent_instructions)
            or agent_store.agent("negative", args.negative_agent_profile),
        )
        report = run_judgement(config)
        if args.record:
            RunRecordStore(args.records_dir).save(report)
            LOG.info("CLI 运行已保存记录 run_id=%s records_dir=%s", report.run_id, args.records_dir)
        payload = json.dumps(to_jsonable(report), ensure_ascii=False, indent=2, sort_keys=True)
        if args.out:
            args.out.expanduser().resolve().write_text(payload + "\n", encoding="utf-8")
            LOG.info("CLI 运行已写入输出 run_id=%s out=%s", report.run_id, args.out)
            print(_summary(report))
        else:
            print(payload)
        LOG.info("CLI 运行完成 run_id=%s", report.run_id)
        return 0
    return 2


def _parse_languages(raw: str) -> List[str]:
    languages = [item.strip().lower() for item in raw.split(",") if item.strip()]
    return languages or ["java", "cpp", "python"]


def _agent_config(name: Optional[str], instructions: Optional[str]) -> Optional[AgentConfig]:
    name = (name or "").strip()
    instructions = (instructions or "").strip()
    if not name and not instructions:
        return None
    return AgentConfig(name=name, instructions=instructions)


def _summary(report) -> str:
    counts = {}
    for item in report.reports:
        counts[item.verdict.value] = counts.get(item.verdict.value, 0) + 1
    counts_text = ", ".join(f"{key}={value}" for key, value in sorted(counts.items())) or "无发现"
    return f"{report.run_id}: 已研判 {report.finding_count} 个发现（{counts_text}）"


if __name__ == "__main__":
    sys.exit(main())
