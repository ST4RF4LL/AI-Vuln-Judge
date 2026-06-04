# vuln-judger

`vuln-judger` 是一个 LLM 辅助的静态漏洞研判 MVP。它接收 SARIF 或
Markdown 静态分析报告、报告对应的源码目录，以及以 Agent skill 形式维护的项目知识库，
并输出面向分析人员的证据化漏洞研判结论。

当前实现优先支持 Java、C++、Python 的数据流和调用链证据。Atlas、CodeGraph 和
CodeQL 作为可插拔分析器：可用时补充更强证据，不可用时回退到本地报告/源码校验，并在报告
中明确记录诊断信息。

## 快速开始

```bash
uv run vuln-judger run \
  --report report.sarif \
  --source ./target-project \
  --skills ./skills \
  --out result.json
```

也支持 Markdown 报告：

```bash
uv run vuln-judger run \
  --report report.md \
  --source ./target-project \
  --skills ./skills
```

命令会输出 JSON 研判报告，包含每个发现的结论、置信度、证据链、正反方博弈回合、争议点、
源码位置和建议下一步。项目语言构成会在分析源码目录时自动检测；默认语言为中文；
机器接口字段名和枚举值保持稳定。

默认情况下，博弈过程是确定性的、证据约束的。配置 OpenAI 兼容 Provider 并使用 `--llm`
后，可以让模型生成正方/反方回合，最终结论仍由证据规则约束。

## 博弈流程

每个发现会按固定协议生成多轮中文 Markdown 博弈记录：

1. 正方提交完整证据报告：从 SARIF/Markdown 输入报告开始，引用源码位置、代码片段、
   Atlas 或本地 rg/grep 检索证据，说明调用链、数据流、攻击链、
   攻击前提、限制、防护消减和直接攻击影响。证据不足时必须明确降级。
2. 反方提交质疑报告：复核攻击链真实性、调用链/数据流断点、攻击前提是否过高、
   源码或知识库中的安全防护，以及攻击影响是否被非技术路径夸大。
3. 正方逐项澄清，反方继续复审；直到质疑闭环，或达到 `--max-rounds` 上限。
4. 双方各自输出唯一结论标签：`误报`、`真实漏洞`、`证据不足`。最终结论格式为
   `【结论标签】，正方结案陈述；反方结案陈述`。如果双方标签不一致，最终结论会标记为
   `存在分歧`，并将整体结论降级为 `INCONCLUSIVE`。

Atlas 证据优先检查 `.atlas/atlas.db`。缺少数据库时，报告会提示执行
`atlas index --analysis full`；启用 `--auto-index-tools` 时会自动 Atlas 构建索引。
检测到新版 Atlas 的 `mcp` 子命令后，平台会优先通过 `atlas mcp --project <源码目录>`
调用 `project/status`、`project/files`、`trace`、`search` 和 `calls` 工具，生成
`atlas-mcp` 来源的源码真实性、数据流和调用图证据。MCP 不可用时才回退到 CLI
`status/files` 诊断；旧版 `atlas trace` CLI 不再作为主路径。

## MCP 和 Skills 管理

MCP Server 配置默认存储在 `.vuln-judger/mcp.json`，示例文件为
`.vuln-judger/mcp.json.example`。默认 Atlas 配置如下：

```json
{
  "id": "atlas-default",
  "kind": "atlas",
  "transport": "stdio",
  "command": "atlas",
  "args": ["mcp", "--project", "{project}", "--log-format", "json"],
  "cwd": "{project}",
  "enabled": true
}
```

Skill Source 配置默认存储在 `.vuln-judger/skills.json`，示例文件为
`.vuln-judger/skills.json.example`。Skill Source 用于管理项目知识库目录；启动任务时可在
Web 端选择 Skill Source，或继续手动填写 `skills_path`。

Web 端右上角提供 `MCP / Skills` 配置入口，支持 MCP Server 保存、删除、默认 Atlas MCP
选择、连通性测试，以及 Skill Source 保存、删除、默认知识库选择和加载测试。

## vuln-judger MCP Server

`vuln-judger` 也可以作为 stdio MCP Server 暴露给 Codex、opencode 等 CLI 客户端。客户端
可以通过 MCP 工具触发漏洞研判、采集证据、解析报告位置、读取历史记录并导出 Markdown。

启动命令：

```bash
uv run vuln-judger mcp \
  --records-dir .vuln-judger/runs \
  --providers-file .vuln-judger/providers.json \
  --mcp-servers-file .vuln-judger/mcp.json \
  --skills-file .vuln-judger/skills.json \
  --agents-dir agents
```

可用工具：

- `judge_report`：对 SARIF/Markdown 报告和源码目录运行完整研判，可保存 run 记录。
- `collect_evidence`：只采集某个 finding 的源码、SARIF、Atlas、检索和影响证据，不运行博弈。
- `resolve_report_locations`：把报告路径映射到源码树中的真实文件并返回代码片段。
- `list_runs` / `get_run` / `get_finding`：读取历史研判记录。
- `export_run_markdown`：导出指定 run 的 Markdown 报告。

### Codex 配置

在项目级 `.codex/config.toml` 或全局 `~/.codex/config.toml` 中加入：

```toml
[mcp_servers.vuln-judger]
type = "stdio"
command = "uv"
args = [
  "--directory",
  "/path/to/vuln_judger",
  "run",
  "vuln-judger",
  "mcp",
  "--records-dir",
  "/path/to/vuln_judger/.vuln-judger/runs",
  "--providers-file",
  "/path/to/vuln_judger/.vuln-judger/providers.json",
  "--mcp-servers-file",
  "/path/to/vuln_judger/.vuln-judger/mcp.json",
  "--skills-file",
  "/path/to/vuln_judger/.vuln-judger/skills.json",
  "--agents-dir",
  "/path/to/vuln_judger/agents",
]
startup_timeout_sec = 120
```

如果 `uv` 不在 Codex 启动环境的 `PATH` 中，把 `command` 改为 `which uv` 输出的绝对路径。
改完后重启 Codex 会话，再让 Codex 使用 `vuln-judger` MCP 工具即可。

### opencode 配置

在项目级或全局 `opencode.jsonc` 中加入：

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "vuln-judger": {
      "type": "local",
      "command": [
        "uv",
        "--directory",
        "/path/to/vuln_judger",
        "run",
        "vuln-judger",
        "mcp",
        "--records-dir",
        "/path/to/vuln_judger/.vuln-judger/runs",
        "--providers-file",
        "/path/to/vuln_judger/.vuln-judger/providers.json",
        "--mcp-servers-file",
        "/path/to/vuln_judger/.vuln-judger/mcp.json",
        "--skills-file",
        "/path/to/vuln_judger/.vuln-judger/skills.json",
        "--agents-dir",
        "/path/to/vuln_judger/agents"
      ],
      "enabled": true,
      "timeout": 120000
    }
  }
}
```

opencode 的本地 MCP server 使用 `type: "local"`，并把启动命令及参数放在同一个
`command` 数组中。改完后重启 opencode，或执行 `opencode mcp list` 检查 server 状态。

以上示例中的 `/path/to/vuln_judger` 需要替换为本仓库绝对路径。若 MCP 客户端从本仓库
目录内启动，也可以把 `.vuln-judger/...`、`agents` 等参数改回相对路径。

## LLM 提供商

提供商配置默认存储在 `.vuln-judger/providers.json`。当前仅支持 OpenAI 兼容的
Chat Completions API。建议优先使用 `api_key_env`，避免将明文密钥写入磁盘；明文密钥
仅建议本地开发使用，并会在 API/Web 中被掩码。

示例配置：

```json
{
  "version": 1,
  "defaults": {
    "affirmative": "openai-main",
    "negative": "qwen-fast"
  },
  "providers": [
    {
      "id": "openai-main",
      "name": "OpenAI 主模型",
      "type": "openai-compatible",
      "endpoint": "https://api.openai.com/v1/chat/completions",
      "model": "gpt-4.1",
      "api_key_env": "OPENAI_API_KEY",
      "extra_json": {
        "temperature": 0.1,
        "max_tokens": 1200
      }
    }
  ]
}
```

使用默认提供商运行：

```bash
uv run vuln-judger run \
  --report report.sarif \
  --source ./target-project \
  --skills ./skills \
  --llm \
  --providers-file .vuln-judger/providers.json
```

显式指定正方/反方提供商：

```bash
uv run vuln-judger run \
  --report report.sarif \
  --source ./target-project \
  --skills ./skills \
  --llm \
  --affirmative-provider openai-main \
  --negative-provider qwen-fast
```

## Agent 配置

正方和反方 Agent 使用固定角色目录，每个配置档案都以 `AGENT.md` 保存提示词：

```text
agents/Affirmative/Affirmative_default/AGENT.md
agents/Negative/Negative_default/AGENT.md
```

Web 界面右上角的“Agent 配置”按钮可以管理这些配置档案。新任务可以分别选择一个正方
配置档案和一个反方配置档案。配置档案支持星标，非默认配置档案可以删除；内置默认配置档案
`Affirmative_default` 和 `Negative_default` 不能删除。

命令行运行时也可以指定 Agent 配置档案：

```bash
uv run vuln-judger run \
  --report report.md \
  --source ./target-project \
  --agents-dir agents \
  --affirmative-agent-profile Affirmative_default \
  --negative-agent-profile Negative_default
```

兼容旧路径：未选择提供商 ID 时，`--llm-model` / `--llm-endpoint` 仍可作为共享旧版
提供商使用。

## API 和 Web 界面

```bash
uv run vuln-judger api \
  --host 127.0.0.1 \
  --port 8765 \
  --records-dir .vuln-judger/runs \
  --providers-file .vuln-judger/providers.json \
  --agents-dir agents \
  --mcp-servers-file .vuln-judger/mcp.json \
  --skills-file .vuln-judger/skills.json \
  --log-file .vuln-judger/logs/vuln-judger.log
```

打开 http://127.0.0.1:8765 查看保存的研判记录。页面提供运行历史、结论统计、发现摘要、
证据链、博弈过程、防护分析、影响分析、LLM 提供商配置、正反方默认提供商选择、
提供商连通性测试、正反方 Agent 配置管理，以及 MCP / Skill Source 配置管理。

默认日志文件为 `.vuln-judger/logs/vuln-judger.log`，会记录 API 启动、任务创建、后台任务
执行、LLM 请求状态、Provider 连通性测试和异常 traceback。日志文件会自动轮转，且已被
`.gitignore` 忽略。

创建任务：

```bash
curl -X POST http://127.0.0.1:8765/runs \
  -H 'content-type: application/json' \
  -d '{
    "report_path": "report.md",
    "source_path": "./target-project",
    "skills_path": "./skills",
    "enable_llm": true,
    "affirmative_provider_id": "openai-main",
    "negative_provider_id": "qwen-fast",
    "affirmative_agent_profile": "Affirmative_default",
    "negative_agent_profile": "Negative_default"
  }'
```

查看接口：

```bash
curl http://127.0.0.1:8765/runs
curl http://127.0.0.1:8765/runs/<run_id>
curl http://127.0.0.1:8765/runs/<run_id>/findings
curl http://127.0.0.1:8765/runs/<run_id>/findings/<finding_id>
curl http://127.0.0.1:8765/providers
curl http://127.0.0.1:8765/providers/defaults
curl http://127.0.0.1:8765/agent-prompts
```

测试提供商连通性：

```bash
curl -X POST http://127.0.0.1:8765/providers/openai-main/test \
  -H 'content-type: application/json' \
  -d '{}'
```

CLI 运行也可以保存到同一个 Web 记录目录：

```bash
uv run vuln-judger run \
  --report report.sarif \
  --source ./target-project \
  --skills ./skills \
  --record \
  --records-dir .vuln-judger/runs
```

## 工具行为

- Java：优先使用 CodeQL 获取语义数据流；Atlas 和 CodeGraph 可补充符号/调用链上下文。
- C++：优先检测编译数据库。缺少 `compile_commands.json` 或可见构建数据库时，C++ 发现
  会标记为部分证据。
- Python：无需构建步骤即可进行源码索引，结合 SARIF 代码流、本地源码检查和可选分析器证据。

外部工具在 MVP 中是可选能力。最终报告会记录工具可用性和诊断信息，帮助分析人员区分强静态证据
和降级的本地校验结果。

## 开发

```bash
uv run python -m unittest discover -s tests -p 'test_*.py'
```
