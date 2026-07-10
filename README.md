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

Markdown 或 SARIF 报告经 Moderator 预处理后生成的单漏洞 Markdown 报告会保存在
`.vuln-judger/tmp/` 下，默认不会自动删除，便于复查模型整理后的输入。

命令会输出 JSON 研判报告，包含每个发现的结论、置信度、证据链、正反方与主持人博弈回合、争议点、
源码位置和建议下一步。项目语言构成会在分析源码目录时自动检测；默认语言为中文；
机器接口字段名和枚举值保持稳定。

默认情况下，博弈过程是确定性的、证据约束的。配置 OpenAI 兼容 Provider 并使用 `--llm`
后，可以让模型生成正方/反方回合，最终结论仍由证据规则约束。

## 博弈流程

每个发现会按固定协议生成多轮中文 Markdown 博弈记录：

1. 正方提交完整证据报告：从 SARIF/Markdown 输入报告开始，引用源码位置、代码片段、
   Atlas 或本地 rg/grep 检索证据，说明代码上下文业务逻辑、调用链、数据流、攻击链、
   攻击前提、限制、防护消减和直接攻击影响。证据不足时必须明确降级。
2. 反方提交质疑报告：自主围绕原始报告、源码位置、Atlas/rg/源码证据复核攻击链真实性、
   代码上下文业务逻辑、调用链/数据流断点、攻击前提是否过高、敏感信息类变量是否真实敏感、源码或知识库中的安全防护，
   以及攻击影响是否被非技术路径夸大。
3. 正方逐项澄清，反方继续自主复审；Moderator 独立审查双方是否围绕报告验证、是否复读、
   是否存在异常报告读取或关键证据缺口，直到质疑闭环，或达到 `--max-rounds` 上限。
4. `--max-rounds` 表示正反方可交锋的最大轮数；即使达到最后一轮，正反方仍继续补证和质证，
   不输出结案陈述。最终总结和唯一结论标签由 Moderator 生成，标签为 `误报`、`真实漏洞`、
   `证据不足`、`可达性存疑`。
   `可达性存疑` 表示局部源码或源汇路径看起来成立，但尚未证明外部或内部 REST/API/接口入口能调用到漏洞相关函数。

Atlas 证据基于 [Atlas](https://github.com/LordCasser/atlas) MCP。当前适配 Atlas
v1.5.0+ 的 Focus Runtime：即使源码目录尚未存在 `.atlas/atlas.db`，也会通过 MCP
按查询范围进行增量分析，不要求用户预先执行 `atlas index`。启用 LLM 时，平台不再由
预分析器写死 `trace/calls` 调用流程，而是在正方、反方和 Moderator 的回合中开放 Atlas
MCP 工具循环：Agent 自主决定是否请求 `project`、`search`、`symbol`、`trace`、
`calls`、`path`、`impact`、`file_dependencies` 或 `explore`，平台只负责执行这些
MCP 工具调用、把 observation 转换为 `agent-atlas-mcp:<role>` 来源的证据并回灌给同一
Agent 继续分析。默认不开放 `index` 工具；`project(action="open", project_path=...)`
只负责激活项目，Focus 由 Agent 围绕报告文件和符号主动调用 scoped `search(query, scope)`
触发，然后继续 `trace` / `calls` / `symbol` 等追溯。未启用 LLM
时，Atlas 预分析器仍可作为非 LLM 模式的兼容补证路径。AI 自主源码阅读会同时运行，输出
`agentic-source-reader` 来源的源码分析证据。MCP 不可用时也会保留该源码阅读路径。
每个正方/反方 Agent 回合默认最多执行 5 次 LLM 调度（含最终正文）和 20 次 Atlas MCP
工具调用，以便完成一次较完整的证据收集，同时避免无限循环。

相关运行参数：

- `--auto-index-tools`：可选预热 Atlas 持久缓存；不再是使用 Atlas MCP 的前置条件。

Web 端启动任务弹窗不再提供 Atlas 执行分支开关。MCP Server 的 `judge_report` 和
`one_round_judge` 在启用 LLM 时同样使用 Agent 自主 Atlas MCP 工具循环；
`collect_evidence` 作为纯证据收集工具仍返回预分析证据和源码阅读证据。

## MCP 和 Skills 管理

MCP Server 配置默认存储在 `.vuln-judger/mcp.json`，示例文件为
`.vuln-judger/mcp.json.example`。默认 Atlas 配置如下：

```json
{
  "id": "atlas-default",
  "kind": "atlas",
  "transport": "stdio",
  "command": "atlas",
  "args": ["mcp", "--log-format", "json"],
  "cwd": "{project}",
  "enabled": true
}
```

这是 Atlas v1.5.0+ 推荐的 no-project MCP 启动方式：MCP Server 以源码目录为 `cwd`
启动，vuln-judger 会在查询前调用 `project/open` 激活项目。需要持久化缓存或预热全量
项目时，再使用 `--auto-index-tools` 或单独运行 `atlas index --analysis full`。

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
  --records-dir /path/to/vuln_judger/.vuln-judger/runs \
  --providers-file /path/to/vuln_judger/.vuln-judger/providers.json \
  --mcp-servers-file /path/to/vuln_judger/.vuln-judger/mcp.json \
  --skills-file /path/to/vuln_judger/.vuln-judger/skills.json \
  --agents-dir /path/to/vuln_judger/agents
```

可用工具：

- `judge_report`：对 SARIF/Markdown 报告和源码目录启动完整研判。默认使用重构后的
  `codex` 三会话引擎并立即返回 `run_id`；使用 `get_run` 轮询运行状态。传
  `engine: "builtin"` 可继续使用旧的同步内置流程。
- `stop_run`：停止由当前 MCP Server 启动且仍在运行的异步 Codex 研判。
- `one_round_judge`：使用内置流程对单个 finding 进行单轮快速验证，默认保存 run 记录。
  默认 `response_mode: compact` 只返回关键结论、调用链/数据流概览、关键缺口和完整报告访问方式，
  以减少 CLI Agent 上下文占用；如不希望 Web 端显示该快速验证记录，可传 `save: false`。
- `collect_evidence`：只采集某个 finding 的源码、SARIF、Atlas、检索和影响证据，不运行博弈。
- `resolve_report_locations`：把报告路径映射到源码树中的真实文件并返回代码片段。
- `list_runs` / `get_run` / `get_finding`：读取历史研判记录。
- `export_run_markdown`：导出指定 run 的 Markdown 报告。

`one_round_judge` 的默认返回中会包含 `full_report_access`，指向 `get_run`、`get_finding`
和 `export_run_markdown` 的调用参数。Agent 需要更多证据、辩论过程或源码片段时，应按该字段
继续读取完整报告。调试时可传 `response_mode: standard` 返回证据摘要和诊断，或传
`response_mode: full` 返回完整 run/report 内容。

`judge_report` 的 Codex 引擎会启动 Moderator、Affirmative、Negative 三个 tmux/Codex
会话。任务进度持续写入 `--records-dir`，因此 Codex 引擎要求 `save: true`。通常不要设置
`wait_for_completion: true`，否则长任务可能触发 MCP 客户端工具超时。

### Codex 配置

在项目级 `.codex/config.toml` 或全局 `~/.codex/config.toml` 中加入：

```toml
[mcp_servers.vuln-judger]
type = "stdio"
command = "uv"
enabled = true
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

以上示例中的 `/path/to/vuln_judger` 需要替换为本仓库绝对路径。建议 MCP Server 和 Web/API
使用同一个绝对 `--records-dir`，否则 Codex/opencode 与 Web 进程的工作目录不同，会导致
`one_round_judge` 已保存但 Web 端看不到记录。

大型项目上 Atlas MCP 的 `trace` / `calls` 可能耗时较长。vuln-judger 默认等待单次 MCP
请求 120 秒；如仍发生超时，可在启动 Web/API 或 MCP Server 前设置：

```bash
export VULN_JUDGER_ATLAS_MCP_TIMEOUT=300
```

单个 Atlas MCP 工具调用超时会作为诊断证据写入报告，流程会继续尝试源码阅读和检索补证，
不会因为某一次 `trace` 或 `calls` 超时直接终止整个 finding。

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
    "negative": "qwen-fast",
    "moderator": "openai-main"
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

显式指定正方/反方/主持人提供商：

```bash
uv run vuln-judger run \
  --report report.sarif \
  --source ./target-project \
  --skills ./skills \
  --llm \
  --affirmative-provider openai-main \
  --negative-provider qwen-fast \
  --moderator-provider openai-main
```

## Agent 配置

正方、反方和主持人 Agent 使用固定角色目录，每个配置档案都以 `AGENT.md` 保存提示词：

```text
agents/Affirmative/Affirmative_default/AGENT.md
agents/Negative/Negative_default/AGENT.md
agents/Moderator/Moderator_default/AGENT.md
```

Web 界面右上角的“Agent 配置”按钮可以管理这些配置档案。新任务可以分别选择一个正方
配置档案、一个反方配置档案和一个主持人配置档案。配置档案支持星标，非默认配置档案可以删除；
内置默认配置档案 `Affirmative_default`、`Negative_default` 和 `Moderator_default` 不能删除。
Moderator 是中立角色，主要总结双方核心观点、证据闭环状态、主要分歧和最终研判；它的
AGENT.md 配置和 LLM provider 选择与正反方相互独立。

命令行运行时也可以指定 Agent 配置档案：

```bash
uv run vuln-judger run \
  --report report.md \
  --source ./target-project \
  --agents-dir agents \
  --affirmative-agent-profile Affirmative_default \
  --negative-agent-profile Negative_default \
  --moderator-agent-profile Moderator_default
```

兼容旧路径：未选择提供商 ID 时，`--llm-model` / `--llm-endpoint` 仍可作为共享旧版
提供商使用。

## API 和 Web 界面

快速启动默认 Web/API 服务：

```bash
uv run vuln-judger api
```

等效完整参数：

```bash
uv run vuln-judger api \
  --host 127.0.0.1 \
  --port 8765 \
  --records-dir .vuln-judger/runs \
  --providers-file .vuln-judger/providers.json \
  --agents-dir agents \
  --mcp-servers-file .vuln-judger/mcp.json \
  --skills-file .vuln-judger/skills.json \
  --log-file .vuln-judger/logs/vuln-judger.log \
  --log-retention-days 31
```

打开 http://127.0.0.1:8765 查看保存的研判记录。页面提供运行历史、结论统计、发现摘要、
证据链、博弈过程、防护分析、影响分析、LLM 提供商配置、正反方和主持人默认提供商选择、
提供商连通性测试、三方 Agent 配置管理，以及 MCP / Skill Source 配置管理。

Codex 三方复核引擎在 Moderator 拆分报告后，会立即把全部 finding 写入运行记录，并在
`.workspaces/runs/<run-id>/findings/<finding-id>/brief.json` 保存各自的输入材料。前端会将
尚未裁决的 finding 标记为“未完成”或“处理中”。暂停后恢复时，新 session 会保留已完成结果，
清理首个未完成 finding 的旧阶段输出，并从该 finding 重新开始。

启动 Codex 任务时可设置“静默提醒时间”，默认 60 分钟。等待下一阶段 JSON 输出期间，如果
目标 Codex session 仍有输出或处于执行状态，静默计时器会重新开始；如果上一阶段已经交付而
下一 Agent 持续静默，系统会发送简短的继续任务提醒。退出的 session 会重启并重新接收完整阶段
prompt。默认不再用一小时硬超时终止阶段；需要绝对步骤超时时可显式设置
`VULN_JUDGER_CODEX_STEP_TIMEOUT`（秒）。

默认日志按天写入 `.vuln-judger/logs/vuln-judger-YYYY-MM-DD.log`，会记录 API 启动、任务创建、
后台任务执行、LLM 请求状态、Provider 连通性测试和异常 traceback。日志使用 key=value 文本格式，
默认保留 31 天，且已被 `.gitignore` 忽略。

创建任务：

```bash
curl -X POST http://127.0.0.1:8765/runs \
  -H 'content-type: application/json' \
  -d '{
    "report_path": "report.md",
    "source_path": "./target-project",
    "skills_path": "./skills",
    "silence_reminder_minutes": 60,
    "enable_llm": true,
    "affirmative_provider_id": "openai-main",
    "negative_provider_id": "qwen-fast",
    "moderator_provider_id": "openai-main",
    "affirmative_agent_profile": "Affirmative_default",
    "negative_agent_profile": "Negative_default",
    "moderator_agent_profile": "Moderator_default"
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
  --records-dir /path/to/vuln_judger/.vuln-judger/runs
```

## 工具行为

- Java：优先使用 CodeQL 获取语义数据流；Atlas 和 CodeGraph 可补充符号/调用链上下文。
- C/C++：优先通过 Atlas 调用图/数据流追溯和源码阅读取证。
- Python：无需构建步骤即可进行源码索引，结合 SARIF 代码流、本地源码检查和可选分析器证据。

外部工具在 MVP 中是可选能力。最终报告会记录工具可用性和诊断信息，帮助分析人员区分强静态证据
和降级的本地校验结果。

## 开发

```bash
uv run python -m unittest discover -s tests -p 'test_*.py'
```
