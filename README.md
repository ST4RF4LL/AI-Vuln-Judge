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
  --languages java,cpp,python \
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
源码位置和建议下一步。默认语言为中文；机器接口字段名和枚举值保持稳定。

默认情况下，博弈过程是确定性的、证据约束的。配置 OpenAI 兼容 Provider 并使用 `--llm`
后，可以让模型生成正方/反方回合，最终结论仍由证据规则约束。

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
  --log-file .vuln-judger/logs/vuln-judger.log
```

打开 http://127.0.0.1:8765 查看保存的研判记录。页面提供运行历史、结论统计、发现摘要、
证据链、博弈过程、防护分析、影响分析、LLM 提供商配置、正反方默认提供商选择、
提供商连通性测试，以及正反方 Agent 配置管理。

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
