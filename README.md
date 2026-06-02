# vuln-judger

`vuln-judger` is an MVP for LLM-assisted static vulnerability adjudication.
It ingests a SARIF or Markdown static-analysis report, the matching source
tree, and project knowledge written as Agent skills, then produces an
analyst-facing verdict with cited evidence.

The first implementation prioritizes Java, C++, and Python data-flow/call-chain
evidence. Atlas, CodeGraph, and CodeQL are treated as pluggable analyzers:
when available they can add stronger evidence, and when unavailable the run
falls back to local report/source validation with explicit diagnostics.

## Quick Start

```bash
uv run vuln-judger run \
  --report report.sarif \
  --source ./target-project \
  --skills ./skills \
  --languages java,cpp,python \
  --out result.json
```

Markdown reports are also accepted:

```bash
uv run vuln-judger run \
  --report report.md \
  --source ./target-project \
  --skills ./skills
```

The command writes a JSON report containing per-finding verdicts, confidence,
evidence chains, debate turns, disputed points, source locations, and next steps.

By default the debate is deterministic and evidence-bound. To let
OpenAI-compatible models draft the正方/反方 debate turns while keeping the final
verdict rule-bound, configure providers and run with `--llm`.

Provider configuration is stored in `.vuln-judger/providers.json` by default.
Only OpenAI-compatible Chat Completions APIs are supported. Prefer
`api_key_env` to avoid writing plaintext keys to disk; plaintext keys are
supported for local-only development and are masked by the API/UI.

Agent prompts are maintained as role-specific profile directories. Each profile
stores its prompt in `AGENT.md`, for example:

```text
agents/Affirmative/Affirmative_1/AGENT.md
agents/Negative/Negative_web/AGENT.md
```

The web UI exposes these profiles through the top-right `Agent Prompts` button.
New runs choose one affirmative profile and one negative profile. Profiles can
be starred in the UI, and non-default profiles can be deleted. The built-in
default profiles `Affirmative_1` and `Negative_web` cannot be deleted.

Example provider file:

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
      "name": "OpenAI Main",
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

Run with default providers:

```bash
uv run vuln-judger run \
  --report report.sarif \
  --source ./target-project \
  --skills ./skills \
  --llm \
  --providers-file .vuln-judger/providers.json
```

Run with explicit正方/反方 providers:

```bash
uv run vuln-judger run \
  --report report.sarif \
  --source ./target-project \
  --skills ./skills \
  --llm \
  --affirmative-provider openai-main \
  --negative-provider qwen-fast
```

正方/反方 Agent profiles can be selected per run. The selected `AGENT.md`
content is recorded with the run and injected into LLM debate prompts:

```bash
uv run vuln-judger run \
  --report report.md \
  --source ./target-project \
  --agents-dir agents \
  --affirmative-agent-profile Affirmative_1 \
  --negative-agent-profile Negative_web
```

The older `--llm-model` / `--llm-endpoint` path still works as a shared legacy
provider when no provider IDs are selected.

## API

```bash
uv run vuln-judger api \
  --host 127.0.0.1 \
  --port 8765 \
  --records-dir .vuln-judger/runs \
  --providers-file .vuln-judger/providers.json \
  --agents-dir agents
```

Open http://127.0.0.1:8765 to view saved judgement records. The page shows
run history, verdict counts, finding summaries, evidence, debate turns,
protection analysis, impact analysis, LLM provider settings, default
正方/反方 provider selection, provider connectivity testing, and default
正方/反方 Agent prompt configuration.

Create a run:

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
    "affirmative_agent_profile": "Affirmative_1",
    "negative_agent_profile": "Negative_web"
  }'
```

Then inspect:

```bash
curl http://127.0.0.1:8765/runs
curl http://127.0.0.1:8765/runs/<run_id>
curl http://127.0.0.1:8765/runs/<run_id>/findings
curl http://127.0.0.1:8765/runs/<run_id>/findings/<finding_id>
curl http://127.0.0.1:8765/providers
curl http://127.0.0.1:8765/providers/defaults
curl http://127.0.0.1:8765/agent-prompts
```

Test provider connectivity:

```bash
curl -X POST http://127.0.0.1:8765/providers/openai-main/test \
  -H 'content-type: application/json' \
  -d '{}'
```

CLI runs can also be saved into the same records directory:

```bash
uv run vuln-judger run \
  --report report.sarif \
  --source ./target-project \
  --skills ./skills \
  --record \
  --records-dir .vuln-judger/runs
```

## Tool Behavior

- Java: CodeQL is preferred for semantic data-flow when installed; Atlas and
  CodeGraph can add symbol/call-chain context.
- C++: compile database detection is first-class. Without `compile_commands.json`
  or a visible build database, C++ findings are marked as partial evidence.
- Python: source indexing works without a build step and uses SARIF code flows,
  local source inspection, and optional analyzer evidence.

External tools are optional in the MVP. Their availability and diagnostics are
included in the final report so analysts can distinguish strong static evidence
from degraded local checks.

## Development

```bash
uv run python -m unittest discover -s tests -p 'test_*.py'
```
