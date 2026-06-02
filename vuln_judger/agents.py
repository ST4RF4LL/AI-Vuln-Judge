from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Optional

from .models import AgentConfig


DEFAULT_AGENT_PROMPTS_FILE = Path(".vuln-judger") / "agent_prompts.json"

DEFAULT_AFFIRMATIVE_AGENT = AgentConfig(
    name="Affirmative Agent",
    instructions=(
        "Collect evidence that the report is grounded in real source code, "
        "validate reachability/data flow, assess missing protections, and state practical impact without exaggeration."
    ),
)
DEFAULT_NEGATIVE_AGENT = AgentConfig(
    name="Negative Agent",
    instructions=(
        "Challenge the vulnerability claim by checking hallucination risk, unreachable paths, mitigating controls, "
        "weak exploit preconditions, and overstated impact."
    ),
)


class AgentPromptStore:
    def __init__(self, path: Path):
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def get(self) -> Dict[str, Dict[str, str]]:
        data = self._load()
        return {
            "affirmative": asdict(_agent_from_payload(data.get("affirmative"), DEFAULT_AFFIRMATIVE_AGENT)),
            "negative": asdict(_agent_from_payload(data.get("negative"), DEFAULT_NEGATIVE_AGENT)),
        }

    def defaults(self) -> Dict[str, Dict[str, str]]:
        return {
            "affirmative": asdict(DEFAULT_AFFIRMATIVE_AGENT),
            "negative": asdict(DEFAULT_NEGATIVE_AGENT),
        }

    def save(self, payload: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
        data = {
            "version": 1,
            "affirmative": asdict(_agent_from_payload(payload.get("affirmative"), DEFAULT_AFFIRMATIVE_AGENT)),
            "negative": asdict(_agent_from_payload(payload.get("negative"), DEFAULT_NEGATIVE_AGENT)),
        }
        self._save(data)
        return self.get()

    def reset(self) -> Dict[str, Dict[str, str]]:
        if self.path.exists():
            self.path.unlink()
        return self.get()

    def agent(self, role: str) -> AgentConfig:
        data = self.get()
        default = DEFAULT_AFFIRMATIVE_AGENT if role == "affirmative" else DEFAULT_NEGATIVE_AGENT
        return _agent_from_payload(data.get(role), default)

    def _load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, **self.defaults()}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        data.setdefault("version", 1)
        return data

    def _save(self, data: Dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            self.path.chmod(0o600)
        except OSError:
            pass


def _agent_from_payload(payload: Optional[Any], default: AgentConfig) -> AgentConfig:
    if not isinstance(payload, dict):
        return default
    name = str(payload.get("name") or "").strip() or default.name
    instructions = str(payload.get("instructions") or "").strip() or default.instructions
    return AgentConfig(name=name, instructions=instructions)
