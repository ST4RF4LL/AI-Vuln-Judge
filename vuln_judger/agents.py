from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import AgentConfig, to_jsonable


DEFAULT_AGENTS_DIR = Path("agents")
AGENT_FILE = "AGENT.md"

ROLE_DIRS = {
    "affirmative": "Affirmative",
    "negative": "Negative",
}
DEFAULT_PROFILE_IDS = {
    "affirmative": "Affirmative_1",
    "negative": "Negative_web",
}

DEFAULT_AFFIRMATIVE_AGENT = AgentConfig(
    name="Affirmative_1",
    instructions=(
        "Collect evidence that the report is grounded in real source code, "
        "validate reachability/data flow, assess missing protections, and state practical impact without exaggeration."
    ),
    role="Affirmative",
    profile_id="Affirmative_1",
    path=str(DEFAULT_AGENTS_DIR / "Affirmative" / "Affirmative_1" / AGENT_FILE),
)
DEFAULT_NEGATIVE_AGENT = AgentConfig(
    name="Negative_web",
    instructions=(
        "Challenge the vulnerability claim by checking hallucination risk, unreachable paths, mitigating controls, "
        "weak exploit preconditions, and overstated impact."
    ),
    role="Negative",
    profile_id="Negative_web",
    path=str(DEFAULT_AGENTS_DIR / "Negative" / "Negative_web" / AGENT_FILE),
)


class AgentDirectoryStore:
    def __init__(self, root: Path):
        self.root = root.expanduser().resolve()

    def summary(self) -> Dict[str, Any]:
        self.ensure_defaults()
        return {
            "root": str(self.root),
            "defaults": {
                "affirmative": DEFAULT_PROFILE_IDS["affirmative"],
                "negative": DEFAULT_PROFILE_IDS["negative"],
            },
            "roles": {
                "affirmative": [to_jsonable(profile) for profile in self.list_profiles("affirmative")],
                "negative": [to_jsonable(profile) for profile in self.list_profiles("negative")],
            },
        }

    def defaults(self) -> Dict[str, Dict[str, Any]]:
        self.ensure_defaults()
        return {
            "affirmative": to_jsonable(self.agent("affirmative", DEFAULT_PROFILE_IDS["affirmative"])),
            "negative": to_jsonable(self.agent("negative", DEFAULT_PROFILE_IDS["negative"])),
        }

    def list_profiles(self, role: str) -> List[AgentConfig]:
        role_key = _role_key(role)
        role_dir = self._role_dir(role_key)
        if not role_dir.exists():
            return []
        profiles = []
        for item in sorted(role_dir.iterdir(), key=lambda path: path.name.lower()):
            if not item.is_dir():
                continue
            agent_file = item / AGENT_FILE
            if not agent_file.exists():
                continue
            profiles.append(self._agent_from_file(role_key, item.name, agent_file))
        return profiles

    def agent(self, role: str, profile_id: Optional[str] = None) -> AgentConfig:
        self.ensure_defaults()
        role_key = _role_key(role)
        chosen_id = _profile_id(profile_id or DEFAULT_PROFILE_IDS[role_key])
        agent_file = self._role_dir(role_key) / chosen_id / AGENT_FILE
        if not agent_file.exists():
            raise ValueError(f"unknown {ROLE_DIRS[role_key]} agent profile: {chosen_id}")
        return self._agent_from_file(role_key, chosen_id, agent_file)

    def save_profile(self, role: str, profile_id: str, instructions: str) -> AgentConfig:
        role_key = _role_key(role)
        chosen_id = _profile_id(profile_id)
        text = str(instructions or "").strip()
        if not text:
            raise ValueError("AGENT.md prompt cannot be empty")
        agent_file = self._role_dir(role_key) / chosen_id / AGENT_FILE
        agent_file.parent.mkdir(parents=True, exist_ok=True)
        agent_file.write_text(text + "\n", encoding="utf-8")
        return self._agent_from_file(role_key, chosen_id, agent_file)

    def ensure_defaults(self) -> None:
        affirmative_file = self._role_dir("affirmative") / DEFAULT_PROFILE_IDS["affirmative"] / AGENT_FILE
        if not affirmative_file.exists():
            affirmative_file.parent.mkdir(parents=True, exist_ok=True)
            affirmative_file.write_text(DEFAULT_AFFIRMATIVE_AGENT.instructions + "\n", encoding="utf-8")
        negative_file = self._role_dir("negative") / DEFAULT_PROFILE_IDS["negative"] / AGENT_FILE
        if not negative_file.exists():
            negative_file.parent.mkdir(parents=True, exist_ok=True)
            negative_file.write_text(DEFAULT_NEGATIVE_AGENT.instructions + "\n", encoding="utf-8")

    def _role_dir(self, role_key: str) -> Path:
        return self.root / ROLE_DIRS[role_key]

    def _agent_from_file(self, role_key: str, profile_id: str, path: Path) -> AgentConfig:
        return AgentConfig(
            name=profile_id,
            instructions=path.read_text(encoding="utf-8", errors="replace").strip(),
            role=ROLE_DIRS[role_key],
            profile_id=profile_id,
            path=str(path.relative_to(Path.cwd())) if _is_under(path, Path.cwd()) else str(path),
        )


def _role_key(role: str) -> str:
    normalized = str(role or "").strip().lower()
    if normalized in {"affirmative", "positive", "pro", "正方"}:
        return "affirmative"
    if normalized in {"negative", "con", "反方"}:
        return "negative"
    raise ValueError("role must be affirmative or negative")


def _profile_id(value: str) -> str:
    profile_id = str(value or "").strip()
    if not profile_id:
        raise ValueError("agent profile id is required")
    if not re.match(r"^[A-Za-z0-9_.-]+$", profile_id):
        raise ValueError("agent profile id may only contain letters, numbers, dot, underscore, and hyphen")
    return profile_id


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False
