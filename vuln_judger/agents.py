from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import AgentConfig, to_jsonable


DEFAULT_AGENTS_DIR = Path("agents")
AGENT_FILE = "AGENT.md"
AGENT_META_FILE = "AGENT.json"

ROLE_DIRS = {
    "affirmative": "Affirmative",
    "negative": "Negative",
    "moderator": "Moderator",
}
DEFAULT_PROFILE_IDS = {
    "affirmative": "Affirmative_default",
    "negative": "Negative_default",
    "moderator": "Moderator_default",
}

DEFAULT_AFFIRMATIVE_AGENT = AgentConfig(
    name="Affirmative_default",
    instructions=(
        "围绕报告收集证据，证明报告对应真实源码位置和真实代码片段，验证能否由外部接口或内部接口调用触发，"
        "给出准确调用链、数据流和最终影响。rg/grep、Atlas 和源码阅读都必须围绕报告位置、报告符号、codeFlow 或调用邻域。"
        "调用链追溯必须优先使用 Atlas search/trace/calls 从报告位置、危险汇点或中间函数向上游追到外部输入源头"
        "（用户输入、文件输入、网络报文输入、命令行参数、标准输入、请求参数或消息队列载荷等）。"
        "当 Atlas 无法继续追溯、trace partial/empty/No data node、calls 缺边或 search 未命中时，不得直接承认证据不足或误报；"
        "应合理怀疑 Atlas 漏掉或未正确解析调用关系，转用源码阅读和 grep/ripgrep 围绕报告路径、符号、调用邻域、入口函数、源点词和汇点词补证。"
        "一旦源码阅读或 grep/ripgrep 拼出当前调用链、上游调用者或数据流节点，必须转回 Atlas 对新发现上游符号继续追溯。"
        "只有 Atlas、源码阅读、grep/ripgrep 和交叉验证均无法证明从外部输入源头到危险汇点的可达路径时，才可怀疑误报、不可利用或证据不足。"
        "防护消减只在源码或 Skill/项目上下文存在明确证据时分析；没有证据就不引入防护消减假设。证据不足时，"
        "必须优先寻找新证据：重新阅读源码上下文、检查 Atlas project/status 和 project/files、"
        "用 search/trace/calls 补齐调用链与数据流，再说明仍未闭环的限制。"
    ),
    role="Affirmative",
    profile_id="Affirmative_default",
    path=str(DEFAULT_AGENTS_DIR / "Affirmative" / "Affirmative_default" / AGENT_FILE),
    deletable=False,
    is_default=True,
)
DEFAULT_NEGATIVE_AGENT = AgentConfig(
    name="Negative_default",
    instructions=(
        "客观复核正方漏洞主张，重点检查报告源码真实性、外部/内部入口可达性、调用链、数据流和影响是否准确。"
        "验证 Atlas、rg/grep 和源码证据是否围绕报告本身，识别无关候选汇点、证据跳跃、遗漏调用前提或影响夸大。"
        "防护消减只能基于源码或 Skill/项目上下文中的明确防护证据提出。"
    ),
    role="Negative",
    profile_id="Negative_default",
    path=str(DEFAULT_AGENTS_DIR / "Negative" / "Negative_default" / AGENT_FILE),
    deletable=False,
    is_default=True,
)
DEFAULT_MODERATOR_AGENT = AgentConfig(
    name="Moderator_default",
    instructions=(
        "作为中立主持人，总结正方和反方的核心观点、证据闭环状态、仍存在的分歧和最终结论。"
        "不得新增双方没有提出或证据链没有支持的新事实；必须客观区分已证实证据、候选证据和未闭环缺口。"
        "输出应简洁、可审计，重点帮助用户快速理解双方争议点和下一步验证方向。"
    ),
    role="Moderator",
    profile_id="Moderator_default",
    path=str(DEFAULT_AGENTS_DIR / "Moderator" / "Moderator_default" / AGENT_FILE),
    deletable=False,
    is_default=True,
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
                "moderator": DEFAULT_PROFILE_IDS["moderator"],
            },
            "roles": {
                "affirmative": [to_jsonable(profile) for profile in self.list_profiles("affirmative")],
                "negative": [to_jsonable(profile) for profile in self.list_profiles("negative")],
                "moderator": [to_jsonable(profile) for profile in self.list_profiles("moderator")],
            },
        }

    def defaults(self) -> Dict[str, Dict[str, Any]]:
        self.ensure_defaults()
        return {
            "affirmative": to_jsonable(self.agent("affirmative", DEFAULT_PROFILE_IDS["affirmative"])),
            "negative": to_jsonable(self.agent("negative", DEFAULT_PROFILE_IDS["negative"])),
            "moderator": to_jsonable(self.agent("moderator", DEFAULT_PROFILE_IDS["moderator"])),
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
        profiles.sort(key=lambda profile: (not profile.starred, not profile.is_default, (profile.profile_id or "").lower()))
        return profiles

    def agent(self, role: str, profile_id: Optional[str] = None) -> AgentConfig:
        self.ensure_defaults()
        role_key = _role_key(role)
        chosen_id = _profile_id(profile_id or DEFAULT_PROFILE_IDS[role_key])
        agent_file = self._role_dir(role_key) / chosen_id / AGENT_FILE
        if not agent_file.exists():
            raise ValueError(f"未知 {ROLE_DIRS[role_key]} Agent 配置：{chosen_id}")
        return self._agent_from_file(role_key, chosen_id, agent_file)

    def save_profile(self, role: str, profile_id: str, instructions: str) -> AgentConfig:
        role_key = _role_key(role)
        chosen_id = _profile_id(profile_id)
        text = str(instructions or "").strip()
        if not text:
            raise ValueError("AGENT.md 提示词不能为空")
        agent_file = self._role_dir(role_key) / chosen_id / AGENT_FILE
        agent_file.parent.mkdir(parents=True, exist_ok=True)
        agent_file.write_text(text + "\n", encoding="utf-8")
        return self._agent_from_file(role_key, chosen_id, agent_file)

    def set_starred(self, role: str, profile_id: str, starred: bool) -> AgentConfig:
        role_key = _role_key(role)
        chosen_id = _profile_id(profile_id)
        agent_file = self._role_dir(role_key) / chosen_id / AGENT_FILE
        if not agent_file.exists():
            raise ValueError(f"未知 {ROLE_DIRS[role_key]} Agent 配置：{chosen_id}")
        metadata = self._metadata(agent_file.parent)
        metadata["starred"] = bool(starred)
        self._write_metadata(agent_file.parent, metadata)
        return self._agent_from_file(role_key, chosen_id, agent_file)

    def delete_profile(self, role: str, profile_id: str) -> Dict[str, Any]:
        role_key = _role_key(role)
        chosen_id = _profile_id(profile_id)
        if chosen_id == DEFAULT_PROFILE_IDS[role_key]:
            raise ValueError(f"默认 {ROLE_DIRS[role_key]} Agent 配置不能删除")
        profile_dir = self._role_dir(role_key) / chosen_id
        agent_file = profile_dir / AGENT_FILE
        if not agent_file.exists():
            raise ValueError(f"未知 {ROLE_DIRS[role_key]} Agent 配置：{chosen_id}")
        shutil.rmtree(profile_dir)
        return self.summary()

    def ensure_defaults(self) -> None:
        affirmative_file = self._role_dir("affirmative") / DEFAULT_PROFILE_IDS["affirmative"] / AGENT_FILE
        if not affirmative_file.exists():
            affirmative_file.parent.mkdir(parents=True, exist_ok=True)
            affirmative_file.write_text(DEFAULT_AFFIRMATIVE_AGENT.instructions + "\n", encoding="utf-8")
        negative_file = self._role_dir("negative") / DEFAULT_PROFILE_IDS["negative"] / AGENT_FILE
        if not negative_file.exists():
            negative_file.parent.mkdir(parents=True, exist_ok=True)
            negative_file.write_text(DEFAULT_NEGATIVE_AGENT.instructions + "\n", encoding="utf-8")
        moderator_file = self._role_dir("moderator") / DEFAULT_PROFILE_IDS["moderator"] / AGENT_FILE
        if not moderator_file.exists():
            moderator_file.parent.mkdir(parents=True, exist_ok=True)
            moderator_file.write_text(DEFAULT_MODERATOR_AGENT.instructions + "\n", encoding="utf-8")

    def _role_dir(self, role_key: str) -> Path:
        return self.root / ROLE_DIRS[role_key]

    def _agent_from_file(self, role_key: str, profile_id: str, path: Path) -> AgentConfig:
        metadata = self._metadata(path.parent)
        is_default = profile_id == DEFAULT_PROFILE_IDS[role_key]
        return AgentConfig(
            name=profile_id,
            instructions=path.read_text(encoding="utf-8", errors="replace").strip(),
            role=ROLE_DIRS[role_key],
            profile_id=profile_id,
            path=str(path.relative_to(Path.cwd())) if _is_under(path, Path.cwd()) else str(path),
            starred=bool(metadata.get("starred")),
            deletable=not is_default,
            is_default=is_default,
        )

    def _metadata(self, profile_dir: Path) -> Dict[str, Any]:
        path = profile_dir / AGENT_META_FILE
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def _write_metadata(self, profile_dir: Path, metadata: Dict[str, Any]) -> None:
        path = profile_dir / AGENT_META_FILE
        path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _role_key(role: str) -> str:
    normalized = str(role or "").strip().lower()
    if normalized in {"affirmative", "positive", "pro", "正方"}:
        return "affirmative"
    if normalized in {"negative", "con", "反方"}:
        return "negative"
    if normalized in {"moderator", "host", "neutral", "中立", "中立方", "主持人"}:
        return "moderator"
    raise ValueError("role 必须是 affirmative/negative/moderator 或正方/反方/主持人")


def _profile_id(value: str) -> str:
    profile_id = str(value or "").strip()
    if not profile_id:
        raise ValueError("Agent 配置 ID 不能为空")
    if not re.match(r"^[A-Za-z0-9_.-]+$", profile_id):
        raise ValueError("Agent 配置 ID 只能包含字母、数字、点、下划线和连字符")
    return profile_id


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False
