from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .models import ProjectContext, ProjectFact


SUPPORTED_SKILL_SUFFIXES = {".md", ".txt", ".json", ".yaml", ".yml"}
DEFAULT_SKILLS_FILE = Path(".vuln-judger") / "skills.json"


@dataclass
class SkillSourceConfig:
    id: str
    name: str
    path: str
    description: str = ""
    enabled: bool = True
    starred: bool = False

    def public_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "path": self.path,
            "description": self.description,
            "enabled": self.enabled,
            "starred": self.starred,
        }


class SkillSourceStore:
    def __init__(self, path: Path):
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def list(self) -> List[Dict[str, Any]]:
        sources = [source.public_dict() for source in self._sources().values()]
        sources.sort(key=lambda item: (not item.get("starred"), item.get("name", "").lower()))
        return sources

    def get(self, source_id: str) -> Optional[SkillSourceConfig]:
        return self._sources().get(source_id)

    def upsert(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        data = self._load()
        sources = data.setdefault("sources", [])
        source = source_from_payload(payload, existing=self.get(str(payload.get("id") or "")))
        replaced = False
        for index, item in enumerate(sources):
            if item.get("id") == source.id:
                sources[index] = source.public_dict()
                replaced = True
                break
        if not replaced:
            sources.append(source.public_dict())
        defaults = data.setdefault("defaults", {})
        if not defaults.get("project"):
            defaults["project"] = source.id
        self._save(data)
        return source.public_dict()

    def delete(self, source_id: str) -> bool:
        data = self._load()
        sources = data.setdefault("sources", [])
        kept = [item for item in sources if item.get("id") != source_id]
        removed = len(kept) != len(sources)
        data["sources"] = kept
        defaults = data.setdefault("defaults", {})
        if defaults.get("project") == source_id:
            defaults["project"] = None
        if removed:
            self._save(data)
        return removed

    def defaults(self) -> Dict[str, Optional[str]]:
        defaults = self._load().get("defaults") or {}
        return {"project": defaults.get("project")}

    def set_defaults(self, project: Optional[str]) -> Dict[str, Optional[str]]:
        sources = self._sources()
        if project and project not in sources:
            raise ValueError(f"未知 Skill Source：{project}")
        data = self._load()
        data["defaults"] = {"project": project}
        self._save(data)
        return self.defaults()

    def default(self) -> Optional[SkillSourceConfig]:
        source_id = self.defaults().get("project")
        sources = self._sources()
        if source_id and source_id in sources:
            source = sources[source_id]
            return source if source.enabled else None
        for source in sources.values():
            if source.enabled:
                return source
        return None

    def test(self, source_id: str) -> Dict[str, Any]:
        source = self.get(source_id)
        if source is None:
            raise ValueError("Skill Source 未找到")
        context = load_project_context(Path(source.path))
        root = Path(source.path).expanduser().resolve()
        return {
            "ok": root.exists(),
            "source_id": source.id,
            "root": str(root),
            "exists": root.exists(),
            "is_dir": root.is_dir(),
            "fact_count": len(context.facts),
            "facts": [
                {"fact_id": fact.fact_id, "title": fact.title, "source": fact.source, "tags": fact.tags}
                for fact in context.facts[:20]
            ],
        }

    def _sources(self) -> Dict[str, SkillSourceConfig]:
        result = {}
        for item in self._load().get("sources", []):
            source = source_from_payload(item)
            result[source.id] = source
        return result

    def _load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "defaults": {"project": None}, "sources": []}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        data.setdefault("version", 1)
        data.setdefault("defaults", {"project": None})
        data.setdefault("sources", [])
        return data

    def _save(self, data: Dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def source_from_payload(payload: Dict[str, Any], existing: Optional[SkillSourceConfig] = None) -> SkillSourceConfig:
    source_id = str(payload.get("id") or "").strip()
    if not source_id:
        raise ValueError("Skill Source ID 不能为空")
    if not re.match(r"^[A-Za-z0-9_.-]+$", source_id):
        raise ValueError("Skill Source ID 只能包含字母、数字、点、下划线和连字符")
    path = str(payload.get("path") or (existing.path if existing else "")).strip()
    if not path:
        raise ValueError("Skill Source 路径不能为空")
    return SkillSourceConfig(
        id=source_id,
        name=str(payload.get("name") or source_id).strip(),
        path=path,
        description=str(payload.get("description") or "").strip(),
        enabled=bool(payload.get("enabled", existing.enabled if existing else True)),
        starred=bool(payload.get("starred", existing.starred if existing else False)),
    )


def load_project_context(skills_path: Optional[Path]) -> ProjectContext:
    if skills_path is None:
        return ProjectContext(root=None, facts=[])
    root = skills_path.expanduser().resolve()
    if not root.exists():
        return ProjectContext(root=str(root), facts=[])
    if root.is_file():
        files = [root]
    else:
        files = sorted(
            file
            for file in root.rglob("*")
            if file.is_file() and file.suffix.lower() in SUPPORTED_SKILL_SUFFIXES
        )
    facts = [_fact_from_file(file, root) for file in files]
    return ProjectContext(root=str(root), facts=facts)


def _fact_from_file(file: Path, root: Path) -> ProjectFact:
    content = _read_file(file)
    title = _title_from_content(content) or file.stem
    tags = _tags_from_path(file, root)
    return ProjectFact(
        fact_id=_fact_id(file, content),
        source=str(file),
        title=title,
        content=content,
        tags=tags,
    )


def _read_file(file: Path) -> str:
    raw = file.read_text(encoding="utf-8", errors="replace")
    if file.suffix.lower() == ".json":
        try:
            parsed = json.loads(raw)
            return json.dumps(parsed, ensure_ascii=False, indent=2, sort_keys=True)
        except json.JSONDecodeError:
            return raw
    return raw


def _title_from_content(content: str) -> str:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip()
        if stripped:
            return stripped[:80]
    return ""


def _tags_from_path(file: Path, root: Path) -> List[str]:
    try:
        rel = file.relative_to(root)
    except ValueError:
        rel = file.name
    parts: Iterable[str]
    if isinstance(rel, Path):
        parts = rel.with_suffix("").parts
    else:
        parts = [str(rel)]
    tags = []
    for part in parts:
        for token in part.replace("-", "_").split("_"):
            normalized = token.strip().lower()
            if normalized and normalized not in tags:
                tags.append(normalized)
    return tags


def _fact_id(file: Path, content: str) -> str:
    digest = hashlib.sha256(f"{file}\n{content}".encode("utf-8")).hexdigest()
    return f"fact-{digest[:12]}"
