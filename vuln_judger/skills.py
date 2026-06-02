from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable, List, Optional

from .models import ProjectContext, ProjectFact


SUPPORTED_SKILL_SUFFIXES = {".md", ".txt", ".json", ".yaml", ".yml"}


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
