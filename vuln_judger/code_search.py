from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence


@dataclass
class GrepMatch:
    file: str
    line: int
    column: int
    text: str


def _find_rg() -> Optional[str]:
    path = shutil.which("rg")
    if path is not None:
        return path
    return None


def _find_grep() -> str:
    return shutil.which("grep") or "grep"


def search_source(
    source_root: Path,
    pattern: str,
    *,
    file_globs: Optional[Sequence[str]] = None,
    context_lines: int = 3,
    max_matches: int = 30,
    timeout: int = 30,
) -> List[GrepMatch]:
    rg = _find_rg()
    if rg is not None:
        return _search_rg(rg, source_root, pattern, file_globs, context_lines, max_matches, timeout)
    grep = _find_grep()
    return _search_grep(grep, source_root, pattern, file_globs, context_lines, max_matches, timeout)


def _search_rg(
    rg: str,
    source_root: Path,
    pattern: str,
    file_globs: Optional[Sequence[str]],
    context_lines: int,
    max_matches: int,
    timeout: int,
) -> List[GrepMatch]:
    args: List[str] = [
        rg,
        "--no-heading",
        "--line-number",
        "--column",
        f"--max-count={max_matches}",
        "-C",
        str(context_lines),
    ]
    if file_globs:
        for glob in file_globs:
            args.extend(["-g", glob])
    args.append(pattern)
    args.append(str(source_root))
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=str(source_root),
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    return _parse_rg_output(result.stdout, max_matches)


def _search_grep(
    grep: str,
    source_root: Path,
    pattern: str,
    file_globs: Optional[Sequence[str]],
    context_lines: int,
    max_matches: int,
    timeout: int,
) -> List[GrepMatch]:
    args: List[str] = [
        grep,
        "-rn",
        "-C",
        str(context_lines),
        "--include=*",
        f"--max-count={max_matches}",
    ]
    if file_globs:
        include = "|".join(g.lstrip("*.") for g in file_globs if g.startswith("*."))
        if include:
            args = [a for a in args if a != "--include=*"]
            args.extend(["--include", f"*.{{{include}}}"])
    args.append(pattern)
    args.append(str(source_root))
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=str(source_root),
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    return _parse_grep_output(result.stdout, max_matches)


def _parse_rg_output(stdout: str, max_matches: int) -> List[GrepMatch]:
    matches: List[GrepMatch] = []
    for raw in stdout.splitlines():
        raw = raw.strip()
        if not raw or raw == "--":
            continue
        parts = raw.split(":", 2)
        if len(parts) < 3:
            continue
        try:
            line_num = int(parts[1])
        except ValueError:
            continue
        matches.append(
            GrepMatch(
                file=parts[0],
                line=line_num,
                column=0,
                text=parts[2].strip(),
            )
        )
        if len(matches) >= max_matches:
            break
    return matches


def _parse_grep_output(stdout: str, max_matches: int) -> List[GrepMatch]:
    matches: List[GrepMatch] = []
    for raw in stdout.splitlines():
        raw = raw.strip()
        if not raw or raw == "--":
            continue
        parts = raw.split(":", 2)
        if len(parts) < 3:
            continue
        try:
            line_num = int(parts[1])
        except ValueError:
            continue
        matches.append(
            GrepMatch(
                file=parts[0],
                line=line_num,
                column=0,
                text=parts[2].strip(),
            )
        )
        if len(matches) >= max_matches:
            break
    return matches


def grep_count(source_root: Path, pattern: str, timeout: int = 30) -> int:
    rg = _find_rg()
    if rg is not None:
        args = [rg, "--count", pattern, str(source_root)]
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
            total = 0
            for line in result.stdout.splitlines():
                parts = line.split(":", 1)
                if len(parts) == 2:
                    try:
                        total += int(parts[1])
                    except ValueError:
                        pass
            return total
        except (subprocess.TimeoutExpired, OSError):
            pass
    return 0


SEARCH_PATTERNS = {
    "source": r"\b(request|param|input|body|query|header|cookie|argv|stdin|getParameter|getHeader|recv|read\b(?![_a-z]))\b",
    "sink": r"\b(execute|exec|system|popen|eval|deserialize|loads|query|createStatement|open|send_file|redirect|write|printf|fprintf|sprintf|snprintf|memcpy|strcpy|strcat|scanf|gets)\b",
    "protection": r"\b(sanitize|sanitise|escape|validate|validator|allowlist|whitelist|checkpermission|haspermission|isauthorized|authorise|authorize|authz|csrf|rate_limit|ratelimit|permission|policy|guard|filter|check|verify)\b",
}
