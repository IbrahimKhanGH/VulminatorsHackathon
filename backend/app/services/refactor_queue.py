"""Builds a queue of files to refactor using LLM assistance."""

from dataclasses import dataclass
from pathlib import Path
from typing import List, Set

SEVERITIES_FOR_REFACTOR = {"critical", "high", "moderate"}
SKIP_FILENAMES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
}
MAX_TASKS = 8


@dataclass
class RefactorTask:
    file_path: Path
    severity: str
    summary: str
    snippet: str


def _extract_snippet(path: Path, max_chars: int = 1500) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""
    return text[:max_chars]


def build_refactor_queue(repo_dir: Path, findings: List[dict], max_tasks: int = MAX_TASKS) -> List[RefactorTask]:
    tasks: List[RefactorTask] = []
    seen: Set[Path] = set()

    for finding in findings:
        file_rel = finding.get("file_path")
        severity = str(finding.get("severity", "")).lower()
        if not file_rel or severity not in SEVERITIES_FOR_REFACTOR:
            continue

        candidate_path = (repo_dir / file_rel).resolve()
        if (
            not candidate_path.exists()
            or candidate_path in seen
            or candidate_path.name in SKIP_FILENAMES
        ):
            continue

        snippet = _extract_snippet(candidate_path)
        if not snippet.strip():
            continue

        tasks.append(
            RefactorTask(
                file_path=candidate_path.relative_to(repo_dir),
                severity=severity,
                summary=str(finding.get("summary", "")),
                snippet=snippet,
            )
        )
        seen.add(candidate_path)

        if len(tasks) >= max_tasks:
            break

    return tasks
