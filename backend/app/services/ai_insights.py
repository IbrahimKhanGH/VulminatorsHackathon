import json
import logging
import os
from pathlib import Path
from typing import Dict, List

from openai import AsyncOpenAI, OpenAIError

from ..config import get_settings

logger = logging.getLogger(__name__)

MAX_SNIPPET_CHARS = 1600


def _read_snippet(repo_dir: Path, relative_path: str) -> str:
    if not relative_path:
        return ""
    try:
        target = (repo_dir / relative_path).resolve()
        if not target.is_file():
            return ""
        text = target.read_text(encoding="utf-8", errors="ignore")
        return text[:MAX_SNIPPET_CHARS]
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Unable to read snippet for %s: %s", relative_path, exc)
        return ""


def _should_enrich(finding: Dict) -> bool:
    title = (finding.get("title") or "").lower()
    if title.startswith("upgraded") or title.startswith("refactor"):
        return False
    severity = (finding.get("severity") or "").lower()
    return severity not in {"info"}  # prioritize anything above info


async def _request_json(prompt: str, model: str) -> Dict[str, str]:
    client = AsyncOpenAI()
    try:
        response = await client.responses.create(
            model=model,
            input=prompt,
            response_format={"type": "json_object"},
        )
        content = response.output[0].content[0].text
    except AttributeError:
        response = await client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "You are Vulminator, an AI security engineer producing JSON.",
                },
                {"role": "user", "content": prompt},
            ],
        )
        content = response.choices[0].message.content or ""
    if not content:
        return {}
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        logger.debug("AI insight response was not valid JSON: %s", content)
        return {}


async def enrich_findings_with_ai(
    findings: List[dict], repo_dir: Path, max_findings: int = 3
) -> List[dict]:
    if not os.getenv("OPENAI_API_KEY"):
        return findings

    settings = get_settings()
    candidates = [
        (index, finding)
        for index, finding in enumerate(findings)
        if _should_enrich(finding)
    ][:max_findings]

    if not candidates:
        return findings

    for index, finding in candidates:
        snippet = ""
        file_path = finding.get("file_path")
        if file_path:
            snippet = _read_snippet(repo_dir, file_path)

        prompt = f"""
Return JSON with two keys: "risk_brief" (<=3 sentences describing real-world impact)
and "patch_suggestion" (<=5 sentences describing how to fix) for the following finding.
Finding title: {finding.get("title")}
Severity: {finding.get("severity")}
Summary: {finding.get("summary")}
File Path: {file_path or "N/A"}
Relevant code (may be empty):
```text
{snippet}
```
"""
        try:
            response_data = await _request_json(prompt.strip(), settings.openai_model)
        except OpenAIError as exc:
            logger.exception("AI insight generation failed: %s", exc)
            break
        if not response_data:
            continue
        finding["risk_brief"] = response_data.get("risk_brief")
        finding["patch_suggestion"] = response_data.get("patch_suggestion")

    return findings

