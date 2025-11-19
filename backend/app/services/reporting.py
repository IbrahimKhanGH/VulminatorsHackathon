import os
import logging
from textwrap import dedent
from typing import List

from openai import AsyncOpenAI, OpenAIError

from ..config import get_settings
from ..schemas import FindingSummary

logger = logging.getLogger(__name__)


def _fallback_report(findings: List[FindingSummary]) -> str:
    lines = [
        "# Vulminator Security Report (fallback)",
        "",
        "OpenAI API key missing or summarization failed. Here is a direct listing of findings:",
        "",
    ]
    if findings:
        for finding in findings:
            lines.append(
                f"- **{finding.severity.upper()}** | {finding.title}"
                f"{f' ({finding.file_path})' if finding.file_path else ''}: "
                f"{finding.summary}"
            )
    else:
        lines.append("- No findings were recorded for this run.")
    return "\n".join(lines)


async def _call_openai(prompt: str, model: str) -> str:
    client = AsyncOpenAI()

    if hasattr(client, "responses"):
        response = await client.responses.create(
            model=model,
            input=prompt,
        )
        chunks = response.output[0].content
        text = "\n".join(part.text for part in chunks if hasattr(part, "text"))
        if text.strip():
            return text

    chat_method = getattr(client, "chat", None)
    if chat_method and hasattr(chat_method, "completions"):
        completion = await chat_method.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are Vulminator, an AI security engineer."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        message = completion.choices[0].message.content
        if message:
            return message

    raise OpenAIError("No compatible OpenAI response method available")


async def generate_markdown_report(findings: List[FindingSummary]) -> str:
    settings = get_settings()

    if not os.getenv("OPENAI_API_KEY"):
        return _fallback_report(findings)

    def _render_finding(finding: FindingSummary) -> str:
        details = f"- [{finding.severity.upper()}] {finding.title}: {finding.summary}"
        if finding.risk_brief:
            details += f"\n  Risk: {finding.risk_brief}"
        if finding.patch_suggestion:
            details += f"\n  Patch: {finding.patch_suggestion}"
        return details

    findings_payload = "\n".join(_render_finding(finding) for finding in findings) or (
        "No findings generated."
    )

    prompt = dedent(
        f"""
        You are Vulminator, an AI security engineer. Using the findings below,
        craft a Markdown report with sections for:
        1. TL;DR
        2. Risk Overview
        3. Recommended Remediations
        4. Finding Details (include file paths when present)

        Findings:
        {findings_payload}
        """
    ).strip()

    try:
        return await _call_openai(prompt, settings.openai_model)
    except OpenAIError as exc:
        logger.exception("OpenAI reporting failed: %s", exc)
        return _fallback_report(findings)
