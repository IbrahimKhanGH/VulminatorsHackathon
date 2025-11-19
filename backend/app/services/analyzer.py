import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .. import schemas
from ..config import get_settings
from .dependency_scan import DependencyScannerError, run_dependency_audits
from .dependency_upgrader import DependencyUpgradeError, apply_dependency_upgrades
from .pr_publisher import publish_report_pr
from .refactor_queue import build_refactor_queue
from .refactor_worker import RefactorResult, apply_refactor_tasks
from .repo_workspace import RepoWorkspace
from .reporting import generate_markdown_report
from .scanners import ScannerError, run_semgrep_scan

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    findings: List[dict]
    pr_url: Optional[str]
    message: str


async def run_analysis_pipeline(
    run_id: str,
    request: schemas.AnalyzeRequest,
) -> PipelineResult:
    settings = get_settings()
    repo_url = str(request.repo_url)
    logger.info("Run %s: starting analysis of %s", run_id, repo_url)
    workspace = RepoWorkspace(run_id)
    repo_dir = workspace.clone(repo_url)

    findings: List[dict] = []
    messages: List[str] = []

    try:
        semgrep_findings = await asyncio.to_thread(
            run_semgrep_scan, str(repo_dir), request.preset
        )
        findings.extend(semgrep_findings)
        messages.append(
            f"Semgrep finished {len(semgrep_findings)} finding(s) "
            f"at {datetime.utcnow().isoformat()}"
        )
        logger.info(
            "Run %s: Semgrep completed with %s finding(s)",
            run_id,
            len(semgrep_findings),
        )
    except ScannerError as exc:
        findings.append(
            {
                "title": "Semgrep",
                "severity": "error",
                "summary": str(exc),
                "file_path": None,
            }
        )
        messages.append("Semgrep failed")
        logger.warning("Run %s: Semgrep failed - %s", run_id, exc)

    try:
        dependency_result = await asyncio.to_thread(
            run_dependency_audits, str(repo_dir)
        )
        findings.extend(dependency_result.findings)
        messages.append(
            f"Dependency audit returned {len(dependency_result.findings)} finding(s)"
        )
        logger.info(
            "Run %s: Dependency audit returned %s finding(s)",
            run_id,
            len(dependency_result.findings),
        )

        if dependency_result.upgrade_plan:
            try:
                upgrade_actions = await asyncio.to_thread(
                    apply_dependency_upgrades,
                    repo_dir,
                    dependency_result.upgrade_plan,
                )
                for action in upgrade_actions:
                    findings.append(
                        {
                            "title": f"Upgraded {action.package}",
                            "severity": "info",
                            "file_path": str(action.lockfile),
                            "summary": (
                                "Auto-installed latest version via npm install."
                                if action.success
                                else f"Upgrade failed: {action.message}"
                            ),
                        }
                    )
                messages.append(
                    f"Upgraded {len(upgrade_actions)} dependency package(s) automatically"
                )
                logger.info(
                    "Run %s: Dependency upgrades attempted=%s",
                    run_id,
                    len(upgrade_actions),
                )
            except DependencyUpgradeError as exc:
                findings.append(
                    {
                        "title": "Dependency upgrade",
                        "severity": "error",
                        "summary": str(exc),
                        "file_path": None,
                    }
                )
                messages.append("Dependency upgrade step failed")
                logger.warning("Run %s: Dependency upgrade failed - %s", run_id, exc)
    except DependencyScannerError as exc:
        findings.append(
            {
                "title": "Dependency audit",
                "severity": "error",
                "summary": str(exc),
                "file_path": None,
            }
        )
        messages.append("Dependency audit failed")
        logger.warning("Run %s: Dependency audit failed - %s", run_id, exc)

    refactor_tasks = build_refactor_queue(repo_dir, findings)
    refactor_results: List[RefactorResult] = []
    if refactor_tasks:
        try:
            refactor_results = await asyncio.to_thread(
                apply_refactor_tasks, repo_dir, refactor_tasks
            )
            applied = [result for result in refactor_results if result.applied]
            if applied:
                messages.append(f"Applied {len(applied)} AI refactor comment(s)")
            skipped = len(refactor_results) - len(applied)
            if skipped:
                messages.append(f"Skipped {skipped} refactor target(s)")
            logger.info(
                "Run %s: Refactor applied=%s skipped=%s",
                run_id,
                len(applied),
                skipped,
            )
        except Exception as exc:  # pragma: no cover
            messages.append(f"Refactor worker failed: {exc}")
            logger.warning("Run %s: Refactor worker failed - %s", run_id, exc)
    else:
        messages.append("No files qualified for AI refactor queue")
        logger.info("Run %s: No refactor tasks generated", run_id)

    for result in refactor_results:
        findings.append(
            {
                "title": f"Refactor {result.task.file_path}",
                "severity": "info" if result.applied else "warning",
                "file_path": str(result.task.file_path),
                "summary": result.message,
            }
        )

    finding_models = [schemas.FindingSummary(**finding) for finding in findings]
    report_relative_path = Path("reports") / "VulminatorReport.md"

    try:
        report_contents = await generate_markdown_report(finding_models)
        messages.append("Generated Markdown report")
        logger.info("Run %s: Report generation succeeded", run_id)
    except Exception as exc:  # pragma: no cover
        report_contents = "Report generation failed.\n\n" + str(exc)
        messages.append("Report generation failed; using fallback text")
        logger.exception("Run %s: Report generation failed", run_id)

    report_path = repo_dir / report_relative_path
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_contents, encoding="utf-8")

    pr_url: Optional[str] = None
    token = (request.github_token or settings.github_token or "").strip()
    if token and token.lower() != "placeholder":
        try:
            pr_url = await asyncio.to_thread(
                publish_report_pr,
                repo_dir,
                repo_url,
                token,
                report_relative_path,
                report_contents,
                len(finding_models),
            )
            if pr_url:
                messages.append("Opened pull request")
                logger.info("Run %s: PR created %s", run_id, pr_url)
        except Exception as exc:  # pragma: no cover
            messages.append(f"Pull request failed: {exc}")
            logger.exception("Run %s: PR creation failed", run_id)
    else:
        messages.append("Skipped PR (no GitHub token provided)")
        logger.info("Run %s: Skipped PR (missing token)", run_id)

    final_message = "; ".join(messages)
    logger.info("Run %s: pipeline complete", run_id)

    return PipelineResult(
        findings=findings,
        pr_url=pr_url,
        message=final_message,
    )
