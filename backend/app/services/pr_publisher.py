import logging
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import quote

from git import Repo

from ..config import get_settings
from .github_client import GitHubService

logger = logging.getLogger(__name__)


def _ensure_remote(repo: Repo, name: str, url: str) -> None:
    existing = next((remote for remote in repo.remotes if remote.name == name), None)
    if existing:
        repo.delete_remote(existing)
    repo.create_remote(name, url)


def _build_pr_body(findings_count: int, report_relative_path: Path, summary: str) -> str:
    excerpt = "\n".join(summary.splitlines()[:40])
    return (
        "## Vulminator Security Report\n\n"
        f"- Total findings: **{findings_count}**\n"
        f"- Report file: `{report_relative_path.as_posix()}`\n"
        f"- Generated: {datetime.utcnow().isoformat()} UTC\n\n"
        "---\n\n"
        f"{excerpt}\n\n"
        "---\n"
        "Automated by Vulminator."
    )


def publish_report_pr(
    repo_dir: Path,
    repo_url: str,
    github_token: str,
    report_relative_path: Path,
    report_contents: str,
    findings_count: int,
) -> Optional[str]:
    settings = get_settings()
    gh = GitHubService(github_token)
    logger.info("Preparing PR for %s", repo_url)
    target_repo = gh.get_repo(repo_url)
    fork_repo = gh.ensure_fork(repo_url)
    head_branch = f"{settings.default_branch_prefix}/{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"

    repo = Repo(repo_dir)
    base_branch = repo.active_branch.name
    repo.git.checkout(base_branch)
    repo.git.checkout("-B", head_branch)

    repo.git.add(all=True)
    commit_message = f"Add Vulminator report ({findings_count} findings)"
    repo.index.commit(commit_message)
    logger.info("Committed report to branch %s", head_branch)

    remote_url = fork_repo.clone_url.replace(
        "https://", f"https://{quote(github_token)}@"
    )
    remote_name = "vulminator-fork"
    _ensure_remote(repo, remote_name, remote_url)
    repo.git.push(remote_name, head_branch, "--force")
    logger.info("Pushed branch %s to %s", head_branch, fork_repo.full_name)

    pr_title = f"Vulminator security report ({findings_count} findings)"
    pr_body = _build_pr_body(findings_count, report_relative_path, report_contents)
    head_ref = f"{fork_repo.owner.login}:{head_branch}"
    try:
        pr_url = gh.create_pull_request(
            repo_url,
            head_reference=head_ref,
            title=pr_title,
            body=pr_body,
            base_branch=target_repo.default_branch,
        )
        logger.info("Opened PR %s targeting %s", pr_url, repo_url)
    except Exception as exc:
        logger.exception("Pull request creation failed for %s: %s", repo_url, exc)
        raise

    return pr_url
