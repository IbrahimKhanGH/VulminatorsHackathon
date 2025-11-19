"""Dependency vulnerability scanning helpers (npm audit)."""

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set

logger = logging.getLogger(__name__)


def _ensure_npm() -> str:
    npm_path = shutil.which("npm")
    if npm_path:
        logger.debug("Found npm binary at %s", npm_path)
        return npm_path
    logger.error("npm CLI missing from Lambda layer/ZIP")
    raise DependencyScannerError(
        "npm CLI not found. Install Node.js/npm to enable dependency audits."
    )


UPGRADE_SEVERITIES = {"high", "critical"}


def _relative_path(path: Path, root: Path) -> Path:
    try:
        return path.relative_to(root)
    except ValueError:
        return Path(os.path.relpath(path, root))


@dataclass
class DependencyScanResult:
    findings: List[dict] = field(default_factory=list)
    lockfiles: List[Path] = field(default_factory=list)
    upgrade_plan: Dict[Path, Set[str]] = field(default_factory=dict)


class DependencyScannerError(RuntimeError):
    pass


def _parse_vulnerabilities(payload: dict, lockfile_path: Path):
    vulnerabilities = payload.get("vulnerabilities", {})
    findings: List[dict] = []
    upgrade_packages: Set[str] = set()

    for package_name, vuln in vulnerabilities.items():
        via = vuln.get("via") or []
        advisory = None
        if isinstance(via, list):
            for item in via:
                if isinstance(item, dict):
                    advisory = item
                    break
        elif isinstance(via, dict):
            advisory = via

        title = advisory.get("title") if advisory else f"{package_name} vulnerability"
        url = advisory.get("url") if advisory else ""
        severity = vuln.get("severity", "info")
        range_spec = vuln.get("range")
        detail_parts = [title]
        if range_spec:
            detail_parts.append(f"Affected versions: {range_spec}")
        if url:
            detail_parts.append(url)

        findings.append(
            {
                "title": f"{package_name} ({severity})",
                "severity": severity,
                "file_path": str(lockfile_path),
                "summary": " — ".join(detail_parts),
            }
        )

        if severity in UPGRADE_SEVERITIES:
            upgrade_packages.add(package_name)

    return findings, upgrade_packages


def run_dependency_audits(repo_path: str) -> DependencyScanResult:
    npm_bin = _ensure_npm()
    root = Path(repo_path).resolve()
    lockfiles = [lock.resolve() for lock in root.rglob("package-lock.json")]

    result = DependencyScanResult(lockfiles=[_relative_path(lock, root) for lock in lockfiles])

    if not lockfiles:
        logger.info("No package-lock.json files found under %s", repo_path)
        result.findings.append(
            {
                "title": "Dependency audit",
                "severity": "info",
                "file_path": None,
                "summary": "No npm lockfiles found; skipped npm audit.",
            }
        )
        return result

    for lockfile in lockfiles:
        relative_lock = _relative_path(lockfile, root)
        logger.info("Running npm audit in %s", lockfile.parent)
        cmd = [npm_bin, "audit", "--json", "--package-lock-only"]
        process = subprocess.run(
            cmd,
            cwd=lockfile.parent,
            capture_output=True,
            text=True,
            check=False,
        )

        if process.returncode not in (0, 1):
            logger.error(
                "npm audit failed for %s (code %s): %s",
                lockfile,
                process.returncode,
                process.stderr,
            )
            raise DependencyScannerError(
                f"npm audit failed for {lockfile} (code {process.returncode}): "
                f"{process.stderr.strip()}"
            )

        try:
            data = json.loads(process.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise DependencyScannerError(
                f"Unable to parse npm audit output for {lockfile}"
            ) from exc

        findings, upgrade_candidates = _parse_vulnerabilities(
            data, relative_lock
        )
        result.findings.extend(findings)
        if upgrade_candidates:
            result.upgrade_plan[relative_lock] = upgrade_candidates

    if not result.findings:
        result.findings.append(
            {
                "title": "Dependency audit",
                "severity": "info",
                "file_path": None,
                "summary": "npm audit reported no vulnerabilities.",
            }
        )

    return result
