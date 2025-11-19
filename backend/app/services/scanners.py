import json
import shutil
from pathlib import Path
import subprocess
from typing import List

from ..schemas import ScanPreset

SEMGREP_CONFIG_MAP = {
    ScanPreset.fast: "p/ci",
    ScanPreset.balanced: "p/security-audit",
    ScanPreset.exhaustive: "p/owasp-top-ten",
}


class ScannerError(RuntimeError):
    pass


def _resolve_semgrep_binary() -> str:
    binary = shutil.which("semgrep")
    fallback = Path("/opt/python/bin/semgrep")
    if binary:
        return binary
    if fallback.exists():
        return str(fallback)
    raise ScannerError(
        "Semgrep CLI not found. Install it via pip (pip install semgrep) "
        "or brew (brew install semgrep)."
    )


def run_semgrep_scan(repo_path: str, preset: ScanPreset) -> List[dict]:
    semgrep_bin = _resolve_semgrep_binary()
    config = SEMGREP_CONFIG_MAP.get(preset, SEMGREP_CONFIG_MAP[ScanPreset.fast])
    cmd = [
        semgrep_bin,
        "--config",
        config,
        "--json",
        "--quiet",
    ]

    process = subprocess.run(
        cmd,
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=False,
    )

    if process.returncode not in (0, 1):
        raise ScannerError(
            f"Semgrep failed with code {process.returncode}: {process.stderr.strip()}"
        )

    try:
        payload = json.loads(process.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise ScannerError("Failed to parse Semgrep JSON output") from exc

    results = payload.get("results", [])
    findings = []
    for result in results:
        extra = result.get("extra", {})
        findings.append(
            {
                "title": result.get("check_id", "semgrep finding"),
                "severity": extra.get("severity", "info"),
                "file_path": result.get("path"),
                "summary": extra.get("message", "No description provided."),
            }
        )

    if not findings:
        findings.append(
            {
                "title": "Semgrep",
                "severity": "info",
                "summary": "Semgrep completed with no findings for the selected preset.",
                "file_path": None,
            }
        )

    return findings
