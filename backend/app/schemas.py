from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl


class ScanPreset(str, Enum):
    fast = "fast"
    balanced = "balanced"
    exhaustive = "exhaustive"


class AnalyzeRequest(BaseModel):
    repo_url: HttpUrl = Field(..., description="HTTPS URL to the target GitHub repo")
    github_token: Optional[str] = Field(
        default=None, description="GitHub PAT with repo scope (optional if .env set)"
    )
    preset: ScanPreset = Field(default=ScanPreset.fast)
    run_ai_report: bool = Field(default=True)


class AnalyzeResponse(BaseModel):
    run_id: str
    status: str


class RunStatus(str, Enum):
    queued = "queued"
    running = "running"
    failed = "failed"
    completed = "completed"


class FindingSummary(BaseModel):
    title: str
    severity: str
    file_path: Optional[str] = None
    summary: str
    risk_brief: Optional[str] = None
    patch_suggestion: Optional[str] = None


class StepStatus(str, Enum):
    pending = "pending"
    running = "running"
    done = "done"
    failed = "failed"
    skipped = "skipped"


class PipelineStep(BaseModel):
    id: str
    label: str
    status: StepStatus


class RunStatusResponse(BaseModel):
    run_id: str
    status: RunStatus
    message: Optional[str] = None
    findings: Optional[List[FindingSummary]] = None
    pr_url: Optional[HttpUrl] = None
    steps: Optional[List[PipelineStep]] = None
