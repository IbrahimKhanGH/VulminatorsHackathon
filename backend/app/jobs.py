import asyncio
import uuid
from typing import Dict, List, Optional

from . import schemas
from .config import get_settings
from .services.analyzer import run_analysis_pipeline


class JobRecord:
    def __init__(self, request: schemas.AnalyzeRequest):
        self.run_id = str(uuid.uuid4())
        self.request = request
        self.status = schemas.RunStatus.queued
        self.message: Optional[str] = None
        self.findings = []
        self.pr_url: Optional[str] = None
        self.steps: List[Dict[str, str]] = []


class JobStore:
    def __init__(self) -> None:
        self._jobs: Dict[str, JobRecord] = {}
        self._lock = asyncio.Lock()

    async def create_job(self, request: schemas.AnalyzeRequest) -> JobRecord:
        async with self._lock:
            job = JobRecord(request)
            self._jobs[job.run_id] = job
            return job

    async def get_job(self, run_id: str) -> Optional[JobRecord]:
        async with self._lock:
            return self._jobs.get(run_id)

    async def update_job(self, run_id: str, **updates) -> None:
        async with self._lock:
            job = self._jobs.get(run_id)
            if not job:
                return
            for key, value in updates.items():
                setattr(job, key, value)


job_store = JobStore()
settings = get_settings()


async def _execute_job(run_id: str) -> None:
    job = await job_store.get_job(run_id)
    if not job:
        return

    await job_store.update_job(run_id, status=schemas.RunStatus.running)

    async def progress_update(message: str, steps: List[Dict[str, str]]) -> None:
        await job_store.update_job(run_id, message=message, steps=steps)

    try:
        result = await run_analysis_pipeline(
            job.run_id, job.request, progress_callback=progress_update
        )
        await job_store.update_job(
            run_id,
            status=schemas.RunStatus.completed,
            findings=result.findings,
            pr_url=result.pr_url,
            message=result.message,
            steps=result.steps,
        )
    except NotImplementedError:
        await job_store.update_job(
            run_id,
            status=schemas.RunStatus.failed,
            message="Pipeline not implemented yet",
        )
    except Exception as exc:  # pragma: no cover
        await job_store.update_job(
            run_id,
            status=schemas.RunStatus.failed,
            message=str(exc),
        )


async def enqueue_job(request: schemas.AnalyzeRequest) -> str:
    job = await job_store.create_job(request)
    if settings.run_jobs_inline:
        await _execute_job(job.run_id)
    else:
        asyncio.create_task(_execute_job(job.run_id))
    return job.run_id


async def get_job_status(run_id: str) -> Optional[schemas.RunStatusResponse]:
    job = await job_store.get_job(run_id)
    if not job:
        return None

    return schemas.RunStatusResponse(
        run_id=run_id,
        status=job.status,
        message=job.message,
        pr_url=job.pr_url,
        findings=[schemas.FindingSummary(**finding) for finding in job.findings]
        if job.findings
        else None,
        steps=[schemas.PipelineStep(**step) for step in job.steps] if job.steps else None,
    )
