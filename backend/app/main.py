from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum

from .config import get_settings
from .jobs import enqueue_job, get_job_status
from .schemas import AnalyzeRequest, AnalyzeResponse, RunStatusResponse

settings = get_settings()
app = FastAPI(title=settings.app_name)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def healthcheck() -> dict:
    return {"status": "ok", "workspace": str(settings.workspace_root)}

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_repo(payload: AnalyzeRequest) -> AnalyzeResponse:
    run_id = await enqueue_job(payload)
    return AnalyzeResponse(run_id=run_id, status="queued")

@app.get("/runs/{run_id}", response_model=RunStatusResponse)
async def fetch_run(run_id: str) -> RunStatusResponse:
    status = await get_job_status(run_id)
    if not status:
        raise HTTPException(status_code=404, detail="Run not found")
    return status

handler = Mangum(app)