import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(BASE_DIR / ".env")


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


class Settings(BaseModel):
    app_name: str = "Vulminators API"
    default_branch_prefix: str = "vulminator"
    workspace_root: Path = Path(
        os.getenv("VULMINATOR_WORKSPACE", Path.cwd() / ".runs")
    )
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    max_concurrent_jobs: int = int(os.getenv("MAX_JOBS", "4"))
    github_token: Optional[str] = os.getenv("VULMINATOR_GITHUB_TOKEN")
    run_jobs_inline: bool = _env_bool(
        "RUN_JOBS_INLINE", default=bool(os.getenv("AWS_LAMBDA_FUNCTION_NAME"))
    )


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.workspace_root.mkdir(parents=True, exist_ok=True)
    return settings
