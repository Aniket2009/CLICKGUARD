import os
import sys
import asyncio
from pathlib import Path

# Add project root directory to sys.path so "backend" package is always resolvable
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent
for p in [str(PROJECT_ROOT), str(CURRENT_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

# Fix for Windows asyncio loop with Playwright subprocesses
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Try to load local .env if python-dotenv is present
try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")
    load_dotenv()
except ImportError:
    pass

try:
    from backend.models import AnalyzeRequest, AnalyzeResponse
    from backend.analyzer import analyze_url
except ImportError:
    from models import AnalyzeRequest, AnalyzeResponse
    from analyzer import analyze_url

app = FastAPI(title="ClickGuard API")

# Enable CORS for local and hosted frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "ClickGuard",
        "groq_ai_configured": bool(os.environ.get("GROQ_API_KEY"))
    }


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest):
    try:
        result = await analyze_url(
            url=request.url,
            task=request.task,
            groq_api_key=request.groq_api_key
        )
        return result
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(exc)}"
        ) from exc


if __name__ == "__main__":
    import uvicorn
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    uvicorn.run(app, host="127.0.0.1", port=8000, loop="asyncio")

