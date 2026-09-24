from pydantic import BaseModel
from typing import Dict, List, Any, Optional


class AnalyzeRequest(BaseModel):
    url: str
    task: str
    groq_api_key: Optional[str] = None


class AnalyzeResponse(BaseModel):
    verdict: str
    risk_score: int
    summary: str
    metrics: Dict[str, Any]
    findings: List[Dict[str, Any]]
    redirect_chain: List[Dict[str, Any]]
    interactions: List[Dict[str, Any]]
    javascript_signals: List[Dict[str, Any]]
    recommendation: Dict[str, Any]
    telemetry: Dict[str, Any]
    ai_insights: Optional[Dict[str, Any]] = None
