from pydantic import BaseModel
from typing import Dict, List, Any, Optional, Union


class AnalyzeRequest(BaseModel):
    url: str
    task: str
    groq_api_key: Optional[str] = None


class AuthorizeActionRequest(BaseModel):
    action: str = "click"  # click, navigation, download
    target: Optional[Union[str, Dict[str, Any]]] = None
    task: str = ""
    url: str
    groq_api_key: Optional[str] = None


class AuthorizeActionResponse(BaseModel):
    verdict: str  # ALLOW / CAUTION / BLOCK
    action_authorized: bool
    interaction_risk_score: int
    score_breakdown: List[Dict[str, Any]]
    intent_vs_reality: Dict[str, Any]
    overlay_interception: Optional[Dict[str, Any]] = None
    destination_mismatch: Optional[Dict[str, Any]] = None
    prompt_injection: Optional[Dict[str, Any]] = None
    redirect_chain: List[Dict[str, Any]]
    javascript_signals: List[Dict[str, Any]]
    forensic_details: Dict[str, Any]
    summary: str
    ai_reasoning: Optional[Dict[str, Any]] = None
    telemetry: Dict[str, Any]


class AnalyzeResponse(BaseModel):
    verdict: str
    risk_score: int
    interaction_risk_score: int
    score_breakdown: List[Dict[str, Any]]
    intent_vs_reality: Dict[str, Any]
    summary: str
    metrics: Dict[str, Any]
    findings: List[Dict[str, Any]]
    redirect_chain: List[Dict[str, Any]]
    interactions: List[Dict[str, Any]]
    javascript_signals: List[Dict[str, Any]]
    recommendation: Dict[str, Any]
    telemetry: Dict[str, Any]
    ai_insights: Optional[Dict[str, Any]] = None
    screenshot: Optional[str] = None
    raw_elements: Optional[List[Dict[str, Any]]] = None
    forensic_details: Optional[Dict[str, Any]] = None