from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from datetime import datetime, timezone
import re

from backend.browser import inspect_page
from backend.ai_auditor import run_groq_audit


async def analyze_url(url: str, task: str, groq_api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Deterministic rule-based security analyzer for ClickGuard, with optional
    Groq Llama-3 real-time AI reasoning for auditing live external websites.
    """
    # 1. Fetch raw browser inspection telemetry
    page_data = await inspect_page(url)

    risk_score = 0
    findings: List[Dict[str, Any]] = []
    javascript_signals: List[Dict[str, Any]] = []
    formatted_redirects: List[Dict[str, Any]] = []
    formatted_interactions: List[Dict[str, Any]] = []

    initial_parsed = urlparse(url)
    initial_domain = initial_parsed.netloc.lower() or initial_parsed.path.split("/")[-1] or "local_target"

    final_url = page_data.get("final_url", url)
    final_parsed = urlparse(final_url)
    final_domain = final_parsed.netloc.lower() or final_parsed.path.split("/")[-1] or "local_target"

    # -------------------------------------------------------------
    # Rule 1: Invisible or suspicious overlay/intercepting element (+40)
    # -------------------------------------------------------------
    overlay_detected = False
    for el in page_data.get("interactive_elements", []):
        z_idx = str(el.get("z_index", "")).strip()
        is_high_z = False
        try:
            is_high_z = int(z_idx) > 1000
        except ValueError:
            is_high_z = False

        opacity_val = 1.0
        try:
            opacity_val = float(el.get("opacity", 1.0))
        except (ValueError, TypeError):
            opacity_val = 1.0

        is_suspicious_overlay = (
            el.get("is_overlay", False) or
            (is_high_z and opacity_val < 0.1) or
            (el.get("pointer_events") == "auto" and opacity_val == 0.0)
        )

        if is_suspicious_overlay and not overlay_detected:
            overlay_detected = True
            risk_score += 40
            findings.append({
                "severity": "critical",
                "title": "Invisible or suspicious overlay element detected",
                "description": "A high-z-index or low-opacity element was detected covering the page, which may intercept agent click coordinates.",
                "evidence": f"Tag: <{el.get('tag_name')}> id='{el.get('id')}' class='{el.get('class_name')}' opacity={el.get('opacity')} z-index={el.get('z_index')} bbox={el.get('bounding_box')}"
            })

    # -------------------------------------------------------------
    # Rule 2: Suspicious destination mismatch between visible text & href (+30)
    # -------------------------------------------------------------
    destination_mismatch = False
    for el in page_data.get("interactive_elements", []):
        href = el.get("href")
        text = (el.get("visible_text") or "").lower()
        onclick = (el.get("onclick_attr") or "").lower()

        # Format for interaction table
        element_label = f"{el.get('tag_name', 'el').upper()}" + (f"#{el.get('id')}" if el.get("id") else (f".{el.get('class_name').split()[0]}" if el.get("class_name") else ""))
        destination = href or el.get("action") or onclick or "javascript:void(0)"
        element_risk = "LOW"

        # Check for destination mismatch heuristic
        if href:
            href_lower = href.lower()
            if any(term in text for term in ["download", "pdf", "invoice", "document", "view", "login", "continue"]):
                # If text suggests document/auth but link is disparate domain or javascript:
                if href_lower.startswith("http://") or href_lower.startswith("https://"):
                    href_domain = urlparse(href_lower).netloc.lower()
                    if href_domain and href_domain != initial_domain and initial_domain not in href_domain:
                        element_risk = "HIGH"
                        if not destination_mismatch:
                            destination_mismatch = True
                            risk_score += 30
                            findings.append({
                                "severity": "high",
                                "title": "Suspicious destination mismatch between label and target href",
                                "description": f"Interactive anchor claims '{text}', but points to disparate domain: '{href_domain}'.",
                                "evidence": f"Text: '{el.get('visible_text')}' -> Target href: '{href}'"
                            })
                elif "javascript:" in href_lower or onclick:
                    element_risk = "MEDIUM"

        formatted_interactions.append({
            "element": element_label,
            "visible_text": el.get("visible_text") or "[No Text]",
            "type": f"{el.get('tag_name', '').capitalize()} Target",
            "destination": destination[:120],
            "visibility": "Visible" if el.get("is_visible") else "Hidden",
            "risk": element_risk
        })

    # -------------------------------------------------------------
    # Rule 3: Cross-domain or multi-hop redirect (+20)
    # -------------------------------------------------------------
    raw_redirects = page_data.get("redirect_chain", [])
    redirect_count = len(raw_redirects)
    is_cross_domain = (initial_domain != final_domain) and bool(final_domain)

    if redirect_count > 1 or is_cross_domain:
        risk_score += 20
        findings.append({
            "severity": "high",
            "title": "Cross-domain or multi-hop redirect detected",
            "description": f"Page performed navigation hops from initial domain '{initial_domain}' to '{final_domain}'.",
            "evidence": f"Total recorded redirects: {redirect_count}. Final destination: {final_url}"
        })

    # Format redirect chain
    if raw_redirects:
        for idx, r in enumerate(raw_redirects):
            r_url = r.get("url", "")
            r_domain = urlparse(r_url).netloc or r_url
            formatted_redirects.append({
                "domain": r_domain,
                "status": r.get("status", 302),
                "status_text": r.get("status_text", "Redirect"),
                "type": "Intermediate Hop" if idx < len(raw_redirects) - 1 else "Redirect Target",
                "severity": "danger" if is_cross_domain else "warning"
            })
    else:
        formatted_redirects.append({
            "domain": final_domain or initial_domain,
            "status": 200,
            "status_text": "OK",
            "type": "Direct Navigation",
            "severity": "safe"
        })

    # -------------------------------------------------------------
    # Rule 4: Suspicious JavaScript signals (+10)
    # (window.location, location.replace, window.open, eval, atob)
    # -------------------------------------------------------------
    js_patterns = [
        ("window.location", "Dynamic page location reassignment", "medium"),
        ("location.replace", "History-stripping URL replacement", "high"),
        ("window.open", "Automated popup/window spawn routine", "medium"),
        ("eval", "Dynamic execution routine (eval)", "critical"),
        ("atob", "Base64 payload decoding routine (atob)", "high")
    ]

    inline_scripts = page_data.get("inline_scripts", [])
    combined_scripts = "\n".join(inline_scripts)

    js_found_any = False
    for token, desc, severity in js_patterns:
        # Match whole word or function call
        if re.search(r'\b' + re.escape(token) + r'\b', combined_scripts, re.IGNORECASE):
            js_found_any = True
            javascript_signals.append({
                "signal": token,
                "source": "inline script",
                "severity": severity,
                "details": desc
            })

    if js_found_any:
        risk_score += 10
        findings.append({
            "severity": "medium",
            "title": "Suspicious JavaScript execution primitives identified",
            "description": "The page script contains dynamic evaluation, navigation overrides, or base64 decoding routines.",
            "evidence": f"Signals detected: {', '.join([s['signal'] for s in javascript_signals])}"
        })

    # -------------------------------------------------------------
    # Rule 5: Page text containing agent-targeted prompt injection phrases (+25)
    # ("ignore previous instructions", "ignore all previous instructions", "AI agent", "assistant, click")
    # -------------------------------------------------------------
    visible_text = page_data.get("visible_text", "")
    injection_phrases = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "ai agent",
        "assistant, click",
        "system override",
        "do not download"
    ]

    found_injections = []
    for phrase in injection_phrases:
        if phrase in visible_text.lower():
            found_injections.append(phrase)

    if found_injections:
        risk_score += 25
        findings.append({
            "severity": "critical",
            "title": "Potential agent-targeted prompt injection string in page content",
            "description": "Page text contains patterns frequently used to alter LLM agent instructions or override autonomy guardrails.",
            "evidence": f"Matched pattern(s): {', '.join(found_injections)}"
        })

    # -------------------------------------------------------------
    # Rule 6 (Optional): Real-time Groq AI Security Audit
    # Evaluates live external websites with Llama-3 reasoning
    # -------------------------------------------------------------
    ai_insights = run_groq_audit(url, task, page_data, groq_api_key)
    if ai_insights and "error" not in ai_insights:
        delta = ai_insights.get("risk_score_delta", 0)
        risk_score += delta
        for ai_f in ai_insights.get("ai_findings", []):
            findings.append({
                "severity": ai_f.get("severity", "medium"),
                "title": f"[AI Audit] {ai_f.get('title', 'Adversarial Risk')}",
                "description": ai_f.get("description", ""),
                "evidence": ai_f.get("evidence", f"Evaluated via Groq ({ai_insights.get('model_used')})")
            })

    # -------------------------------------------------------------
    # Score clamping and verdict calculation
    # 0-29 = SAFE
    # 30-59 = CAUTION
    # 60-100 = BLOCK
    # -------------------------------------------------------------
    risk_score = max(0, min(100, risk_score))

    if risk_score >= 60:
        verdict = "BLOCK"
        summary = (
            "Heuristic and AI analysis detected high-risk indicators such as transparent overlays, "
            "untrusted redirection hops, or prompt injection patterns. Autonomous interaction should be aborted."
        )
        recommendation = {
            "action": "BLOCK ACTION",
            "title": "DO NOT EXECUTE",
            "description": (
                "The target page exhibits anomalous heuristics that conflict with the intended agent task. "
                "Agent should abort the scheduled interaction to protect credentials and workflow integrity."
            )
        }
    elif risk_score >= 30:
        verdict = "CAUTION"
        summary = (
            "Heuristic and AI analysis identified potential anomalies such as cross-domain redirects or sensitive JavaScript routines. "
            "Verification is advised prior to simulated clicks."
        )
        recommendation = {
            "action": "CAUTION REQUIRED",
            "title": "PROCEED WITH CAUTION",
            "description": (
                "Review the detected network redirects and script signals before completing autonomous interaction."
            )
        }
    else:
        verdict = "SAFE"
        summary = (
            "No significant deceptive patterns, transparent click overlays, or prompt injection heuristics detected. "
            "Interaction surface appears consistent."
        )
        recommendation = {
            "action": "ALLOW ACTION",
            "title": "PROCEED WITH TASK",
            "description": (
                "Interaction targets align with the intended task and visible UI anchors. The agent may proceed safely."
            )
        }

    # If Groq provided an executive summary, prioritize its nuanced explanation
    if ai_insights and ai_insights.get("executive_summary") and "error" not in ai_insights:
        summary = ai_insights.get("executive_summary")

    # Assemble complete response structure
    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "summary": summary,
        "metrics": {
            "dom_elements": page_data.get("dom_element_count", 0),
            "scripts": page_data.get("script_count", 0),
            "network_requests": page_data.get("network_request_count", 0),
            "redirects": redirect_count,
            "suspicious_signals": len(findings)
        },
        "findings": findings,
        "redirect_chain": formatted_redirects,
        "interactions": formatted_interactions[:25],
        "javascript_signals": javascript_signals,
        "recommendation": recommendation,
        "telemetry": {
            "target_url": url,
            "final_url": final_url,
            "page_title": page_data.get("title", ""),
            "intended_task": task,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "dom_elements_count": page_data.get("dom_element_count", 0),
            "scripts_count": page_data.get("script_count", 0),
            "network_requests_logged": len(page_data.get("network_requests", [])),
            "raw_redirect_count": redirect_count,
            "heuristic_flags": {
                "overlay_detected": overlay_detected,
                "destination_mismatch": destination_mismatch,
                "cross_domain_redirect": is_cross_domain,
                "suspicious_js": js_found_any,
                "prompt_injection_flags": found_injections
            }
        },
        "ai_insights": ai_insights
    }
