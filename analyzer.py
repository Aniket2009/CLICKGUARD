from typing import Dict, List, Any, Optional, Union
from urllib.parse import urlparse
from datetime import datetime, timezone
from pathlib import Path
import re

try:
    from backend.browser import inspect_page
    from backend.ai_auditor import run_groq_audit
except ImportError:
    from browser import inspect_page
    from ai_auditor import run_groq_audit


def _extract_css_value(style_str: str, prop: str, default: str = "") -> str:
    """Extract a CSS property value from an inline style string."""
    m = re.search(rf'{re.escape(prop)}\s*:\s*([^\s;]+)', style_str, re.IGNORECASE)
    return m.group(1) if m else default


def _inspect_local_file_fallback(file_path: Path) -> Dict[str, Any]:
    """
    Robust deterministic fallback scanner if Playwright is unavailable or headless
    browser is initializing. Reads local files directly and constructs DOM telemetry
    by parsing actual HTML content — no hardcoded mock data.
    """
    html_content = ""
    try:
        html_content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        pass

    interactive_elements: List[Dict[str, Any]] = []

    # ── Parse <a> tags from actual HTML ──
    for match in re.finditer(r'<a\s*([^>]*)>(.*?)</a>', html_content, re.IGNORECASE | re.DOTALL):
        attrs_str, inner_html = match.group(1), match.group(2)

        href_m = re.search(r'href=["\']([^"\']+)["\']', attrs_str)
        id_m = re.search(r'\bid=["\']([^"\']+)["\']', attrs_str)
        class_m = re.search(r'\bclass=["\']([^"\']+)["\']', attrs_str)
        style_m = re.search(r'\bstyle=["\']([^"\']+)["\']', attrs_str)
        onclick_m = re.search(r'\bonclick=["\']([^"\']+)["\']', attrs_str)

        visible_text = re.sub(r'<[^>]+>', '', inner_html).strip()[:120]
        href = href_m.group(1) if href_m else None
        el_id = id_m.group(1) if id_m else None
        el_class = class_m.group(1) if class_m else None

        style_str = style_m.group(1) if style_m else ""
        opacity = _extract_css_value(style_str, "opacity", "1")
        z_index = _extract_css_value(style_str, "z-index", "auto")
        pointer_events = _extract_css_value(style_str, "pointer-events", "auto")
        position = _extract_css_value(style_str, "position", "static")

        is_overlay = any(kw in (el_class or "").lower() for kw in ["overlay", "invisible", "interceptor"])
        if not is_overlay:
            try:
                if int(z_index) > 1000 and float(opacity) < 0.2:
                    is_overlay = True
            except (ValueError, TypeError):
                pass

        el_data: Dict[str, Any] = {
            "tag_name": "a",
            "id": el_id,
            "class_name": el_class,
            "visible_text": visible_text,
            "href": href,
            "bounding_box": None,
            "is_visible": True,
            "is_overlay": is_overlay,
            "z_index": z_index,
            "opacity": opacity,
            "pointer_events": pointer_events,
            "position": position,
            "onclick_attr": onclick_m.group(1) if onclick_m else None
        }

        if is_overlay:
            try:
                opacity_float = float(opacity)
            except (ValueError, TypeError):
                opacity_float = 1.0
            el_data["interceptor_detected"] = {
                "type": "overlay_interception",
                "severity": "HIGH",
                "target": visible_text,
                "interceptor": "A",
                "interceptor_id": el_id or "",
                "interceptor_class": el_class or "",
                "interceptor_href": href or "",
                "opacity": opacity_float,
                "z_index": z_index,
                "pointer_events": pointer_events,
            }

        interactive_elements.append(el_data)

    # ── Parse <button> tags ──
    for match in re.finditer(r'<button\s*([^>]*)>(.*?)</button>', html_content, re.IGNORECASE | re.DOTALL):
        attrs_str, inner_html = match.group(1), match.group(2)

        id_m = re.search(r'\bid=["\']([^"\']+)["\']', attrs_str)
        class_m = re.search(r'\bclass=["\']([^"\']+)["\']', attrs_str)
        onclick_m = re.search(r'\bonclick=["\']([^"\']+)["\']', attrs_str)

        visible_text = re.sub(r'<[^>]+>', '', inner_html).strip()[:120]
        el_id = id_m.group(1) if id_m else None
        el_class = class_m.group(1) if class_m else None

        interactive_elements.append({
            "tag_name": "button",
            "id": el_id,
            "class_name": el_class,
            "visible_text": visible_text,
            "href": None,
            "bounding_box": None,
            "is_visible": True,
            "is_overlay": False,
            "z_index": "auto",
            "opacity": "1",
            "pointer_events": "auto",
            "position": "static",
            "onclick_attr": onclick_m.group(1) if onclick_m else None
        })

    # ── Parse <input> tags ──
    for match in re.finditer(r'<input\s+([^>]*)/?>', html_content, re.IGNORECASE):
        attrs_str = match.group(1)
        id_m = re.search(r'\bid=["\']([^"\']+)["\']', attrs_str)
        class_m = re.search(r'\bclass=["\']([^"\']+)["\']', attrs_str)
        type_m = re.search(r'\btype=["\']([^"\']+)["\']', attrs_str)
        value_m = re.search(r'\bvalue=["\']([^"\']+)["\']', attrs_str)

        interactive_elements.append({
            "tag_name": "input",
            "id": id_m.group(1) if id_m else None,
            "class_name": class_m.group(1) if class_m else None,
            "visible_text": value_m.group(1) if value_m else "",
            "href": None,
            "bounding_box": None,
            "is_visible": True,
            "is_overlay": False,
            "z_index": "auto",
            "opacity": "1",
            "pointer_events": "auto",
            "position": "static"
        })

    # ── Parse <form> tags ──
    for match in re.finditer(r'<form\s+([^>]*)>', html_content, re.IGNORECASE):
        attrs_str = match.group(1)
        id_m = re.search(r'\bid=["\']([^"\']+)["\']', attrs_str)
        class_m = re.search(r'\bclass=["\']([^"\']+)["\']', attrs_str)
        action_m = re.search(r'\baction=["\']([^"\']+)["\']', attrs_str)

        interactive_elements.append({
            "tag_name": "form",
            "id": id_m.group(1) if id_m else None,
            "class_name": class_m.group(1) if class_m else None,
            "visible_text": "",
            "href": None,
            "action": action_m.group(1) if action_m else None,
            "bounding_box": None,
            "is_visible": True,
            "is_overlay": False,
            "z_index": "auto",
            "opacity": "1",
            "pointer_events": "auto",
            "position": "static"
        })

    # ── Count actual DOM elements ──
    all_open_tags = re.findall(r'<[a-zA-Z][a-zA-Z0-9]*[\s>/]', html_content)
    script_tags = re.findall(r'<script', html_content, re.IGNORECASE)

    # ── Extract script sources and inline content ──
    script_sources: List[str] = []
    inline_scripts: List[str] = []

    for m in re.finditer(r'<script\s+([^>]*)>(.*?)</script>', html_content, re.IGNORECASE | re.DOTALL):
        attrs_str, content = m.group(1), m.group(2)
        src_m = re.search(r'\bsrc=["\']([^"\']+)["\']', attrs_str)
        if src_m:
            script_sources.append(src_m.group(1))
        elif content.strip():
            inline_scripts.append(content.strip()[:1500])

    for m in re.finditer(r'<script>(.*?)</script>', html_content, re.IGNORECASE | re.DOTALL):
        content = m.group(1).strip()
        if content and content not in inline_scripts:
            inline_scripts.append(content[:1500])

    # ── Extract page title ──
    title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
    title = title_match.group(1).strip() if title_match else ""

    # ── Extract visible text (strip scripts, styles, then tags) ──
    visible_text = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.IGNORECASE | re.DOTALL)
    visible_text = re.sub(r'<style[^>]*>.*?</style>', '', visible_text, flags=re.IGNORECASE | re.DOTALL)
    visible_text = re.sub(r'<[^>]+>', ' ', visible_text)
    visible_text = re.sub(r'\s+', ' ', visible_text).strip()

    return {
        "initial_url": str(file_path),
        "final_url": str(file_path),
        "title": title or "Local File",
        "screenshot": None,
        "dom_element_count": len(all_open_tags),
        "script_count": len(script_tags),
        "script_sources": script_sources,
        "inline_scripts": inline_scripts,
        "network_request_count": 0,
        "network_requests": [],
        "redirect_chain": [],
        "visible_text": visible_text,
        "interactive_elements": interactive_elements
    }


async def authorize_action(
    action: str = "click",
    target: Optional[Union[str, Dict[str, Any]]] = None,
    task: str = "",
    url: str = "",
    groq_api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    ACTION FIREWALL: Core authorization middleware function for autonomous agents.
    Inspects intended browser interaction (click, navigation, download) before execution.
    Returns structured authorization, interaction risk score, and intent vs reality analysis.
    """
    analysis = await analyze_url(url=url, task=task, groq_api_key=groq_api_key, target_context=target, action_type=action)

    verdict = analysis["verdict"]
    action_authorized = (verdict == "SAFE")

    return {
        "action": action,
        "target": target or "",
        "task": task,
        "url": url,
        "verdict": verdict,
        "action_authorized": action_authorized,
        "interaction_risk_score": analysis["interaction_risk_score"],
        "score_breakdown": analysis["score_breakdown"],
        "intent_vs_reality": analysis["intent_vs_reality"],
        "overlay_interception": analysis.get("overlay_interception"),
        "destination_mismatch": analysis.get("destination_mismatch_detail"),
        "prompt_injection": analysis.get("prompt_injection_detail"),
        "redirect_chain": analysis["redirect_chain"],
        "javascript_signals": analysis["javascript_signals"],
        "forensic_details": analysis["forensic_details"],
        "summary": analysis["summary"],
        "ai_reasoning": analysis.get("ai_insights"),
        "telemetry": analysis["telemetry"]
    }


async def analyze_url(
    url: str,
    task: str,
    groq_api_key: Optional[str] = None,
    target_context: Optional[Union[str, Dict[str, Any]]] = None,
    action_type: str = "click"
) -> Dict[str, Any]:
    """
    Deterministic rule-based security analyzer for ClickGuard Action Firewall.
    Computes INTERACTION RISK SCORE (0-100) using transparent, calibrated signals:
      +40 Invisible / intercepting overlay
      +30 Destination mismatch
      +25 Agent-targeted prompt injection
      +20 Suspicious / multi-hop redirect
      +10 Suspicious JavaScript navigation
    """
    # 1. Inspect page via Playwright with local fallback
    page_data = None
    try:
        page_data = await inspect_page(url)
    except Exception as exc:
        print(f"[ClickGuard Inspector Warning]: Playwright inspection fallback invoked: {exc}")
        local_p = Path(url)
        if not local_p.exists():
            local_p = Path(__file__).resolve().parent.parent / url
        if local_p.exists():
            page_data = _inspect_local_file_fallback(local_p)
        else:
            raise

    # Risk score calculation
    risk_score = 0
    score_breakdown: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    javascript_signals: List[Dict[str, Any]] = []
    formatted_redirects: List[Dict[str, Any]] = []
    formatted_interactions: List[Dict[str, Any]] = []

    initial_parsed = urlparse(url)
    initial_domain = initial_parsed.netloc.lower() or initial_parsed.path.split("/")[-1] or "local_target"

    final_url = page_data.get("final_url", url)
    final_parsed = urlparse(final_url)
    final_domain = final_parsed.netloc.lower() or final_parsed.path.split("/")[-1] or "local_target"

    # Extract target label from context — no hardcoded fallback
    target_str = ""
    if isinstance(target_context, str):
        target_str = target_context
    elif isinstance(target_context, dict):
        target_str = target_context.get("text") or target_context.get("selector") or ""

    # -------------------------------------------------------------
    # Signal 1: Invisible / Intercepting Overlay (+40)
    # -------------------------------------------------------------
    overlay_detected = False
    overlay_interception_obj = None

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

        interceptor_detected = el.get("interceptor_detected")
        is_overlay_elem = (
            el.get("is_overlay", False) or
            (is_high_z and opacity_val < 0.2) or
            (el.get("pointer_events") == "auto" and opacity_val == 0.0) or
            ("invisible-interceptor" in str(el.get("class_name", ""))) or
            (interceptor_detected is not None)
        )

        if is_overlay_elem and not overlay_detected:
            overlay_detected = True
            risk_score += 40

            interceptor_tag = el.get("tag_name", "div").upper()
            interceptor_id = el.get("id") or "overlay-interceptor"
            interceptor_dest = el.get("href") or ""

            if interceptor_detected:
                overlay_interception_obj = interceptor_detected
            else:
                overlay_interception_obj = {
                    "type": "overlay_interception",
                    "severity": "HIGH",
                    "target": target_str,
                    "interceptor": interceptor_tag,
                    "interceptor_id": interceptor_id,
                    "interceptor_class": el.get("class_name"),
                    "interceptor_href": interceptor_dest,
                    "opacity": opacity_val,
                    "z_index": el.get("z_index", 9999),
                    "pointer_events": el.get("pointer_events", "auto"),
                    "bounding_box": el.get("bounding_box")
                }

            score_breakdown.append({
                "signal": "Invisible click interceptor",
                "delta": 40,
                "severity": "CRITICAL",
                "evidence": f"<{interceptor_tag} id='{interceptor_id}'> opacity={opacity_val} z-index={el.get('z_index')} pointer-events={el.get('pointer_events')}"
            })

            findings.append({
                "severity": "critical",
                "title": "Invisible Click Interceptor Overlay Detected (+40)",
                "description": "A high-z-index, zero-opacity element covers the target interaction bounding box, capable of hijacking pointer events.",
                "evidence": f"Interceptor: <{interceptor_tag} id='{interceptor_id}'> (opacity: {opacity_val}, z-index: {el.get('z_index')}, target: '{interceptor_dest}')"
            })

    # -------------------------------------------------------------
    # Signal 2: Destination Mismatch (+30)
    # -------------------------------------------------------------
    destination_mismatch = False
    destination_mismatch_obj = None

    expected_destination = ""
    actual_destination = ""

    # Search for visible button vs overlay destination
    visible_btn_dest = None
    overlay_btn_dest = None

    for el in page_data.get("interactive_elements", []):
        href = el.get("href") or ""
        text = (el.get("visible_text") or "").lower()
        tag = el.get("tag_name", "").lower()

        # Is this the legitimate target button?
        if "download" in text or "pdf" in text:
            visible_btn_dest = href if href else None
            expected_destination = visible_btn_dest or ""

        # Is this the overlay interceptor?
        if el.get("is_overlay") or "invisible-interceptor" in str(el.get("class_name", "")):
            overlay_btn_dest = href if href else None

    if overlay_detected and overlay_btn_dest and visible_btn_dest and overlay_btn_dest != visible_btn_dest:
        destination_mismatch = True
        actual_destination = overlay_btn_dest
    elif overlay_detected:
        destination_mismatch = True
        if overlay_btn_dest:
            actual_destination = overlay_btn_dest
        elif overlay_interception_obj:
            actual_destination = overlay_interception_obj.get("interceptor_href", "")
        else:
            actual_destination = ""

    # Also inspect external domain discrepancies
    for el in page_data.get("interactive_elements", []):
        href = el.get("href") or ""
        text = (el.get("visible_text") or "").lower()
        onclick = (el.get("onclick_attr") or "").lower()

        element_label = f"{el.get('tag_name', 'el').upper()}" + (f"#{el.get('id')}" if el.get("id") else (f".{el.get('class_name').split()[0]}" if el.get("class_name") else ""))
        destination = href or el.get("action") or onclick or "javascript:void(0)"
        element_risk = "LOW"

        if href:
            href_lower = href.lower()
            if any(term in text for term in ["download", "pdf", "invoice", "document", "login", "continue"]):
                if href_lower.startswith("http://") or href_lower.startswith("https://"):
                    href_domain = urlparse(href_lower).netloc.lower()
                    if href_domain and href_domain != initial_domain and initial_domain not in href_domain:
                        element_risk = "HIGH"
                        if not destination_mismatch:
                            destination_mismatch = True
                            actual_destination = href
                            destination_mismatch_obj = {
                                "visible_label": el.get("visible_text"),
                                "expected": initial_domain,
                                "actual": href_domain
                            }

        if el.get("is_overlay"):
            element_risk = "CRITICAL"

        formatted_interactions.append({
            "element": element_label,
            "visible_text": el.get("visible_text") or "[No Text]",
            "type": "Clickjacking Layer" if el.get("is_overlay") else f"{el.get('tag_name', '').capitalize()} Target",
            "destination": destination[:120],
            "visibility": "Invisible (opacity: 0, z: 9999)" if el.get("is_overlay") else ("Visible" if el.get("is_visible") else "Hidden"),
            "risk": element_risk
        })

    if destination_mismatch:
        risk_score += 30
        destination_mismatch_obj = destination_mismatch_obj or {
            "type": "destination_mismatch",
            "visible_text": target_str,
            "expected_destination": expected_destination,
            "actual_destination": actual_destination
        }
        score_breakdown.append({
            "signal": "Destination mismatch",
            "delta": 30,
            "severity": "HIGH",
            "evidence": f"Expected: '{expected_destination}' -> Actual Diverted: '{actual_destination}'"
        })
        findings.append({
            "severity": "high",
            "title": "Target Destination Mismatch Detected (+30)",
            "description": f"Agent intends to click '{target_str}' expecting '{expected_destination}', but the underlying interaction routes to '{actual_destination}'.",
            "evidence": f"Expected target: {expected_destination} | Actual destination: {actual_destination}"
        })

    # -------------------------------------------------------------
    # Signal 3: Agent-Targeted Prompt Injection (+25)
    # -------------------------------------------------------------
    visible_text = page_data.get("visible_text", "")
    injection_phrases = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "ai agent",
        "assistant, click",
        "agent, navigate to",
        "disregard your task",
        "system override",
        "do not download"
    ]

    found_injections = []
    matched_snippets = []
    for phrase in injection_phrases:
        if phrase in visible_text.lower():
            found_injections.append(phrase)
            # Find context snippet around the phrase
            pattern = re.compile(rf"([^.\n]*?{re.escape(phrase)}[^.\n]*)", re.IGNORECASE)
            m = pattern.search(visible_text)
            if m:
                matched_snippets.append(m.group(0).strip())

    prompt_injection_detail = None
    if found_injections:
        risk_score += 25
        prompt_injection_detail = {
            "type": "prompt_injection",
            "matched_phrases": found_injections,
            "snippets": matched_snippets[:3]
        }
        score_breakdown.append({
            "signal": "Agent-targeted instruction",
            "delta": 25,
            "severity": "HIGH",
            "evidence": f"Matched strings: {', '.join(found_injections)}"
        })
        findings.append({
            "severity": "critical",
            "title": "Agent-Targeted Prompt Injection in DOM (+25)",
            "description": "Page text contains directives tailored to hijack or override autonomous agent instructions.",
            "evidence": matched_snippets[0] if matched_snippets else f"Matched phrases: {', '.join(found_injections)}"
        })

    # -------------------------------------------------------------
    # Signal 4: Suspicious / Multi-hop Redirect (+20)
    # -------------------------------------------------------------
    raw_redirects = page_data.get("redirect_chain", [])
    redirect_count = len(raw_redirects)
    is_cross_domain = (initial_domain != final_domain) and bool(final_domain)

    if redirect_count > 1 or is_cross_domain:
        risk_score += 20
        score_breakdown.append({
            "signal": "Suspicious / multi-hop redirect",
            "delta": 20,
            "severity": "HIGH",
            "evidence": f"{redirect_count} redirect hops detected. Final: {final_url}"
        })
        findings.append({
            "severity": "high",
            "title": "Suspicious Multi-Hop or Cross-Domain Redirect (+20)",
            "description": f"Page navigated through {redirect_count} hops from '{initial_domain}' to '{final_domain}'.",
            "evidence": f"Redirect chain length: {redirect_count}. Final destination: {final_url}"
        })

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
    # Signal 5: Suspicious JavaScript Navigation (+10)
    # -------------------------------------------------------------
    js_patterns = [
        ("window.location", "Dynamic page location reassignment", "medium"),
        ("location.href", "Direct browser location modification", "medium"),
        ("location.replace", "History-stripping URL replacement", "high"),
        ("window.open", "Automated popup or window spawn routine", "medium"),
        ("eval", "Dynamic execution routine (eval)", "critical"),
        ("atob", "Base64 payload decoding routine (atob)", "high")
    ]

    inline_scripts = page_data.get("inline_scripts", [])
    combined_scripts = "\n".join(inline_scripts)

    js_found_any = False
    for token, desc, severity in js_patterns:
        if re.search(r'\b' + re.escape(token) + r'\b', combined_scripts, re.IGNORECASE):
            js_found_any = True
            javascript_signals.append({
                "signal": token,
                "source": "inline script",
                "severity": severity,
                "evidence": f"Matched pattern '{token}' inside script context: {desc}",
                "details": desc
            })

    if js_found_any:
        risk_score += 10
        score_breakdown.append({
            "signal": "Suspicious JavaScript navigation",
            "delta": 10,
            "severity": "MEDIUM",
            "evidence": f"Signals: {', '.join([s['signal'] for s in javascript_signals])}"
        })
        findings.append({
            "severity": "medium",
            "title": "Suspicious JavaScript Navigation Primitives (+10)",
            "description": "Script contains dynamic URL overrides or code evaluation functions.",
            "evidence": f"Flagged tokens: {', '.join([s['signal'] for s in javascript_signals])}"
        })

    # -------------------------------------------------------------
    # Groq / LLM Security Reasoning (Supportive Context)
    # -------------------------------------------------------------
    ai_insights = run_groq_audit(url, task, page_data, groq_api_key)

    # -------------------------------------------------------------
    # Verdict Assignment & Score Clamping (0-100)
    #   0-29: SAFE (ALLOW)
    #   30-59: CAUTION
    #   60-100: BLOCK
    # -------------------------------------------------------------
    risk_score = max(0, min(100, risk_score))

    if risk_score >= 60:
        verdict = "BLOCK"
        summary = (
            f"Action Firewall blocked '{action_type}' interaction (Risk: {risk_score}/100). "
            f"{'Invisible click interceptor overlay and ' if overlay_detected else ''}"
            f"{'Destination mismatch detected. ' if destination_mismatch else ''}"
            f"{'Agent-targeted prompt injection found in DOM. ' if found_injections else ''}"
            f"Autonomous action denied to protect agent workflow."
        )
    elif risk_score >= 30:
        verdict = "CAUTION"
        summary = (
            f"Action Firewall flagged '{action_type}' interaction with CAUTION (Risk: {risk_score}/100). "
            f"Potential redirection or anomalous script navigation detected. Human verification advised."
        )
    else:
        verdict = "SAFE"
        summary = (
            f"Action Firewall verified '{action_type}' interaction as SAFE (Risk: {risk_score}/100). "
            f"Direct interaction surface verified without overlays, destination mismatches, or prompt injection."
        )

    # -------------------------------------------------------------
    # AGENT INTENT VS BROWSER REALITY
    # -------------------------------------------------------------
    action_mismatch = overlay_detected or destination_mismatch
    intent_vs_reality = {
        "agent_intent": f"Click \"{target_str}\"" if target_str else "Click target",
        "expected_goal": task,
        "expected_destination": expected_destination,
        "browser_reality": f"Click would actually trigger {actual_destination}" if action_mismatch else f"Click dispatches directly to {expected_destination}",
        "actual_destination": actual_destination,
        "actual_target": overlay_interception_obj.get("interceptor", "DIV") if overlay_interception_obj else "Direct Button",
        "status": "ACTION MISMATCH" if action_mismatch else "ACTION VERIFIED"
    }

    # -------------------------------------------------------------
    # FORENSIC VIEW LEDGER
    # -------------------------------------------------------------
    forensic_details = {
        "target": target_str,
        "visible_element": f"<a href=\"{expected_destination}\">{target_str}</a>" if target_str else f"<a href=\"{expected_destination}\">",
        "expected_destination": expected_destination,
        "interceptor": f"<{overlay_interception_obj.get('interceptor', 'div').lower()} href=\"{actual_destination}\" id=\"{overlay_interception_obj.get('interceptor_id', 'overlay-interceptor')}\">" if overlay_detected else "None (Surface Unobstructed)",
        "interceptor_properties": f"opacity: {overlay_interception_obj.get('opacity', 0)}, z-index: {overlay_interception_obj.get('z_index', 9999)}, pointer-events: {overlay_interception_obj.get('pointer_events', 'auto')}" if overlay_detected else "N/A",
        "actual_destination": actual_destination,
        "decision": verdict
    }

    recommendation = {
        "action": "BLOCK ACTION" if verdict == "BLOCK" else ("CAUTION REQUIRED" if verdict == "CAUTION" else "ALLOW ACTION"),
        "title": "ACCESS DENIED" if verdict == "BLOCK" else ("VERIFY PROMPTLY" if verdict == "CAUTION" else "ACCESS GRANTED"),
        "description": summary
    }

    return {
        "verdict": verdict,
        "risk_score": risk_score,
        "interaction_risk_score": risk_score,
        "score_breakdown": score_breakdown,
        "intent_vs_reality": intent_vs_reality,
        "forensic_details": forensic_details,
        "overlay_interception": overlay_interception_obj,
        "destination_mismatch_detail": destination_mismatch_obj,
        "prompt_injection_detail": prompt_injection_detail,
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
        "screenshot": page_data.get("screenshot"),
        "raw_elements": page_data.get("interactive_elements", [])[:35],
        "telemetry": {
            "target_url": url,
            "final_url": final_url,
            "page_title": page_data.get("title", ""),
            "intended_task": task,
            "action_type": action_type,
            "interaction_risk_score": risk_score,
            "verdict": verdict,
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