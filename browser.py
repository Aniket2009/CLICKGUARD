from typing import Dict, List, Any
from urllib.parse import urlparse
from pathlib import Path
import os
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    async_playwright = None
    PLAYWRIGHT_AVAILABLE = False


async def inspect_page(url: str) -> Dict[str, Any]:
    """
    Launches a headless Chromium browser using Playwright, navigates to the target URL,
    monitors network requests & redirects, extracts DOM elements and interactive surfaces,
    and returns comprehensive telemetry data.
    """
    if not PLAYWRIGHT_AVAILABLE:
        raise RuntimeError("Playwright is not installed in the current Python environment.")

    # Normalize local relative or absolute file paths to file:// URI
    normalized_url = url
    if not (url.startswith("http://") or url.startswith("https://") or url.startswith("file://")):
        local_path = Path(url).resolve()
        if local_path.exists():
            normalized_url = local_path.as_uri()

    requests_log: List[Dict[str, Any]] = []
    redirect_chain: List[Dict[str, Any]] = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 ClickGuard/1.0",
                ignore_https_errors=True
            )
            page = await context.new_page()

            # Record all network requests
            def on_request(request):
                requests_log.append({
                    "url": request.url,
                    "method": request.method,
                    "resource_type": request.resource_type,
                    "is_navigation_request": request.is_navigation_request()
                })

            # Record response navigation & redirects
            def on_response(response):
                if response.status in (301, 302, 303, 307, 308):
                    redirect_chain.append({
                        "url": response.url,
                        "status": response.status,
                        "status_text": response.status_text,
                        "location_header": response.headers.get("location", "")
                    })

            page.on("request", on_request)
            page.on("response", on_response)

            # Navigate to the supplied URL with resilience for real-world heavy pages
            nav_response = None
            try:
                nav_response = await page.goto(normalized_url, wait_until="domcontentloaded", timeout=20000)
                await page.wait_for_timeout(1000)
            except Exception as nav_err:
                # If domcontentloaded timed out on heavy ads/trackers, proceed with whatever DOM loaded
                print(f"[Browser Nav Warning]: {nav_err}")

            # Record initial / final redirect states if not captured by listener
            if nav_response and nav_response.request.redirected_from:
                curr_req = nav_response.request.redirected_from
                hops = []
                while curr_req:
                    hops.append({
                        "url": curr_req.url,
                        "method": curr_req.method
                    })
                    curr_req = curr_req.redirected_from
                for hop in reversed(hops):
                    parsed_hop = urlparse(hop["url"])
                    if not any(r.get("url") == hop["url"] for r in redirect_chain):
                        redirect_chain.append({
                            "url": hop["url"],
                            "domain": parsed_hop.netloc or parsed_hop.path,
                            "status": 302,
                            "status_text": "Redirect",
                            "location_header": ""
                        })

            # Collect basic page metadata
            final_url = page.url
            title = await page.title()

            # Collect DOM counts, scripts, and visible page text
            page_stats = await page.evaluate("""() => {
                const allElements = document.querySelectorAll('*');
                const scriptElements = document.querySelectorAll('script');
                const scriptSources = [];
                const inlineScripts = [];

                scriptElements.forEach(s => {
                    if (s.src) {
                        scriptSources.push(s.src);
                    } else if (s.textContent) {
                        inlineScripts.push(s.textContent.slice(0, 1500));
                    }
                });

                return {
                    dom_element_count: allElements.length,
                    script_count: scriptElements.length,
                    script_sources: scriptSources,
                    inline_scripts: inlineScripts,
                    visible_text: document.body ? (document.body.innerText || '') : ''
                };
            }""")

            # Collect interactive elements (buttons, links, forms, inputs) and check for overlapping interceptors
            interactive_elements = await page.evaluate("""() => {
                const targets = document.querySelectorAll('button, a, input, form, [role="button"], [onclick], .btn-download, .invisible-interceptor-overlay');
                const collected = [];

                targets.forEach((el, idx) => {
                    if (idx >= 60) return; // limit to first 60 elements for performance
                    const rect = el.getBoundingClientRect();
                    const style = window.getComputedStyle(el);

                    const isVisible = !(
                        style.display === 'none' ||
                        style.visibility === 'hidden' ||
                        parseFloat(style.opacity) === 0 ||
                        (rect.width === 0 && rect.height === 0)
                    );

                    // Check if element is full-screen or transparent overlay
                    const opacityVal = parseFloat(style.opacity);
                    const isOverlay = (
                        (style.position === 'fixed' || style.position === 'absolute') &&
                        (
                            (rect.width >= window.innerWidth * 0.7 && rect.height >= window.innerHeight * 0.7) ||
                            (parseInt(style.zIndex, 10) > 1000 && opacityVal < 0.2) ||
                            el.classList.contains('invisible-interceptor-overlay')
                        ) &&
                        (opacityVal < 0.2 || style.backgroundColor.includes('rgba(0, 0, 0, 0)') || style.backgroundColor === 'transparent')
                    );

                    // Check whether another element intercepts clicks at the element's center point
                    let interceptor = null;
                    if (rect.width > 0 && rect.height > 0) {
                        const cx = rect.x + rect.width / 2;
                        const cy = rect.y + rect.height / 2;
                        if (cx >= 0 && cx <= window.innerWidth && cy >= 0 && cy <= window.innerHeight) {
                            const topEl = document.elementFromPoint(cx, cy);
                            if (topEl && topEl !== el && !el.contains(topEl) && !topEl.contains(el)) {
                                const topStyle = window.getComputedStyle(topEl);
                                const topRect = topEl.getBoundingClientRect();
                                const topOpacity = parseFloat(topStyle.opacity);
                                const topZ = topStyle.zIndex || 'auto';
                                const topPE = topStyle.pointerEvents || 'auto';

                                if (topPE !== 'none') {
                                    interceptor = {
                                        type: "overlay_interception",
                                        severity: "HIGH",
                                        target: (el.innerText || el.value || el.id || 'target').trim().slice(0, 60),
                                        interceptor: topEl.tagName,
                                        interceptor_id: topEl.id || null,
                                        interceptor_class: topEl.className || null,
                                        interceptor_href: topEl.getAttribute('href') || null,
                                        opacity: isNaN(topOpacity) ? 1.0 : topOpacity,
                                        z_index: topZ,
                                        pointer_events: topPE,
                                        bounding_box: {
                                            x: Math.round(topRect.x),
                                            y: Math.round(topRect.y),
                                            width: Math.round(topRect.width),
                                            height: Math.round(topRect.height)
                                        }
                                    };
                                }
                            }
                        }
                    }

                    collected.push({
                        tag_name: el.tagName.toLowerCase(),
                        id: el.id || null,
                        class_name: el.className || null,
                        visible_text: (el.innerText || el.value || el.getAttribute('aria-label') || '').trim().slice(0, 120),
                        href: el.getAttribute('href') || null,
                        action: el.getAttribute('action') || null,
                        bounding_box: {
                            x: Math.round(rect.x),
                            y: Math.round(rect.y),
                            width: Math.round(rect.width),
                            height: Math.round(rect.height)
                        },
                        is_visible: isVisible,
                        is_overlay: isOverlay,
                        z_index: style.zIndex || 'auto',
                        opacity: style.opacity || '1',
                        pointer_events: style.pointerEvents || 'auto',
                        position: style.position || 'static',
                        onclick_attr: el.getAttribute('onclick') || null,
                        interceptor_detected: interceptor
                    });
                });

                return collected;
            }""")

            # Capture real page screenshot for the visual X-ray viewport
            screenshot_data = None
            try:
                import base64
                screenshot_bytes = await page.screenshot(type="jpeg", quality=65)
                screenshot_data = f"data:image/jpeg;base64,{base64.b64encode(screenshot_bytes).decode('utf-8')}"
            except Exception as ss_err:
                print(f"[Screenshot Notice]: {ss_err}")

            return {
                "initial_url": url,
                "final_url": final_url,
                "title": title,
                "screenshot": screenshot_data,
                "dom_element_count": page_stats.get("dom_element_count", 0),
                "script_count": page_stats.get("script_count", 0),
                "script_sources": page_stats.get("script_sources", []),
                "inline_scripts": page_stats.get("inline_scripts", []),
                "network_request_count": len(requests_log),
                "network_requests": requests_log[:100],
                "redirect_chain": redirect_chain,
                "visible_text": page_stats.get("visible_text", ""),
                "interactive_elements": interactive_elements
            }

        finally:
            await browser.close()