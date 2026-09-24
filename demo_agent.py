import asyncio
import sys
import os
from pathlib import Path
from playwright.async_api import async_playwright

# Ensure project root is in sys.path so backend modules can be imported
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Load .env if available
try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    pass

from backend.analyzer import analyze_url

# Default to the local demo trap page
DEFAULT_DEMO_PAGE = (PROJECT_ROOT / "demo_site" / "trap.html").as_uri()
DEFAULT_TASK = "Download the PDF from this page"


async def unshielded_agent(page, url: str):
    """
    Simulates a standard autonomous browser agent interacting with a webpage
    without any security middleware or pre-execution inspection.
    """
    print("\n" + "=" * 60)
    print(" [UNSHIELDED AGENT] - Execution Started")
    print("=" * 60)
    print(f"[*] Navigating to target URL: {url}")

    await page.goto(url, wait_until="load")
    print(f"[+] Page successfully loaded: '{await page.title()}'")

    print(f"[*] Locating interaction target matching: '{DEFAULT_TASK}'...")
    # Locate the visible download button/link
    target_locator = page.locator("text=Download PDF").first
    await target_locator.wait_for(state="visible", timeout=5000)
    print("[+] Target interaction element located on page.")

    print("[!] Interacting directly without security middleware...")
    # Standard agent directly clicks the element bounding box
    await target_locator.click()
    print("[+] Action executed: Click performed.")

    # Wait briefly to observe destination navigation
    await page.wait_for_timeout(1500)
    final_url = page.url
    print(f"[*] Final browser destination: {final_url}")

    if "trap_result.html" in final_url:
        print("\n [!] COMPROMISED: Agent fell into the deceptive clickjacking trap!")
    elif "safe_result.html" in final_url:
        print("\n [+] SUCCESS: Agent reached the intended safe destination.")
    else:
        print(f"\n [*] Agent ended on: {final_url}")
    print("=" * 60 + "\n")


async def shielded_agent(page, url: str):
    """
    Simulates a protected autonomous agent operating with ClickGuard middleware.
    Inspects webpage heuristics before executing any interaction.
    """
    print("\n" + "=" * 60)
    print(" [SHIELDED AGENT] - Protected by ClickGuard")
    print("=" * 60)
    print(f"[*] Target URL: {url}")
    print(f"[*] Intended Agent Task: {DEFAULT_TASK}")

    print("\n[>>>] ClickGuard: Running pre-interaction security inspection...")
    analysis = await analyze_url(url, DEFAULT_TASK)

    risk_score = analysis.get("risk_score", 0)
    verdict = analysis.get("verdict", "BLOCK")
    findings = analysis.get("findings", [])

    print("\n" + "-" * 40)
    print(" CLICKGUARD INSPECTION TELEMETRY")
    print("-" * 40)
    print(f" > Verdict:    {verdict}")
    print(f" > Risk Score: {risk_score} / 100")
    print(f" > Total Findings: {len(findings)}")

    for i, finding in enumerate(findings, 1):
        sev = finding.get("severity", "info").upper()
        title = finding.get("title", "")
        print(f"   [{sev}] Finding #{i}: {title}")
        evidence = finding.get("evidence")
        if evidence:
            print(f"         Evidence: {evidence}")

    ai_insights = analysis.get("ai_insights")
    if ai_insights and "error" not in ai_insights:
        print("\n [AI REASONING - GROQ LLAMA-3]")
        print(f" > Model:      {ai_insights.get('model_used')}")
        print(f" > AI Verdict: {ai_insights.get('ai_verdict')}")
        print(f" > Assessment: {ai_insights.get('deception_analysis') or ai_insights.get('executive_summary')}")
        if ai_insights.get("recommended_action"):
            print(f" > AI Advice:  {ai_insights.get('recommended_action')}")

    print("-" * 40)

    # Security policy evaluation
    if verdict == "BLOCK":
        print("\n" + "!" * 50)
        print(" [!] CLICKGUARD ENFORCEMENT: ACCESS DENIED")
        print(" [!] Execution blocked before pointer coordinates reached the DOM.")
        print(f" [!] Reason: {analysis.get('summary', 'Adversarial pattern detected.')}")
        print("!" * 50)
        print(" [*] Agent aborted click interaction. Security posture preserved.")
    else:
        print("\n" + "*" * 50)
        print(" [+] CLICKGUARD VERDICT: ACCESS GRANTED")
        print(" [+] Webpage interaction surface verified clean.")
        print("*" * 50)
        print("[*] Proceeding with authorized interaction...")

        await page.goto(url, wait_until="load")
        target_locator = page.locator("text=Download PDF").first
        await target_locator.click()
        await page.wait_for_timeout(1000)
        print(f"[+] Task completed. Current destination: {page.url}")

    print("=" * 60 + "\n")


async def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python agents/demo_agent.py unshielded [url]")
        print("  python agents/demo_agent.py shielded   [url]")
        print(f"\nDefault URL: {DEFAULT_DEMO_PAGE}")
        sys.exit(1)

    mode = sys.argv[1].lower().strip()
    target_url = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_DEMO_PAGE

    if mode not in ("unshielded", "shielded"):
        print(f"Invalid mode '{mode}'. Choose 'unshielded' or 'shielded'.")
        sys.exit(1)

    async with async_playwright() as p:
        # Launch with headless=False so judges can visually observe the browser in real time
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        try:
            if mode == "unshielded":
                await unshielded_agent(page, target_url)
            elif mode == "shielded":
                await shielded_agent(page, target_url)
        finally:
            await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
