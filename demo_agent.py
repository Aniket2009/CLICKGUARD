import asyncio
import sys
import os

# Fix for Windows asyncio loop with Playwright subprocesses
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from pathlib import Path

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    async_playwright = None
    PLAYWRIGHT_AVAILABLE = False


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

try:
    from backend.analyzer import analyze_url, authorize_action
except ImportError:
    from analyzer import analyze_url, authorize_action

# Default to the local demo trap page
DEFAULT_DEMO_PAGE = (PROJECT_ROOT / "demo_site" / "trap.html").as_uri()
DEFAULT_TASK = "Download the PDF from this page"


async def unshielded_agent(page, url: str):
    """
    Simulates a standard autonomous browser agent interacting with a webpage
    without any security middleware or pre-execution inspection.
    """
    print("\n" + "=" * 60)
    print(" [UNSHIELDED AGENT] - Execution Started (No Action Firewall)")
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
        print(" [!] The agent clicked an invisible overlay that hijacked pointer coordinates.")
    elif "safe_result.html" in final_url:
        print("\n [+] SUCCESS: Agent reached the intended safe destination.")
    else:
        print(f"\n [*] Agent ended on: {final_url}")
    print("=" * 60 + "\n")


async def shielded_agent(page, url: str):
    """
    Simulates a protected autonomous agent operating with ClickGuard Action Firewall.
    Requests authorization before dispatching sensitive browser interactions.
    """
    print("\n" + "=" * 60)
    print(" [SHIELDED AGENT] - Protected by ClickGuard Action Firewall")
    print("=" * 60)
    print(f"[*] Target URL: {url}")
    print(f"[*] Intended Agent Task: {DEFAULT_TASK}")
    print(f"[*] Proposed Browser Action: Click \"Download PDF\"")

    print("\n[>>>] ClickGuard Action Firewall: Requesting pre-interaction authorization...")
    auth = await authorize_action(
        action="click",
        target="Download PDF",
        task=DEFAULT_TASK,
        url=url
    )

    risk_score = auth.get("interaction_risk_score", 0)
    verdict = auth.get("verdict", "BLOCK")
    authorized = auth.get("action_authorized", False)
    breakdown = auth.get("score_breakdown", [])
    ivr = auth.get("intent_vs_reality", {})
    forensics = auth.get("forensic_details", {})

    print("\n" + "-" * 50)
    print(f" INTERACTION RISK SCORE: {risk_score} / 100")
    print("-" * 50)
    for b in breakdown:
        print(f"  +{b.get('delta', 0):<2} {b.get('signal')}")

    print("\n" + "-" * 50)
    print(" AGENT INTENT VS BROWSER REALITY")
    print("-" * 50)
    print(f"  AGENT INTENT:        {ivr.get('agent_intent')}")
    print(f"  EXPECTED GOAL:       {ivr.get('expected_goal')}")
    print(f"  EXPECTED TARGET:     {ivr.get('expected_destination')}")
    print(f"  BROWSER REALITY:     {ivr.get('browser_reality')}")
    print(f"  ACTUAL DESTINATION:  {ivr.get('actual_destination')}")
    print(f"  STATUS:              {ivr.get('status')}")

    if forensics and forensics.get("interceptor") != "None (Surface Unobstructed)":
        print("\n" + "-" * 50)
        print(" FORENSIC EVIDENCE")
        print("-" * 50)
        print(f"  VISIBLE ELEMENT:     {forensics.get('visible_element')}")
        print(f"  INTERCEPTOR ELEMENT: {forensics.get('interceptor')}")
        print(f"  PROPERTIES:          {forensics.get('interceptor_properties')}")

    ai_insights = auth.get("ai_reasoning")
    if ai_insights and "error" not in ai_insights:
        print("\n [GROQ AI CONTEXTUAL REASONING]")
        print(f" > Model:      {ai_insights.get('model_used')}")
        print(f" > AI Verdict: {ai_insights.get('ai_verdict')}")
        print(f" > Assessment: {ai_insights.get('deception_analysis') or ai_insights.get('executive_summary')}")

    print("-" * 50)

    # Security policy evaluation
    if not authorized or verdict == "BLOCK":
        print("\n" + "!" * 55)
        print(" [!] CLICKGUARD ACTION FIREWALL: ACCESS DENIED")
        print(" [!] Action blocked before pointer coordinates reached the DOM.")
        print(f" [!] Reason: {auth.get('summary')}")
        print("!" * 55)
        print(" [*] Agent aborted click interaction. Security posture preserved.")
    else:
        print("\n" + "*" * 55)
        print(" [+] CLICKGUARD ACTION FIREWALL: ACCESS GRANTED")
        print(" [+] Interaction surface verified clean.")
        print("*" * 55)
        print("[*] Proceeding with authorized interaction...")

        await page.goto(url, wait_until="load")
        target_locator = page.locator("text=Download PDF").first
        await target_locator.click()
        await page.wait_for_timeout(1000)
        print(f"[+] Task completed safely. Current destination: {page.url}")

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

    if PLAYWRIGHT_AVAILABLE:
        async with async_playwright() as p:
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
    else:
        # Standalone simulated agent mode (no external browser binary needed)
        class SimulatedPage:
            def __init__(self, current_url):
                self.url = current_url
            async def title(self):
                return "Quantum Research Archive"
            async def goto(self, url, wait_until=None):
                self.url = url
            async def wait_for_timeout(self, ms):
                await asyncio.sleep(ms / 1000)
            def locator(self, sel):
                class SimLocator:
                    def __init__(self, page_ref):
                        self.p = page_ref
                        self.first = self
                    async def wait_for(self, state=None, timeout=None):
                        pass
                    async def click(self):
                        if "trap" in self.p.url:
                            self.p.url = "demo_site/trap_result.html"
                        else:
                            self.p.url = "demo_site/safe_result.html"
                return SimLocator(self)


        sim_page = SimulatedPage(target_url)
        if mode == "unshielded":
            await unshielded_agent(sim_page, target_url)
        elif mode == "shielded":
            await shielded_agent(sim_page, target_url)



if __name__ == "__main__":
    asyncio.run(main())
