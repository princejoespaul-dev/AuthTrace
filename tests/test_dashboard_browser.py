from pathlib import Path
from playwright.sync_api import sync_playwright, expect

BASE_URL = "http://127.0.0.1:8010"
ARTIFACTS = Path("artifacts")
ARTIFACTS.mkdir(exist_ok=True)


def test_dashboard_in_chromium():
    console_errors = []
    page_errors = []
    failed_responses = []

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
        page.on("pageerror", lambda exc: page_errors.append(str(exc)))
        page.on("response", lambda response: failed_responses.append(
            f"{response.status} {response.url}"
        ) if response.status >= 500 else None)

        response = page.goto(BASE_URL, wait_until="networkidle", timeout=30000)
        assert response and response.status == 200, "Dashboard root did not return HTTP 200"
        expect(page).to_have_title("AuthTrace — Security Control Center")
        expect(page.locator("#demoMode")).to_be_visible()
        expect(page.locator("#content h1")).to_contain_text("Overview", timeout=15000)

        mode_response = page.request.get(f"{BASE_URL}/api/demo-mode")
        assert mode_response.status == 200, f"/api/demo-mode returned {mode_response.status}"
        mode_data = mode_response.json()
        assert mode_data.get("mode") in {"fixed", "vulnerable", "unknown"}, mode_data
        expect(page.locator("#demoMode")).to_contain_text(
            "Fixed" if mode_data["mode"] == "fixed" else
            "Vulnerable" if mode_data["mode"] == "vulnerable" else "Unknown"
        )

        # Exercise primary navigation and confirm each view renders real page content.
        for page_id, heading in [
            ("diff", "Policy Diff"),
            ("lab", "Test Lab"),
            ("runs", "Test Runs"),
            ("reports", "Reports"),
        ]:
            page.locator(f'button[data-page="{page_id}"]').click()
            expect(page.locator("#content h1")).to_contain_text(heading, timeout=10000)
            expect(page.locator("#crumb")).to_contain_text(heading)

        # Check the theme control responds without crashing the page.
        page.locator("#themeBtn").click()
        page.screenshot(path=str(ARTIFACTS / "dashboard-desktop.png"), full_page=True)

        # Check a narrow viewport for horizontal page overflow and visible navigation.
        page.set_viewport_size({"width": 390, "height": 844})
        page.reload(wait_until="networkidle")
        expect(page.locator("#content h1")).to_contain_text("Overview", timeout=15000)
        mobile_metrics = page.evaluate("""() => ({
            viewport: document.documentElement.clientWidth,
            document: document.documentElement.scrollWidth,
            body: document.body.scrollWidth
        })""")
        page.screenshot(path=str(ARTIFACTS / "dashboard-mobile.png"), full_page=True)
        assert mobile_metrics["document"] <= mobile_metrics["viewport"] + 2, (
            f"Horizontal overflow on mobile: {mobile_metrics}"
        )

        browser.close()

    assert not page_errors, "Uncaught browser exceptions: " + " | ".join(page_errors)
    assert not failed_responses, "Server errors in browser: " + " | ".join(failed_responses)
    assert not console_errors, "Browser console errors: " + " | ".join(console_errors)
