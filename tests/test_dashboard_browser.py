"""Real Chromium smoke test for the AuthTrace core workflow.

Runs against the local synthetic API only; never targets an external service.
"""
from pathlib import Path
import pytest

playwright_api = pytest.importorskip("playwright.sync_api")
sync_playwright = playwright_api.sync_playwright
expect = playwright_api.expect

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
        page.on(
            "response",
            lambda response: failed_responses.append(f"{response.status} {response.url}")
            if response.status >= 500 else None,
        )

        response = page.goto(BASE_URL, wait_until="networkidle", timeout=30000)
        assert response and response.status == 200, "Dashboard root did not return HTTP 200"
        expect(page).to_have_title("AuthTrace — Security Control Center")
        expect(page.locator("#demoMode")).to_be_visible()
        expect(page.locator("#content h1")).to_contain_text("Security at a glance", timeout=15000)

        mode_response = page.request.get(f"{BASE_URL}/api/demo-mode")
        assert mode_response.status == 200, f"/api/demo-mode returned {mode_response.status}"
        mode_data = mode_response.json()
        assert mode_data.get("mode") in {"fixed", "vulnerable", "unknown"}, mode_data
        expected_mode = {
            "fixed": "Demo mode: Fixed",
            "vulnerable": "Demo mode: Vulnerable",
            "unknown": "Demo mode: Unknown / API unavailable",
        }[mode_data["mode"]]
        expect(page.locator("#demoMode")).to_contain_text(expected_mode)

        # Verify each primary view uses its real title and updates navigation state.
        for page_id, heading in [
            ("diff", "Policy Diff"),
            ("lab", "Run a security test"),
            ("runs", "Test History"),
            ("reports", "Reports"),
        ]:
            page.locator(f'button[data-page="{page_id}"]').click()
            expect(page.locator("#content h1")).to_contain_text(heading, timeout=10000)
            expect(page.locator("#crumb")).to_contain_text(
                {"diff": "Policy Diff", "lab": "Test Lab", "runs": "Test Runs", "reports": "Reports"}[page_id]
            )
            expect(page.locator(f'button[data-page="{page_id}"]')).to_have_attribute("aria-current", "page")
            if page_id == "diff":
                policies_before = page.request.get(f"{BASE_URL}/api/policies").json()
                page.locator('[data-example="unsafe"]').click()
                assert '"expected": "allow"' in page.locator("#policyEditor").input_value()
                expect(page.locator("#policyMessage")).to_contain_text("editor only")
                # Loading and validating examples must not silently submit them.
                page.locator("#validatePolicy").click()
                expect(page.locator("#policyMessage")).to_contain_text("VALID", timeout=10000)
                policies_after = page.request.get(f"{BASE_URL}/api/policies").json()
                assert policies_after["proposal_sha256"] == policies_before["proposal_sha256"], (
                    "Loading/validating an example unexpectedly changed the submitted proposal"
                )

        # Advanced pages remain navigable and render their actual content.
        page.locator(".nav-more summary").click()
        for page_id, heading in [
            ("planner", "Regression Planner"),
            ("evidence", "Evidence Explorer"),
            ("targets", "API Targets"),
            ("suites", "Test Suites"),
            ("settings", "Settings"),
        ]:
            page.locator(f'button[data-page="{page_id}"]').click()
            expect(page.locator("#content h1")).to_contain_text(heading, timeout=10000)

        # Execute the selected policy-linked test against the fixed local synthetic API.
        page.locator('button[data-page="lab"]').click()
        expect(page.locator("#content h1")).to_contain_text("Run a security test")
        expect(page.locator("#launchRun")).to_be_enabled()
        page.locator("#confirmTarget").check()
        page.once("dialog", lambda dialog: dialog.accept())
        page.locator("#launchRun").click()
        expect(page.locator("#content h1")).to_contain_text("Test History", timeout=30000)
        expect(page.locator("#runDetail")).to_contain_text("Test run results", timeout=30000)
        expect(page.locator("#runDetail")).to_contain_text("Run ID:")
        expect(page.locator("#runDetail")).to_contain_text("Technical report")

        # Open the same run through Evidence Explorer and ensure its detail panel works.
        # The advanced menu remains expanded after visiting an advanced page.
        page.locator('button[data-page="evidence"]').click()
        expect(page.locator("#content h1")).to_contain_text("Evidence Explorer")
        page.locator('button[data-run]').first.click()
        expect(page.locator("#evidenceDetail")).to_contain_text("Test run results", timeout=15000)
        expect(page.locator("#evidenceDetail")).to_contain_text("Technical report")

        page.locator("#themeBtn").click()
        page.screenshot(path=str(ARTIFACTS / "dashboard-desktop.png"), full_page=True)

        # Check a narrow viewport for horizontal overflow and visible page content.
        page.set_viewport_size({"width": 390, "height": 844})
        page.reload(wait_until="networkidle")
        expect(page.locator("#content h1")).to_contain_text("Security at a glance", timeout=15000)
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
